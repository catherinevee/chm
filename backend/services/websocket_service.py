"""
WebSocket Service for real-time updates in CHM.

This module provides comprehensive WebSocket functionality including:
- Real-time metric streaming
- Alert notifications
- Device status updates
- Dashboard live updates
- Multi-client broadcasting
- Room-based messaging
- Authentication and authorization
- Connection management and heartbeat
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
import uuid
from collections import defaultdict

from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
import jwt

from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from backend.common.exceptions import AuthenticationError, WebSocketError
from backend.services.auth_service import auth_service
from backend.services.permission_service import permission_service, PermissionContext
# Cache manager not yet implemented
cache_manager = None




class MessageType(str, Enum):
    """WebSocket message types."""
    # Connection management
    CONNECT = "connect"
    DISCONNECT = "disconnect"
    PING = "ping"
    PONG = "pong"
    AUTH = "auth"
    
    # Subscriptions
    SUBSCRIBE = "subscribe"
    UNSUBSCRIBE = "unsubscribe"
    
    # Data messages
    METRIC = "metric"
    ALERT = "alert"
    DEVICE_STATUS = "device_status"
    NOTIFICATION = "notification"
    EVENT = "event"
    
    # Control messages
    COMMAND = "command"
    RESPONSE = "response"
    ERROR = "error"


class SubscriptionType(str, Enum):
    """Types of subscriptions."""
    ALL = "all"
    METRICS = "metrics"
    ALERTS = "alerts"
    DEVICE = "device"
    DASHBOARD = "dashboard"
    EVENTS = "events"


class ConnectionState(str, Enum):
    """WebSocket connection states."""
    CONNECTING = "connecting"
    AUTHENTICATED = "authenticated"
    ACTIVE = "active"
    IDLE = "idle"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"


@dataclass
class WebSocketClient:
    """WebSocket client connection."""
    id: str
    websocket: WebSocket
    user_id: Optional[int] = None
    username: Optional[str] = None
    state: ConnectionState = ConnectionState.CONNECTING
    subscriptions: Set[str] = field(default_factory=set)
    rooms: Set[str] = field(default_factory=set)
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebSocketMessage:
    """WebSocket message structure."""
    type: MessageType
    data: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender: Optional[str] = None
    room: Optional[str] = None


class WebSocketConfig(BaseModel):
    """WebSocket service configuration."""
    max_connections: int = 1000
    max_connections_per_user: int = 5
    heartbeat_interval: int = 30
    idle_timeout: int = 300
    reconnect_timeout: int = 60
    message_queue_size: int = 100
    enable_compression: bool = True
    max_message_size: int = 65536
    auth_required: bool = True


class RateLimiter:
    """Rate limiter for WebSocket messages."""
    
    def __init__(self, max_messages: int = 100, window: int = 60):
        """Initialize rate limiter."""
        self.max_messages = max_messages
        self.window = window
        self.clients: Dict[str, List[float]] = defaultdict(list)
    
    def check_rate_limit(self, client_id: str) -> bool:
        """Check if client is within rate limit."""
        now = time.time()
        cutoff = now - self.window
        
        # Clean old timestamps
        self.clients[client_id] = [
            ts for ts in self.clients[client_id]
            if ts > cutoff
        ]
        
        # Check limit
        if len(self.clients[client_id]) >= self.max_messages:
            return False
        
        # Add current timestamp
        self.clients[client_id].append(now)
        return True


class WebSocketService:
    """Service for WebSocket communication."""
    
    def __init__(self, config: Optional[WebSocketConfig] = None):
        """Initialize WebSocket service."""
        self.config = config or WebSocketConfig()
        self.clients: Dict[str, WebSocketClient] = {}
        self.rooms: Dict[str, Set[str]] = defaultdict(set)
        self.subscriptions: Dict[str, Set[str]] = defaultdict(set)
        self.message_queue: Dict[str, List[WebSocketMessage]] = defaultdict(list)
        self.rate_limiter = RateLimiter()
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start WebSocket service."""
        if self._running:
            logger.warning("WebSocket service already running")
            return
        
        self._running = True
        
        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("WebSocket service started")
    
    async def stop(self):
        """Stop WebSocket service."""
        self._running = False
        
        # Cancel background tasks
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        # Disconnect all clients
        for client_id in list(self.clients.keys()):
            await self.disconnect_client(client_id)
        
        logger.info("WebSocket service stopped")
    
    async def connect_client(
        self,
        websocket: WebSocket,
        token: Optional[str] = None
    ) -> str:
        """Connect a new WebSocket client."""
        try:
            # Accept WebSocket connection
            await websocket.accept()
            
            # Generate client ID
            client_id = str(uuid.uuid4())
            
            # Create client instance
            client = WebSocketClient(
                id=client_id,
                websocket=websocket
            )
            
            # Authenticate if required
            if self.config.auth_required and token:
                user_info = await self._authenticate_client(token)
                if user_info:
                    client.user_id = user_info.get("user_id")
                    client.username = user_info.get("username")
                    client.state = ConnectionState.AUTHENTICATED
                    
                    # Check connection limit per user
                    if not await self._check_user_connection_limit(client.user_id):
                        await websocket.send_json({
                            "type": MessageType.ERROR.value,
                            "data": {"error": "Connection limit exceeded"}
                        })
                        await websocket.close()
                        return None
            
            # Store client
            self.clients[client_id] = client
            client.state = ConnectionState.ACTIVE
            
            # Send connection confirmation
            await self.send_to_client(
                client_id,
                WebSocketMessage(
                    type=MessageType.CONNECT,
                    data={
                        "client_id": client_id,
                        "connected": True,
                        "authenticated": client.state == ConnectionState.AUTHENTICATED
                    }
                )
            )
            
            logger.info(f"WebSocket client connected: {client_id}")
            return client_id
            
        except Exception as e:
            logger.error(f"Failed to connect WebSocket client: {e}")
            await websocket.close()
            return None
    
    async def disconnect_client(self, client_id: str):
        """Disconnect a WebSocket client."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return
            
            client.state = ConnectionState.DISCONNECTING
            
            # Remove from rooms
            for room in list(client.rooms):
                await self.leave_room(client_id, room)
            
            # Remove subscriptions
            for subscription in list(client.subscriptions):
                await self.unsubscribe(client_id, subscription)
            
            # Close WebSocket
            try:
                await client.websocket.close()
            except Exception as e:
                logger.debug(f"Exception caught: {e}")
            
            # Remove client
            del self.clients[client_id]
            
            logger.info(f"WebSocket client disconnected: {client_id}")
            
        except Exception as e:
            logger.error(f"Error disconnecting client {client_id}: {e}")
    
    async def handle_message(
        self,
        client_id: str,
        message: Dict[str, Any]
    ):
        """Handle incoming WebSocket message."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return
            
            # Check rate limit
            if not self.rate_limiter.check_rate_limit(client_id):
                await self.send_error(client_id, "Rate limit exceeded")
                return
            
            # Update activity
            client.last_activity = datetime.utcnow()
            
            # Parse message type
            msg_type = message.get("type")
            data = message.get("data", {})
            
            # Handle message based on type
            if msg_type == MessageType.PING.value:
                await self.handle_ping(client_id)
                
            elif msg_type == MessageType.AUTH.value:
                await self.handle_auth(client_id, data)
                
            elif msg_type == MessageType.SUBSCRIBE.value:
                await self.handle_subscribe(client_id, data)
                
            elif msg_type == MessageType.UNSUBSCRIBE.value:
                await self.handle_unsubscribe(client_id, data)
                
            elif msg_type == MessageType.COMMAND.value:
                await self.handle_command(client_id, data)
                
            else:
                await self.send_error(client_id, f"Unknown message type: {msg_type}")
                
        except Exception as e:
            logger.error(f"Error handling message from {client_id}: {e}")
            await self.send_error(client_id, str(e))
    
    async def send_to_client(
        self,
        client_id: str,
        message: WebSocketMessage
    ) -> bool:
        """Send message to specific client."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return False
            
            # Convert message to dict
            msg_dict = {
                "type": message.type.value,
                "data": message.data,
                "timestamp": message.timestamp.isoformat(),
                "id": message.id
            }
            
            if message.sender:
                msg_dict["sender"] = message.sender
            
            # Send message
            await client.websocket.send_json(msg_dict)
            return True
            
        except WebSocketDisconnect:
            await self.disconnect_client(client_id)
            return False
        except Exception as e:
            logger.error(f"Failed to send message to {client_id}: {e}")
            return False
    
    async def broadcast(
        self,
        message: WebSocketMessage,
        exclude: Optional[List[str]] = None
    ):
        """Broadcast message to all connected clients."""
        exclude = exclude or []
        
        tasks = []
        for client_id in self.clients:
            if client_id not in exclude:
                tasks.append(self.send_to_client(client_id, message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_to_room(
        self,
        room: str,
        message: WebSocketMessage,
        exclude: Optional[List[str]] = None
    ):
        """Send message to all clients in a room."""
        exclude = exclude or []
        message.room = room
        
        tasks = []
        for client_id in self.rooms.get(room, set()):
            if client_id not in exclude:
                tasks.append(self.send_to_client(client_id, message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_to_subscribers(
        self,
        subscription_type: str,
        message: WebSocketMessage
    ):
        """Send message to all subscribers of a type."""
        tasks = []
        for client_id in self.subscriptions.get(subscription_type, set()):
            tasks.append(self.send_to_client(client_id, message))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def join_room(self, client_id: str, room: str) -> bool:
        """Add client to a room."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return False
            
            # Check authorization
            if not await self._check_room_access(client, room):
                await self.send_error(client_id, f"Access denied to room: {room}")
                return False
            
            # Add to room
            self.rooms[room].add(client_id)
            client.rooms.add(room)
            
            # Notify room members
            await self.send_to_room(
                room,
                WebSocketMessage(
                    type=MessageType.EVENT,
                    data={
                        "event": "user_joined",
                        "user": client.username or client_id,
                        "room": room
                    }
                ),
                exclude=[client_id]
            )
            
            logger.info(f"Client {client_id} joined room: {room}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to join room: {e}")
            return False
    
    async def leave_room(self, client_id: str, room: str) -> bool:
        """Remove client from a room."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return False
            
            # Remove from room
            if client_id in self.rooms.get(room, set()):
                self.rooms[room].remove(client_id)
                client.rooms.discard(room)
                
                # Clean up empty room
                if not self.rooms[room]:
                    del self.rooms[room]
                
                # Notify room members
                await self.send_to_room(
                    room,
                    WebSocketMessage(
                        type=MessageType.EVENT,
                        data={
                            "event": "user_left",
                            "user": client.username or client_id,
                            "room": room
                        }
                    )
                )
            
            logger.info(f"Client {client_id} left room: {room}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to leave room: {e}")
            return False
    
    async def subscribe(
        self,
        client_id: str,
        subscription_type: str,
        filters: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Subscribe client to updates."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return False
            
            # Check authorization
            if not await self._check_subscription_access(client, subscription_type):
                await self.send_error(client_id, f"Access denied to subscription: {subscription_type}")
                return False
            
            # Add subscription
            self.subscriptions[subscription_type].add(client_id)
            client.subscriptions.add(subscription_type)
            
            # Store filters if provided
            if filters:
                client.metadata[f"filters_{subscription_type}"] = filters
            
            # Send confirmation
            await self.send_to_client(
                client_id,
                WebSocketMessage(
                    type=MessageType.RESPONSE,
                    data={
                        "action": "subscribe",
                        "subscription": subscription_type,
                        "success": True
                    }
                )
            )
            
            logger.info(f"Client {client_id} subscribed to: {subscription_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to subscribe: {e}")
            return False
    
    async def unsubscribe(
        self,
        client_id: str,
        subscription_type: str
    ) -> bool:
        """Unsubscribe client from updates."""
        try:
            client = self.clients.get(client_id)
            if not client:
                return False
            
            # Remove subscription
            if client_id in self.subscriptions.get(subscription_type, set()):
                self.subscriptions[subscription_type].remove(client_id)
                client.subscriptions.discard(subscription_type)
                
                # Clean up empty subscription
                if not self.subscriptions[subscription_type]:
                    del self.subscriptions[subscription_type]
            
            # Remove filters
            filter_key = f"filters_{subscription_type}"
            if filter_key in client.metadata:
                del client.metadata[filter_key]
            
            # Send confirmation
            await self.send_to_client(
                client_id,
                WebSocketMessage(
                    type=MessageType.RESPONSE,
                    data={
                        "action": "unsubscribe",
                        "subscription": subscription_type,
                        "success": True
                    }
                )
            )
            
            logger.info(f"Client {client_id} unsubscribed from: {subscription_type}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unsubscribe: {e}")
            return False
    
    # Handler methods
    
    async def handle_ping(self, client_id: str):
        """Handle ping message."""
        await self.send_to_client(
            client_id,
            WebSocketMessage(
                type=MessageType.PONG,
                data={"timestamp": datetime.utcnow().isoformat()}
            )
        )
    
    async def handle_auth(self, client_id: str, data: Dict[str, Any]):
        """Handle authentication message."""
        try:
            token = data.get("token")
            if not token:
                await self.send_error(client_id, "Token required")
                return
            
            user_info = await self._authenticate_client(token)
            if not user_info:
                await self.send_error(client_id, "Authentication failed")
                return
            
            client = self.clients[client_id]
            client.user_id = user_info.get("user_id")
            client.username = user_info.get("username")
            client.state = ConnectionState.AUTHENTICATED
            
            await self.send_to_client(
                client_id,
                WebSocketMessage(
                    type=MessageType.RESPONSE,
                    data={
                        "action": "auth",
                        "success": True,
                        "user": user_info
                    }
                )
            )
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            await self.send_error(client_id, "Authentication error")
    
    async def handle_subscribe(self, client_id: str, data: Dict[str, Any]):
        """Handle subscription request."""
        subscription_type = data.get("type")
        filters = data.get("filters")
        
        if not subscription_type:
            await self.send_error(client_id, "Subscription type required")
            return
        
        await self.subscribe(client_id, subscription_type, filters)
    
    async def handle_unsubscribe(self, client_id: str, data: Dict[str, Any]):
        """Handle unsubscription request."""
        subscription_type = data.get("type")
        
        if not subscription_type:
            await self.send_error(client_id, "Subscription type required")
            return
        
        await self.unsubscribe(client_id, subscription_type)
    
    async def handle_command(self, client_id: str, data: Dict[str, Any]):
        """Handle command message."""
        command = data.get("command")
        params = data.get("params", {})
        
        if not command:
            await self.send_error(client_id, "Command required")
            return
        
        # Process command based on type
        if command == "join_room":
            room = params.get("room")
            if room:
                await self.join_room(client_id, room)
        
        elif command == "leave_room":
            room = params.get("room")
            if room:
                await self.leave_room(client_id, room)
        
        else:
            await self.send_error(client_id, f"Unknown command: {command}")
    
    async def send_error(self, client_id: str, error: str):
        """Send error message to client."""
        await self.send_to_client(
            client_id,
            WebSocketMessage(
                type=MessageType.ERROR,
                data={"error": error}
            )
        )
    
    # Notification methods for external services
    
    async def notify_metric_update(
        self,
        device_id: int,
        metric_name: str,
        value: Any,
        timestamp: datetime
    ):
        """Notify clients of metric update."""
        message = WebSocketMessage(
            type=MessageType.METRIC,
            data={
                "device_id": device_id,
                "metric": metric_name,
                "value": value,
                "timestamp": timestamp.isoformat()
            }
        )
        
        # Send to metric subscribers
        await self.send_to_subscribers(SubscriptionType.METRICS.value, message)
        
        # Send to device-specific subscribers
        await self.send_to_subscribers(f"device_{device_id}", message)
    
    async def notify_alert(
        self,
        alert_id: str,
        device_id: Optional[int],
        severity: str,
        message_text: str
    ):
        """Notify clients of new alert."""
        message = WebSocketMessage(
            type=MessageType.ALERT,
            data={
                "alert_id": alert_id,
                "device_id": device_id,
                "severity": severity,
                "message": message_text,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Send to alert subscribers
        await self.send_to_subscribers(SubscriptionType.ALERTS.value, message)
        
        # Broadcast critical alerts
        if severity in ["critical", "emergency"]:
            await self.broadcast(message)
    
    async def notify_device_status(
        self,
        device_id: int,
        status: str,
        details: Optional[Dict[str, Any]] = None
    ):
        """Notify clients of device status change."""
        message = WebSocketMessage(
            type=MessageType.DEVICE_STATUS,
            data={
                "device_id": device_id,
                "status": status,
                "details": details or {},
                "timestamp": datetime.utcnow().isoformat()
            }
        )
        
        # Send to device subscribers
        await self.send_to_subscribers(f"device_{device_id}", message)
        
        # Send to all device status subscribers
        await self.send_to_subscribers(SubscriptionType.DEVICE.value, message)
    
    # Private helper methods
    
    async def _authenticate_client(self, token: str) -> Optional[Dict[str, Any]]:
        """Authenticate client with token."""
        try:
            # Verify JWT token
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=["HS256"]
            )
            
            return {
                "user_id": payload.get("sub"),
                "username": payload.get("username"),
                "roles": payload.get("roles", [])
            }
            
        except jwt.ExpiredSignatureError:
            logger.warning("Expired token")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return None
    
    async def _check_user_connection_limit(self, user_id: int) -> bool:
        """Check if user has reached connection limit."""
        user_connections = sum(
            1 for client in self.clients.values()
            if client.user_id == user_id
        )
        return user_connections < self.config.max_connections_per_user
    
    async def _check_room_access(
        self,
        client: WebSocketClient,
        room: str
    ) -> bool:
        """Check if client has access to room."""
        # Simplified - should check permissions
        return client.state == ConnectionState.AUTHENTICATED
    
    async def _check_subscription_access(
        self,
        client: WebSocketClient,
        subscription_type: str
    ) -> bool:
        """Check if client has access to subscription."""
        # Simplified - should check permissions
        return client.state == ConnectionState.AUTHENTICATED
    
    async def _heartbeat_loop(self):
        """Send heartbeat to all clients."""
        while self._running:
            try:
                await asyncio.sleep(self.config.heartbeat_interval)
                
                # Send heartbeat to all active clients
                message = WebSocketMessage(
                    type=MessageType.PING,
                    data={"timestamp": datetime.utcnow().isoformat()}
                )
                
                disconnected = []
                for client_id, client in self.clients.items():
                    if client.state == ConnectionState.ACTIVE:
                        success = await self.send_to_client(client_id, message)
                        if not success:
                            disconnected.append(client_id)
                
                # Clean up disconnected clients
                for client_id in disconnected:
                    await self.disconnect_client(client_id)
                
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
    
    async def _cleanup_loop(self):
        """Clean up idle connections."""
        while self._running:
            try:
                await asyncio.sleep(60)
                
                now = datetime.utcnow()
                idle_timeout = timedelta(seconds=self.config.idle_timeout)
                
                # Find idle clients
                idle_clients = []
                for client_id, client in self.clients.items():
                    if now - client.last_activity > idle_timeout:
                        idle_clients.append(client_id)
                
                # Disconnect idle clients
                for client_id in idle_clients:
                    logger.info(f"Disconnecting idle client: {client_id}")
                    await self.disconnect_client(client_id)
                
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WebSocket service statistics."""
        return {
            "total_clients": len(self.clients),
            "authenticated_clients": sum(
                1 for c in self.clients.values()
                if c.state == ConnectionState.AUTHENTICATED
            ),
            "total_rooms": len(self.rooms),
            "total_subscriptions": sum(len(subs) for subs in self.subscriptions.values()),
            "clients_by_state": {
                state.value: sum(1 for c in self.clients.values() if c.state == state)
                for state in ConnectionState
            }
        }


# Create singleton instance
websocket_service = WebSocketService()
# Global instance
websocket_manager = WebSocketService()
