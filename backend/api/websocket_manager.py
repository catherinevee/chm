"""
WebSocket connection manager for real-time updates
"""

from fastapi import WebSocket
from typing import List, Dict, Set, Optional, Any
import json
import logging
from datetime import datetime
import asyncio
from collections import defaultdict

logger = logging.getLogger(__name__)

class WebSocketManager:
    """Manages WebSocket connections and event subscriptions"""
    
    def __init__(self):
        # Active connections
        self.active_connections: List[WebSocket] = []
        
        # Connection metadata
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        
        # Event subscriptions
        self.event_subscriptions: Dict[str, Set[WebSocket]] = defaultdict(set)
        
        # User connections mapping
        self.user_connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        
        # Connection statistics
        self.connection_stats = {
            "total_connections": 0,
            "messages_sent": 0,
            "messages_received": 0,
            "errors": 0
        }
    
    async def connect(self, websocket: WebSocket, user: Optional[Any] = None):
        """Accept and store a WebSocket connection"""
        await websocket.accept()
        self.active_connections.append(websocket)
        
        # Store metadata
        self.connection_metadata[websocket] = {
            "connected_at": datetime.utcnow(),
            "user": user,
            "user_id": str(user.id) if user else None,
            "username": user.username if user else "anonymous",
            "subscriptions": set()
        }
        
        # Add to user connections if authenticated
        if user:
            self.user_connections[str(user.id)].add(websocket)
        
        self.connection_stats["total_connections"] += 1
        
        logger.info(f"WebSocket connected. User: {self.connection_metadata[websocket]['username']}. "
                   f"Active connections: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection"""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            
            # Remove from subscriptions
            for event_type in list(self.event_subscriptions.keys()):
                self.event_subscriptions[event_type].discard(websocket)
                if not self.event_subscriptions[event_type]:
                    del self.event_subscriptions[event_type]
            
            # Remove from user connections
            metadata = self.connection_metadata.get(websocket, {})
            user_id = metadata.get("user_id")
            if user_id:
                self.user_connections[user_id].discard(websocket)
                if not self.user_connections[user_id]:
                    del self.user_connections[user_id]
            
            # Remove metadata
            if websocket in self.connection_metadata:
                del self.connection_metadata[websocket]
            
            logger.info(f"WebSocket disconnected. Active connections: {len(self.active_connections)}")
    
    async def subscribe(self, websocket: WebSocket, events: List[str]):
        """Subscribe a connection to specific event types"""
        if websocket in self.active_connections:
            for event_type in events:
                self.event_subscriptions[event_type].add(websocket)
                
                if websocket in self.connection_metadata:
                    self.connection_metadata[websocket]["subscriptions"].add(event_type)
                
                logger.debug(f"WebSocket subscribed to {event_type}")
    
    async def unsubscribe(self, websocket: WebSocket, event_type: str):
        """Unsubscribe a connection from specific event types"""
        self.event_subscriptions[event_type].discard(websocket)
        
        if websocket in self.connection_metadata:
            self.connection_metadata[websocket]["subscriptions"].discard(event_type)
        
        if not self.event_subscriptions[event_type]:
            del self.event_subscriptions[event_type]
    
    async def send_personal_message(self, message: str, websocket: WebSocket):
        """Send a message to a specific WebSocket"""
        try:
            await websocket.send_text(message)
            self.connection_stats["messages_sent"] += 1
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
            self.connection_stats["errors"] += 1
            self.disconnect(websocket)
    
    async def send_personal_json(self, data: dict, websocket: WebSocket):
        """Send JSON data to a specific WebSocket"""
        await self.send_personal_message(json.dumps(data), websocket)
    
    async def send_to_user(self, user_id: str, message: str):
        """Send a message to all connections of a specific user"""
        connections = self.user_connections.get(user_id, set())
        disconnected = []
        
        for connection in connections:
            try:
                await connection.send_text(message)
                self.connection_stats["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Error sending message to user {user_id}: {e}")
                self.connection_stats["errors"] += 1
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    async def send_to_user_json(self, user_id: str, data: dict):
        """Send JSON data to all connections of a specific user"""
        await self.send_to_user(user_id, json.dumps(data))
    
    async def broadcast(self, message: str, exclude: Optional[WebSocket] = None):
        """Broadcast a message to all connected WebSockets"""
        if not self.active_connections:
            return
        
        disconnected = []
        for connection in self.active_connections:
            if connection == exclude:
                continue
            
            try:
                await connection.send_text(message)
                self.connection_stats["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Error broadcasting message: {e}")
                self.connection_stats["errors"] += 1
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_json(self, data: dict, exclude: Optional[WebSocket] = None):
        """Broadcast JSON data to all connected WebSockets"""
        await self.broadcast(json.dumps(data), exclude)
    
    async def broadcast_to_event_subscribers(self, event_type: str, message: str):
        """Broadcast a message to all subscribers of a specific event type"""
        subscribers = self.event_subscriptions.get(event_type, set())
        disconnected = []
        
        for connection in subscribers:
            try:
                await connection.send_text(message)
                self.connection_stats["messages_sent"] += 1
            except Exception as e:
                logger.error(f"Error broadcasting to {event_type} subscribers: {e}")
                self.connection_stats["errors"] += 1
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_event(self, event_type: str, data: dict):
        """Broadcast an event to all subscribers"""
        event_data = {
            "type": "event",
            "event_type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self.broadcast_to_event_subscribers(event_type, json.dumps(event_data))
    
    async def disconnect_all(self):
        """Disconnect all active WebSocket connections"""
        for connection in self.active_connections[:]:
            try:
                await connection.close()
            except Exception as e:
                logger.error(f"Error closing WebSocket connection: {e}")
            self.disconnect(connection)
        
        self.active_connections.clear()
        self.connection_metadata.clear()
        self.event_subscriptions.clear()
        self.user_connections.clear()
        
        logger.info("All WebSocket connections closed")
    
    # Event-specific broadcast methods
    async def broadcast_device_update(self, device_data: dict):
        """Broadcast device update event"""
        await self.broadcast_event("device_update", device_data)
    
    async def broadcast_alert(self, alert_data: dict):
        """Broadcast alert event"""
        severity = alert_data.get("severity", "info")
        
        # Send to all connections for critical alerts
        if severity == "critical":
            await self.broadcast_json({
                "type": "critical_alert",
                "data": alert_data,
                "timestamp": datetime.utcnow().isoformat()
            })
        else:
            # Send only to subscribers
            await self.broadcast_event("alert", alert_data)
    
    async def broadcast_metric_update(self, metric_data: dict):
        """Broadcast metric update event"""
        await self.broadcast_event("metric_update", metric_data)
    
    async def broadcast_discovery_progress(self, progress_data: dict):
        """Broadcast discovery progress event"""
        await self.broadcast_event("discovery_progress", progress_data)
    
    async def broadcast_notification(self, notification_data: dict):
        """Broadcast notification event"""
        user_id = notification_data.get("user_id")
        
        if user_id:
            # Send to specific user
            await self.send_to_user_json(user_id, {
                "type": "notification",
                "data": notification_data,
                "timestamp": datetime.utcnow().isoformat()
            })
        else:
            # Broadcast to all
            await self.broadcast_event("notification", notification_data)
    
    def get_connection_info(self, websocket: WebSocket) -> Optional[Dict[str, Any]]:
        """Get information about a specific connection"""
        return self.connection_metadata.get(websocket)
    
    def get_user_connections(self, user_id: str) -> Set[WebSocket]:
        """Get all connections for a specific user"""
        return self.user_connections.get(user_id, set())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get WebSocket manager statistics"""
        return {
            "active_connections": len(self.active_connections),
            "authenticated_users": len(self.user_connections),
            "event_subscriptions": {
                event_type: len(subscribers)
                for event_type, subscribers in self.event_subscriptions.items()
            },
            "connection_stats": self.connection_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def health_check(self):
        """Perform health check on all connections"""
        disconnected = []
        
        for connection in self.active_connections:
            try:
                # Send ping
                await connection.send_json({
                    "type": "ping",
                    "timestamp": datetime.utcnow().isoformat()
                })
            except Exception:
                disconnected.append(connection)
        
        # Remove disconnected connections
        for conn in disconnected:
            self.disconnect(conn)
        
        return {
            "checked": len(self.active_connections) + len(disconnected),
            "alive": len(self.active_connections),
            "disconnected": len(disconnected)
        }

# Global WebSocket manager instance
ws_manager = WebSocketManager()

# Helper function for background broadcasting
async def broadcast_system_event(event_type: str, data: dict):
    """Helper function to broadcast system events"""
    await ws_manager.broadcast_event(f"system_{event_type}", data)