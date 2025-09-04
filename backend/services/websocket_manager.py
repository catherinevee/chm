"""
WebSocket manager for real-time updates in CHM
"""
import asyncio
import json
import logging
from typing import Dict, Set, Any, Optional
from datetime import datetime
import uuid

from fastapi import WebSocket, WebSocketDisconnect, status
from fastapi.websockets import WebSocketState
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and broadcasting"""
    
    def __init__(self):
        # Store active connections by client ID
        self.active_connections: Dict[str, WebSocket] = {}
        # Store subscriptions by topic
        self.subscriptions: Dict[str, Set[str]] = {
            "alerts": set(),
            "metrics": set(),
            "devices": set(),
            "system": set(),
            "all": set()
        }
        # Store client metadata
        self.client_metadata: Dict[str, Dict[str, Any]] = {}
        # Message queue for offline clients
        self.message_queue: Dict[str, list] = {}
        
    async def connect(
        self, 
        websocket: WebSocket, 
        client_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Accept WebSocket connection and register client"""
        await websocket.accept()
        
        # Generate client ID if not provided
        if not client_id:
            client_id = str(uuid.uuid4())
        
        # Store connection
        self.active_connections[client_id] = websocket
        
        # Store metadata
        self.client_metadata[client_id] = metadata or {}
        self.client_metadata[client_id]["connected_at"] = datetime.utcnow()
        
        # Subscribe to default topics
        self.subscriptions["all"].add(client_id)
        
        # Send connection confirmation
        await self.send_personal_message(
            {
                "type": "connection",
                "status": "connected",
                "client_id": client_id,
                "timestamp": datetime.utcnow().isoformat()
            },
            client_id
        )
        
        # Send any queued messages
        if client_id in self.message_queue:
            for message in self.message_queue[client_id]:
                await self.send_personal_message(message, client_id)
            del self.message_queue[client_id]
        
        logger.info(f"WebSocket client {client_id} connected")
        return client_id
    
    def disconnect(self, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        # Remove from all subscriptions
        for topic in self.subscriptions:
            self.subscriptions[topic].discard(client_id)
        
        # Clean up metadata
        if client_id in self.client_metadata:
            del self.client_metadata[client_id]
        
        logger.info(f"WebSocket client {client_id} disconnected")
    
    async def send_personal_message(self, message: Any, client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            websocket = self.active_connections[client_id]
            try:
                if websocket.client_state == WebSocketState.CONNECTED:
                    if isinstance(message, dict):
                        message = json.dumps(message)
                    await websocket.send_text(message)
                else:
                    # Queue message if client is not connected
                    self._queue_message(client_id, message)
            except Exception as e:
                logger.error(f"Error sending message to {client_id}: {e}")
                self.disconnect(client_id)
        else:
            # Queue message for offline client
            self._queue_message(client_id, message)
    
    async def broadcast(self, message: Any, topic: str = "all"):
        """Broadcast message to all subscribed clients"""
        if isinstance(message, dict):
            message = json.dumps(message)
        
        # Get subscribers for topic
        subscribers = self.subscriptions.get(topic, set()) | self.subscriptions.get("all", set())
        
        # Send to all subscribers
        disconnected_clients = []
        for client_id in subscribers:
            if client_id in self.active_connections:
                websocket = self.active_connections[client_id]
                try:
                    if websocket.client_state == WebSocketState.CONNECTED:
                        await websocket.send_text(message)
                    else:
                        disconnected_clients.append(client_id)
                except Exception as e:
                    logger.error(f"Error broadcasting to {client_id}: {e}")
                    disconnected_clients.append(client_id)
        
        # Clean up disconnected clients
        for client_id in disconnected_clients:
            self.disconnect(client_id)
    
    async def subscribe(self, client_id: str, topics: list):
        """Subscribe client to topics"""
        for topic in topics:
            if topic in self.subscriptions:
                self.subscriptions[topic].add(client_id)
                logger.debug(f"Client {client_id} subscribed to {topic}")
        
        # Send confirmation
        await self.send_personal_message(
            {
                "type": "subscription",
                "topics": topics,
                "status": "subscribed",
                "timestamp": datetime.utcnow().isoformat()
            },
            client_id
        )
    
    async def unsubscribe(self, client_id: str, topics: list):
        """Unsubscribe client from topics"""
        for topic in topics:
            if topic in self.subscriptions:
                self.subscriptions[topic].discard(client_id)
                logger.debug(f"Client {client_id} unsubscribed from {topic}")
        
        # Send confirmation
        await self.send_personal_message(
            {
                "type": "subscription",
                "topics": topics,
                "status": "unsubscribed",
                "timestamp": datetime.utcnow().isoformat()
            },
            client_id
        )
    
    def _queue_message(self, client_id: str, message: Any):
        """Queue message for offline client"""
        if client_id not in self.message_queue:
            self.message_queue[client_id] = []
        
        # Limit queue size
        if len(self.message_queue[client_id]) < 100:
            self.message_queue[client_id].append(message)
    
    async def send_alert_update(self, alert_data: Dict[str, Any]):
        """Send alert update to subscribed clients"""
        message = {
            "type": "alert_update",
            "data": alert_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message, "alerts")
    
    async def send_metric_update(self, metric_data: Dict[str, Any]):
        """Send metric update to subscribed clients"""
        message = {
            "type": "metric_update",
            "data": metric_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message, "metrics")
    
    async def send_device_update(self, device_data: Dict[str, Any]):
        """Send device status update to subscribed clients"""
        message = {
            "type": "device_update",
            "data": device_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message, "devices")
    
    async def send_system_message(self, message_text: str, severity: str = "info"):
        """Send system message to all clients"""
        message = {
            "type": "system_message",
            "message": message_text,
            "severity": severity,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message, "system")
    
    def get_connection_count(self) -> int:
        """Get number of active connections"""
        return len(self.active_connections)
    
    def get_client_info(self, client_id: str) -> Dict[str, Any]:
        """Get client information"""
        if client_id in self.client_metadata:
            return create_success_result(
                fallback_data=FallbackData(
                    data=self.client_metadata[client_id],
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Client information retrieved successfully",
                        details=f"Client information for {client_id} retrieved successfully",
                        timestamp=datetime.now().isoformat()
                    )
                )
            ).data
        
        # Return fallback client info when client not found
        fallback_data = FallbackData(
            data={},
            health_status=HealthStatus(
                level=HealthLevel.WARNING,
                message="Client not found",
                details=f"Client {client_id} not found in metadata",
                timestamp=datetime.now().isoformat()
            )
        )
        
        return create_partial_success_result(
            data={},
            fallback_data=fallback_data,
            health_status=HealthStatus(
                level=HealthLevel.WARNING,
                message="Client not found",
                details=f"Client {client_id} not found in metadata",
                timestamp=datetime.now().isoformat()
            ),
            suggestions=[
                "Client not found",
                "Check client ID",
                "Use fallback client info",
                "Verify client connection status"
            ]
        ).data
    
    def get_all_clients(self) -> Dict[str, Dict[str, Any]]:
        """Get all connected clients with metadata"""
        return {
            client_id: self.client_metadata.get(client_id, {})
            for client_id in self.active_connections
        }


class WebSocketManager:
    """High-level WebSocket manager with application logic"""
    
    def __init__(self):
        self.connection_manager = ConnectionManager()
        self.heartbeat_interval = 30  # seconds
        self.heartbeat_tasks: Dict[str, asyncio.Task] = {}
        
    async def handle_connection(self, websocket: WebSocket, client_id: Optional[str] = None):
        """Handle WebSocket connection lifecycle"""
        try:
            # Accept connection
            client_id = await self.connection_manager.connect(websocket, client_id)
            
            # Start heartbeat
            self.heartbeat_tasks[client_id] = asyncio.create_task(
                self._heartbeat(client_id)
            )
            
            # Handle messages
            await self._handle_messages(websocket, client_id)
            
        except WebSocketDisconnect:
            logger.info(f"Client {client_id} disconnected normally")
        except Exception as e:
            logger.error(f"WebSocket error for {client_id}: {e}")
        finally:
            # Clean up
            if client_id in self.heartbeat_tasks:
                self.heartbeat_tasks[client_id].cancel()
                del self.heartbeat_tasks[client_id]
            
            self.connection_manager.disconnect(client_id)
    
    async def _handle_messages(self, websocket: WebSocket, client_id: str):
        """Handle incoming WebSocket messages"""
        while True:
            try:
                # Receive message
                data = await websocket.receive_text()
                message = json.loads(data)
                
                # Process message based on type
                message_type = message.get("type")
                
                if message_type == "ping":
                    # Respond to ping
                    await self.connection_manager.send_personal_message(
                        {"type": "pong", "timestamp": datetime.utcnow().isoformat()},
                        client_id
                    )
                
                elif message_type == "subscribe":
                    # Subscribe to topics
                    topics = message.get("topics", [])
                    await self.connection_manager.subscribe(client_id, topics)
                
                elif message_type == "unsubscribe":
                    # Unsubscribe from topics
                    topics = message.get("topics", [])
                    await self.connection_manager.unsubscribe(client_id, topics)
                
                elif message_type == "get_status":
                    # Send current status
                    await self._send_status(client_id)
                
                else:
                    # Unknown message type
                    await self.connection_manager.send_personal_message(
                        {
                            "type": "error",
                            "message": f"Unknown message type: {message_type}",
                            "timestamp": datetime.utcnow().isoformat()
                        },
                        client_id
                    )
                
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                await self.connection_manager.send_personal_message(
                    {
                        "type": "error",
                        "message": "Invalid JSON",
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    client_id
                )
            except Exception as e:
                logger.error(f"Error handling message from {client_id}: {e}")
                break
    
    async def _heartbeat(self, client_id: str):
        """Send periodic heartbeat to client"""
        while client_id in self.connection_manager.active_connections:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                await self.connection_manager.send_personal_message(
                    {
                        "type": "heartbeat",
                        "timestamp": datetime.utcnow().isoformat()
                    },
                    client_id
                )
            except Exception as e:
                logger.error(f"Heartbeat error for {client_id}: {e}")
                break
    
    async def _send_status(self, client_id: str):
        """Send current system status to client"""
        # TODO: Get actual system status
        status_data = {
            "type": "status",
            "data": {
                "connected_clients": self.connection_manager.get_connection_count(),
                "server_time": datetime.utcnow().isoformat(),
                "uptime_seconds": 0,  # TODO: Calculate actual uptime
                "active_alerts": 0,  # TODO: Get from alert service
                "monitored_devices": 0  # TODO: Get from device service
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.connection_manager.send_personal_message(status_data, client_id)
    
    async def broadcast(self, message: Any, topic: str = "all"):
        """Broadcast message to clients"""
        await self.connection_manager.broadcast(message, topic)
    
    async def send_alert(self, alert_data: Dict[str, Any]):
        """Send alert notification"""
        await self.connection_manager.send_alert_update(alert_data)
    
    async def send_metric(self, metric_data: Dict[str, Any]):
        """Send metric update"""
        await self.connection_manager.send_metric_update(metric_data)
    
    async def send_device_status(self, device_data: Dict[str, Any]):
        """Send device status update"""
        await self.connection_manager.send_device_update(device_data)
    
    async def send_system_notification(self, message: str, severity: str = "info"):
        """Send system notification"""
        await self.connection_manager.send_system_message(message, severity)


# Global WebSocket manager instance
websocket_manager = WebSocketManager()