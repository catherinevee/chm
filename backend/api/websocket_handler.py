"""
WebSocket Handler - Real-time communication for CHM
"""

import asyncio
import json
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from uuid import UUID
from fastapi import WebSocket, WebSocketDisconnect, Depends, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from jose import JWTError, jwt

from backend.database.base import get_session
from backend.database.models import User, Device, Alert
from backend.config import settings
from backend.auth.jwt_auth import verify_token

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections and broadcasting
    """
    
    def __init__(self):
        # Store active connections by user ID
        self.active_connections: Dict[str, List[WebSocket]] = {}
        # Store user subscriptions
        self.subscriptions: Dict[str, Set[str]] = {}
        # Store connection metadata
        self.connection_metadata: Dict[WebSocket, Dict[str, Any]] = {}
        
    async def connect(self, websocket: WebSocket, user_id: str, metadata: Dict[str, Any] = None):
        """
        Accept and register a new WebSocket connection
        
        Args:
            websocket: WebSocket connection
            user_id: User identifier
            metadata: Additional connection metadata
        """
        await websocket.accept()
        
        # Add to active connections
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        self.active_connections[user_id].append(websocket)
        
        # Store metadata
        self.connection_metadata[websocket] = {
            'user_id': user_id,
            'connected_at': datetime.utcnow(),
            'metadata': metadata or {}
        }
        
        # Initialize subscriptions
        if user_id not in self.subscriptions:
            self.subscriptions[user_id] = set()
        
        logger.info(f"WebSocket connected for user {user_id}")
        
        # Send welcome message
        await self.send_personal_message(
            {
                'type': 'connection',
                'status': 'connected',
                'message': 'WebSocket connection established',
                'timestamp': datetime.utcnow().isoformat()
            },
            websocket
        )
    
    def disconnect(self, websocket: WebSocket):
        """
        Remove a WebSocket connection
        
        Args:
            websocket: WebSocket connection to remove
        """
        # Get user ID from metadata
        metadata = self.connection_metadata.get(websocket)
        if metadata:
            user_id = metadata['user_id']
            
            # Remove from active connections
            if user_id in self.active_connections:
                self.active_connections[user_id].remove(websocket)
                
                # Clean up if no more connections for user
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
                    del self.subscriptions[user_id]
            
            # Remove metadata
            del self.connection_metadata[websocket]
            
            logger.info(f"WebSocket disconnected for user {user_id}")
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """
        Send message to specific WebSocket
        
        Args:
            message: Message to send
            websocket: Target WebSocket
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending message: {str(e)}")
    
    async def send_user_message(self, message: Dict[str, Any], user_id: str):
        """
        Send message to all connections of a specific user
        
        Args:
            message: Message to send
            user_id: Target user ID
        """
        if user_id in self.active_connections:
            for connection in self.active_connections[user_id]:
                await self.send_personal_message(message, connection)
    
    async def broadcast(self, message: Dict[str, Any], channel: str = None):
        """
        Broadcast message to all connected clients or specific channel
        
        Args:
            message: Message to broadcast
            channel: Optional channel to broadcast to
        """
        # Add timestamp if not present
        if 'timestamp' not in message:
            message['timestamp'] = datetime.utcnow().isoformat()
        
        if channel:
            # Broadcast to subscribers of specific channel
            for user_id, channels in self.subscriptions.items():
                if channel in channels:
                    await self.send_user_message(message, user_id)
        else:
            # Broadcast to all connections
            for user_id in self.active_connections:
                await self.send_user_message(message, user_id)
    
    async def subscribe(self, user_id: str, channel: str):
        """
        Subscribe user to a channel
        
        Args:
            user_id: User ID
            channel: Channel name
        """
        if user_id in self.subscriptions:
            self.subscriptions[user_id].add(channel)
            logger.info(f"User {user_id} subscribed to channel {channel}")
            
            # Send confirmation
            await self.send_user_message(
                {
                    'type': 'subscription',
                    'action': 'subscribed',
                    'channel': channel,
                    'timestamp': datetime.utcnow().isoformat()
                },
                user_id
            )
    
    async def unsubscribe(self, user_id: str, channel: str):
        """
        Unsubscribe user from a channel
        
        Args:
            user_id: User ID
            channel: Channel name
        """
        if user_id in self.subscriptions:
            self.subscriptions[user_id].discard(channel)
            logger.info(f"User {user_id} unsubscribed from channel {channel}")
            
            # Send confirmation
            await self.send_user_message(
                {
                    'type': 'subscription',
                    'action': 'unsubscribed',
                    'channel': channel,
                    'timestamp': datetime.utcnow().isoformat()
                },
                user_id
            )
    
    async def broadcast_device_update(self, device_data: Dict[str, Any]):
        """
        Broadcast device update to relevant subscribers
        
        Args:
            device_data: Device update data
        """
        message = {
            'type': 'device_update',
            'data': device_data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Broadcast to device channel
        device_id = device_data.get('device_id')
        if device_id:
            await self.broadcast(message, f"device:{device_id}")
        
        # Also broadcast to all devices channel
        await self.broadcast(message, "devices:all")
    
    async def broadcast_alert(self, alert_data: Dict[str, Any]):
        """
        Broadcast alert to relevant subscribers
        
        Args:
            alert_data: Alert data
        """
        message = {
            'type': 'alert',
            'data': alert_data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Broadcast based on severity
        severity = alert_data.get('severity', 'info')
        await self.broadcast(message, f"alerts:{severity}")
        
        # Also broadcast to all alerts channel
        await self.broadcast(message, "alerts:all")
        
        # Broadcast to device channel if device-specific
        device_id = alert_data.get('device_id')
        if device_id:
            await self.broadcast(message, f"device:{device_id}")
    
    async def broadcast_metric_update(self, metric_data: Dict[str, Any]):
        """
        Broadcast metric update to relevant subscribers
        
        Args:
            metric_data: Metric data
        """
        message = {
            'type': 'metric_update',
            'data': metric_data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Broadcast to device channel
        device_id = metric_data.get('device_id')
        if device_id:
            await self.broadcast(message, f"metrics:device:{device_id}")
        
        # Broadcast to metric type channel
        metric_type = metric_data.get('metric_type')
        if metric_type:
            await self.broadcast(message, f"metrics:{metric_type}")
    
    def get_connection_info(self) -> Dict[str, Any]:
        """
        Get information about current connections
        
        Returns:
            Connection statistics
        """
        total_connections = sum(len(conns) for conns in self.active_connections.values())
        
        return {
            'total_connections': total_connections,
            'unique_users': len(self.active_connections),
            'subscriptions': {
                user_id: list(channels)
                for user_id, channels in self.subscriptions.items()
            },
            'connection_details': [
                {
                    'user_id': meta['user_id'],
                    'connected_at': meta['connected_at'].isoformat(),
                    'metadata': meta['metadata']
                }
                for meta in self.connection_metadata.values()
            ]
        }


# Global connection manager instance
ws_manager = ConnectionManager()


async def get_current_user_ws(websocket: WebSocket, token: str = None) -> Optional[str]:
    """
    Authenticate WebSocket connection
    
    Args:
        websocket: WebSocket connection
        token: JWT token
        
    Returns:
        User ID if authenticated, None otherwise
    """
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise NotImplementedError("Function not yet implemented")
    
    try:
        # Verify JWT token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        user_id = payload.get("sub")
        
        if user_id is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            raise NotImplementedError("Function not yet implemented")
        
        return user_id
        
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise NotImplementedError("Function not yet implemented")


class WebSocketHandler:
    """
    Handles WebSocket message processing
    """
    
    def __init__(self, websocket: WebSocket, user_id: str, db: AsyncSession):
        self.websocket = websocket
        self.user_id = user_id
        self.db = db
        
    async def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process incoming WebSocket message
        
        Args:
            message: Received message
            
        Returns:
            Response message
        """
        message_type = message.get('type')
        
        if message_type == 'ping':
            return await self.handle_ping()
        elif message_type == 'subscribe':
            return await self.handle_subscribe(message)
        elif message_type == 'unsubscribe':
            return await self.handle_unsubscribe(message)
        elif message_type == 'get_devices':
            return await self.handle_get_devices(message)
        elif message_type == 'get_alerts':
            return await self.handle_get_alerts(message)
        elif message_type == 'get_metrics':
            return await self.handle_get_metrics(message)
        elif message_type == 'poll_device':
            return await self.handle_poll_device(message)
        elif message_type == 'acknowledge_alert':
            return await self.handle_acknowledge_alert(message)
        else:
            return {
                'type': 'error',
                'message': f'Unknown message type: {message_type}'
            }
    
    async def handle_ping(self) -> Dict[str, Any]:
        """Handle ping message"""
        return {
            'type': 'pong',
            'timestamp': datetime.utcnow().isoformat()
        }
    
    async def handle_subscribe(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle subscription request"""
        channel = message.get('channel')
        if channel:
            await ws_manager.subscribe(self.user_id, channel)
            return {
                'type': 'subscription_confirmed',
                'channel': channel
            }
        return {
            'type': 'error',
            'message': 'Channel not specified'
        }
    
    async def handle_unsubscribe(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle unsubscription request"""
        channel = message.get('channel')
        if channel:
            await ws_manager.unsubscribe(self.user_id, channel)
            return {
                'type': 'unsubscription_confirmed',
                'channel': channel
            }
        return {
            'type': 'error',
            'message': 'Channel not specified'
        }
    
    async def handle_get_devices(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get devices request"""
        from sqlalchemy import select
        
        # Get filter parameters
        filters = message.get('filters', {})
        
        # Build query
        query = select(Device)
        
        if filters.get('is_active') is not None:
            query = query.where(Device.is_active == filters['is_active'])
        
        if filters.get('device_type'):
            query = query.where(Device.device_type == filters['device_type'])
        
        # Execute query
        result = await self.db.execute(query)
        devices = result.scalars().all()
        
        # Format response
        device_list = [
            {
                'id': str(device.id),
                'hostname': device.hostname,
                'ip_address': device.ip_address,
                'device_type': device.device_type,
                'state': device.current_state,
                'is_active': device.is_active
            }
            for device in devices
        ]
        
        return {
            'type': 'devices',
            'data': device_list,
            'count': len(device_list)
        }
    
    async def handle_get_alerts(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get alerts request"""
        from sqlalchemy import select
        
        # Get filter parameters
        filters = message.get('filters', {})
        
        # Build query
        query = select(Alert)
        
        if filters.get('status'):
            query = query.where(Alert.status == filters['status'])
        
        if filters.get('severity'):
            query = query.where(Alert.severity == filters['severity'])
        
        # Limit to recent alerts
        query = query.order_by(Alert.created_at.desc()).limit(50)
        
        # Execute query
        result = await self.db.execute(query)
        alerts = result.scalars().all()
        
        # Format response
        alert_list = [
            {
                'id': str(alert.id),
                'device_id': str(alert.device_id) if alert.device_id else None,
                'alert_type': alert.alert_type,
                'severity': alert.severity,
                'message': alert.message,
                'status': alert.status,
                'created_at': alert.created_at.isoformat()
            }
            for alert in alerts
        ]
        
        return {
            'type': 'alerts',
            'data': alert_list,
            'count': len(alert_list)
        }
    
    async def handle_get_metrics(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get metrics request"""
        from backend.services.metrics_service import MetricsService
        
        device_id = message.get('device_id')
        if not device_id:
            return {
                'type': 'error',
                'message': 'Device ID not specified'
            }
        
        # Get metrics
        metrics_service = MetricsService()
        metrics = await metrics_service.get_graph_data(
            self.db,
            UUID(device_id),
            message.get('metric_name', 'cpu_usage'),
            message.get('hours', 24)
        )
        
        return {
            'type': 'metrics',
            'device_id': device_id,
            'data': metrics
        }
    
    async def handle_poll_device(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle device poll request"""
        from backend.tasks.monitoring_tasks import poll_device
        
        device_id = message.get('device_id')
        if not device_id:
            return {
                'type': 'error',
                'message': 'Device ID not specified'
            }
        
        # Queue polling task
        task = poll_device.delay(device_id)
        
        return {
            'type': 'task_queued',
            'task_id': task.id,
            'message': f'Polling task queued for device {device_id}'
        }
    
    async def handle_acknowledge_alert(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle alert acknowledgement"""
        from backend.services.alert_service import AlertService
        
        alert_id = message.get('alert_id')
        if not alert_id:
            return {
                'type': 'error',
                'message': 'Alert ID not specified'
            }
        
        # Acknowledge alert
        alert_service = AlertService()
        try:
            alert = await alert_service.acknowledge_alert(
                self.db,
                UUID(alert_id),
                UUID(self.user_id),
                message.get('notes')
            )
            
            return {
                'type': 'alert_acknowledged',
                'alert_id': alert_id,
                'status': alert.status
            }
            
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }


async def websocket_endpoint(
    websocket: WebSocket,
    token: str,
    db: AsyncSession = Depends(get_session)
):
    """
    WebSocket endpoint handler
    
    Args:
        websocket: WebSocket connection
        token: JWT authentication token
        db: Database session
    """
    # Authenticate user
    user_id = await get_current_user_ws(websocket, token)
    if not user_id:
        return
    
    # Connect to manager
    await ws_manager.connect(websocket, user_id)
    
    # Create handler
    handler = WebSocketHandler(websocket, user_id, db)
    
    try:
        while True:
            # Receive message
            data = await websocket.receive_json()
            
            # Process message
            response = await handler.handle_message(data)
            
            # Send response
            await websocket.send_json(response)
            
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
        logger.info(f"WebSocket disconnected for user {user_id}")
    except Exception as e:
        logger.error(f"WebSocket error: {str(e)}")
        ws_manager.disconnect(websocket)
        await websocket.close()