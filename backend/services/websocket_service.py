"""
WebSocket Manager for real-time updates
"""
from fastapi import WebSocket, WebSocketDisconnect
from typing import Dict, List, Set
import json
import asyncio
import logging

logger = logging.getLogger(__name__)

class ConnectionManager:
    """Manages WebSocket connections"""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {}

    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept WebSocket connection"""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        self.subscriptions[client_id] = set()
        logger.info(f"Client {client_id} connected")

    def disconnect(self, client_id: str):
        """Remove WebSocket connection"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
            del self.subscriptions[client_id]
            logger.info(f"Client {client_id} disconnected")

    async def send_personal_message(self, message: str, client_id: str):
        """Send message to specific client"""
        if client_id in self.active_connections:
            await self.active_connections[client_id].send_text(message)

    async def broadcast(self, message: str, channel: str = "general"):
        """Broadcast message to all connected clients"""
        for client_id, connection in self.active_connections.items():
            if channel in self.subscriptions.get(client_id, set()) or channel == "general":
                await connection.send_text(message)

    async def subscribe(self, client_id: str, channel: str):
        """Subscribe client to channel"""
        if client_id in self.subscriptions:
            self.subscriptions[client_id].add(channel)

    async def unsubscribe(self, client_id: str, channel: str):
        """Unsubscribe client from channel"""
        if client_id in self.subscriptions:
            self.subscriptions[client_id].discard(channel)

# Global instance
websocket_manager = ConnectionManager()

async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint handler"""
    await websocket_manager.connect(websocket, client_id)

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("type") == "subscribe":
                await websocket_manager.subscribe(client_id, message.get("channel"))
            elif message.get("type") == "unsubscribe":
                await websocket_manager.unsubscribe(client_id, message.get("channel"))
            else:
                # Echo message back
                await websocket_manager.send_personal_message(data, client_id)

    except WebSocketDisconnect:
        websocket_manager.disconnect(client_id)
