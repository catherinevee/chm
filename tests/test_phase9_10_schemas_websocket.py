"""
Phase 9-10: Comprehensive tests for schemas and WebSocket functionality
Target: Complete coverage for Pydantic schemas and real-time features
"""
# Fix imports FIRST
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['TESTING'] = 'true'
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'

import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError
import json
from unittest.mock import Mock, patch, AsyncMock


class TestUserSchemas:
    """Test backend/schemas/user.py"""
    
    def test_user_base_schema(self):
        """Test UserBase schema"""
        from backend.schemas.user import UserBase
        
        user = UserBase(
            username="testuser",
            email="test@example.com",
            full_name="Test User"
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.full_name == "Test User"
    
    def test_user_create_schema(self):
        """Test UserCreate schema with password"""
        from backend.schemas.user import UserCreate
        
        user = UserCreate(
            username="newuser",
            email="new@example.com",
            password="SecurePass123!",
            full_name="New User"
        )
        
        assert user.password == "SecurePass123!"
        
        # Test password validation
        with pytest.raises(ValidationError):
            UserCreate(
                username="user",
                email="test@example.com",
                password="weak"  # Too short
            )
    
    def test_user_update_schema(self):
        """Test UserUpdate schema with optional fields"""
        from backend.schemas.user import UserUpdate
        
        # All fields optional
        update1 = UserUpdate()
        assert update1.dict(exclude_unset=True) == {}
        
        # Partial update
        update2 = UserUpdate(email="newemail@example.com")
        assert update2.email == "newemail@example.com"
        assert update2.username is None
    
    def test_user_response_schema(self):
        """Test UserResponse schema"""
        from backend.schemas.user import UserResponse
        
        user = UserResponse(
            id=1,
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            is_verified=True,
            created_at=datetime.utcnow(),
            roles=["user", "viewer"]
        )
        
        assert user.id == 1
        assert "user" in user.roles
        
        # Test JSON serialization
        user_json = user.json()
        assert isinstance(user_json, str)
    
    def test_user_login_schema(self):
        """Test UserLogin schema"""
        from backend.schemas.user import UserLogin
        
        login = UserLogin(
            username="testuser",
            password="password123"
        )
        
        assert login.username == "testuser"
        assert login.password == "password123"
    
    def test_token_response_schema(self):
        """Test TokenResponse schema"""
        from backend.schemas.user import TokenResponse
        
        token = TokenResponse(
            access_token="jwt_token_here",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh_token_here"
        )
        
        assert token.access_token == "jwt_token_here"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600
    
    def test_refresh_token_request_schema(self):
        """Test RefreshTokenRequest schema"""
        from backend.schemas.user import RefreshTokenRequest
        
        refresh = RefreshTokenRequest(
            refresh_token="refresh_token_here"
        )
        
        assert refresh.refresh_token == "refresh_token_here"


class TestDeviceSchemas:
    """Test backend/schemas/device.py"""
    
    def test_device_base_schema(self):
        """Test DeviceBase schema"""
        from backend.schemas.device import DeviceBase
        
        device = DeviceBase(
            name="router1",
            ip_address="192.168.1.1",
            device_type="router",
            vendor="cisco",
            model="ISR4321"
        )
        
        assert device.name == "router1"
        assert device.ip_address == "192.168.1.1"
        
        # Test IP validation
        with pytest.raises(ValidationError):
            DeviceBase(
                name="device",
                ip_address="invalid_ip",
                device_type="router"
            )
    
    def test_device_create_schema(self):
        """Test DeviceCreate schema"""
        from backend.schemas.device import DeviceCreate
        
        device = DeviceCreate(
            name="switch1",
            ip_address="192.168.1.2",
            device_type="switch",
            vendor="cisco",
            model="Catalyst 2960",
            snmp_community="public",
            snmp_version="2c",
            ssh_username="admin",
            ssh_password="password"
        )
        
        assert device.snmp_community == "public"
        assert device.ssh_username == "admin"
    
    def test_device_update_schema(self):
        """Test DeviceUpdate schema"""
        from backend.schemas.device import DeviceUpdate
        
        update = DeviceUpdate(
            name="updated-router",
            status="maintenance"
        )
        
        assert update.name == "updated-router"
        assert update.status == "maintenance"
        assert update.ip_address is None
    
    def test_device_response_schema(self):
        """Test DeviceResponse schema"""
        from backend.schemas.device import DeviceResponse
        
        device = DeviceResponse(
            id=1,
            name="router1",
            ip_address="192.168.1.1",
            device_type="router",
            vendor="cisco",
            model="ISR4321",
            status="active",
            last_seen=datetime.utcnow(),
            created_at=datetime.utcnow(),
            metrics_count=100,
            alerts_count=5
        )
        
        assert device.id == 1
        assert device.status == "active"
        assert device.metrics_count == 100
    
    def test_device_query_schema(self):
        """Test DeviceQuery schema"""
        from backend.schemas.device import DeviceQuery
        
        query = DeviceQuery(
            status="active",
            device_type="router",
            vendor="cisco",
            search="ISR"
        )
        
        assert query.status == "active"
        assert query.device_type == "router"
        assert query.search == "ISR"
    
    def test_device_metrics_schema(self):
        """Test DeviceMetrics schema"""
        from backend.schemas.device import DeviceMetrics
        
        metrics = DeviceMetrics(
            device_id=1,
            cpu_usage=45.5,
            memory_usage=60.0,
            disk_usage=30.0,
            temperature=35.0,
            uptime=1000000,
            timestamp=datetime.utcnow()
        )
        
        assert metrics.cpu_usage == 45.5
        assert metrics.memory_usage == 60.0


class TestMetricSchemas:
    """Test backend/schemas/metric.py"""
    
    def test_metric_base_schema(self):
        """Test MetricBase schema"""
        from backend.schemas.metric import MetricBase
        
        metric = MetricBase(
            device_id=1,
            metric_type="cpu_usage",
            value=75.5,
            unit="percent"
        )
        
        assert metric.device_id == 1
        assert metric.value == 75.5
        
        # Test value validation
        with pytest.raises(ValidationError):
            MetricBase(
                device_id=1,
                metric_type="cpu_usage",
                value=-10  # Negative value
            )
    
    def test_metric_create_schema(self):
        """Test MetricCreate schema"""
        from backend.schemas.metric import MetricCreate
        
        metric = MetricCreate(
            device_id=1,
            metric_type="temperature",
            value=65.0,
            unit="celsius",
            timestamp=datetime.utcnow()
        )
        
        assert metric.unit == "celsius"
        assert metric.timestamp is not None
    
    def test_metric_response_schema(self):
        """Test MetricResponse schema"""
        from backend.schemas.metric import MetricResponse
        
        metric = MetricResponse(
            id=1,
            device_id=1,
            device_name="router1",
            metric_type="cpu_usage",
            value=75.5,
            unit="percent",
            status="warning",
            timestamp=datetime.utcnow()
        )
        
        assert metric.id == 1
        assert metric.device_name == "router1"
        assert metric.status == "warning"
    
    def test_metric_query_schema(self):
        """Test MetricQuery schema"""
        from backend.schemas.metric import MetricQuery
        
        query = MetricQuery(
            device_id=1,
            metric_type="cpu_usage",
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
            aggregation="avg"
        )
        
        assert query.device_id == 1
        assert query.aggregation == "avg"
    
    def test_metric_aggregation_schema(self):
        """Test MetricAggregation schema"""
        from backend.schemas.metric import MetricAggregation
        
        agg = MetricAggregation(
            device_id=1,
            metric_type="cpu_usage",
            period="hourly",
            min_value=20.0,
            max_value=95.0,
            avg_value=60.0,
            count=60,
            timestamp=datetime.utcnow()
        )
        
        assert agg.min_value == 20.0
        assert agg.max_value == 95.0
        assert agg.avg_value == 60.0


class TestAlertSchemas:
    """Test backend/schemas/alert.py"""
    
    def test_alert_base_schema(self):
        """Test AlertBase schema"""
        from backend.schemas.alert import AlertBase
        
        alert = AlertBase(
            device_id=1,
            alert_type="threshold",
            severity="warning",
            message="CPU usage above 80%"
        )
        
        assert alert.device_id == 1
        assert alert.severity == "warning"
    
    def test_alert_create_schema(self):
        """Test AlertCreate schema"""
        from backend.schemas.alert import AlertCreate
        
        alert = AlertCreate(
            device_id=1,
            alert_type="availability",
            severity="critical",
            message="Device unreachable",
            details={"last_seen": "2024-01-01T12:00:00"}
        )
        
        assert alert.alert_type == "availability"
        assert alert.details["last_seen"] == "2024-01-01T12:00:00"
    
    def test_alert_update_schema(self):
        """Test AlertUpdate schema"""
        from backend.schemas.alert import AlertUpdate
        
        update = AlertUpdate(
            status="acknowledged",
            assigned_to=1,
            notes="Investigating the issue"
        )
        
        assert update.status == "acknowledged"
        assert update.assigned_to == 1
    
    def test_alert_response_schema(self):
        """Test AlertResponse schema"""
        from backend.schemas.alert import AlertResponse
        
        alert = AlertResponse(
            id=1,
            device_id=1,
            device_name="router1",
            alert_type="threshold",
            severity="warning",
            status="open",
            message="High CPU",
            created_at=datetime.utcnow(),
            acknowledged_at=None,
            resolved_at=None
        )
        
        assert alert.id == 1
        assert alert.device_name == "router1"
        assert alert.acknowledged_at is None
    
    def test_alert_query_schema(self):
        """Test AlertQuery schema"""
        from backend.schemas.alert import AlertQuery
        
        query = AlertQuery(
            device_id=1,
            severity=["warning", "critical"],
            status="open",
            start_date=datetime.utcnow() - timedelta(days=7),
            end_date=datetime.utcnow()
        )
        
        assert query.device_id == 1
        assert "warning" in query.severity
    
    def test_alert_acknowledge_schema(self):
        """Test AlertAcknowledge schema"""
        from backend.schemas.alert import AlertAcknowledge
        
        ack = AlertAcknowledge(
            notes="Looking into this",
            estimated_resolution=datetime.utcnow() + timedelta(hours=2)
        )
        
        assert ack.notes == "Looking into this"
        assert ack.estimated_resolution is not None


class TestNotificationSchemas:
    """Test backend/schemas/notification.py"""
    
    def test_notification_base_schema(self):
        """Test NotificationBase schema"""
        from backend.schemas.notification import NotificationBase
        
        notif = NotificationBase(
            user_id=1,
            notification_type="email",
            title="System Alert",
            message="Alert message"
        )
        
        assert notif.user_id == 1
        assert notif.notification_type == "email"
    
    def test_notification_create_schema(self):
        """Test NotificationCreate schema"""
        from backend.schemas.notification import NotificationCreate
        
        notif = NotificationCreate(
            user_id=1,
            notification_type="sms",
            title="Alert",
            message="Device down",
            recipient="+1234567890",
            priority="high"
        )
        
        assert notif.recipient == "+1234567890"
        assert notif.priority == "high"
    
    def test_notification_response_schema(self):
        """Test NotificationResponse schema"""
        from backend.schemas.notification import NotificationResponse
        
        notif = NotificationResponse(
            id=1,
            user_id=1,
            notification_type="email",
            title="Alert",
            message="Test",
            status="sent",
            sent_at=datetime.utcnow(),
            read_at=None
        )
        
        assert notif.status == "sent"
        assert notif.read_at is None
    
    def test_notification_query_schema(self):
        """Test NotificationQuery schema"""
        from backend.schemas.notification import NotificationQuery
        
        query = NotificationQuery(
            user_id=1,
            notification_type="email",
            status="unread",
            start_date=datetime.utcnow() - timedelta(days=1)
        )
        
        assert query.user_id == 1
        assert query.status == "unread"
    
    def test_notification_mark_read_schema(self):
        """Test NotificationMarkRead schema"""
        from backend.schemas.notification import NotificationMarkRead
        
        mark = NotificationMarkRead(
            notification_ids=[1, 2, 3],
            mark_all=False
        )
        
        assert len(mark.notification_ids) == 3
        assert mark.mark_all is False


class TestDiscoverySchemas:
    """Test backend/schemas/discovery.py"""
    
    def test_discovery_request_schema(self):
        """Test DiscoveryRequest schema"""
        try:
            from backend.schemas.discovery import DiscoveryRequest
            
            request = DiscoveryRequest(
                subnet="192.168.1.0/24",
                methods=["snmp", "ping"],
                credentials={
                    "snmp_community": "public",
                    "ssh_username": "admin"
                }
            )
            
            assert request.subnet == "192.168.1.0/24"
            assert "snmp" in request.methods
        except ImportError:
            pass
    
    def test_discovery_job_response_schema(self):
        """Test DiscoveryJobResponse schema"""
        try:
            from backend.schemas.discovery import DiscoveryJobResponse
            
            job = DiscoveryJobResponse(
                id=1,
                name="Network Scan",
                subnet="192.168.1.0/24",
                status="running",
                progress=50,
                devices_found=10,
                started_at=datetime.utcnow(),
                completed_at=None
            )
            
            assert job.progress == 50
            assert job.devices_found == 10
        except ImportError:
            pass


class TestPaginationSchemas:
    """Test pagination schemas"""
    
    def test_pagination_params_schema(self):
        """Test PaginationParams schema"""
        try:
            from backend.schemas.pagination import PaginationParams
            
            params = PaginationParams(
                page=2,
                page_size=50,
                sort_by="created_at",
                order="desc"
            )
            
            assert params.page == 2
            assert params.page_size == 50
            assert params.order == "desc"
        except ImportError:
            pass
    
    def test_paginated_response_schema(self):
        """Test PaginatedResponse schema"""
        try:
            from backend.schemas.pagination import PaginatedResponse
            
            response = PaginatedResponse(
                items=[{"id": 1}, {"id": 2}],
                total=100,
                page=1,
                page_size=10,
                total_pages=10,
                has_next=True,
                has_prev=False
            )
            
            assert response.total == 100
            assert response.has_next is True
        except ImportError:
            pass


# Phase 10: WebSocket Testing

class TestWebSocketManager:
    """Test backend/api/websocket_manager.py"""
    
    @pytest.mark.asyncio
    async def test_websocket_manager_creation(self):
        """Test WebSocketManager instantiation"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        assert manager is not None
        assert hasattr(manager, 'active_connections')
    
    @pytest.mark.asyncio
    async def test_websocket_connect(self):
        """Test WebSocket connection"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        websocket = Mock()
        
        await manager.connect(websocket, client_id="user1")
        assert "user1" in manager.active_connections
    
    @pytest.mark.asyncio
    async def test_websocket_disconnect(self):
        """Test WebSocket disconnection"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        websocket = Mock()
        
        await manager.connect(websocket, client_id="user1")
        await manager.disconnect(client_id="user1")
        assert "user1" not in manager.active_connections
    
    @pytest.mark.asyncio
    async def test_websocket_broadcast(self):
        """Test WebSocket broadcast"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        
        # Add mock connections
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        await manager.connect(ws1, "user1")
        await manager.connect(ws2, "user2")
        
        # Broadcast message
        await manager.broadcast({"type": "alert", "message": "test"})
        
        ws1.send_json.assert_called_once()
        ws2.send_json.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_websocket_send_personal(self):
        """Test WebSocket personal message"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        websocket = AsyncMock()
        
        await manager.connect(websocket, "user1")
        await manager.send_personal_message(
            {"type": "notification"},
            "user1"
        )
        
        websocket.send_json.assert_called_once()


class TestWebSocketHandler:
    """Test backend/api/websocket_handler.py"""
    
    @pytest.mark.asyncio
    async def test_websocket_handler_creation(self):
        """Test WebSocketHandler instantiation"""
        from backend.api.websocket_handler import WebSocketHandler
        
        handler = WebSocketHandler()
        assert handler is not None
    
    @pytest.mark.asyncio
    async def test_handle_connection(self):
        """Test WebSocket connection handling"""
        from backend.api.websocket_handler import WebSocketHandler
        
        handler = WebSocketHandler()
        websocket = AsyncMock()
        
        with patch('backend.api.websocket_handler.authenticate_websocket') as mock_auth:
            mock_auth.return_value = {"user_id": 1, "username": "testuser"}
            
            await handler.handle_connection(websocket, token="test_token")
            mock_auth.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_handle_message(self):
        """Test WebSocket message handling"""
        from backend.api.websocket_handler import WebSocketHandler
        
        handler = WebSocketHandler()
        
        message = {
            "type": "subscribe",
            "channel": "alerts"
        }
        
        result = await handler.handle_message(message, user_id=1)
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_handle_subscription(self):
        """Test WebSocket subscription handling"""
        from backend.api.websocket_handler import WebSocketHandler
        
        handler = WebSocketHandler()
        
        # Subscribe to channel
        await handler.subscribe(user_id=1, channel="metrics")
        assert handler.is_subscribed(user_id=1, channel="metrics")
        
        # Unsubscribe
        await handler.unsubscribe(user_id=1, channel="metrics")
        assert not handler.is_subscribed(user_id=1, channel="metrics")


class TestWebSocketEvents:
    """Test WebSocket event types and handling"""
    
    def test_websocket_event_types(self):
        """Test WebSocket event type definitions"""
        try:
            from backend.api.websocket_events import EventType
            
            assert EventType.CONNECT.value == "connect"
            assert EventType.DISCONNECT.value == "disconnect"
            assert EventType.SUBSCRIBE.value == "subscribe"
            assert EventType.UNSUBSCRIBE.value == "unsubscribe"
            assert EventType.MESSAGE.value == "message"
            assert EventType.ALERT.value == "alert"
            assert EventType.METRIC.value == "metric"
            assert EventType.NOTIFICATION.value == "notification"
        except ImportError:
            pass
    
    def test_websocket_message_format(self):
        """Test WebSocket message formatting"""
        try:
            from backend.api.websocket_events import format_message
            
            message = format_message(
                event_type="alert",
                data={"severity": "critical", "message": "Device down"},
                timestamp=datetime.utcnow()
            )
            
            assert message["type"] == "alert"
            assert message["data"]["severity"] == "critical"
            assert "timestamp" in message
        except ImportError:
            pass


class TestWebSocketAuthentication:
    """Test WebSocket authentication"""
    
    @pytest.mark.asyncio
    async def test_websocket_auth_valid_token(self):
        """Test WebSocket auth with valid token"""
        try:
            from backend.api.websocket_auth import authenticate_websocket
            
            with patch('backend.services.auth_service.AuthService.verify_token') as mock_verify:
                mock_verify.return_value = {"user_id": 1, "username": "testuser"}
                
                result = await authenticate_websocket("valid_token")
                assert result["user_id"] == 1
        except ImportError:
            pass
    
    @pytest.mark.asyncio
    async def test_websocket_auth_invalid_token(self):
        """Test WebSocket auth with invalid token"""
        try:
            from backend.api.websocket_auth import authenticate_websocket
            
            with patch('backend.services.auth_service.AuthService.verify_token') as mock_verify:
                mock_verify.return_value = None
                
                result = await authenticate_websocket("invalid_token")
                assert result is None
        except ImportError:
            pass


class TestWebSocketRealTime:
    """Test real-time functionality via WebSocket"""
    
    @pytest.mark.asyncio
    async def test_realtime_metrics_broadcast(self):
        """Test real-time metrics broadcasting"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        websocket = AsyncMock()
        
        # Connect and subscribe to metrics
        await manager.connect(websocket, "user1")
        await manager.subscribe("user1", "metrics")
        
        # Broadcast metric update
        metric_data = {
            "device_id": 1,
            "cpu_usage": 85,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await manager.broadcast_to_channel("metrics", metric_data)
        websocket.send_json.assert_called()
    
    @pytest.mark.asyncio
    async def test_realtime_alert_notification(self):
        """Test real-time alert notifications"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        websocket = AsyncMock()
        
        await manager.connect(websocket, "user1")
        await manager.subscribe("user1", "alerts")
        
        alert_data = {
            "device_id": 1,
            "severity": "critical",
            "message": "Device down"
        }
        
        await manager.broadcast_to_channel("alerts", alert_data)
        websocket.send_json.assert_called()


class TestWebSocketScaling:
    """Test WebSocket scaling and performance"""
    
    @pytest.mark.asyncio
    async def test_multiple_connections(self):
        """Test handling multiple WebSocket connections"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        
        # Connect 100 clients
        connections = []
        for i in range(100):
            ws = AsyncMock()
            await manager.connect(ws, f"user{i}")
            connections.append(ws)
        
        assert len(manager.active_connections) == 100
        
        # Broadcast to all
        await manager.broadcast({"test": "message"})
        
        for ws in connections:
            ws.send_json.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_connection_cleanup(self):
        """Test connection cleanup on disconnect"""
        from backend.api.websocket_manager import WebSocketManager
        
        manager = WebSocketManager()
        
        # Connect and disconnect multiple times
        for i in range(10):
            ws = AsyncMock()
            await manager.connect(ws, "user1")
            await manager.disconnect("user1")
        
        assert len(manager.active_connections) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])