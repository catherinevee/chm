"""
Comprehensive tests for Service files to boost coverage to 65%
Simplified approach that focuses on core functionality without complex mocking
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession

# Mock all external dependencies before importing services
import sys

# Mock ValidationService
class MockValidationService:
    def validate_metric_data(self, data):
        return 'value' in data and isinstance(data['value'], (int, float))
    
    def validate_hostname(self, hostname):
        if not hostname or len(hostname) < 3:
            raise ValueError("Invalid hostname")
        return hostname
    
    def validate_ip_address(self, ip):
        if not ip or "." not in ip:
            raise ValueError("Invalid IP address")
        return ip
    
    def validate_device_type(self, device_type):
        valid_types = ["router", "switch", "firewall", "server"]
        if device_type not in valid_types:
            raise ValueError("Invalid device type")
        return device_type
    
    def sanitize_string(self, value, max_length):
        return str(value)[:max_length] if value else value
    
    def validate_snmp_community(self, community):
        return community
    
    def validate_snmp_version(self, version):
        return version

# Mock credential encryption
class MockCredentialEncryption:
    @staticmethod
    def encrypt_snmp_credential(credential, version):
        return f"encrypted_{credential}_{version}"
    
    @staticmethod
    def encrypt_credential(credential, metadata=None):
        return f"encrypted_{credential}"

# Mock WebSocket Manager
class MockWebSocketManager:
    async def send_to_user(self, user_id, message):
        return True
    
    async def broadcast_alert(self, data):
        return True
    
    async def broadcast_metric_update(self, data):
        return True
    
    async def broadcast_device_update(self, data):
        return True

# Apply mocks
sys.modules['backend.services.validation_service'] = MagicMock()
sys.modules['backend.services.validation_service'].ValidationService = MockValidationService

sys.modules['backend.common.security'] = MagicMock()
sys.modules['backend.common.security'].credential_encryption = MockCredentialEncryption()

sys.modules['backend.services.websocket_manager'] = MagicMock()
sys.modules['backend.services.websocket_manager'].WebSocketManager = MockWebSocketManager

# Mock ws_manager import
mock_ws_manager = MockWebSocketManager()

# Now import the services
from backend.services.alert_service import AlertService
from backend.services.device_service import DeviceService
from backend.services.metrics_service import MetricsService
from backend.services.notification_service import NotificationService
from backend.common.exceptions import AppException


class TestServicesCoverageBoosting:
    """Test service coverage with simplified mocking approach"""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock(spec=AsyncSession)
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.add = MagicMock()
        session.get = AsyncMock()
        session.execute = AsyncMock()
        session.scalar = AsyncMock()
        session.delete = AsyncMock()
        return session
    
    # ALERT SERVICE TESTS
    @pytest.mark.asyncio
    async def test_alert_service_create_alert_success(self, mock_db_session):
        """Test alert creation success path"""
        # Setup mocks
        mock_device = MagicMock()
        mock_device.id = uuid4()
        mock_device.hostname = "test-device"
        mock_db_session.get.return_value = mock_device
        
        alert_data = {
            "device_id": str(mock_device.id),
            "message": "Test alert",
            "severity": "warning"
        }
        
        with patch('backend.api.websocket_manager.ws_manager', mock_ws_manager):
            with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
                result = await AlertService.create_alert(mock_db_session, alert_data)
                
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_alert_service_get_alerts(self, mock_db_session):
        """Test alert retrieval"""
        mock_alert = MagicMock()
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_alert]
        mock_db_session.execute.return_value = mock_result
        
        results = await AlertService.get_alerts(mock_db_session)
        assert len(results) == 1
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_alert_service_get_statistics(self, mock_db_session):
        """Test alert statistics retrieval"""
        # Mock results for different queries
        mock_db_session.execute.side_effect = [
            AsyncMock(scalar=lambda: 10),  # total count
            AsyncMock(__iter__=lambda x: iter([MagicMock(severity="critical", count=2)])),  # severity
            AsyncMock(__iter__=lambda x: iter([MagicMock(status="active", count=8)])),  # status
            AsyncMock(scalar=lambda: 8),  # active count
            AsyncMock(scalar=lambda: 3600)  # avg resolution time
        ]
        
        result = await AlertService.get_alert_statistics(mock_db_session)
        assert "total_alerts" in result
        assert "active_alerts" in result
        assert "by_severity" in result
    
    @pytest.mark.asyncio
    async def test_alert_service_acknowledge_alert(self, mock_db_session):
        """Test alert acknowledgment"""
        mock_alert = MagicMock()
        mock_alert.status = "active"
        mock_alert.created_by = uuid4()
        mock_alert.metadata = {}
        mock_db_session.get.return_value = mock_alert
        
        with patch('backend.services.notification_service.NotificationService'):
            result = await AlertService.acknowledge_alert(
                mock_db_session, uuid4(), uuid4(), "Investigating"
            )
            
            assert mock_alert.status == "acknowledged"
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_alert_service_resolve_alert(self, mock_db_session):
        """Test alert resolution"""
        mock_alert = MagicMock()
        mock_alert.status = "active"
        mock_alert.created_by = uuid4()
        mock_alert.metadata = {}
        mock_db_session.get.return_value = mock_alert
        
        with patch('backend.services.notification_service.NotificationService'):
            result = await AlertService.resolve_alert(
                mock_db_session, uuid4(), uuid4(), "Fixed issue"
            )
            
            assert mock_alert.status == "resolved"
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_alert_service_escalate_alert(self, mock_db_session):
        """Test alert escalation"""
        mock_alert = MagicMock()
        mock_alert.severity = "warning"
        mock_alert.status = "active"
        mock_alert.metadata = {}
        mock_db_session.get.return_value = mock_alert
        
        with patch.object(AlertService, '_send_escalation_notifications', new=AsyncMock()):
            result = await AlertService.escalate_alert(
                mock_db_session, uuid4(), uuid4()
            )
            
            assert mock_alert.severity == "error"
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_alert_service_bulk_update(self, mock_db_session):
        """Test bulk alert status update"""
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_db_session.execute.return_value = mock_result
        
        count = await AlertService.bulk_update_status(
            mock_db_session, [uuid4(), uuid4()], "acknowledged", uuid4()
        )
        
        assert count == 5
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_alert_service_instance_methods(self):
        """Test instance methods"""
        service = AlertService()
        count = await service.get_active_alert_count()
        assert isinstance(count, int)
    
    # DEVICE SERVICE TESTS
    @pytest.mark.asyncio
    async def test_device_service_create_device(self, mock_db_session):
        """Test device creation"""
        service = DeviceService(mock_db_session)
        
        # Mock no existing device
        mock_db_session.execute.return_value.scalar_one_or_none.return_value = None
        
        device_data = {
            "hostname": "test-device",
            "ip_address": "192.168.1.1",
            "device_type": "router"
        }
        
        with patch('backend.api.websocket_manager.ws_manager', mock_ws_manager):
            with patch.object(service, '_trigger_device_discovery', new=AsyncMock()):
                result = await service.create_device(device_data)
                
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_device_service_get_device(self, mock_db_session):
        """Test device retrieval"""
        service = DeviceService(mock_db_session)
        
        mock_device = MagicMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result
        
        result = await service.get_device(str(uuid4()))
        assert result == mock_device
    
    @pytest.mark.asyncio
    async def test_device_service_list_devices(self, mock_db_session):
        """Test device listing"""
        service = DeviceService(mock_db_session)
        
        mock_devices = [MagicMock(), MagicMock()]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_devices
        mock_db_session.execute.return_value = mock_result
        mock_db_session.scalar.return_value = 2
        
        devices, total = await service.list_devices()
        assert len(devices) == 2
        assert total == 2
    
    @pytest.mark.asyncio
    async def test_device_service_update_device(self, mock_db_session):
        """Test device update"""
        service = DeviceService(mock_db_session)
        
        mock_device = MagicMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result
        
        with patch('backend.api.websocket_manager.ws_manager', mock_ws_manager):
            result = await service.update_device(
                str(uuid4()), {"hostname": "updated-device"}
            )
            
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_device_service_delete_device(self, mock_db_session):
        """Test device deletion"""
        service = DeviceService(mock_db_session)
        
        mock_device = MagicMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute.return_value = mock_result
        
        result = await service.delete_device(str(uuid4()))
        assert result is True
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_device_service_get_metrics(self, mock_db_session):
        """Test device metrics retrieval"""
        service = DeviceService(mock_db_session)
        
        mock_device = MagicMock()
        mock_metrics = [MagicMock(), MagicMock()]
        
        # Mock two execute calls: device check and metrics query
        mock_device_result = AsyncMock()
        mock_device_result.scalar_one_or_none.return_value = mock_device
        
        mock_metrics_result = AsyncMock()
        mock_metrics_result.scalars.return_value.all.return_value = mock_metrics
        
        mock_db_session.execute.side_effect = [mock_device_result, mock_metrics_result]
        
        result = await service.get_device_metrics(str(uuid4()))
        assert len(result) == 2
    
    @pytest.mark.asyncio
    async def test_device_service_get_status(self, mock_db_session):
        """Test device status retrieval"""
        service = DeviceService(mock_db_session)
        
        mock_device = MagicMock()
        mock_device.id = str(uuid4())
        mock_device.hostname = "test-device"
        mock_device.ip_address = "192.168.1.1"
        mock_device.current_state = "active"
        mock_device.is_active = True
        mock_device.last_poll_time = None
        mock_device.discovery_status = "complete"
        mock_device.consecutive_failures = 0
        
        mock_device_result = AsyncMock()
        mock_device_result.scalar_one_or_none.return_value = mock_device
        
        mock_metrics_result = AsyncMock()
        mock_metrics_result.scalars.return_value = [MagicMock()]
        
        mock_db_session.execute.side_effect = [mock_device_result, mock_metrics_result]
        mock_db_session.scalar.side_effect = [2, 3]  # alerts, interfaces
        
        with patch.object(service, '_calculate_health_score', return_value=85.0):
            result = await service.get_device_status(str(uuid4()))
            
            assert result["device_id"] == mock_device.id
            assert result["hostname"] == mock_device.hostname
            assert result["health_score"] == 85.0
    
    @pytest.mark.asyncio
    async def test_device_service_instance_methods(self, mock_db_session):
        """Test device service instance methods"""
        service = DeviceService(mock_db_session)
        
        count = await service.get_monitored_device_count()
        assert isinstance(count, int)
        
        # Test private methods
        mock_device = MagicMock()
        mock_device.current_state = "active"
        mock_device.consecutive_failures = 0
        mock_device.circuit_breaker_trips = 0
        
        health_score = await service._calculate_health_score(mock_device)
        assert health_score == 100.0
    
    # METRICS SERVICE TESTS
    @pytest.mark.asyncio
    async def test_metrics_service_create_metric(self, mock_db_session):
        """Test metric creation"""
        mock_device = MagicMock()
        mock_device.id = uuid4()
        mock_db_session.get.return_value = mock_device
        
        metric_data = {
            "name": "cpu_usage",
            "value": 75.0,
            "unit": "percent"
        }
        
        with patch('backend.api.websocket_manager.ws_manager', mock_ws_manager):
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                result = await MetricsService.create_metric(
                    mock_db_session, mock_device.id, metric_data
                )
                
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_metrics_service_get_performance_summary(self, mock_db_session):
        """Test performance summary"""
        mock_row = MagicMock()
        mock_row.metric_type = "cpu_usage"
        mock_row.avg_value = 75.5
        mock_row.min_value = 50.0
        mock_row.max_value = 95.0
        mock_row.sample_count = 100
        
        mock_result = AsyncMock()
        mock_result.all.return_value = [mock_row]
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(MetricsService, '_calculate_availability', return_value=99.5):
            result = await MetricsService.get_performance_summary(
                mock_db_session, device_id=uuid4()
            )
            
            assert "metrics" in result
            assert "cpu_usage" in result["metrics"]
            assert result["availability"] == 99.5
    
    @pytest.mark.asyncio
    async def test_metrics_service_get_graph_data(self, mock_db_session):
        """Test graph data retrieval"""
        mock_metrics = []
        base_time = datetime.utcnow()
        for i in range(3):
            mock_metric = MagicMock()
            mock_metric.value = 70 + i * 5
            mock_metric.timestamp = base_time + timedelta(minutes=i * 5)
            mock_metrics.append(mock_metric)
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        result = await MetricsService.get_graph_data(
            mock_db_session, uuid4(), "cpu_usage"
        )
        
        assert len(result) > 0
        assert "timestamp" in result[0]
        assert "value" in result[0]
    
    @pytest.mark.asyncio
    async def test_metrics_service_bulk_create(self, mock_db_session):
        """Test bulk metric creation"""
        mock_device = MagicMock()
        mock_device.id = uuid4()
        mock_db_session.get.return_value = mock_device
        
        metrics_data = [
            {"device_id": mock_device.id, "name": "cpu_usage", "value": 75.0},
            {"device_id": mock_device.id, "name": "memory_usage", "value": 60.0}
        ]
        
        with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
            result = await MetricsService.bulk_create_metrics(
                mock_db_session, metrics_data
            )
            
            assert len(result) == 2
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_metrics_service_delete_old_metrics(self, mock_db_session):
        """Test old metrics deletion"""
        old_metrics = [MagicMock(), MagicMock()]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = old_metrics
        mock_db_session.execute.return_value = mock_result
        
        count = await MetricsService.delete_old_metrics(mock_db_session)
        
        assert count == 2
        assert mock_db_session.delete.call_count == 2
        mock_db_session.commit.assert_called_once()
    
    # NOTIFICATION SERVICE TESTS
    @pytest.mark.asyncio
    async def test_notification_service_create_notification(self, mock_db_session):
        """Test notification creation"""
        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_db_session.get.return_value = mock_user
        
        with patch.object(NotificationService, '_send_websocket_notification', new=AsyncMock()):
            result = await NotificationService.create_notification(
                mock_db_session,
                user_id=mock_user.id,
                title="Test Notification",
                message="Test message"
            )
            
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_get_notifications(self, mock_db_session):
        """Test notification retrieval"""
        mock_notifications = [MagicMock(), MagicMock()]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_notifications
        mock_db_session.execute.return_value = mock_result
        
        result = await NotificationService.get_user_notifications(
            mock_db_session, uuid4()
        )
        
        assert len(result) == 2
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_mark_as_read(self, mock_db_session):
        """Test notification mark as read"""
        mock_notification = MagicMock()
        mock_notification.read = False
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, 'get_unread_count', return_value=5):
            with patch.object(NotificationService, '_send_websocket_update', new=AsyncMock()):
                result = await NotificationService.mark_as_read(
                    mock_db_session, uuid4(), uuid4()
                )
                
                assert mock_notification.read is True
                mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_get_unread_count(self, mock_db_session):
        """Test unread count retrieval"""
        mock_result = AsyncMock()
        mock_result.scalar.return_value = 5
        mock_db_session.execute.return_value = mock_result
        
        count = await NotificationService.get_unread_count(
            mock_db_session, uuid4()
        )
        
        assert count == 5
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_mark_all_as_read(self, mock_db_session):
        """Test mark all notifications as read"""
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, '_send_websocket_update', new=AsyncMock()):
            count = await NotificationService.mark_all_as_read(
                mock_db_session, uuid4()
            )
            
            assert count == 3
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_delete_notification(self, mock_db_session):
        """Test notification deletion"""
        mock_notification = MagicMock()
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        
        result = await NotificationService.delete_notification(
            mock_db_session, uuid4(), uuid4()
        )
        
        assert result is True
        mock_db_session.delete.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_delete_old_notifications(self, mock_db_session):
        """Test old notification deletion"""
        old_notifications = [MagicMock(), MagicMock()]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = old_notifications
        mock_db_session.execute.return_value = mock_result
        
        count = await NotificationService.delete_old_notifications(mock_db_session)
        
        assert count == 2
        assert mock_db_session.delete.call_count == 2
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_test_notification(self, mock_db_session):
        """Test test notification creation"""
        mock_user = MagicMock()
        mock_user.id = uuid4()
        
        with patch.object(NotificationService, 'create_notification', new=AsyncMock()) as mock_create:
            mock_create.return_value = mock_user
            
            result = await NotificationService.create_test_notification(
                mock_db_session, mock_user.id
            )
            
            mock_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_notification_service_broadcast_notification(self, mock_db_session):
        """Test notification broadcast"""
        mock_users = [MagicMock(), MagicMock()]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_users
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, 'create_notification', new=AsyncMock()):
            count = await NotificationService.broadcast_notification(
                mock_db_session, "Test Title", "Test Message"
            )
            
            assert count == 2
    
    @pytest.mark.asyncio
    async def test_notification_service_instance_methods(self):
        """Test notification service instance methods"""
        service = NotificationService()
        
        # Test alert notification
        result = await service.send_alert_notification(
            "alert_123", "critical", "Test alert"
        )
        assert result is True
        
        # Test password reset email
        result = await service.send_password_reset_email(
            "test@example.com", "reset_token", "Test User"
        )
        assert result is True
    
    # ERROR PATH TESTS
    @pytest.mark.asyncio
    async def test_error_handling_patterns(self, mock_db_session):
        """Test error handling in various scenarios"""
        # Test database errors
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with pytest.raises(AppException):
            await AlertService.create_alert(mock_db_session, {"message": "test"})
        
        mock_db_session.rollback.assert_called()
        
        # Reset for next test
        mock_db_session.reset_mock()
        mock_db_session.commit.side_effect = None
        
        # Test not found errors
        mock_db_session.get.return_value = None
        
        with pytest.raises(AppException):
            await AlertService.create_alert(mock_db_session, {
                "device_id": str(uuid4()),
                "message": "test"
            })
    
    @pytest.mark.asyncio
    async def test_private_method_coverage(self, mock_db_session):
        """Test private methods for coverage"""
        # Test alert notifications
        mock_alert = MagicMock()
        mock_alert.severity = "critical"
        
        # Mock admin query
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [MagicMock()]
        mock_db_session.execute.return_value = mock_result
        
        with patch('backend.services.notification_service.NotificationService'):
            await AlertService._send_alert_notifications(mock_db_session, mock_alert)
        
        # Test availability calculation
        mock_metrics = [MagicMock(metric_value=1) for _ in range(10)]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        availability = await MetricsService._calculate_availability(
            mock_db_session, uuid4(), datetime.utcnow() - timedelta(days=1)
        )
        assert availability == 100.0
    
    @pytest.mark.asyncio
    async def test_websocket_notification_methods(self):
        """Test WebSocket notification methods"""
        mock_notification = MagicMock()
        mock_notification.id = uuid4()
        mock_notification.user_id = uuid4()
        mock_notification.title = "Test"
        mock_notification.message = "Test message"
        mock_notification.notification_type = "info"
        mock_notification.severity = "normal"
        mock_notification.created_at = datetime.utcnow()
        
        # These should not raise exceptions
        await NotificationService._send_websocket_notification(
            mock_notification.user_id, mock_notification
        )
        
        await NotificationService._send_websocket_update(
            uuid4(), {"unread_count": 5}
        )
        
        # Test email notification
        mock_user = MagicMock()
        mock_user.email = "test@example.com"
        
        await NotificationService._send_email_notification(
            mock_user, mock_notification
        )