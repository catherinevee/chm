"""
Comprehensive tests for Alert Service to boost coverage to 65%
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession

# Mock ValidationService before importing
class MockValidationService:
    def __init__(self):
        pass
    
    def validate_metric_data(self, data):
        return True

# Apply the mock
import sys
sys.modules['backend.services.validation_service'] = MagicMock()
sys.modules['backend.services.validation_service'].ValidationService = MockValidationService

from backend.services.alert_service import AlertService
from backend.common.exceptions import AppException


class TestAlertService:
    """Comprehensive test cases for AlertService"""
    
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
    
    @pytest.fixture
    def mock_device(self):
        """Mock device object"""
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        device.ip_address = "192.168.1.1"
        return device
    
    @pytest.fixture
    def mock_alert(self):
        """Mock alert object"""
        alert = MagicMock()
        alert.id = uuid4()
        alert.device_id = uuid4()
        alert.alert_type = "cpu_high"
        alert.severity = "warning"
        alert.message = "CPU usage high"
        alert.status = "active"
        alert.created_at = datetime.utcnow()
        alert.metadata = {}
        return alert
    
    @pytest.fixture
    def alert_data(self):
        """Sample alert data"""
        return {
            "device_id": str(uuid4()),
            "alert_type": "cpu_high",
            "severity": "warning",
            "message": "CPU usage is high",
            "description": "CPU utilization exceeded 80%",
            "metadata": {"cpu_value": 85}
        }
    
    # Test create_alert method
    @pytest.mark.asyncio
    async def test_create_alert_success(self, mock_db_session, mock_device, alert_data):
        """Test successful alert creation"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        with patch('backend.services.alert_service.ws_manager') as mock_ws:
            mock_ws.broadcast_alert = AsyncMock()
            
            # Execute
            result = await AlertService.create_alert(
                mock_db_session,
                alert_data,
                user_id=uuid4()
            )
            
            # Verify
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once()
            mock_ws.broadcast_alert.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_device_not_found(self, mock_db_session, alert_data):
        """Test alert creation with non-existent device"""
        # Setup mocks
        mock_db_session.get.return_value = None
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.create_alert(mock_db_session, alert_data)
        
        assert exc_info.value.status_code == 404
        assert "Device" in str(exc_info.value.detail)
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_no_device_id(self, mock_db_session):
        """Test alert creation without device_id"""
        alert_data = {
            "message": "Test alert without device",
            "severity": "info"
        }
        
        with patch('backend.services.alert_service.ws_manager') as mock_ws:
            mock_ws.broadcast_alert = AsyncMock()
            
            # Execute
            result = await AlertService.create_alert(mock_db_session, alert_data)
            
            # Verify
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_database_error(self, mock_db_session, alert_data):
        """Test alert creation with database error"""
        # Setup mocks
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.create_alert(mock_db_session, alert_data)
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test get_alerts method
    @pytest.mark.asyncio
    async def test_get_alerts_success(self, mock_db_session, mock_alert):
        """Test successful alerts retrieval"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_alert]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        results = await AlertService.get_alerts(mock_db_session)
        
        # Verify
        assert len(results) == 1
        assert results[0] == mock_alert
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, mock_db_session, mock_alert):
        """Test alerts retrieval with filters"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_alert]
        mock_db_session.execute.return_value = mock_result
        
        # Execute with filters
        results = await AlertService.get_alerts(
            mock_db_session,
            device_id=uuid4(),
            severity="critical",
            status="active",
            alert_type="cpu_high",
            skip=10,
            limit=20
        )
        
        # Verify
        assert len(results) == 1
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alerts_database_error(self, mock_db_session):
        """Test alerts retrieval with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.get_alerts(mock_db_session)
        
        assert exc_info.value.status_code == 500
    
    # Test get_alert_statistics method
    @pytest.mark.asyncio
    async def test_get_alert_statistics_success(self, mock_db_session):
        """Test successful alert statistics retrieval"""
        # Setup mocks
        mock_total_result = AsyncMock()
        mock_total_result.scalar.return_value = 10
        
        mock_severity_result = AsyncMock()
        mock_severity_rows = [
            MagicMock(severity="critical", count=2),
            MagicMock(severity="warning", count=5),
            MagicMock(severity="info", count=3)
        ]
        mock_severity_result.__iter__.return_value = iter(mock_severity_rows)
        
        mock_status_result = AsyncMock()
        mock_status_rows = [
            MagicMock(status="active", count=7),
            MagicMock(status="resolved", count=3)
        ]
        mock_status_result.__iter__.return_value = iter(mock_status_rows)
        
        mock_active_result = AsyncMock()
        mock_active_result.scalar.return_value = 7
        
        mock_resolved_result = AsyncMock()
        mock_resolved_result.scalar.return_value = 3600.0  # 1 hour in seconds
        
        # Configure execute to return different results for different queries
        mock_db_session.execute.side_effect = [
            mock_total_result,
            mock_severity_result,
            mock_status_result,
            mock_active_result,
            mock_resolved_result
        ]
        
        # Execute
        result = await AlertService.get_alert_statistics(mock_db_session, hours=24)
        
        # Verify
        assert result["period_hours"] == 24
        assert result["total_alerts"] == 10
        assert result["active_alerts"] == 7
        assert result["by_severity"]["critical"] == 2
        assert result["by_status"]["active"] == 7
        assert result["avg_resolution_time_minutes"] == 60.0
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_no_data(self, mock_db_session):
        """Test alert statistics with no data"""
        # Setup mocks to return None/empty
        mock_result = AsyncMock()
        mock_result.scalar.return_value = None
        mock_result.__iter__.return_value = iter([])
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await AlertService.get_alert_statistics(mock_db_session)
        
        # Verify
        assert result["total_alerts"] == 0
        assert result["active_alerts"] == 0
        assert result["avg_resolution_time_minutes"] is None
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_database_error(self, mock_db_session):
        """Test alert statistics with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.get_alert_statistics(mock_db_session)
        
        assert exc_info.value.status_code == 500
    
    # Test acknowledge_alert method
    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(self, mock_db_session, mock_alert):
        """Test successful alert acknowledgment"""
        # Setup mocks
        mock_alert.status = "active"
        mock_alert.created_by = uuid4()
        mock_db_session.get.return_value = mock_alert
        
        with patch('backend.services.notification_service.NotificationService') as mock_notif:
            mock_notif_instance = MagicMock()
            mock_notif_instance.create_notification = AsyncMock()
            mock_notif.return_value = mock_notif_instance
            
            # Execute
            result = await AlertService.acknowledge_alert(
                mock_db_session,
                mock_alert.id,
                uuid4(),
                notes="Investigating issue"
            )
            
            # Verify
            assert result.status == "acknowledged"
            assert result.metadata.get("acknowledgment_notes") == "Investigating issue"
            mock_db_session.commit.assert_called_once()
            mock_notif_instance.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_found(self, mock_db_session):
        """Test acknowledging non-existent alert"""
        # Setup mocks
        mock_db_session.get.return_value = None
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(mock_db_session, uuid4(), uuid4())
        
        assert exc_info.value.status_code == 404
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_active(self, mock_db_session, mock_alert):
        """Test acknowledging non-active alert"""
        # Setup mocks
        mock_alert.status = "resolved"
        mock_db_session.get.return_value = mock_alert
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(mock_db_session, mock_alert.id, uuid4())
        
        assert exc_info.value.status_code == 400
        assert "not active" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_database_error(self, mock_db_session, mock_alert):
        """Test alert acknowledgment with database error"""
        # Setup mocks
        mock_alert.status = "active"
        mock_db_session.get.return_value = mock_alert
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(mock_db_session, mock_alert.id, uuid4())
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test resolve_alert method
    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, mock_db_session, mock_alert):
        """Test successful alert resolution"""
        # Setup mocks
        mock_alert.status = "active"
        mock_alert.created_by = uuid4()
        mock_db_session.get.return_value = mock_alert
        
        with patch('backend.services.notification_service.NotificationService') as mock_notif:
            mock_notif_instance = MagicMock()
            mock_notif_instance.create_notification = AsyncMock()
            mock_notif.return_value = mock_notif_instance
            
            # Execute
            result = await AlertService.resolve_alert(
                mock_db_session,
                mock_alert.id,
                uuid4(),
                resolution="Fixed network cable"
            )
            
            # Verify
            assert result.status == "resolved"
            assert result.metadata.get("resolution") == "Fixed network cable"
            mock_db_session.commit.assert_called_once()
            mock_notif_instance.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resolve_alert_already_resolved(self, mock_db_session, mock_alert):
        """Test resolving already resolved alert"""
        # Setup mocks
        mock_alert.status = "resolved"
        mock_db_session.get.return_value = mock_alert
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.resolve_alert(mock_db_session, mock_alert.id, uuid4())
        
        assert exc_info.value.status_code == 400
        assert "already resolved" in str(exc_info.value.detail)
    
    # Test escalate_alert method
    @pytest.mark.asyncio
    async def test_escalate_alert_success(self, mock_db_session, mock_alert):
        """Test successful alert escalation"""
        # Setup mocks
        mock_alert.severity = "warning"
        mock_alert.status = "active"
        mock_alert.metadata = {}
        mock_db_session.get.return_value = mock_alert
        
        with patch.object(AlertService, '_send_escalation_notifications', new=AsyncMock()):
            # Execute
            result = await AlertService.escalate_alert(
                mock_db_session,
                mock_alert.id,
                uuid4(),
                escalation_level=2
            )
            
            # Verify
            assert result.severity == "critical"  # warning -> error -> critical
            assert result.metadata.get("escalated") is True
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_escalate_alert_max_severity(self, mock_db_session, mock_alert):
        """Test escalating alert already at max severity"""
        # Setup mocks
        mock_alert.severity = "critical"
        mock_alert.status = "active"
        mock_db_session.get.return_value = mock_alert
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(mock_db_session, mock_alert.id, uuid4())
        
        assert exc_info.value.status_code == 400
        assert "maximum severity" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_escalate_alert_resolved(self, mock_db_session, mock_alert):
        """Test escalating resolved alert"""
        # Setup mocks
        mock_alert.status = "resolved"
        mock_db_session.get.return_value = mock_alert
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(mock_db_session, mock_alert.id, uuid4())
        
        assert exc_info.value.status_code == 400
        assert "Cannot escalate resolved alert" in str(exc_info.value.detail)
    
    # Test bulk_update_status method
    @pytest.mark.asyncio
    async def test_bulk_update_status_success(self, mock_db_session):
        """Test successful bulk status update"""
        # Setup mocks
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await AlertService.bulk_update_status(
            mock_db_session,
            [uuid4(), uuid4(), uuid4()],
            "acknowledged",
            uuid4()
        )
        
        # Verify
        assert count == 5
        mock_db_session.execute.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_invalid_status(self, mock_db_session):
        """Test bulk update with invalid status"""
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.bulk_update_status(
                mock_db_session,
                [uuid4()],
                "invalid_status",
                uuid4()
            )
        
        assert exc_info.value.status_code == 400
        assert "Invalid status" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_database_error(self, mock_db_session):
        """Test bulk update with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await AlertService.bulk_update_status(
                mock_db_session,
                [uuid4()],
                "acknowledged",
                uuid4()
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test private methods
    @pytest.mark.asyncio
    async def test_send_alert_notifications_critical(self, mock_db_session, mock_alert):
        """Test sending notifications for critical alerts"""
        # Setup mocks
        mock_alert.severity = "critical"
        
        mock_admin1 = MagicMock()
        mock_admin1.id = uuid4()
        mock_admin2 = MagicMock()
        mock_admin2.id = uuid4()
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_admin1, mock_admin2]
        mock_db_session.execute.return_value = mock_result
        
        with patch('backend.services.notification_service.NotificationService') as mock_notif:
            mock_notif_instance = MagicMock()
            mock_notif_instance.create_notification = AsyncMock()
            mock_notif.return_value = mock_notif_instance
            
            # Execute
            await AlertService._send_alert_notifications(mock_db_session, mock_alert)
            
            # Verify
            assert mock_notif_instance.create_notification.call_count == 2
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_info(self, mock_db_session, mock_alert):
        """Test sending notifications for info alerts (should not send)"""
        # Setup mocks
        mock_alert.severity = "info"
        
        with patch('backend.services.notification_service.NotificationService') as mock_notif:
            mock_notif_instance = MagicMock()
            mock_notif_instance.create_notification = AsyncMock()
            mock_notif.return_value = mock_notif_instance
            
            # Execute
            await AlertService._send_alert_notifications(mock_db_session, mock_alert)
            
            # Verify no notifications sent for info alerts
            mock_notif_instance.create_notification.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_send_escalation_notifications_success(self, mock_db_session, mock_alert):
        """Test sending escalation notifications"""
        # Setup mocks
        mock_admin = MagicMock()
        mock_admin.id = uuid4()
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_admin]
        mock_db_session.execute.return_value = mock_result
        
        with patch('backend.services.notification_service.NotificationService') as mock_notif:
            mock_notif_instance = MagicMock()
            mock_notif_instance.create_notification = AsyncMock()
            mock_notif.return_value = mock_notif_instance
            
            # Execute
            await AlertService._send_escalation_notifications(
                mock_db_session,
                mock_alert,
                uuid4()
            )
            
            # Verify
            mock_notif_instance.create_notification.assert_called_once()
    
    # Test instance methods
    @pytest.mark.asyncio
    async def test_get_active_alert_count(self):
        """Test getting active alert count"""
        service = AlertService()
        count = await service.get_active_alert_count()
        
        # Should return sample data
        assert isinstance(count, int)
        assert count >= 0
    
    # Test error handling in private methods
    @pytest.mark.asyncio
    async def test_send_alert_notifications_error(self, mock_db_session, mock_alert):
        """Test error handling in alert notifications"""
        # Setup mocks
        mock_alert.severity = "critical"
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute - should not raise exception, just log error
        await AlertService._send_alert_notifications(mock_db_session, mock_alert)
        
        # Verify it handled the error gracefully
        assert True  # If we get here, the error was handled
    
    @pytest.mark.asyncio
    async def test_send_escalation_notifications_error(self, mock_db_session, mock_alert):
        """Test error handling in escalation notifications"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute - should not raise exception, just log error
        await AlertService._send_escalation_notifications(
            mock_db_session,
            mock_alert,
            uuid4()
        )
        
        # Verify it handled the error gracefully
        assert True  # If we get here, the error was handled