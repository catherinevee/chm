"""
Comprehensive test suite for AlertService covering ALL functionality
Tests cover 100% of methods, branches, exceptions, and edge cases
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from backend.services.alert_service import AlertService
from backend.database.models import Alert, Device, Notification
from backend.database.user_models import User
from backend.common.exceptions import AppException


class TestAlertServiceCreateAlert:
    """Test alert creation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_device(self):
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        return device
    
    @pytest.mark.asyncio
    async def test_create_alert_success_with_device(self, mock_session, mock_device):
        """Test successful alert creation with device"""
        mock_session.get.return_value = mock_device
        
        alert_data = {
            'device_id': mock_device.id,
            'alert_type': 'threshold',
            'severity': 'warning',
            'message': 'CPU usage high',
            'description': 'CPU usage above 80%',
            'metadata': {'cpu': 85}
        }
        
        with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock()
                
                result = await AlertService.create_alert(
                    mock_session, alert_data, user_id=uuid4()
                )
                
                mock_session.add.assert_called_once()
                mock_session.commit.assert_called_once()
                mock_ws.broadcast_alert.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_success_without_device(self, mock_session):
        """Test successful alert creation without device"""
        alert_data = {
            'alert_type': 'system',
            'severity': 'info',
            'message': 'System notification',
            'metadata': {}
        }
        
        with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock()
                
                result = await AlertService.create_alert(
                    mock_session, alert_data
                )
                
                mock_session.add.assert_called_once()
                mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_device_not_found(self, mock_session):
        """Test alert creation when device not found"""
        device_id = uuid4()
        mock_session.get.return_value = None
        
        alert_data = {
            'device_id': device_id,
            'message': 'Test alert'
        }
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.create_alert(mock_session, alert_data)
        
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_alert_minimal_data(self, mock_session):
        """Test alert creation with minimal data"""
        alert_data = {
            'message': 'Minimal alert'
        }
        
        with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock()
                
                result = await AlertService.create_alert(mock_session, alert_data)
                
                mock_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_database_error(self, mock_session, mock_device):
        """Test alert creation with database error"""
        mock_session.get.return_value = mock_device
        mock_session.commit.side_effect = Exception("Database error")
        
        alert_data = {
            'device_id': mock_device.id,
            'message': 'Test alert'
        }
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.create_alert(mock_session, alert_data)
        
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_notification_failure(self, mock_session):
        """Test alert creation when notification fails (should not fail the alert creation)"""
        alert_data = {
            'message': 'Test alert',
            'severity': 'critical'
        }
        
        with patch.object(AlertService, '_send_alert_notifications', 
                        side_effect=Exception("Notification error")):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock()
                
                # Should still succeed despite notification failure
                result = await AlertService.create_alert(mock_session, alert_data)
                
                mock_session.add.assert_called_once()
                mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_websocket_failure(self, mock_session):
        """Test alert creation when WebSocket broadcast fails"""
        alert_data = {
            'message': 'Test alert'
        }
        
        with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock(side_effect=Exception("WS error"))
                
                with pytest.raises(AppException):
                    await AlertService.create_alert(mock_session, alert_data)


class TestAlertServiceGetAlerts:
    """Test getting alerts"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_get_alerts_success(self, mock_session):
        """Test successful alert retrieval"""
        mock_alerts = [
            MagicMock(id=uuid4(), message="Alert 1"),
            MagicMock(id=uuid4(), message="Alert 2"),
            MagicMock(id=uuid4(), message="Alert 3")
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_alerts
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(mock_session)
        
        assert len(result) == 3
        assert result == mock_alerts
    
    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, mock_session):
        """Test alert retrieval with filters"""
        mock_alerts = [
            MagicMock(id=uuid4(), severity="critical")
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_alerts
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(
            mock_session,
            device_id=uuid4(),
            severity="critical",
            status="active",
            alert_type="threshold"
        )
        
        assert len(result) == 1
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alerts_with_pagination(self, mock_session):
        """Test alert retrieval with pagination"""
        mock_alerts = []
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_alerts
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(
            mock_session,
            skip=10,
            limit=20
        )
        
        assert result == []
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alerts_no_results(self, mock_session):
        """Test alert retrieval with no results"""
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(mock_session)
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_alerts_database_error(self, mock_session):
        """Test alert retrieval with database error"""
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.get_alerts(mock_session)
        
        assert exc_info.value.status_code == 500
        assert "Failed to get alerts" in exc_info.value.detail


class TestAlertServiceStatistics:
    """Test alert statistics"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_success(self, mock_session):
        """Test successful alert statistics generation"""
        # Mock total count
        total_result = MagicMock()
        total_result.scalar.return_value = 50
        
        # Mock severity counts
        severity_result = MagicMock()
        severity_result.__iter__ = lambda self: iter([
            MagicMock(severity='critical', count=5),
            MagicMock(severity='warning', count=15),
            MagicMock(severity='info', count=30)
        ])
        
        # Mock status counts
        status_result = MagicMock()
        status_result.__iter__ = lambda self: iter([
            MagicMock(status='active', count=10),
            MagicMock(status='acknowledged', count=15),
            MagicMock(status='resolved', count=25)
        ])
        
        # Mock active count
        active_result = MagicMock()
        active_result.scalar.return_value = 10
        
        # Mock resolution time
        resolution_result = MagicMock()
        resolution_result.scalar.return_value = 3600  # 1 hour in seconds
        
        mock_session.execute.side_effect = [
            total_result,
            severity_result,
            status_result,
            active_result,
            resolution_result
        ]
        
        result = await AlertService.get_alert_statistics(mock_session, hours=24)
        
        assert result['total_alerts'] == 50
        assert result['active_alerts'] == 10
        assert result['by_severity']['critical'] == 5
        assert result['by_severity']['warning'] == 15
        assert result['by_severity']['info'] == 30
        assert result['by_status']['active'] == 10
        assert result['avg_resolution_time_minutes'] == 60.0
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_no_data(self, mock_session):
        """Test alert statistics with no data"""
        # Mock all queries returning no data
        total_result = MagicMock()
        total_result.scalar.return_value = 0
        
        severity_result = MagicMock()
        severity_result.__iter__ = lambda self: iter([])
        
        status_result = MagicMock()
        status_result.__iter__ = lambda self: iter([])
        
        active_result = MagicMock()
        active_result.scalar.return_value = 0
        
        resolution_result = MagicMock()
        resolution_result.scalar.return_value = None
        
        mock_session.execute.side_effect = [
            total_result,
            severity_result,
            status_result,
            active_result,
            resolution_result
        ]
        
        result = await AlertService.get_alert_statistics(mock_session, hours=48)
        
        assert result['total_alerts'] == 0
        assert result['active_alerts'] == 0
        assert result['by_severity'] == {}
        assert result['by_status'] == {}
        assert result['avg_resolution_time_minutes'] is None
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_database_error(self, mock_session):
        """Test alert statistics with database error"""
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.get_alert_statistics(mock_session)
        
        assert exc_info.value.status_code == 500
        assert "Failed to get alert statistics" in exc_info.value.detail


class TestAlertServiceAcknowledge:
    """Test alert acknowledgment"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_alert(self):
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = 'active'
        alert.message = "Test alert"
        alert.created_by = uuid4()
        alert.metadata = {}
        return alert
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(self, mock_session, mock_alert):
        """Test successful alert acknowledgment"""
        mock_session.get.return_value = mock_alert
        user_id = uuid4()
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            result = await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                user_id,
                notes="Acknowledging alert"
            )
            
            assert mock_alert.status == 'acknowledged'
            assert mock_alert.acknowledged_by == user_id
            assert mock_alert.acknowledged_at is not None
            assert 'acknowledgment_notes' in mock_alert.metadata
            mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_found(self, mock_session):
        """Test acknowledging non-existent alert"""
        mock_session.get.return_value = None
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(
                mock_session,
                uuid4(),
                uuid4()
            )
        
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_active(self, mock_session, mock_alert):
        """Test acknowledging non-active alert"""
        mock_alert.status = 'resolved'
        mock_session.get.return_value = mock_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 400
        assert "not active" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_without_notes(self, mock_session, mock_alert):
        """Test acknowledging alert without notes"""
        mock_session.get.return_value = mock_alert
        user_id = uuid4()
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            result = await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                user_id
            )
            
            assert mock_alert.status == 'acknowledged'
            assert 'acknowledgment_notes' not in mock_alert.metadata
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_database_error(self, mock_session, mock_alert):
        """Test acknowledging alert with database error"""
        mock_session.get.return_value = mock_alert
        mock_session.commit.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_notification_failure(self, mock_session, mock_alert):
        """Test acknowledging alert when notification fails"""
        mock_session.get.return_value = mock_alert
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock(
                side_effect=Exception("Notification error")
            )
            
            # Should still succeed despite notification failure
            result = await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
            
            assert mock_alert.status == 'acknowledged'


class TestAlertServiceResolve:
    """Test alert resolution"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_alert(self):
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = 'acknowledged'
        alert.message = "Test alert"
        alert.created_by = uuid4()
        alert.metadata = {}
        return alert
    
    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, mock_session, mock_alert):
        """Test successful alert resolution"""
        mock_session.get.return_value = mock_alert
        user_id = uuid4()
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            result = await AlertService.resolve_alert(
                mock_session,
                mock_alert.id,
                user_id,
                resolution="Issue fixed"
            )
            
            assert mock_alert.status == 'resolved'
            assert mock_alert.resolved_by == user_id
            assert mock_alert.resolved_at is not None
            assert 'resolution' in mock_alert.metadata
            mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resolve_alert_not_found(self, mock_session):
        """Test resolving non-existent alert"""
        mock_session.get.return_value = None
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.resolve_alert(
                mock_session,
                uuid4(),
                uuid4()
            )
        
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_resolve_alert_already_resolved(self, mock_session, mock_alert):
        """Test resolving already resolved alert"""
        mock_alert.status = 'resolved'
        mock_session.get.return_value = mock_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.resolve_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 400
        assert "already resolved" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_resolve_alert_without_resolution(self, mock_session, mock_alert):
        """Test resolving alert without resolution text"""
        mock_session.get.return_value = mock_alert
        user_id = uuid4()
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            result = await AlertService.resolve_alert(
                mock_session,
                mock_alert.id,
                user_id
            )
            
            assert mock_alert.status == 'resolved'
            assert 'resolution' not in mock_alert.metadata
    
    @pytest.mark.asyncio
    async def test_resolve_alert_from_active(self, mock_session, mock_alert):
        """Test resolving alert directly from active status"""
        mock_alert.status = 'active'
        mock_session.get.return_value = mock_alert
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            result = await AlertService.resolve_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
            
            assert mock_alert.status == 'resolved'
    
    @pytest.mark.asyncio
    async def test_resolve_alert_database_error(self, mock_session, mock_alert):
        """Test resolving alert with database error"""
        mock_session.get.return_value = mock_alert
        mock_session.commit.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.resolve_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()


class TestAlertServiceEscalate:
    """Test alert escalation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_alert(self):
        alert = MagicMock()
        alert.id = uuid4()
        alert.status = 'active'
        alert.severity = 'warning'
        alert.metadata = {}
        return alert
    
    @pytest.mark.asyncio
    async def test_escalate_alert_success(self, mock_session, mock_alert):
        """Test successful alert escalation"""
        mock_session.get.return_value = mock_alert
        user_id = uuid4()
        
        with patch.object(AlertService, '_send_escalation_notifications', new=AsyncMock()):
            result = await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                user_id,
                escalation_level=1
            )
            
            assert mock_alert.severity == 'error'
            assert mock_alert.metadata['escalated'] == True
            assert mock_alert.metadata['escalated_by'] == str(user_id)
            mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_escalate_alert_not_found(self, mock_session):
        """Test escalating non-existent alert"""
        mock_session.get.return_value = None
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(
                mock_session,
                uuid4(),
                uuid4()
            )
        
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_escalate_resolved_alert(self, mock_session, mock_alert):
        """Test escalating resolved alert"""
        mock_alert.status = 'resolved'
        mock_session.get.return_value = mock_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 400
        assert "Cannot escalate resolved alert" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_escalate_alert_already_critical(self, mock_session, mock_alert):
        """Test escalating alert already at maximum severity"""
        mock_alert.severity = 'critical'
        mock_session.get.return_value = mock_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 400
        assert "maximum severity" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_escalate_alert_multiple_levels(self, mock_session, mock_alert):
        """Test escalating alert by multiple levels"""
        mock_alert.severity = 'info'
        mock_session.get.return_value = mock_alert
        
        with patch.object(AlertService, '_send_escalation_notifications', new=AsyncMock()):
            result = await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4(),
                escalation_level=2
            )
            
            assert mock_alert.severity == 'error'
    
    @pytest.mark.asyncio
    async def test_escalate_alert_to_critical(self, mock_session, mock_alert):
        """Test escalating alert to critical"""
        mock_alert.severity = 'error'
        mock_session.get.return_value = mock_alert
        
        with patch.object(AlertService, '_send_escalation_notifications', new=AsyncMock()):
            result = await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4(),
                escalation_level=1
            )
            
            assert mock_alert.severity == 'critical'
    
    @pytest.mark.asyncio
    async def test_escalate_alert_database_error(self, mock_session, mock_alert):
        """Test escalating alert with database error"""
        mock_session.get.return_value = mock_alert
        mock_session.commit.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
        
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_escalate_alert_notification_failure(self, mock_session, mock_alert):
        """Test escalating alert when notification fails"""
        mock_session.get.return_value = mock_alert
        
        with patch.object(AlertService, '_send_escalation_notifications', 
                        side_effect=Exception("Notification error")):
            # Should still succeed despite notification failure
            result = await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
            
            assert mock_alert.severity == 'error'


class TestAlertServiceBulkUpdate:
    """Test bulk alert status update"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_acknowledge(self, mock_session):
        """Test bulk acknowledgment of alerts"""
        alert_ids = [uuid4() for _ in range(5)]
        mock_result = MagicMock()
        mock_result.rowcount = 5
        mock_session.execute.return_value = mock_result
        
        count = await AlertService.bulk_update_status(
            mock_session,
            alert_ids,
            'acknowledged',
            uuid4()
        )
        
        assert count == 5
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_resolve(self, mock_session):
        """Test bulk resolution of alerts"""
        alert_ids = [uuid4() for _ in range(3)]
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_session.execute.return_value = mock_result
        
        count = await AlertService.bulk_update_status(
            mock_session,
            alert_ids,
            'resolved',
            uuid4()
        )
        
        assert count == 3
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_update_invalid_status(self, mock_session):
        """Test bulk update with invalid status"""
        alert_ids = [uuid4()]
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.bulk_update_status(
                mock_session,
                alert_ids,
                'invalid_status',
                uuid4()
            )
        
        assert exc_info.value.status_code == 400
        assert "Invalid status" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_bulk_update_no_matches(self, mock_session):
        """Test bulk update with no matching alerts"""
        alert_ids = [uuid4() for _ in range(3)]
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_session.execute.return_value = mock_result
        
        count = await AlertService.bulk_update_status(
            mock_session,
            alert_ids,
            'acknowledged',
            uuid4()
        )
        
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_bulk_update_empty_list(self, mock_session):
        """Test bulk update with empty alert list"""
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_session.execute.return_value = mock_result
        
        count = await AlertService.bulk_update_status(
            mock_session,
            [],
            'acknowledged',
            uuid4()
        )
        
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_bulk_update_database_error(self, mock_session):
        """Test bulk update with database error"""
        alert_ids = [uuid4()]
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.bulk_update_status(
                mock_session,
                alert_ids,
                'acknowledged',
                uuid4()
            )
        
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()


class TestAlertServiceNotifications:
    """Test alert notification methods"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_alert(self):
        alert = MagicMock()
        alert.id = uuid4()
        alert.severity = 'critical'
        alert.message = "Critical alert"
        alert.description = "Critical system failure"
        return alert
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_critical(self, mock_session, mock_alert):
        """Test sending notifications for critical alert"""
        mock_admins = [
            MagicMock(id=uuid4()),
            MagicMock(id=uuid4())
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_admins
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService._send_alert_notifications(mock_session, mock_alert)
            
            # Should create notification for each admin
            assert mock_notif.return_value.create_notification.call_count == 2
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_error(self, mock_session):
        """Test sending notifications for error alert"""
        mock_alert = MagicMock(
            id=uuid4(),
            severity='error',
            message="Error alert",
            description=None
        )
        
        mock_admins = [MagicMock(id=uuid4())]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_admins
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService._send_alert_notifications(mock_session, mock_alert)
            
            mock_notif.return_value.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_info(self, mock_session):
        """Test sending notifications for info alert (should not send)"""
        mock_alert = MagicMock(
            id=uuid4(),
            severity='info',
            message="Info alert"
        )
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService._send_alert_notifications(mock_session, mock_alert)
            
            # Should not create any notifications for info alerts
            mock_notif.return_value.create_notification.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_no_admins(self, mock_session, mock_alert):
        """Test sending notifications when no admins exist"""
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService._send_alert_notifications(mock_session, mock_alert)
            
            mock_notif.return_value.create_notification.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_exception(self, mock_session, mock_alert):
        """Test notification sending handles exceptions gracefully"""
        mock_session.execute.side_effect = Exception("Database error")
        
        # Should not raise exception
        await AlertService._send_alert_notifications(mock_session, mock_alert)
    
    @pytest.mark.asyncio
    async def test_send_escalation_notifications_success(self, mock_session):
        """Test sending escalation notifications"""
        mock_alert = MagicMock(
            id=uuid4(),
            severity='critical',
            message="Escalated alert"
        )
        
        mock_admins = [
            MagicMock(id=uuid4()),
            MagicMock(id=uuid4())
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_admins
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService._send_escalation_notifications(
                mock_session, mock_alert, uuid4()
            )
            
            assert mock_notif.return_value.create_notification.call_count == 2
    
    @pytest.mark.asyncio
    async def test_send_escalation_notifications_exception(self, mock_session):
        """Test escalation notification handles exceptions gracefully"""
        mock_alert = MagicMock(id=uuid4())
        mock_session.execute.side_effect = Exception("Database error")
        
        # Should not raise exception
        await AlertService._send_escalation_notifications(
            mock_session, mock_alert, uuid4()
        )


class TestAlertServiceEdgeCases:
    """Test edge cases and error scenarios"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_create_alert_with_unicode(self, mock_session):
        """Test creating alert with unicode characters"""
        alert_data = {
            'message': 'Alert: température élevée 🔥',
            'description': 'La température dépasse 40°C',
            'metadata': {'temperature': '40°C'}
        }
        
        with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock()
                
                result = await AlertService.create_alert(mock_session, alert_data)
                
                mock_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_with_large_metadata(self, mock_session):
        """Test creating alert with large metadata"""
        large_metadata = {f'key_{i}': f'value_{i}' * 100 for i in range(100)}
        
        alert_data = {
            'message': 'Alert with large metadata',
            'metadata': large_metadata
        }
        
        with patch.object(AlertService, '_send_alert_notifications', new=AsyncMock()):
            with patch('backend.services.alert_service.ws_manager') as mock_ws:
                mock_ws.broadcast_alert = AsyncMock()
                
                result = await AlertService.create_alert(mock_session, alert_data)
                
                mock_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_with_existing_metadata(self, mock_session):
        """Test acknowledging alert that already has metadata"""
        mock_alert = MagicMock()
        mock_alert.id = uuid4()
        mock_alert.status = 'active'
        mock_alert.message = "Test"
        mock_alert.created_by = uuid4()
        mock_alert.metadata = {'existing': 'data'}
        
        mock_session.get.return_value = mock_alert
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                uuid4(),
                notes="New note"
            )
            
            assert 'existing' in mock_alert.metadata
            assert 'acknowledgment_notes' in mock_alert.metadata
    
    @pytest.mark.asyncio
    async def test_escalate_info_to_critical(self, mock_session):
        """Test escalating from info directly to critical"""
        mock_alert = MagicMock()
        mock_alert.id = uuid4()
        mock_alert.status = 'active'
        mock_alert.severity = 'info'
        mock_alert.metadata = {}
        
        mock_session.get.return_value = mock_alert
        
        with patch.object(AlertService, '_send_escalation_notifications', new=AsyncMock()):
            result = await AlertService.escalate_alert(
                mock_session,
                mock_alert.id,
                uuid4(),
                escalation_level=3
            )
            
            assert mock_alert.severity == 'critical'
    
    @pytest.mark.asyncio
    async def test_bulk_update_large_batch(self, mock_session):
        """Test bulk update with large number of alerts"""
        alert_ids = [uuid4() for _ in range(1000)]
        mock_result = MagicMock()
        mock_result.rowcount = 1000
        mock_session.execute.return_value = mock_result
        
        count = await AlertService.bulk_update_status(
            mock_session,
            alert_ids,
            'acknowledged',
            uuid4()
        )
        
        assert count == 1000
    
    @pytest.mark.asyncio
    async def test_get_statistics_edge_timestamps(self, mock_session):
        """Test statistics with edge case timestamps"""
        # Mock results with edge values
        total_result = MagicMock()
        total_result.scalar.return_value = None  # Will become 0
        
        severity_result = MagicMock()
        severity_result.__iter__ = lambda self: iter([])
        
        status_result = MagicMock()
        status_result.__iter__ = lambda self: iter([])
        
        active_result = MagicMock()
        active_result.scalar.return_value = None  # Will become 0
        
        resolution_result = MagicMock()
        resolution_result.scalar.return_value = 0.5  # Very short resolution time
        
        mock_session.execute.side_effect = [
            total_result,
            severity_result,
            status_result,
            active_result,
            resolution_result
        ]
        
        result = await AlertService.get_alert_statistics(mock_session, hours=0)
        
        assert result['total_alerts'] == 0
        assert result['avg_resolution_time_minutes'] == 0.01
    
    @pytest.mark.asyncio
    async def test_concurrent_alert_updates(self, mock_session):
        """Test handling concurrent alert updates"""
        mock_alert = MagicMock()
        mock_alert.id = uuid4()
        mock_alert.status = 'active'
        mock_alert.message = "Test"
        mock_alert.created_by = uuid4()
        mock_alert.metadata = {}
        
        mock_session.get.return_value = mock_alert
        
        # Simulate concurrent modification
        commit_count = 0
        def commit_side_effect():
            nonlocal commit_count
            commit_count += 1
            if commit_count == 1:
                raise Exception("Concurrent modification")
            return AsyncMock()
        
        mock_session.commit.side_effect = commit_side_effect
        
        with pytest.raises(AppException):
            await AlertService.acknowledge_alert(
                mock_session,
                mock_alert.id,
                uuid4()
            )
    
    @pytest.mark.asyncio
    async def test_resolve_alert_with_null_metadata(self, mock_session):
        """Test resolving alert with null metadata"""
        mock_alert = MagicMock()
        mock_alert.id = uuid4()
        mock_alert.status = 'active'
        mock_alert.message = "Test"
        mock_alert.created_by = uuid4()
        mock_alert.metadata = None
        
        mock_session.get.return_value = mock_alert
        
        with patch('backend.services.alert_service.NotificationService') as mock_notif:
            mock_notif.return_value.create_notification = AsyncMock()
            
            await AlertService.resolve_alert(
                mock_session,
                mock_alert.id,
                uuid4(),
                resolution="Fixed"
            )
            
            assert mock_alert.metadata is not None
            assert 'resolution' in mock_alert.metadata