"""
Comprehensive Alert Service Tests
Tests all actual methods in backend/services/alert_service.py
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
from typing import List, Optional, Dict, Any

# Mock the models and dependencies that AlertService expects
from dataclasses import dataclass


@dataclass
class MockAlert:
    """Mock Alert model for testing"""
    id: UUID
    device_id: Optional[UUID] = None
    alert_type: str = "manual"
    severity: str = "info"
    message: str = ""
    description: Optional[str] = None
    status: str = "active"
    metadata: Optional[Dict[str, Any]] = None
    created_by: Optional[UUID] = None
    created_at: datetime = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[UUID] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[UUID] = None
    
    # Mock relationship
    device: Optional['MockDevice'] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}


@dataclass
class MockDevice:
    """Mock Device model for testing"""
    id: UUID
    hostname: str
    ip_address: str


@dataclass
class MockUser:
    """Mock User model for testing"""
    id: UUID
    username: str
    is_superuser: bool = False


@dataclass
class MockNotification:
    """Mock Notification model for testing"""
    id: UUID
    user_id: UUID
    title: str
    message: str


class MockQueryResult:
    """Mock SQLAlchemy query result"""
    def __init__(self, data):
        self.data = data
    
    def scalars(self):
        return self
    
    def all(self):
        return self.data
    
    def scalar(self):
        return self.data[0] if self.data else None
    
    def scalar_one_or_none(self):
        return self.data[0] if self.data else None


class MockUpdateResult:
    """Mock update result"""
    def __init__(self, rowcount):
        self.rowcount = rowcount


class MockGroupResult:
    """Mock group by result with attributes"""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestAlertServiceComprehensive:
    """Comprehensive test coverage for AlertService"""
    
    @pytest.fixture
    def mock_db(self):
        """Create mock database session"""
        return AsyncMock()
    
    @pytest.fixture
    def sample_device(self):
        """Create sample device for testing"""
        return MockDevice(
            id=uuid4(),
            hostname="test-device",
            ip_address="192.168.1.1"
        )
    
    @pytest.fixture
    def sample_alert(self, sample_device):
        """Create sample alert for testing"""
        return MockAlert(
            id=uuid4(),
            device_id=sample_device.id,
            alert_type="threshold",
            severity="warning",
            message="High CPU usage detected",
            description="CPU usage is above 90% for 5 minutes",
            status="active",
            created_by=uuid4(),
            device=sample_device
        )
    
    @pytest.fixture
    def sample_user(self):
        """Create sample user for testing"""
        return MockUser(
            id=uuid4(),
            username="testuser"
        )
    
    @pytest.fixture
    def admin_user(self):
        """Create sample admin user for testing"""
        return MockUser(
            id=uuid4(),
            username="admin",
            is_superuser=True
        )
    
    @pytest.fixture
    def alert_data(self, sample_device):
        """Sample alert creation data"""
        return {
            "device_id": sample_device.id,
            "alert_type": "threshold",
            "severity": "warning",
            "message": "High CPU usage detected",
            "description": "CPU usage is above 90% for 5 minutes",
            "metadata": {"threshold": 90, "duration": 300}
        }
    
    # Test create_alert method
    @pytest.mark.asyncio
    async def test_create_alert_success(self, mock_db, alert_data, sample_device):
        """Test successful alert creation"""
        from backend.services.alert_service import AlertService
        
        # Mock device lookup
        mock_db.get.return_value = sample_device
        
        # Mock alert creation
        created_alert = MockAlert(
            id=uuid4(),
            device_id=alert_data["device_id"],
            message=alert_data["message"],
            severity=alert_data["severity"]
        )
        
        # Mock database operations
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Mock websocket manager and notification methods
        with patch('backend.services.alert_service.ws_manager') as mock_ws, \
             patch.object(AlertService, '_send_alert_notifications', return_value=None) as mock_notify, \
             patch('backend.services.alert_service.Alert', return_value=created_alert):
            
            mock_ws.broadcast_alert = AsyncMock()
            
            result = await AlertService.create_alert(mock_db, alert_data, user_id=uuid4())
            
            assert result == created_alert
            mock_db.add.assert_called_once()
            mock_db.commit.assert_called_once()
            mock_notify.assert_called_once()
            mock_ws.broadcast_alert.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_device_not_found(self, mock_db, alert_data):
        """Test alert creation when device not found"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Mock device lookup to return None
        mock_db.get.return_value = None
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.create_alert(mock_db, alert_data)
        
        assert exc_info.value.status_code == 404
        assert "Device" in str(exc_info.value.detail)
        assert "not found" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_create_alert_no_device(self, mock_db):
        """Test alert creation without device_id"""
        from backend.services.alert_service import AlertService
        
        alert_data = {
            "alert_type": "manual",
            "severity": "info",
            "message": "Manual alert test"
        }
        
        created_alert = MockAlert(
            id=uuid4(),
            message=alert_data["message"]
        )
        
        # Mock database operations
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch('backend.services.alert_service.ws_manager') as mock_ws, \
             patch.object(AlertService, '_send_alert_notifications', return_value=None), \
             patch('backend.services.alert_service.Alert', return_value=created_alert):
            
            mock_ws.broadcast_alert = AsyncMock()
            
            result = await AlertService.create_alert(mock_db, alert_data)
            
            assert result == created_alert
            # Device lookup should not be called
            mock_db.get.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_create_alert_database_error(self, mock_db, alert_data, sample_device):
        """Test alert creation with database error"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Mock device lookup
        mock_db.get.return_value = sample_device
        
        # Mock database error
        mock_db.add.side_effect = Exception("Database error")
        mock_db.rollback = AsyncMock()
        
        with patch('backend.services.alert_service.Alert') as mock_alert_class:
            
            with pytest.raises(AppException) as exc_info:
                await AlertService.create_alert(mock_db, alert_data)
            
            assert exc_info.value.status_code == 500
            assert "Failed to create alert" in str(exc_info.value.detail)
            mock_db.rollback.assert_called_once()
    
    # Test get_alerts method
    @pytest.mark.asyncio
    async def test_get_alerts_success(self, mock_db, sample_alert):
        """Test successful alerts retrieval"""
        from backend.services.alert_service import AlertService
        
        alerts = [sample_alert]
        mock_result = MockQueryResult(alerts)
        mock_db.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(mock_db)
        
        assert result == alerts
        mock_db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, mock_db, sample_alert, sample_device):
        """Test alerts retrieval with filters"""
        from backend.services.alert_service import AlertService
        
        alerts = [sample_alert]
        mock_result = MockQueryResult(alerts)
        mock_db.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(
            mock_db,
            skip=10,
            limit=50,
            device_id=sample_device.id,
            severity="warning",
            status="active",
            alert_type="threshold"
        )
        
        assert result == alerts
        mock_db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alerts_empty_result(self, mock_db):
        """Test alerts retrieval with empty result"""
        from backend.services.alert_service import AlertService
        
        mock_result = MockQueryResult([])
        mock_db.execute.return_value = mock_result
        
        result = await AlertService.get_alerts(mock_db)
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_alerts_exception(self, mock_db):
        """Test alerts retrieval with exception"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        mock_db.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.get_alerts(mock_db)
        
        assert exc_info.value.status_code == 500
        assert "Failed to get alerts" in str(exc_info.value.detail)
    
    # Test get_alert_statistics method
    @pytest.mark.asyncio
    async def test_get_alert_statistics_success(self, mock_db):
        """Test successful alert statistics retrieval"""
        from backend.services.alert_service import AlertService
        
        # Mock multiple query results
        mock_db.execute.side_effect = [
            MockQueryResult([50]),  # Total count
            MockQueryResult([  # Severity counts
                MockGroupResult(severity="critical", count=5),
                MockGroupResult(severity="warning", count=20),
                MockGroupResult(severity="info", count=25)
            ]),
            MockQueryResult([  # Status counts
                MockGroupResult(status="active", count=30),
                MockGroupResult(status="acknowledged", count=15),
                MockGroupResult(status="resolved", count=5)
            ]),
            MockQueryResult([20]),  # Active count
            MockQueryResult([1800])  # Average resolution time in seconds
        ]
        
        result = await AlertService.get_alert_statistics(mock_db, hours=24)
        
        assert result["period_hours"] == 24
        assert result["total_alerts"] == 50
        assert result["active_alerts"] == 20
        assert result["by_severity"]["critical"] == 5
        assert result["by_severity"]["warning"] == 20
        assert result["by_status"]["active"] == 30
        assert result["avg_resolution_time_minutes"] == 30.0  # 1800 seconds / 60
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_no_data(self, mock_db):
        """Test alert statistics with no data"""
        from backend.services.alert_service import AlertService
        
        # Mock empty results
        mock_db.execute.side_effect = [
            MockQueryResult([0]),   # Total count
            MockQueryResult([]),    # Severity counts
            MockQueryResult([]),    # Status counts
            MockQueryResult([0]),   # Active count
            MockQueryResult([None]) # Average resolution time
        ]
        
        result = await AlertService.get_alert_statistics(mock_db)
        
        assert result["total_alerts"] == 0
        assert result["active_alerts"] == 0
        assert result["by_severity"] == {}
        assert result["by_status"] == {}
        assert result["avg_resolution_time_minutes"] is None
    
    @pytest.mark.asyncio
    async def test_get_alert_statistics_exception(self, mock_db):
        """Test alert statistics with exception"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        mock_db.execute.side_effect = Exception("Query error")
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.get_alert_statistics(mock_db)
        
        assert exc_info.value.status_code == 500
        assert "Failed to get alert statistics" in str(exc_info.value.detail)
    
    # Test acknowledge_alert method
    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(self, mock_db, sample_alert, sample_user):
        """Test successful alert acknowledgment"""
        from backend.services.alert_service import AlertService
        
        # Mock alert lookup
        mock_db.get.return_value = sample_alert
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Mock notification service
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            result = await AlertService.acknowledge_alert(
                mock_db,
                sample_alert.id,
                sample_user.id,
                notes="Investigating the issue"
            )
            
            assert result == sample_alert
            assert sample_alert.status == "acknowledged"
            assert sample_alert.acknowledged_by == sample_user.id
            assert sample_alert.acknowledged_at is not None
            assert sample_alert.metadata["acknowledgment_notes"] == "Investigating the issue"
            mock_notification_service.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_found(self, mock_db):
        """Test acknowledge alert when alert not found"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Mock alert lookup to return None
        mock_db.get.return_value = None
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(mock_db, uuid4(), uuid4())
        
        assert exc_info.value.status_code == 404
        assert "Alert" in str(exc_info.value.detail)
        assert "not found" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_active(self, mock_db, sample_alert, sample_user):
        """Test acknowledge alert when alert is not active"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Set alert status to resolved
        sample_alert.status = "resolved"
        mock_db.get.return_value = sample_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(mock_db, sample_alert.id, sample_user.id)
        
        assert exc_info.value.status_code == 400
        assert "not active" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_database_error(self, mock_db, sample_alert, sample_user):
        """Test acknowledge alert with database error"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        mock_db.get.return_value = sample_alert
        mock_db.commit.side_effect = Exception("Database error")
        mock_db.rollback = AsyncMock()
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.acknowledge_alert(mock_db, sample_alert.id, sample_user.id)
        
        assert exc_info.value.status_code == 500
        assert "Failed to acknowledge alert" in str(exc_info.value.detail)
        mock_db.rollback.assert_called_once()
    
    # Test resolve_alert method
    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, mock_db, sample_alert, sample_user):
        """Test successful alert resolution"""
        from backend.services.alert_service import AlertService
        
        # Mock alert lookup
        mock_db.get.return_value = sample_alert
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Mock notification service
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            result = await AlertService.resolve_alert(
                mock_db,
                sample_alert.id,
                sample_user.id,
                resolution="Fixed by restarting service"
            )
            
            assert result == sample_alert
            assert sample_alert.status == "resolved"
            assert sample_alert.resolved_by == sample_user.id
            assert sample_alert.resolved_at is not None
            assert sample_alert.metadata["resolution"] == "Fixed by restarting service"
            mock_notification_service.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resolve_alert_not_found(self, mock_db):
        """Test resolve alert when alert not found"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Mock alert lookup to return None
        mock_db.get.return_value = None
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.resolve_alert(mock_db, uuid4(), uuid4())
        
        assert exc_info.value.status_code == 404
        assert "Alert" in str(exc_info.value.detail)
        assert "not found" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_resolve_alert_already_resolved(self, mock_db, sample_alert, sample_user):
        """Test resolve alert when alert is already resolved"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Set alert status to resolved
        sample_alert.status = "resolved"
        mock_db.get.return_value = sample_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.resolve_alert(mock_db, sample_alert.id, sample_user.id)
        
        assert exc_info.value.status_code == 400
        assert "already resolved" in str(exc_info.value.detail)
    
    # Test escalate_alert method
    @pytest.mark.asyncio
    async def test_escalate_alert_success(self, mock_db, sample_alert, sample_user):
        """Test successful alert escalation"""
        from backend.services.alert_service import AlertService
        
        # Set initial severity to warning
        sample_alert.severity = "warning"
        mock_db.get.return_value = sample_alert
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Mock escalation notifications
        with patch.object(AlertService, '_send_escalation_notifications', return_value=None) as mock_notify:
            
            result = await AlertService.escalate_alert(
                mock_db,
                sample_alert.id,
                sample_user.id,
                escalation_level=1
            )
            
            assert result == sample_alert
            assert sample_alert.severity == "error"  # warning -> error
            assert sample_alert.metadata["escalated"] is True
            assert sample_alert.metadata["escalated_by"] == str(sample_user.id)
            mock_notify.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_escalate_alert_max_severity(self, mock_db, sample_alert, sample_user):
        """Test escalate alert when already at maximum severity"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Set severity to critical (maximum)
        sample_alert.severity = "critical"
        mock_db.get.return_value = sample_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(mock_db, sample_alert.id, sample_user.id)
        
        assert exc_info.value.status_code == 400
        assert "maximum severity" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_escalate_alert_resolved(self, mock_db, sample_alert, sample_user):
        """Test escalate alert when alert is resolved"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        # Set alert status to resolved
        sample_alert.status = "resolved"
        mock_db.get.return_value = sample_alert
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.escalate_alert(mock_db, sample_alert.id, sample_user.id)
        
        assert exc_info.value.status_code == 400
        assert "Cannot escalate resolved alert" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_escalate_alert_multiple_levels(self, mock_db, sample_alert, sample_user):
        """Test escalate alert with multiple levels"""
        from backend.services.alert_service import AlertService
        
        # Set initial severity to info
        sample_alert.severity = "info"
        mock_db.get.return_value = sample_alert
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch.object(AlertService, '_send_escalation_notifications', return_value=None):
            
            result = await AlertService.escalate_alert(
                mock_db,
                sample_alert.id,
                sample_user.id,
                escalation_level=2
            )
            
            assert result == sample_alert
            assert sample_alert.severity == "error"  # info -> warning -> error (2 levels)
    
    # Test bulk_update_status method
    @pytest.mark.asyncio
    async def test_bulk_update_status_success(self, mock_db, sample_user):
        """Test successful bulk status update"""
        from backend.services.alert_service import AlertService
        
        alert_ids = [uuid4(), uuid4(), uuid4()]
        
        # Mock update result
        mock_result = MockUpdateResult(rowcount=3)
        mock_db.execute.return_value = mock_result
        mock_db.commit = AsyncMock()
        
        result = await AlertService.bulk_update_status(
            mock_db,
            alert_ids,
            "acknowledged",
            sample_user.id
        )
        
        assert result == 3
        mock_db.execute.assert_called_once()
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_invalid_status(self, mock_db, sample_user):
        """Test bulk update with invalid status"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        alert_ids = [uuid4()]
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.bulk_update_status(
                mock_db,
                alert_ids,
                "invalid_status",
                sample_user.id
            )
        
        assert exc_info.value.status_code == 400
        assert "Invalid status" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_database_error(self, mock_db, sample_user):
        """Test bulk update with database error"""
        from backend.services.alert_service import AlertService
        from backend.common.exceptions import AppException
        
        alert_ids = [uuid4()]
        
        mock_db.execute.side_effect = Exception("Database error")
        mock_db.rollback = AsyncMock()
        
        with pytest.raises(AppException) as exc_info:
            await AlertService.bulk_update_status(
                mock_db,
                alert_ids,
                "acknowledged",
                sample_user.id
            )
        
        assert exc_info.value.status_code == 500
        assert "Failed to bulk update alerts" in str(exc_info.value.detail)
        mock_db.rollback.assert_called_once()
    
    # Test private helper methods
    @pytest.mark.asyncio
    async def test_send_alert_notifications_critical(self, mock_db, sample_alert, admin_user):
        """Test sending notifications for critical alerts"""
        from backend.services.alert_service import AlertService
        
        # Set alert to critical
        sample_alert.severity = "critical"
        
        # Mock admin users query
        admin_users = [admin_user]
        mock_result = MockQueryResult(admin_users)
        mock_db.execute.return_value = mock_result
        
        # Mock notification service
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            await AlertService._send_alert_notifications(mock_db, sample_alert)
            
            # Should send notification to admin
            mock_notification_service.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_info(self, mock_db, sample_alert):
        """Test sending notifications for info alerts"""
        from backend.services.alert_service import AlertService
        
        # Set alert to info (should not send notifications)
        sample_alert.severity = "info"
        
        # Mock notification service
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            await AlertService._send_alert_notifications(mock_db, sample_alert)
            
            # Should not send notifications for info alerts
            mock_notification_service.create_notification.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_send_alert_notifications_exception(self, mock_db, sample_alert):
        """Test sending notifications with exception"""
        from backend.services.alert_service import AlertService
        
        sample_alert.severity = "critical"
        
        # Mock query to raise exception
        mock_db.execute.side_effect = Exception("Query error")
        
        # Should not raise exception (error is logged)
        await AlertService._send_alert_notifications(mock_db, sample_alert)
    
    @pytest.mark.asyncio
    async def test_send_escalation_notifications_success(self, mock_db, sample_alert, admin_user, sample_user):
        """Test sending escalation notifications"""
        from backend.services.alert_service import AlertService
        
        # Mock admin users query
        admin_users = [admin_user]
        mock_result = MockQueryResult(admin_users)
        mock_db.execute.return_value = mock_result
        
        # Mock notification service
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            await AlertService._send_escalation_notifications(mock_db, sample_alert, sample_user.id)
            
            # Should send notification to admin
            mock_notification_service.create_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_escalation_notifications_exception(self, mock_db, sample_alert, sample_user):
        """Test sending escalation notifications with exception"""
        from backend.services.alert_service import AlertService
        
        # Mock query to raise exception
        mock_db.execute.side_effect = Exception("Query error")
        
        # Should not raise exception (error is logged)
        await AlertService._send_escalation_notifications(mock_db, sample_alert, sample_user.id)
    
    # Integration-style tests
    @pytest.mark.asyncio
    async def test_alert_lifecycle_complete(self, mock_db, alert_data, sample_device, sample_user):
        """Test complete alert lifecycle: create -> acknowledge -> escalate -> resolve"""
        from backend.services.alert_service import AlertService
        
        # Mock device lookup
        mock_db.get.side_effect = [sample_device]  # For create_alert
        
        created_alert = MockAlert(
            id=uuid4(),
            device_id=alert_data["device_id"],
            message=alert_data["message"],
            severity="info",
            status="active"
        )
        
        # Mock database operations
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        # Mock websocket and notifications
        with patch('backend.services.alert_service.ws_manager') as mock_ws, \
             patch.object(AlertService, '_send_alert_notifications', return_value=None), \
             patch.object(AlertService, '_send_escalation_notifications', return_value=None), \
             patch('backend.services.alert_service.NotificationService') as mock_notification_class, \
             patch('backend.services.alert_service.Alert', return_value=created_alert):
            
            mock_ws.broadcast_alert = AsyncMock()
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            # Update mock_db.get to return the alert for subsequent operations
            mock_db.get = MagicMock(return_value=created_alert)
            
            # 1. Create alert
            create_result = await AlertService.create_alert(mock_db, alert_data)
            assert create_result == created_alert
            
            # 2. Acknowledge alert
            acknowledge_result = await AlertService.acknowledge_alert(
                mock_db, created_alert.id, sample_user.id, notes="Investigating"
            )
            assert acknowledge_result == created_alert
            assert created_alert.status == "acknowledged"
            
            # 3. Escalate alert (reset status to active first)
            created_alert.status = "active"
            escalate_result = await AlertService.escalate_alert(
                mock_db, created_alert.id, sample_user.id
            )
            assert escalate_result == created_alert
            assert created_alert.severity == "warning"  # info -> warning
            
            # 4. Resolve alert
            resolve_result = await AlertService.resolve_alert(
                mock_db, created_alert.id, sample_user.id, resolution="Issue fixed"
            )
            assert resolve_result == created_alert
            assert created_alert.status == "resolved"
    
    @pytest.mark.asyncio
    async def test_alert_statistics_and_bulk_operations(self, mock_db, sample_user):
        """Test alert statistics and bulk operations together"""
        from backend.services.alert_service import AlertService
        
        alert_ids = [uuid4(), uuid4(), uuid4()]
        
        # Mock statistics queries
        mock_db.execute.side_effect = [
            MockQueryResult([10]),  # Total count
            MockQueryResult([MockGroupResult(severity="warning", count=10)]),  # Severity
            MockQueryResult([MockGroupResult(status="active", count=10)]),     # Status
            MockQueryResult([10]),  # Active count
            MockQueryResult([3600]), # Avg resolution time
            # Then bulk update result
            MockUpdateResult(rowcount=3)
        ]
        mock_db.commit = AsyncMock()
        
        # 1. Get statistics
        stats = await AlertService.get_alert_statistics(mock_db, hours=1)
        assert stats["total_alerts"] == 10
        assert stats["active_alerts"] == 10
        
        # 2. Bulk update alerts
        updated_count = await AlertService.bulk_update_status(
            mock_db, alert_ids, "acknowledged", sample_user.id
        )
        assert updated_count == 3
    
    @pytest.mark.asyncio
    async def test_alert_severity_escalation_levels(self, mock_db, sample_user):
        """Test all severity escalation levels"""
        from backend.services.alert_service import AlertService
        
        # Test escalation from each level
        test_cases = [
            ("info", 1, "warning"),
            ("warning", 1, "error"), 
            ("error", 1, "critical"),
            ("info", 2, "error"),     # Skip warning
            ("info", 3, "critical")   # Skip to max
        ]
        
        for initial_severity, escalation_level, expected_severity in test_cases:
            alert = MockAlert(
                id=uuid4(),
                severity=initial_severity,
                status="active"
            )
            
            mock_db.get.return_value = alert
            mock_db.commit = AsyncMock()
            mock_db.refresh = AsyncMock()
            
            with patch.object(AlertService, '_send_escalation_notifications', return_value=None):
                
                result = await AlertService.escalate_alert(
                    mock_db, alert.id, sample_user.id, escalation_level
                )
                
                assert result.severity == expected_severity
    
    @pytest.mark.asyncio 
    async def test_alert_filtering_combinations(self, mock_db, sample_device):
        """Test various alert filtering combinations"""
        from backend.services.alert_service import AlertService
        
        # Test different filter combinations
        filter_combinations = [
            {"device_id": sample_device.id},
            {"severity": "critical"},
            {"status": "active"},
            {"alert_type": "threshold"},
            {"device_id": sample_device.id, "severity": "warning"},
            {"status": "active", "alert_type": "manual"},
            {"device_id": sample_device.id, "severity": "error", "status": "acknowledged"}
        ]
        
        for filters in filter_combinations:
            mock_result = MockQueryResult([])
            mock_db.execute.return_value = mock_result
            
            result = await AlertService.get_alerts(mock_db, **filters)
            
            assert result == []
            mock_db.execute.assert_called()
            
            # Reset mock for next iteration
            mock_db.execute.reset_mock()
    
    # Error handling and edge cases
    @pytest.mark.asyncio
    async def test_acknowledge_alert_without_notes(self, mock_db, sample_alert, sample_user):
        """Test acknowledge alert without notes"""
        from backend.services.alert_service import AlertService
        
        mock_db.get.return_value = sample_alert
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            result = await AlertService.acknowledge_alert(
                mock_db, sample_alert.id, sample_user.id
            )
            
            assert result == sample_alert
            assert sample_alert.status == "acknowledged"
            # Should not add acknowledgment_notes to metadata
            assert "acknowledgment_notes" not in sample_alert.metadata
    
    @pytest.mark.asyncio
    async def test_resolve_alert_without_resolution(self, mock_db, sample_alert, sample_user):
        """Test resolve alert without resolution notes"""
        from backend.services.alert_service import AlertService
        
        mock_db.get.return_value = sample_alert
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch('backend.services.alert_service.NotificationService') as mock_notification_class:
            mock_notification_service = AsyncMock()
            mock_notification_class.return_value = mock_notification_service
            
            result = await AlertService.resolve_alert(
                mock_db, sample_alert.id, sample_user.id
            )
            
            assert result == sample_alert
            assert sample_alert.status == "resolved"
            # Should not add resolution to metadata
            assert "resolution" not in sample_alert.metadata
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_resolved(self, mock_db, sample_user):
        """Test bulk update to resolved status"""
        from backend.services.alert_service import AlertService
        
        alert_ids = [uuid4(), uuid4()]
        
        mock_result = MockUpdateResult(rowcount=2)
        mock_db.execute.return_value = mock_result
        mock_db.commit = AsyncMock()
        
        result = await AlertService.bulk_update_status(
            mock_db, alert_ids, "resolved", sample_user.id
        )
        
        assert result == 2
    
    @pytest.mark.asyncio
    async def test_bulk_update_status_no_matches(self, mock_db, sample_user):
        """Test bulk update with no matching alerts"""
        from backend.services.alert_service import AlertService
        
        alert_ids = [uuid4()]
        
        mock_result = MockUpdateResult(rowcount=0)
        mock_db.execute.return_value = mock_result
        mock_db.commit = AsyncMock()
        
        result = await AlertService.bulk_update_status(
            mock_db, alert_ids, "acknowledged", sample_user.id
        )
        
        assert result == 0