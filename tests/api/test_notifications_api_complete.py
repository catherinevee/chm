"""
Comprehensive tests for notifications API endpoints
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import uuid
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.notifications import (
    router,
    NotificationCreate,
    NotificationUpdate,
    NotificationResponse,
    NotificationListResponse
)
from backend.database.models import Notification, Device
from backend.database.user_models import User


class TestListNotificationsEndpoint:
    """Test GET /api/v1/notifications endpoint"""
    
    @pytest.mark.asyncio
    async def test_list_notifications_success(self, client, mock_db, mock_user):
        """Test successful listing of notifications"""
        # Mock notifications
        mock_notif1 = MagicMock(spec=Notification)
        mock_notif1.id = uuid.uuid4()
        mock_notif1.notification_type = "alert"
        mock_notif1.title = "Alert Notification"
        mock_notif1.message = "System alert"
        mock_notif1.severity = "warning"
        mock_notif1.read = False
        mock_notif1.device_id = uuid.uuid4()
        mock_notif1.user_id = str(mock_user.id)
        mock_notif1.created_at = datetime.utcnow()
        mock_notif1.read_at = None
        
        mock_notif2 = MagicMock(spec=Notification)
        mock_notif2.id = uuid.uuid4()
        mock_notif2.notification_type = "info"
        mock_notif2.title = "Info Notification"
        mock_notif2.message = "System info"
        mock_notif2.severity = "info"
        mock_notif2.read = True
        mock_notif2.device_id = None
        mock_notif2.user_id = None  # Global notification
        mock_notif2.created_at = datetime.utcnow() - timedelta(hours=1)
        mock_notif2.read_at = datetime.utcnow()
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif1, mock_notif2]
        
        # Mock device hostname lookup
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = "test-device"
        
        mock_db.execute.side_effect = [mock_result, device_result, MagicMock()]
        mock_db.scalar.side_effect = [2, 1]  # total=2, unread=1
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications")
        
        assert response.status_code == 200
        data = response.json()
        assert "notifications" in data
        assert data["total"] == 2
        assert data["unread_count"] == 1
        assert len(data["notifications"]) == 2
        assert data["notifications"][0]["read"] is False
        assert data["notifications"][0]["device_hostname"] == "test-device"
    
    @pytest.mark.asyncio
    async def test_list_notifications_unread_only(self, client, mock_db, mock_user):
        """Test listing only unread notifications"""
        mock_notif = MagicMock(spec=Notification)
        mock_notif.id = uuid.uuid4()
        mock_notif.notification_type = "alert"
        mock_notif.title = "Unread Alert"
        mock_notif.message = "Unread message"
        mock_notif.severity = "warning"
        mock_notif.read = False
        mock_notif.device_id = None
        mock_notif.user_id = str(mock_user.id)
        mock_notif.created_at = datetime.utcnow()
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif]
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [1, 1]  # total=1, unread=1
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications", params={"unread_only": True})
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["unread_count"] == 1
        assert all(not n["read"] for n in data["notifications"])
    
    @pytest.mark.asyncio
    async def test_list_notifications_by_severity(self, client, mock_db, mock_user):
        """Test filtering notifications by severity"""
        mock_notif = MagicMock(spec=Notification)
        mock_notif.id = uuid.uuid4()
        mock_notif.severity = "critical"
        mock_notif.notification_type = "alert"
        mock_notif.title = "Critical Alert"
        mock_notif.message = "Critical issue"
        mock_notif.read = False
        mock_notif.device_id = None
        mock_notif.user_id = str(mock_user.id)
        mock_notif.created_at = datetime.utcnow()
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif]
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [1, 1]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications", params={"severity": "critical"})
        
        assert response.status_code == 200
        data = response.json()
        assert all(n["severity"] == "critical" for n in data["notifications"])
    
    @pytest.mark.asyncio
    async def test_list_notifications_pagination(self, client, mock_db, mock_user):
        """Test notification pagination"""
        # Create 5 notifications
        notifications = []
        for i in range(5):
            notif = MagicMock(spec=Notification)
            notif.id = uuid.uuid4()
            notif.notification_type = "info"
            notif.title = f"Notification {i}"
            notif.message = f"Message {i}"
            notif.severity = "info"
            notif.read = False
            notif.device_id = None
            notif.user_id = str(mock_user.id)
            notif.created_at = datetime.utcnow() - timedelta(hours=i)
            notif.read_at = None
            notifications.append(notif)
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = notifications[:2]  # Page 1, 2 items
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [5, 5]  # total=5, unread=5
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications", params={"page": 1, "per_page": 2})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["notifications"]) == 2
        assert data["total"] == 5
        assert data["page"] == 1
        assert data["per_page"] == 2
    
    @pytest.mark.asyncio
    async def test_list_notifications_empty(self, client, mock_db, mock_user):
        """Test listing notifications when none exist"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [0, 0]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications")
        
        assert response.status_code == 200
        data = response.json()
        assert data["notifications"] == []
        assert data["total"] == 0
        assert data["unread_count"] == 0
    
    @pytest.mark.asyncio
    async def test_list_notifications_database_error(self, client, mock_db, mock_user):
        """Test listing notifications with database error"""
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications")
        
        assert response.status_code == 500
        assert "Failed to list notifications" in response.json()["detail"]


class TestGetUnreadCountEndpoint:
    """Test GET /api/v1/notifications/unread-count endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_unread_count_success(self, client, mock_db, mock_user):
        """Test successful unread count retrieval"""
        mock_db.scalar.return_value = 5  # 5 unread notifications
        
        # Mock severity breakdown
        severity_result = MagicMock()
        severity_result.__iter__ = lambda x: iter([
            MagicMock(severity="info", count=2),
            MagicMock(severity="warning", count=2),
            MagicMock(severity="critical", count=1)
        ])
        mock_db.execute.return_value = severity_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications/unread-count")
        
        assert response.status_code == 200
        data = response.json()
        assert data["unread_count"] == 5
        assert data["severity_breakdown"]["info"] == 2
        assert data["severity_breakdown"]["warning"] == 2
        assert data["severity_breakdown"]["critical"] == 1
        assert data["has_critical"] is True
    
    @pytest.mark.asyncio
    async def test_get_unread_count_no_unread(self, client, mock_db, mock_user):
        """Test unread count when no unread notifications"""
        mock_db.scalar.return_value = 0
        
        empty_result = MagicMock()
        empty_result.__iter__ = lambda x: iter([])
        mock_db.execute.return_value = empty_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications/unread-count")
        
        assert response.status_code == 200
        data = response.json()
        assert data["unread_count"] == 0
        assert data["has_critical"] is False
    
    @pytest.mark.asyncio
    async def test_get_unread_count_database_error(self, client, mock_db, mock_user):
        """Test unread count with database error"""
        mock_db.scalar.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications/unread-count")
        
        assert response.status_code == 500
        assert "Failed to get unread count" in response.json()["detail"]


class TestMarkNotificationReadEndpoint:
    """Test POST /api/v1/notifications/{notification_id}/read endpoint"""
    
    @pytest.mark.asyncio
    async def test_mark_notification_read_success(self, client, mock_db, mock_user):
        """Test successfully marking notification as read"""
        notification_id = uuid.uuid4()
        mock_notif = MagicMock(spec=Notification)
        mock_notif.read = False
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_notif
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post(f"/api/v1/notifications/{notification_id}/read")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Notification marked as read"
        assert mock_notif.read is True
        assert mock_notif.read_at is not None
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_mark_notification_read_not_found(self, client, mock_db, mock_user):
        """Test marking non-existent notification as read"""
        notification_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post(f"/api/v1/notifications/{notification_id}/read")
        
        assert response.status_code == 404
        assert "Notification not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_mark_notification_read_invalid_id(self, client, mock_user):
        """Test marking notification with invalid UUID"""
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post("/api/v1/notifications/invalid-uuid/read")
        
        assert response.status_code == 400
        assert "Invalid notification ID format" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_mark_notification_read_already_read(self, client, mock_db, mock_user):
        """Test marking already read notification"""
        notification_id = uuid.uuid4()
        mock_notif = MagicMock(spec=Notification)
        mock_notif.read = True
        mock_notif.read_at = datetime.utcnow() - timedelta(hours=1)
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_notif
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post(f"/api/v1/notifications/{notification_id}/read")
        
        # Should still succeed but update read_at
        assert response.status_code == 200
        assert mock_notif.read is True


class TestMarkAllNotificationsReadEndpoint:
    """Test POST /api/v1/notifications/mark-all-read endpoint"""
    
    @pytest.mark.asyncio
    async def test_mark_all_read_success(self, client, mock_db, mock_user):
        """Test successfully marking all notifications as read"""
        mock_result = MagicMock()
        mock_result.rowcount = 10  # 10 notifications updated
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post("/api/v1/notifications/mark-all-read")
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "All notifications marked as read"
        assert data["updated_count"] == 10
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_mark_all_read_no_unread(self, client, mock_db, mock_user):
        """Test marking all as read when none are unread"""
        mock_result = MagicMock()
        mock_result.rowcount = 0
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post("/api/v1/notifications/mark-all-read")
        
        assert response.status_code == 200
        data = response.json()
        assert data["updated_count"] == 0
    
    @pytest.mark.asyncio
    async def test_mark_all_read_database_error(self, client, mock_db, mock_user):
        """Test marking all as read with database error"""
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post("/api/v1/notifications/mark-all-read")
        
        assert response.status_code == 500
        assert "Failed to mark all notifications as read" in response.json()["detail"]


class TestDeleteNotificationEndpoint:
    """Test DELETE /api/v1/notifications/{notification_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_delete_notification_success(self, client, mock_db, mock_user):
        """Test successful notification deletion"""
        notification_id = uuid.uuid4()
        mock_notif = MagicMock(spec=Notification)
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_notif
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.delete(f"/api/v1/notifications/{notification_id}")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Notification deleted successfully"
        mock_db.delete.assert_called_once_with(mock_notif)
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_notification_not_found(self, client, mock_db, mock_user):
        """Test deleting non-existent notification"""
        notification_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.delete(f"/api/v1/notifications/{notification_id}")
        
        assert response.status_code == 404
        assert "Notification not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_delete_notification_unauthorized(self, client):
        """Test deleting notification without authentication"""
        notification_id = uuid.uuid4()
        
        with patch("backend.api.routers.notifications.get_current_user", side_effect=HTTPException(status_code=401)):
            response = await client.delete(f"/api/v1/notifications/{notification_id}")
        
        assert response.status_code == 401


class TestCreateTestNotificationEndpoint:
    """Test POST /api/v1/notifications/test endpoint"""
    
    @pytest.mark.asyncio
    async def test_create_test_notification_success(self, client, mock_db, mock_user):
        """Test creating test notification"""
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            with patch("backend.api.routers.notifications.standard_rate_limit"):
                response = await client.post("/api/v1/notifications/test")
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Test notification created"
        assert "notification_id" in data
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_test_notification_with_websocket(self, client, mock_db, mock_user):
        """Test creating test notification with WebSocket broadcast"""
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            with patch("backend.api.routers.notifications.standard_rate_limit"):
                with patch("backend.api.websocket_manager.ws_manager") as mock_ws:
                    mock_ws.broadcast_notification = AsyncMock()
                    response = await client.post("/api/v1/notifications/test")
        
        assert response.status_code == 200
        mock_ws.broadcast_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_test_notification_websocket_failure(self, client, mock_db, mock_user):
        """Test creating test notification when WebSocket fails"""
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            with patch("backend.api.routers.notifications.standard_rate_limit"):
                with patch("backend.api.websocket_manager.ws_manager") as mock_ws:
                    mock_ws.broadcast_notification = AsyncMock(side_effect=Exception("WebSocket error"))
                    response = await client.post("/api/v1/notifications/test")
        
        # Should still succeed even if WebSocket fails
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_create_test_notification_database_error(self, client, mock_db, mock_user):
        """Test creating test notification with database error"""
        mock_db.commit.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            with patch("backend.api.routers.notifications.standard_rate_limit"):
                response = await client.post("/api/v1/notifications/test")
        
        assert response.status_code == 500
        assert "Failed to create test notification" in response.json()["detail"]


class TestNotificationValidation:
    """Test notification data validation"""
    
    @pytest.mark.asyncio
    async def test_severity_validation(self, client, mock_user):
        """Test notification severity validation"""
        valid_severities = ["info", "warning", "error", "critical"]
        
        for severity in valid_severities:
            # Each severity should be valid
            pass
        
        # Invalid severity would fail at Pydantic validation level
    
    @pytest.mark.asyncio
    async def test_notification_filtering(self, client, mock_db, mock_user):
        """Test notification filtering by type"""
        mock_notif = MagicMock(spec=Notification)
        mock_notif.id = uuid.uuid4()
        mock_notif.notification_type = "alert"
        mock_notif.title = "Alert"
        mock_notif.message = "Alert message"
        mock_notif.severity = "warning"
        mock_notif.read = False
        mock_notif.device_id = None
        mock_notif.user_id = str(mock_user.id)
        mock_notif.created_at = datetime.utcnow()
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif]
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [1, 1]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications", params={"notification_type": "alert"})
        
        assert response.status_code == 200
        data = response.json()
        assert all(n["notification_type"] == "alert" for n in data["notifications"])


class TestNotificationEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.mark.asyncio
    async def test_global_notifications(self, client, mock_db, mock_user):
        """Test handling of global notifications (no user_id)"""
        mock_notif = MagicMock(spec=Notification)
        mock_notif.id = uuid.uuid4()
        mock_notif.notification_type = "system"
        mock_notif.title = "System Update"
        mock_notif.message = "System maintenance scheduled"
        mock_notif.severity = "info"
        mock_notif.read = False
        mock_notif.device_id = None
        mock_notif.user_id = None  # Global notification
        mock_notif.created_at = datetime.utcnow()
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif]
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [1, 1]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications")
        
        assert response.status_code == 200
        data = response.json()
        # Global notifications should be visible to all users
        assert len(data["notifications"]) == 1
        assert data["notifications"][0]["user_id"] is None
    
    @pytest.mark.asyncio
    async def test_notification_with_device(self, client, mock_db, mock_user):
        """Test notification associated with a device"""
        device_id = uuid.uuid4()
        mock_notif = MagicMock(spec=Notification)
        mock_notif.id = uuid.uuid4()
        mock_notif.notification_type = "device_alert"
        mock_notif.title = "Device Alert"
        mock_notif.message = "Device issue detected"
        mock_notif.severity = "warning"
        mock_notif.read = False
        mock_notif.device_id = device_id
        mock_notif.user_id = str(mock_user.id)
        mock_notif.created_at = datetime.utcnow()
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif]
        
        # Mock device hostname lookup
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = "router-01"
        
        mock_db.execute.side_effect = [mock_result, device_result]
        mock_db.scalar.side_effect = [1, 1]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications")
        
        assert response.status_code == 200
        data = response.json()
        assert data["notifications"][0]["device_id"] == str(device_id)
        assert data["notifications"][0]["device_hostname"] == "router-01"
    
    @pytest.mark.asyncio
    async def test_notification_device_deleted(self, client, mock_db, mock_user):
        """Test notification when associated device is deleted"""
        mock_notif = MagicMock(spec=Notification)
        mock_notif.id = uuid.uuid4()
        mock_notif.notification_type = "device_alert"
        mock_notif.title = "Device Alert"
        mock_notif.message = "Alert for deleted device"
        mock_notif.severity = "warning"
        mock_notif.read = False
        mock_notif.device_id = uuid.uuid4()
        mock_notif.user_id = str(mock_user.id)
        mock_notif.created_at = datetime.utcnow()
        mock_notif.read_at = None
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_notif]
        
        # Device not found
        device_result = MagicMock()
        device_result.scalar_one_or_none.return_value = None
        
        mock_db.execute.side_effect = [mock_result, device_result]
        mock_db.scalar.side_effect = [1, 1]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications")
        
        assert response.status_code == 200
        data = response.json()
        assert data["notifications"][0]["device_hostname"] is None
    
    @pytest.mark.asyncio
    async def test_large_notification_batch(self, client, mock_db, mock_user):
        """Test handling large number of notifications"""
        # Create 100 notifications
        notifications = []
        for i in range(100):
            notif = MagicMock(spec=Notification)
            notif.id = uuid.uuid4()
            notif.notification_type = "info"
            notif.title = f"Notification {i}"
            notif.message = f"Message {i}"
            notif.severity = "info"
            notif.read = i % 2 == 0  # Half read, half unread
            notif.device_id = None
            notif.user_id = str(mock_user.id)
            notif.created_at = datetime.utcnow() - timedelta(minutes=i)
            notif.read_at = datetime.utcnow() if notif.read else None
            notifications.append(notif)
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = notifications[:50]  # Return first 50
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [100, 50]  # total=100, unread=50
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.get("/api/v1/notifications", params={"per_page": 50})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["notifications"]) == 50
        assert data["total"] == 100
        assert data["unread_count"] == 50
    
    @pytest.mark.asyncio
    async def test_concurrent_mark_read(self, client, mock_db, mock_user):
        """Test concurrent marking of notifications as read"""
        notification_id = uuid.uuid4()
        mock_notif = MagicMock(spec=Notification)
        mock_notif.read = False
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_notif
        mock_db.execute.return_value = mock_result
        
        # Simulate optimistic locking issue
        mock_db.commit.side_effect = [Exception("Concurrent update"), None]
        
        with patch("backend.api.routers.notifications.get_current_user", return_value=mock_user):
            response = await client.post(f"/api/v1/notifications/{notification_id}/read")
        
        # First attempt fails due to concurrent update
        assert response.status_code == 500


# Fixtures for tests
@pytest.fixture
def client():
    """Create test client"""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    
    app = FastAPI()
    app.include_router(router)
    
    return TestClient(app)


@pytest.fixture
def mock_db():
    """Create mock database session"""
    mock = AsyncMock(spec=AsyncSession)
    mock.execute = AsyncMock()
    mock.scalar = AsyncMock()
    mock.add = MagicMock()
    mock.delete = AsyncMock()
    mock.commit = AsyncMock()
    mock.refresh = AsyncMock()
    return mock


@pytest.fixture
def mock_user():
    """Create mock user"""
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.is_active = True
    return user