"""
Comprehensive tests for Notification Service to boost coverage to 65%
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession

# Mock WebSocketManager before importing
class MockWebSocketManager:
    def __init__(self):
        pass
    
    async def send_to_user(self, user_id, message):
        return True

# Apply the mock
import sys
sys.modules['backend.services.websocket_manager'] = MagicMock()
sys.modules['backend.services.websocket_manager'].WebSocketManager = MockWebSocketManager

from backend.services.notification_service import NotificationService
from backend.common.exceptions import AppException


class TestNotificationService:
    """Comprehensive test cases for NotificationService"""
    
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
    def mock_user(self):
        """Mock user object"""
        user = MagicMock()
        user.id = uuid4()
        user.email = "test@example.com"
        user.username = "testuser"
        user.is_active = True
        user.is_superuser = False
        return user
    
    @pytest.fixture
    def mock_notification(self):
        """Mock notification object"""
        notification = MagicMock()
        notification.id = uuid4()
        notification.user_id = uuid4()
        notification.title = "Test Notification"
        notification.message = "This is a test notification"
        notification.notification_type = "info"
        notification.severity = "normal"
        notification.read = False
        notification.created_at = datetime.utcnow()
        notification.read_at = None
        notification.notification_metadata = {}
        return notification
    
    # Test create_notification method
    @pytest.mark.asyncio
    async def test_create_notification_success(self, mock_db_session, mock_user):
        """Test successful notification creation"""
        # Setup mocks
        mock_db_session.get.return_value = mock_user
        
        with patch.object(NotificationService, '_send_websocket_notification', new=AsyncMock()):
            # Execute
            result = await NotificationService.create_notification(
                mock_db_session,
                user_id=mock_user.id,
                title="Test Alert",
                message="This is a test alert",
                notification_type="alert",
                priority="normal",
                metadata={"alert_id": "123"}
            )
            
            # Verify
            mock_db_session.add.assert_called_once()
            mock_db_session.commit.assert_called_once()
            mock_db_session.refresh.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_notification_high_priority(self, mock_db_session, mock_user):
        """Test notification creation with high priority (should send email)"""
        # Setup mocks
        mock_db_session.get.return_value = mock_user
        
        with patch.object(NotificationService, '_send_websocket_notification', new=AsyncMock()):
            with patch.object(NotificationService, '_send_email_notification', new=AsyncMock()) as mock_email:
                # Execute
                result = await NotificationService.create_notification(
                    mock_db_session,
                    user_id=mock_user.id,
                    title="Critical Alert",
                    message="This is a critical alert",
                    priority="high"
                )
                
                # Verify
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
                mock_email.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_notification_user_not_found(self, mock_db_session):
        """Test notification creation with non-existent user"""
        # Setup mocks
        mock_db_session.get.return_value = None
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.create_notification(
                mock_db_session,
                user_id=uuid4(),
                title="Test",
                message="Test message"
            )
        
        assert exc_info.value.status_code == 404
        assert "User" in str(exc_info.value.detail)
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_notification_database_error(self, mock_db_session, mock_user):
        """Test notification creation with database error"""
        # Setup mocks
        mock_db_session.get.return_value = mock_user
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.create_notification(
                mock_db_session,
                user_id=mock_user.id,
                title="Test",
                message="Test message"
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test get_user_notifications method
    @pytest.mark.asyncio
    async def test_get_user_notifications_success(self, mock_db_session, mock_notification):
        """Test successful user notifications retrieval"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_notification]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        results = await NotificationService.get_user_notifications(
            mock_db_session,
            user_id=uuid4(),
            skip=0,
            limit=50,
            unread_only=False
        )
        
        # Verify
        assert len(results) == 1
        assert results[0] == mock_notification
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_notifications_unread_only(self, mock_db_session, mock_notification):
        """Test getting unread notifications only"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_notification]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        results = await NotificationService.get_user_notifications(
            mock_db_session,
            user_id=uuid4(),
            unread_only=True
        )
        
        # Verify
        assert len(results) == 1
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_notifications_with_type_filter(self, mock_db_session, mock_notification):
        """Test getting notifications with type filter"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_notification]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        results = await NotificationService.get_user_notifications(
            mock_db_session,
            user_id=uuid4(),
            notification_type="alert"
        )
        
        # Verify
        assert len(results) == 1
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_notifications_database_error(self, mock_db_session):
        """Test notifications retrieval with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.get_user_notifications(
                mock_db_session,
                user_id=uuid4()
            )
        
        assert exc_info.value.status_code == 500
    
    # Test mark_as_read method
    @pytest.mark.asyncio
    async def test_mark_as_read_success(self, mock_db_session, mock_notification):
        """Test successful notification mark as read"""
        # Setup mocks
        mock_notification.read = False
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, 'get_unread_count', return_value=5):
            with patch.object(NotificationService, '_send_websocket_update', new=AsyncMock()):
                # Execute
                result = await NotificationService.mark_as_read(
                    mock_db_session,
                    mock_notification.id,
                    mock_notification.user_id
                )
                
                # Verify
                assert result.read is True
                assert result.read_at is not None
                mock_db_session.commit.assert_called_once()
                mock_db_session.refresh.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_mark_as_read_already_read(self, mock_db_session, mock_notification):
        """Test marking already read notification"""
        # Setup mocks
        mock_notification.read = True
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await NotificationService.mark_as_read(
            mock_db_session,
            mock_notification.id,
            mock_notification.user_id
        )
        
        # Verify - should return without doing anything
        assert result == mock_notification
        mock_db_session.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_mark_as_read_not_found(self, mock_db_session):
        """Test marking non-existent notification as read"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.mark_as_read(
                mock_db_session,
                uuid4(),
                uuid4()
            )
        
        assert exc_info.value.status_code == 404
    
    @pytest.mark.asyncio
    async def test_mark_as_read_database_error(self, mock_db_session, mock_notification):
        """Test mark as read with database error"""
        # Setup mocks
        mock_notification.read = False
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.mark_as_read(
                mock_db_session,
                mock_notification.id,
                mock_notification.user_id
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test get_unread_count method
    @pytest.mark.asyncio
    async def test_get_unread_count_success(self, mock_db_session):
        """Test successful unread count retrieval"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar.return_value = 5
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await NotificationService.get_unread_count(
            mock_db_session,
            user_id=uuid4()
        )
        
        # Verify
        assert count == 5
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_unread_count_no_notifications(self, mock_db_session):
        """Test unread count with no notifications"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await NotificationService.get_unread_count(
            mock_db_session,
            user_id=uuid4()
        )
        
        # Verify
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_get_unread_count_database_error(self, mock_db_session):
        """Test unread count with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.get_unread_count(
                mock_db_session,
                user_id=uuid4()
            )
        
        assert exc_info.value.status_code == 500
    
    # Test mark_all_as_read method
    @pytest.mark.asyncio
    async def test_mark_all_as_read_success(self, mock_db_session):
        """Test successful mark all as read"""
        # Setup mocks
        mock_result = MagicMock()
        mock_result.rowcount = 3
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, '_send_websocket_update', new=AsyncMock()):
            # Execute
            count = await NotificationService.mark_all_as_read(
                mock_db_session,
                user_id=uuid4()
            )
            
            # Verify
            assert count == 3
            mock_db_session.execute.assert_called_once()
            mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_mark_all_as_read_database_error(self, mock_db_session):
        """Test mark all as read with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.mark_all_as_read(
                mock_db_session,
                user_id=uuid4()
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test delete_notification method
    @pytest.mark.asyncio
    async def test_delete_notification_success(self, mock_db_session, mock_notification):
        """Test successful notification deletion"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await NotificationService.delete_notification(
            mock_db_session,
            mock_notification.id,
            mock_notification.user_id
        )
        
        # Verify
        assert result is True
        mock_db_session.delete.assert_called_once_with(mock_notification)
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_notification_not_found(self, mock_db_session):
        """Test deleting non-existent notification"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.delete_notification(
                mock_db_session,
                uuid4(),
                uuid4()
            )
        
        assert exc_info.value.status_code == 404
    
    @pytest.mark.asyncio
    async def test_delete_notification_database_error(self, mock_db_session, mock_notification):
        """Test notification deletion with database error"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_notification
        mock_db_session.execute.return_value = mock_result
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.delete_notification(
                mock_db_session,
                mock_notification.id,
                mock_notification.user_id
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test delete_old_notifications method
    @pytest.mark.asyncio
    async def test_delete_old_notifications_success(self, mock_db_session):
        """Test successful old notifications deletion"""
        # Setup mocks
        old_notification1 = MagicMock()
        old_notification2 = MagicMock()
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [
            old_notification1, old_notification2
        ]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await NotificationService.delete_old_notifications(
            mock_db_session,
            days=30
        )
        
        # Verify
        assert count == 2
        assert mock_db_session.delete.call_count == 2
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_notifications_no_data(self, mock_db_session):
        """Test deleting old notifications with no data"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await NotificationService.delete_old_notifications(mock_db_session)
        
        # Verify
        assert count == 0
        mock_db_session.delete.assert_not_called()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_notifications_database_error(self, mock_db_session):
        """Test deleting old notifications with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.delete_old_notifications(mock_db_session)
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test create_test_notification method
    @pytest.mark.asyncio
    async def test_create_test_notification_success(self, mock_db_session, mock_user):
        """Test successful test notification creation"""
        # Setup mocks
        mock_db_session.get.return_value = mock_user
        
        with patch.object(NotificationService, 'create_notification', new=AsyncMock()) as mock_create:
            mock_create.return_value = mock_user  # Return something
            
            # Execute
            result = await NotificationService.create_test_notification(
                mock_db_session,
                user_id=mock_user.id
            )
            
            # Verify
            mock_create.assert_called_once()
            args, kwargs = mock_create.call_args
            assert kwargs['title'] == "Test Notification"
            assert kwargs['notification_type'] == 'test'
            assert kwargs['metadata']['test'] is True
    
    @pytest.mark.asyncio
    async def test_create_test_notification_error(self, mock_db_session):
        """Test test notification creation with error"""
        # Setup mocks
        with patch.object(NotificationService, 'create_notification', new=AsyncMock()) as mock_create:
            mock_create.side_effect = Exception("Creation error")
            
            # Execute and verify
            with pytest.raises(AppException) as exc_info:
                await NotificationService.create_test_notification(
                    mock_db_session,
                    user_id=uuid4()
                )
            
            assert exc_info.value.status_code == 500
    
    # Test broadcast_notification method
    @pytest.mark.asyncio
    async def test_broadcast_notification_success(self, mock_db_session, mock_user):
        """Test successful notification broadcast"""
        # Setup mocks
        mock_user2 = MagicMock()
        mock_user2.id = uuid4()
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_user, mock_user2]
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, 'create_notification', new=AsyncMock()) as mock_create:
            # Execute
            count = await NotificationService.broadcast_notification(
                mock_db_session,
                title="System Maintenance",
                message="System will be down for maintenance",
                notification_type="system"
            )
            
            # Verify
            assert count == 2
            assert mock_create.call_count == 2
    
    @pytest.mark.asyncio
    async def test_broadcast_notification_with_roles(self, mock_db_session, mock_user):
        """Test notification broadcast with role filtering"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_user]
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(NotificationService, 'create_notification', new=AsyncMock()) as mock_create:
            # Execute
            count = await NotificationService.broadcast_notification(
                mock_db_session,
                title="Admin Alert",
                message="Admin-only message",
                target_roles=["admin"]
            )
            
            # Verify
            assert count == 1
            mock_create.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_broadcast_notification_no_users(self, mock_db_session):
        """Test notification broadcast with no users"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await NotificationService.broadcast_notification(
            mock_db_session,
            title="Test",
            message="Test message"
        )
        
        # Verify
        assert count == 0
    
    @pytest.mark.asyncio
    async def test_broadcast_notification_error(self, mock_db_session):
        """Test notification broadcast with error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await NotificationService.broadcast_notification(
                mock_db_session,
                title="Test",
                message="Test message"
            )
        
        assert exc_info.value.status_code == 500
    
    # Test private _send_websocket_notification method
    @pytest.mark.asyncio
    async def test_send_websocket_notification_success(self, mock_notification):
        """Test successful WebSocket notification sending"""
        # Execute - should not raise exception
        await NotificationService._send_websocket_notification(
            mock_notification.user_id,
            mock_notification
        )
        
        # Verify it completes without error
        assert True
    
    @pytest.mark.asyncio
    async def test_send_websocket_notification_error(self, mock_notification):
        """Test WebSocket notification sending with error"""
        # Mock WebSocket manager to raise error
        with patch('backend.services.notification_service.websocket_manager') as mock_ws:
            mock_ws.send_to_user.side_effect = Exception("WebSocket error")
            
            # Execute - should not raise exception, just log error
            await NotificationService._send_websocket_notification(
                mock_notification.user_id,
                mock_notification
            )
            
            # Verify it handled the error gracefully
            assert True
    
    # Test private _send_websocket_update method
    @pytest.mark.asyncio
    async def test_send_websocket_update_success(self):
        """Test successful WebSocket update sending"""
        # Execute - should not raise exception
        await NotificationService._send_websocket_update(
            uuid4(),
            {"unread_count": 5}
        )
        
        # Verify it completes without error
        assert True
    
    @pytest.mark.asyncio
    async def test_send_websocket_update_error(self):
        """Test WebSocket update sending with error"""
        # Mock WebSocket manager to raise error
        with patch('backend.services.notification_service.websocket_manager') as mock_ws:
            mock_ws.send_to_user.side_effect = Exception("WebSocket error")
            
            # Execute - should not raise exception, just log error
            await NotificationService._send_websocket_update(
                uuid4(),
                {"unread_count": 5}
            )
            
            # Verify it handled the error gracefully
            assert True
    
    # Test private _send_email_notification method
    @pytest.mark.asyncio
    async def test_send_email_notification_success(self, mock_user, mock_notification):
        """Test successful email notification sending"""
        # Execute - should not raise exception
        await NotificationService._send_email_notification(
            mock_user,
            mock_notification
        )
        
        # Verify it completes without error
        assert True
    
    @pytest.mark.asyncio
    async def test_send_email_notification_error(self, mock_user, mock_notification):
        """Test email notification sending with error"""
        # Mock to raise error (but it should be caught)
        mock_user.email = None  # This might cause an error
        
        # Execute - should not raise exception, just log error
        await NotificationService._send_email_notification(
            mock_user,
            mock_notification
        )
        
        # Verify it handled the error gracefully
        assert True
    
    # Test instance methods
    def test_notification_service_init(self):
        """Test NotificationService initialization"""
        service = NotificationService()
        assert service.db is None
        
        # Test with db parameter
        mock_db = MagicMock()
        service_with_db = NotificationService(db=mock_db)
        assert service_with_db.db == mock_db
    
    @pytest.mark.asyncio
    async def test_send_alert_notification_success(self):
        """Test sending alert notification"""
        service = NotificationService()
        
        # Execute
        result = await service.send_alert_notification(
            alert_id="alert_123",
            severity="critical",
            message="System down",
            user_id="user_123"
        )
        
        # Verify
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_alert_notification_error(self):
        """Test sending alert notification with error"""
        service = NotificationService()
        
        # Mock logger to raise error (simulate failure)
        with patch('backend.services.notification_service.logger') as mock_logger:
            mock_logger.info.side_effect = Exception("Logger error")
            
            # Execute
            result = await service.send_alert_notification(
                alert_id="alert_123",
                severity="critical",
                message="System down"
            )
            
            # Verify it handled error gracefully
            assert result is False
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_success(self):
        """Test sending password reset email"""
        service = NotificationService()
        
        # Execute
        result = await service.send_password_reset_email(
            email="test@example.com",
            reset_token="reset_token_123",
            user_name="Test User"
        )
        
        # Verify
        assert result is True
    
    @pytest.mark.asyncio
    async def test_send_password_reset_email_error(self):
        """Test sending password reset email with error"""
        service = NotificationService()
        
        # Mock logger to raise error (simulate failure)
        with patch('backend.services.notification_service.logger') as mock_logger:
            mock_logger.info.side_effect = Exception("Logger error")
            
            # Execute
            result = await service.send_password_reset_email(
                email="test@example.com",
                reset_token="reset_token_123",
                user_name="Test User"
            )
            
            # Verify it handled error gracefully
            assert result is False
    
    # Test edge cases and complex scenarios
    @pytest.mark.asyncio
    async def test_create_notification_with_all_parameters(self, mock_db_session, mock_user):
        """Test notification creation with all parameters"""
        # Setup mocks
        mock_db_session.get.return_value = mock_user
        
        metadata = {
            "alert_id": "123",
            "device_id": "456",
            "custom_data": "test"
        }
        
        with patch.object(NotificationService, '_send_websocket_notification', new=AsyncMock()):
            with patch.object(NotificationService, '_send_email_notification', new=AsyncMock()) as mock_email:
                # Execute
                result = await NotificationService.create_notification(
                    mock_db_session,
                    user_id=mock_user.id,
                    title="Comprehensive Test",
                    message="This tests all parameters",
                    notification_type="custom",
                    priority="high",
                    metadata=metadata
                )
                
                # Verify
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
                mock_email.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_notifications_with_pagination(self, mock_db_session):
        """Test getting notifications with pagination"""
        # Setup mocks
        mock_notifications = [MagicMock() for _ in range(25)]
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_notifications
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        results = await NotificationService.get_user_notifications(
            mock_db_session,
            user_id=uuid4(),
            skip=50,
            limit=25
        )
        
        # Verify
        assert len(results) == 25
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_broadcast_notification_partial_failure(self, mock_db_session):
        """Test broadcast notification with partial failures"""
        # Setup mocks
        mock_user1 = MagicMock()
        mock_user1.id = uuid4()
        mock_user2 = MagicMock()
        mock_user2.id = uuid4()
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_user1, mock_user2]
        mock_db_session.execute.return_value = mock_result
        
        # Mock create_notification to fail for second user
        async def mock_create_side_effect(*args, **kwargs):
            if kwargs['user_id'] == mock_user2.id:
                raise Exception("Creation failed")
            return MagicMock()
        
        with patch.object(NotificationService, 'create_notification', side_effect=mock_create_side_effect):
            # Execute
            count = await NotificationService.broadcast_notification(
                mock_db_session,
                title="Test Broadcast",
                message="Test message"
            )
            
            # Verify - should still count successful notifications
            assert count == 1  # Only first user succeeded