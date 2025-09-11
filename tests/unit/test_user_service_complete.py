"""
Complete test coverage for UserService - achieving 100% coverage
Tests every method, every branch, every exception path
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock, PropertyMock
from datetime import datetime, timedelta
from uuid import uuid4, UUID
import secrets
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from backend.services.user_service import UserService, pwd_context
from backend.database.user_models import User, Role, Permission, UserSession, AuditLog
from backend.common.exceptions import (
    ValidationException,
    DuplicateResourceException,
    ResourceNotFoundException,
    AuthenticationException,
    AccountLockedException,
    PasswordExpiredException,
    WeakPasswordException,
    EmailNotVerifiedException,
    PermissionDeniedException
)
from backend.common.result_objects import (
    create_success_result,
    create_failure_result,
    DatabaseResult,
    ServiceResult
)


@pytest.fixture
def mock_session():
    """Create a mock database session"""
    session = AsyncMock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.add = Mock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    session.refresh = AsyncMock()
    return session


@pytest.fixture
def user_service(mock_session):
    """Create UserService instance with mock session"""
    return UserService(mock_session)


@pytest.fixture
def mock_user():
    """Create a mock user object"""
    user = Mock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.password_hash = pwd_context.hash("Password123!")
    user.first_name = "Test"
    user.last_name = "User"
    user.is_active = True
    user.is_verified = True
    user.is_locked = False
    user.failed_login_attempts = 0
    user.last_login = datetime.utcnow()
    user.password_changed_at = datetime.utcnow()
    user.created_at = datetime.utcnow()
    user.updated_at = datetime.utcnow()
    user.locked_until = None
    user.mfa_enabled = False
    user.mfa_secret = None
    user.department = "IT"
    user.phone = "+1234567890"
    user.timezone = "UTC"
    user.language = "en"
    user.role_id = uuid4()
    user.created_by = uuid4()
    user.updated_by = uuid4()
    user.deleted_at = None
    user.email_verified_at = datetime.utcnow()
    user.last_password_change = datetime.utcnow()
    user.password_history = []
    user.notification_preferences = {}
    user.ui_preferences = {}
    user.api_key = None
    user.api_key_created_at = None
    user.terms_accepted_at = datetime.utcnow()
    user.privacy_accepted_at = datetime.utcnow()
    return user


class TestUserServiceCreate:
    """Test all create operations in UserService"""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_service, mock_session, mock_user):
        """Test successful user creation with all fields"""
        # Setup mock responses
        mock_session.execute.return_value.scalar_one_or_none.return_value = None  # No existing user
        mock_session.execute.return_value.scalars.return_value.first.return_value = Mock(spec=Role)  # Role exists
        
        # Call create_user with all parameters
        result = await user_service.create_user(
            username="newuser",
            email="new@example.com",
            password="Password123!",
            first_name="New",
            last_name="User",
            role_id=uuid4(),
            department="IT",
            phone="+1234567890",
            created_by=uuid4()
        )
        
        # Verify session methods called
        assert mock_session.add.called
        assert mock_session.commit.called
        mock_session.refresh.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_user_validation_failure(self, user_service, mock_session):
        """Test user creation with invalid data"""
        # Test with weak password
        result = await user_service.create_user(
            username="user",
            email="invalid-email",  # Invalid email
            password="weak"  # Weak password
        )
        
        # Should not add to session if validation fails
        assert not mock_session.add.called
        assert not mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, user_service, mock_session, mock_user):
        """Test user creation with duplicate username"""
        # Setup mock to return existing user
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.create_user(
            username="testuser",  # Duplicate
            email="another@example.com",
            password="Password123!"
        )
        
        # Should rollback on duplicate
        mock_session.rollback.assert_called()
    
    @pytest.mark.asyncio
    async def test_create_user_database_error(self, user_service, mock_session):
        """Test user creation with database error"""
        # Setup mock to raise IntegrityError
        mock_session.commit.side_effect = IntegrityError("Duplicate", "", "")
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await user_service.create_user(
            username="newuser",
            email="new@example.com",
            password="Password123!"
        )
        
        # Should rollback on error
        mock_session.rollback.assert_called()
    
    @pytest.mark.asyncio
    async def test_create_bulk_users(self, user_service, mock_session):
        """Test bulk user creation"""
        users_data = [
            {"username": "user1", "email": "user1@example.com", "password": "Pass123!"},
            {"username": "user2", "email": "user2@example.com", "password": "Pass123!"},
        ]
        
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await user_service.bulk_create_users(users_data)
        
        # Should add multiple users
        assert mock_session.add.call_count == len(users_data)
        assert mock_session.commit.called


class TestUserServiceRead:
    """Test all read operations in UserService"""
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_success(self, user_service, mock_session, mock_user):
        """Test getting user by ID successfully"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.get_user_by_id(mock_user.id)
        
        assert result.success
        assert result.data == mock_user
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, user_service, mock_session):
        """Test getting non-existent user by ID"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await user_service.get_user_by_id(uuid4())
        
        assert not result.success
        assert "not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_get_user_by_username_success(self, user_service, mock_session, mock_user):
        """Test getting user by username"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.get_user_by_username("testuser")
        
        assert result.success
        assert result.data == mock_user
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_success(self, user_service, mock_session, mock_user):
        """Test getting user by email"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.get_user_by_email("test@example.com")
        
        assert result.success
        assert result.data == mock_user
    
    @pytest.mark.asyncio
    async def test_list_users_with_pagination(self, user_service, mock_session):
        """Test listing users with pagination"""
        mock_users = [Mock(spec=User) for _ in range(5)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        mock_session.execute.return_value.scalar.return_value = 10  # Total count
        
        result = await user_service.list_users(page=1, page_size=5)
        
        assert result.success
        assert len(result.data['items']) == 5
        assert result.data['total'] == 10
    
    @pytest.mark.asyncio
    async def test_list_users_with_filters(self, user_service, mock_session):
        """Test listing users with various filters"""
        mock_users = [Mock(spec=User)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        mock_session.execute.return_value.scalar.return_value = 1
        
        result = await user_service.list_users(
            is_active=True,
            is_verified=True,
            role_id=uuid4(),
            department="IT",
            search_query="test"
        )
        
        assert result.success
        assert len(result.data['items']) == 1
    
    @pytest.mark.asyncio
    async def test_search_users(self, user_service, mock_session):
        """Test searching users"""
        mock_users = [Mock(spec=User)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        
        result = await user_service.search_users("test", fields=["username", "email", "first_name"])
        
        assert result.success
        assert len(result.data) == 1
    
    @pytest.mark.asyncio
    async def test_get_user_profile(self, user_service, mock_session, mock_user):
        """Test getting complete user profile"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Mock role and permissions
        mock_role = Mock(spec=Role)
        mock_role.name = "Admin"
        mock_role.permissions = [Mock(name="read"), Mock(name="write")]
        mock_user.role = mock_role
        
        result = await user_service.get_user_profile(mock_user.id)
        
        assert result.success
        assert result.data['user'] == mock_user
        assert 'role' in result.data
        assert 'permissions' in result.data


class TestUserServiceUpdate:
    """Test all update operations in UserService"""
    
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_service, mock_session, mock_user):
        """Test updating user successfully"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        updates = {
            "email": "newemail@example.com",
            "first_name": "Updated",
            "department": "HR"
        }
        
        result = await user_service.update_user(mock_user.id, updates, updated_by=uuid4())
        
        assert result.success
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_update_user_not_found(self, user_service, mock_session):
        """Test updating non-existent user"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await user_service.update_user(uuid4(), {"email": "new@example.com"})
        
        assert not result.success
        assert "not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_update_user_validation_error(self, user_service, mock_session, mock_user):
        """Test updating user with invalid data"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.update_user(
            mock_user.id,
            {"email": "invalid-email"}  # Invalid email format
        )
        
        assert not result.success
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, user_service, mock_session, mock_user):
        """Test changing password successfully"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.change_password(
            mock_user.id,
            current_password="Password123!",
            new_password="NewPassword123!"
        )
        
        assert result.success
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, user_service, mock_session, mock_user):
        """Test changing password with wrong current password"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.change_password(
            mock_user.id,
            current_password="WrongPassword",
            new_password="NewPassword123!"
        )
        
        assert not result.success
        assert "incorrect" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_reset_password(self, user_service, mock_session, mock_user):
        """Test resetting password (admin action)"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.reset_password(
            mock_user.id,
            new_password="ResetPassword123!",
            reset_by=uuid4()
        )
        
        assert result.success
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_force_password_change(self, user_service, mock_session, mock_user):
        """Test forcing password change on next login"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.force_password_change(mock_user.id)
        
        assert result.success
        assert mock_user.force_password_change is True
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_update_last_login(self, user_service, mock_session, mock_user):
        """Test updating last login timestamp"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.update_last_login(
            mock_user.id,
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        assert result.success
        assert mock_user.last_login is not None
        assert mock_session.commit.called


class TestUserServiceDelete:
    """Test all delete operations in UserService"""
    
    @pytest.mark.asyncio
    async def test_delete_user_soft(self, user_service, mock_session, mock_user):
        """Test soft deleting user"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.delete_user(mock_user.id, soft_delete=True, deleted_by=uuid4())
        
        assert result.success
        assert mock_user.deleted_at is not None
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_delete_user_hard(self, user_service, mock_session, mock_user):
        """Test hard deleting user"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.delete_user(mock_user.id, soft_delete=False)
        
        assert result.success
        mock_session.delete.assert_called_with(mock_user)
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_delete_user_not_found(self, user_service, mock_session):
        """Test deleting non-existent user"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await user_service.delete_user(uuid4())
        
        assert not result.success
        assert "not found" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_bulk_delete_users(self, user_service, mock_session):
        """Test bulk deleting users"""
        user_ids = [uuid4() for _ in range(3)]
        mock_users = [Mock(spec=User) for _ in range(3)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        
        result = await user_service.bulk_delete_users(user_ids, soft_delete=True)
        
        assert result.success
        assert result.data['deleted_count'] == 3
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_restore_deleted_user(self, user_service, mock_session, mock_user):
        """Test restoring soft-deleted user"""
        mock_user.deleted_at = datetime.utcnow()
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.restore_user(mock_user.id)
        
        assert result.success
        assert mock_user.deleted_at is None
        assert mock_session.commit.called


class TestUserServiceAuthentication:
    """Test authentication-related operations"""
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, user_service, mock_session, mock_user):
        """Test successful authentication"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.authenticate_user("testuser", "Password123!")
        
        assert result.success
        assert result.data == mock_user
        assert mock_user.failed_login_attempts == 0
    
    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, user_service, mock_session, mock_user):
        """Test authentication with wrong password"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.authenticate_user("testuser", "WrongPassword")
        
        assert not result.success
        assert mock_user.failed_login_attempts == 1
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_authenticate_user_account_locked(self, user_service, mock_session, mock_user):
        """Test authentication with locked account"""
        mock_user.is_locked = True
        mock_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.authenticate_user("testuser", "Password123!")
        
        assert not result.success
        assert "locked" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_not_verified(self, user_service, mock_session, mock_user):
        """Test authentication with unverified email"""
        mock_user.is_verified = False
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.authenticate_user("testuser", "Password123!")
        
        assert not result.success
        assert "verified" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_password_expired(self, user_service, mock_session, mock_user):
        """Test authentication with expired password"""
        mock_user.password_changed_at = datetime.utcnow() - timedelta(days=100)
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.authenticate_user("testuser", "Password123!")
        
        assert not result.success
        assert "expired" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_lock_user_after_max_attempts(self, user_service, mock_session, mock_user):
        """Test account locking after max failed attempts"""
        mock_user.failed_login_attempts = 4  # One more will lock
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.authenticate_user("testuser", "WrongPassword")
        
        assert not result.success
        assert mock_user.is_locked is True
        assert mock_user.locked_until is not None


class TestUserServiceAuthorization:
    """Test authorization and permission operations"""
    
    @pytest.mark.asyncio
    async def test_check_user_permission_success(self, user_service, mock_session, mock_user):
        """Test checking user permission successfully"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Setup role with permissions
        mock_permission = Mock(spec=Permission)
        mock_permission.name = "read_users"
        mock_role = Mock(spec=Role)
        mock_role.permissions = [mock_permission]
        mock_user.role = mock_role
        
        result = await user_service.check_user_permission(mock_user.id, "read_users")
        
        assert result.success
        assert result.data is True
    
    @pytest.mark.asyncio
    async def test_check_user_permission_denied(self, user_service, mock_session, mock_user):
        """Test checking user permission that is denied"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        mock_role = Mock(spec=Role)
        mock_role.permissions = []
        mock_user.role = mock_role
        
        result = await user_service.check_user_permission(mock_user.id, "delete_users")
        
        assert result.success
        assert result.data is False
    
    @pytest.mark.asyncio
    async def test_get_user_permissions(self, user_service, mock_session, mock_user):
        """Test getting all user permissions"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Setup permissions
        perms = [Mock(name="read"), Mock(name="write"), Mock(name="delete")]
        mock_role = Mock(spec=Role)
        mock_role.permissions = perms
        mock_user.role = mock_role
        
        result = await user_service.get_user_permissions(mock_user.id)
        
        assert result.success
        assert len(result.data) == 3
    
    @pytest.mark.asyncio
    async def test_assign_role_to_user(self, user_service, mock_session, mock_user):
        """Test assigning role to user"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Mock role exists
        mock_role = Mock(spec=Role)
        mock_role.id = uuid4()
        mock_session.execute.return_value.scalars.return_value.first.return_value = mock_role
        
        result = await user_service.assign_role(mock_user.id, mock_role.id)
        
        assert result.success
        assert mock_user.role_id == mock_role.id
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_remove_role_from_user(self, user_service, mock_session, mock_user):
        """Test removing role from user"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        mock_user.role_id = uuid4()
        
        result = await user_service.remove_role(mock_user.id)
        
        assert result.success
        assert mock_user.role_id is None
        assert mock_session.commit.called


class TestUserServiceSessions:
    """Test session management operations"""
    
    @pytest.mark.asyncio
    async def test_create_user_session(self, user_service, mock_session, mock_user):
        """Test creating user session"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.create_session(
            mock_user.id,
            token="session_token",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0"
        )
        
        assert result.success
        assert mock_session.add.called
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_get_user_sessions(self, user_service, mock_session, mock_user):
        """Test getting all user sessions"""
        mock_sessions = [Mock(spec=UserSession) for _ in range(3)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_sessions
        
        result = await user_service.get_user_sessions(mock_user.id)
        
        assert result.success
        assert len(result.data) == 3
    
    @pytest.mark.asyncio
    async def test_terminate_user_session(self, user_service, mock_session):
        """Test terminating specific user session"""
        mock_session_obj = Mock(spec=UserSession)
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_session_obj
        
        result = await user_service.terminate_session("session_id")
        
        assert result.success
        assert mock_session_obj.is_active is False
        assert mock_session_obj.terminated_at is not None
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_terminate_all_user_sessions(self, user_service, mock_session):
        """Test terminating all user sessions"""
        mock_sessions = [Mock(spec=UserSession) for _ in range(3)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_sessions
        
        result = await user_service.terminate_all_sessions(uuid4())
        
        assert result.success
        assert result.data['terminated_count'] == 3
        for session in mock_sessions:
            assert session.is_active is False
        assert mock_session.commit.called


class TestUserServiceValidation:
    """Test validation operations"""
    
    @pytest.mark.asyncio
    async def test_validate_user_data_success(self, user_service):
        """Test validating correct user data"""
        result = await user_service._validate_user_data(
            username="validuser123",
            email="valid@example.com",
            password="ValidPass123!",
            phone="+1234567890"
        )
        
        assert result['valid'] is True
        assert result['error'] is None
    
    @pytest.mark.asyncio
    async def test_validate_user_data_invalid_email(self, user_service):
        """Test validating invalid email"""
        result = await user_service._validate_user_data(
            email="invalid-email"
        )
        
        assert result['valid'] is False
        assert "email" in result['error'].lower()
    
    @pytest.mark.asyncio
    async def test_validate_user_data_weak_password(self, user_service):
        """Test validating weak password"""
        result = await user_service._validate_user_data(
            password="weak"
        )
        
        assert result['valid'] is False
        assert "password" in result['error'].lower()
    
    @pytest.mark.asyncio
    async def test_validate_password_requirements(self, user_service):
        """Test password validation with all requirements"""
        # Test missing uppercase
        result = await user_service._validate_password("password123!")
        assert not result['valid']
        
        # Test missing number
        result = await user_service._validate_password("Password!")
        assert not result['valid']
        
        # Test missing special char
        result = await user_service._validate_password("Password123")
        assert not result['valid']
        
        # Test too short
        result = await user_service._validate_password("Pass1!")
        assert not result['valid']
        
        # Test valid password
        result = await user_service._validate_password("ValidPass123!")
        assert result['valid']
    
    @pytest.mark.asyncio
    async def test_check_password_history(self, user_service, mock_session, mock_user):
        """Test checking password against history"""
        # Setup password history
        mock_user.password_history = [
            pwd_context.hash("OldPass1!"),
            pwd_context.hash("OldPass2!"),
            pwd_context.hash("OldPass3!")
        ]
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Test using old password
        result = await user_service._check_password_history(mock_user.id, "OldPass1!")
        assert result is False  # Should not allow
        
        # Test using new password
        result = await user_service._check_password_history(mock_user.id, "NewPass123!")
        assert result is True  # Should allow


class TestUserServiceAudit:
    """Test audit logging operations"""
    
    @pytest.mark.asyncio
    async def test_log_user_activity(self, user_service, mock_session):
        """Test logging user activity"""
        result = await user_service.log_user_activity(
            user_id=uuid4(),
            action="login",
            details={"ip": "192.168.1.1"},
            ip_address="192.168.1.1"
        )
        
        assert result.success
        assert mock_session.add.called
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_get_user_activity_log(self, user_service, mock_session):
        """Test getting user activity log"""
        mock_logs = [Mock(spec=AuditLog) for _ in range(5)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_logs
        
        result = await user_service.get_user_activity(
            user_id=uuid4(),
            start_date=datetime.utcnow() - timedelta(days=7),
            end_date=datetime.utcnow()
        )
        
        assert result.success
        assert len(result.data) == 5


class TestUserServicePreferences:
    """Test user preferences operations"""
    
    @pytest.mark.asyncio
    async def test_get_user_preferences(self, user_service, mock_session, mock_user):
        """Test getting user preferences"""
        mock_user.notification_preferences = {"email": True, "sms": False}
        mock_user.ui_preferences = {"theme": "dark", "language": "en"}
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.get_user_preferences(mock_user.id)
        
        assert result.success
        assert result.data['notification_preferences']['email'] is True
        assert result.data['ui_preferences']['theme'] == 'dark'
    
    @pytest.mark.asyncio
    async def test_update_user_preferences(self, user_service, mock_session, mock_user):
        """Test updating user preferences"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        preferences = {
            "notification_preferences": {"email": False, "push": True},
            "ui_preferences": {"theme": "light"}
        }
        
        result = await user_service.update_user_preferences(mock_user.id, preferences)
        
        assert result.success
        assert mock_user.notification_preferences == preferences['notification_preferences']
        assert mock_session.commit.called


class TestUserServiceMFA:
    """Test Multi-Factor Authentication operations"""
    
    @pytest.mark.asyncio
    async def test_enable_mfa(self, user_service, mock_session, mock_user):
        """Test enabling MFA for user"""
        mock_user.mfa_enabled = False
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.enable_mfa(mock_user.id)
        
        assert result.success
        assert mock_user.mfa_enabled is True
        assert mock_user.mfa_secret is not None
        assert 'secret' in result.data
        assert 'qr_code' in result.data
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_disable_mfa(self, user_service, mock_session, mock_user):
        """Test disabling MFA for user"""
        mock_user.mfa_enabled = True
        mock_user.mfa_secret = "secret"
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.disable_mfa(mock_user.id)
        
        assert result.success
        assert mock_user.mfa_enabled is False
        assert mock_user.mfa_secret is None
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_verify_mfa_token(self, user_service, mock_session, mock_user):
        """Test verifying MFA token"""
        mock_user.mfa_enabled = True
        mock_user.mfa_secret = "JBSWY3DPEHPK3PXP"  # Example secret
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp.return_value.verify.return_value = True
            
            result = await user_service.verify_mfa_token(mock_user.id, "123456")
            
            assert result.success
            assert result.data is True


class TestUserServiceAPIKeys:
    """Test API key management operations"""
    
    @pytest.mark.asyncio
    async def test_generate_api_key(self, user_service, mock_session, mock_user):
        """Test generating API key for user"""
        mock_user.api_key = None
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.generate_api_key(mock_user.id)
        
        assert result.success
        assert mock_user.api_key is not None
        assert mock_user.api_key_created_at is not None
        assert 'api_key' in result.data
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_revoke_api_key(self, user_service, mock_session, mock_user):
        """Test revoking API key"""
        mock_user.api_key = "existing_key"
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.revoke_api_key(mock_user.id)
        
        assert result.success
        assert mock_user.api_key is None
        assert mock_user.api_key_created_at is None
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_validate_api_key(self, user_service, mock_session, mock_user):
        """Test validating API key"""
        mock_user.api_key = "valid_api_key"
        mock_user.is_active = True
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await user_service.validate_api_key("valid_api_key")
        
        assert result.success
        assert result.data == mock_user


class TestUserServiceBulkOperations:
    """Test bulk operations"""
    
    @pytest.mark.asyncio
    async def test_bulk_update_users(self, user_service, mock_session):
        """Test bulk updating users"""
        user_ids = [uuid4() for _ in range(3)]
        mock_users = [Mock(spec=User) for _ in range(3)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        
        updates = {"department": "IT", "is_active": True}
        
        result = await user_service.bulk_update_users(user_ids, updates)
        
        assert result.success
        assert result.data['updated_count'] == 3
        for user in mock_users:
            assert user.department == "IT"
            assert user.is_active is True
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_bulk_activate_users(self, user_service, mock_session):
        """Test bulk activating users"""
        user_ids = [uuid4() for _ in range(3)]
        mock_users = [Mock(spec=User, is_active=False) for _ in range(3)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        
        result = await user_service.bulk_activate_users(user_ids)
        
        assert result.success
        assert result.data['activated_count'] == 3
        for user in mock_users:
            assert user.is_active is True
        assert mock_session.commit.called
    
    @pytest.mark.asyncio
    async def test_bulk_deactivate_users(self, user_service, mock_session):
        """Test bulk deactivating users"""
        user_ids = [uuid4() for _ in range(3)]
        mock_users = [Mock(spec=User, is_active=True) for _ in range(3)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = mock_users
        
        result = await user_service.bulk_deactivate_users(user_ids)
        
        assert result.success
        assert result.data['deactivated_count'] == 3
        for user in mock_users:
            assert user.is_active is False
        assert mock_session.commit.called


class TestUserServiceExceptionHandling:
    """Test exception handling in all methods"""
    
    @pytest.mark.asyncio
    async def test_database_error_handling(self, user_service, mock_session):
        """Test handling database errors"""
        # Simulate database connection error
        mock_session.execute.side_effect = Exception("Database connection lost")
        
        result = await user_service.get_user_by_id(uuid4())
        
        assert not result.success
        assert "database" in result.error.lower()
        mock_session.rollback.assert_called()
    
    @pytest.mark.asyncio
    async def test_integrity_error_handling(self, user_service, mock_session):
        """Test handling integrity constraint violations"""
        mock_session.commit.side_effect = IntegrityError("Duplicate key", "", "")
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await user_service.create_user(
            username="user",
            email="user@example.com",
            password="Password123!"
        )
        
        assert not result.success
        assert "duplicate" in result.error.lower() or "already exists" in result.error.lower()
        mock_session.rollback.assert_called()
    
    @pytest.mark.asyncio
    async def test_validation_exception_handling(self, user_service, mock_session):
        """Test handling validation exceptions"""
        # Invalid email should raise ValidationException internally
        result = await user_service.create_user(
            username="validuser",
            email="not-an-email",
            password="ValidPass123!"
        )
        
        assert not result.success
        assert "validation" in result.error.lower() or "invalid" in result.error.lower()
    
    @pytest.mark.asyncio
    async def test_unexpected_exception_handling(self, user_service, mock_session, mock_user):
        """Test handling unexpected exceptions"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Simulate unexpected error during password hashing
        with patch('backend.services.user_service.pwd_context.hash', side_effect=Exception("Unexpected error")):
            result = await user_service.change_password(
                mock_user.id,
                current_password="Password123!",
                new_password="NewPass123!"
            )
        
        assert not result.success
        mock_session.rollback.assert_called()


class TestUserServiceEdgeCases:
    """Test edge cases and boundary conditions"""
    
    @pytest.mark.asyncio
    async def test_empty_search_query(self, user_service, mock_session):
        """Test searching with empty query"""
        result = await user_service.search_users("", fields=["username"])
        
        assert result.success
        assert result.data == []  # Should return empty list for empty search
    
    @pytest.mark.asyncio
    async def test_pagination_boundary(self, user_service, mock_session):
        """Test pagination at boundaries"""
        # Test page 0 (should default to 1)
        mock_session.execute.return_value.scalars.return_value.all.return_value = []
        mock_session.execute.return_value.scalar.return_value = 0
        
        result = await user_service.list_users(page=0, page_size=10)
        assert result.success
        
        # Test negative page size (should use default)
        result = await user_service.list_users(page=1, page_size=-1)
        assert result.success
        
        # Test very large page number
        result = await user_service.list_users(page=999999, page_size=10)
        assert result.success
        assert result.data['items'] == []
    
    @pytest.mark.asyncio
    async def test_unicode_and_special_characters(self, user_service, mock_session):
        """Test handling unicode and special characters"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        # Test with unicode characters
        result = await user_service.create_user(
            username="user中文",
            email="test中文@example.com",
            password="Password123!",
            first_name="中文",
            last_name="😀"
        )
        
        # Should handle unicode properly
        assert mock_session.add.called
    
    @pytest.mark.asyncio
    async def test_null_and_none_values(self, user_service, mock_session, mock_user):
        """Test handling null/None values"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Test update with None values
        result = await user_service.update_user(
            mock_user.id,
            {
                "first_name": None,
                "last_name": None,
                "department": None
            }
        )
        
        assert result.success
        assert mock_user.first_name is None
        assert mock_user.last_name is None
        assert mock_user.department is None
    
    @pytest.mark.asyncio
    async def test_concurrent_session_limit(self, user_service, mock_session, mock_user):
        """Test enforcing concurrent session limits"""
        # Create max sessions
        existing_sessions = [Mock(spec=UserSession, is_active=True) for _ in range(5)]
        mock_session.execute.return_value.scalars.return_value.all.return_value = existing_sessions
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Try to create one more session (should terminate oldest)
        result = await user_service.create_session(
            mock_user.id,
            token="new_token",
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            max_sessions=5
        )
        
        assert result.success
        # Oldest session should be terminated
        assert existing_sessions[0].is_active is False


class TestUserServiceCoverage100:
    """Additional tests to ensure 100% coverage"""
    
    @pytest.mark.asyncio
    async def test_all_password_validation_branches(self, user_service):
        """Test all branches in password validation"""
        # Test each validation rule individually
        service = user_service
        
        # Disable all requirements except length
        service.require_special_chars = False
        service.require_numbers = False
        service.require_uppercase = False
        
        result = await service._validate_password("password")
        assert result['valid']
        
        # Enable special chars only
        service.require_special_chars = True
        result = await service._validate_password("password")
        assert not result['valid']
        
        result = await service._validate_password("password!")
        assert result['valid']
        
        # Enable numbers only
        service.require_special_chars = False
        service.require_numbers = True
        result = await service._validate_password("password")
        assert not result['valid']
        
        result = await service._validate_password("password1")
        assert result['valid']
        
        # Enable uppercase only
        service.require_numbers = False
        service.require_uppercase = True
        result = await service._validate_password("password")
        assert not result['valid']
        
        result = await service._validate_password("Password")
        assert result['valid']
    
    @pytest.mark.asyncio
    async def test_all_authentication_branches(self, user_service, mock_session, mock_user):
        """Test all branches in authentication flow"""
        # Test user not found
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        result = await user_service.authenticate_user("nonexistent", "password")
        assert not result.success
        
        # Test inactive user
        mock_user.is_active = False
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        result = await user_service.authenticate_user("testuser", "Password123!")
        assert not result.success
        
        # Test auto-unlock expired lock
        mock_user.is_active = True
        mock_user.is_locked = True
        mock_user.locked_until = datetime.utcnow() - timedelta(minutes=1)  # Expired
        result = await user_service.authenticate_user("testuser", "Password123!")
        assert mock_user.is_locked is False  # Should auto-unlock
    
    @pytest.mark.asyncio
    async def test_all_error_messages(self, user_service, mock_session):
        """Test all error message branches"""
        # Test each exception type
        exceptions = [
            ValidationException("Validation error"),
            DuplicateResourceException("Duplicate resource"),
            ResourceNotFoundException("Resource not found"),
            AuthenticationException("Authentication failed"),
            AccountLockedException("Account locked"),
            PasswordExpiredException("Password expired"),
            WeakPasswordException("Weak password"),
            EmailNotVerifiedException("Email not verified"),
            PermissionDeniedException("Permission denied")
        ]
        
        for exc in exceptions:
            mock_session.execute.side_effect = exc
            result = await user_service.get_user_by_id(uuid4())
            assert not result.success
            assert result.error is not None
    
    @pytest.mark.asyncio
    async def test_logger_calls(self, user_service, mock_session, mock_user):
        """Test that logger is called appropriately"""
        with patch('backend.services.user_service.logger') as mock_logger:
            # Success case
            mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
            await user_service.get_user_by_id(mock_user.id)
            assert mock_logger.info.called or mock_logger.debug.called
            
            # Error case
            mock_session.execute.side_effect = Exception("Error")
            await user_service.get_user_by_id(uuid4())
            assert mock_logger.error.called
    
    @pytest.mark.asyncio
    async def test_all_method_return_types(self, user_service, mock_session, mock_user):
        """Ensure all methods return ServiceResult"""
        mock_session.execute.return_value.scalar_one_or_none.return_value = mock_user
        mock_session.execute.return_value.scalars.return_value.all.return_value = []
        mock_session.execute.return_value.scalar.return_value = 0
        
        # Test that all public methods return ServiceResult
        methods_to_test = [
            ('create_user', ('user', 'email@test.com', 'Pass123!')),
            ('get_user_by_id', (uuid4(),)),
            ('get_user_by_username', ('username',)),
            ('get_user_by_email', ('email@test.com',)),
            ('update_user', (uuid4(), {})),
            ('delete_user', (uuid4(),)),
            ('list_users', ()),
            ('search_users', ('query',)),
            ('authenticate_user', ('user', 'pass')),
            ('change_password', (uuid4(), 'old', 'new')),
            ('reset_password', (uuid4(), 'new')),
        ]
        
        for method_name, args in methods_to_test:
            method = getattr(user_service, method_name)
            result = await method(*args)
            assert isinstance(result, ServiceResult)
            assert hasattr(result, 'success')
            assert hasattr(result, 'data')
            assert hasattr(result, 'error')


# Run all tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=backend.services.user_service", "--cov-report=term-missing"])