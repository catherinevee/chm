"""
Comprehensive User Service Tests
Tests all actual methods in backend/services/user_service.py
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
import secrets

# Mock the models and dependencies that UserService expects
from dataclasses import dataclass
from typing import Optional, List, Dict, Any


@dataclass
class MockServiceResult:
    """Mock ServiceResult for testing"""
    service_name: str
    success: bool = False
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass 
class MockUser:
    """Mock User model for testing"""
    id: UUID
    username: str
    email: str
    password_hash: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    role_id: Optional[UUID] = None
    department: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool = True
    is_verified: bool = False
    verification_token: Optional[str] = None
    created_at: datetime = None
    updated_at: datetime = None
    password_changed_at: datetime = None
    created_by: Optional[UUID] = None
    updated_by: Optional[UUID] = None
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[UUID] = None
    verified_at: Optional[datetime] = None
    password_expired: bool = False
    force_password_change: bool = False


class TestUserServiceComprehensive:
    """Comprehensive test coverage for UserService"""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock database session"""
        return AsyncMock()
    
    @pytest.fixture
    def user_service(self, mock_session):
        """Create UserService instance for testing"""
        # Mock the dependencies
        with patch('backend.services.user_service.User', MockUser), \
             patch('backend.services.user_service.ServiceResult', MockServiceResult), \
             patch('backend.services.user_service.pwd_context') as mock_pwd:
            
            mock_pwd.hash.return_value = "$2b$12$mocked_hash"
            mock_pwd.verify.return_value = True
            
            from backend.services.user_service import UserService
            return UserService(mock_session)
    
    @pytest.fixture
    def sample_user(self):
        """Create sample user for testing"""
        return MockUser(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$mocked_hash",
            first_name="Test",
            last_name="User",
            is_active=True,
            is_verified=True,
            created_at=datetime.utcnow()
        )
    
    # Test create_user method
    @pytest.mark.asyncio
    async def test_create_user_success(self, user_service, mock_session):
        """Test successful user creation"""
        username = "newuser"
        email = "newuser@example.com"
        password = "TestPassword123!"
        
        # Mock dependencies
        with patch.object(user_service, '_validate_user_data', return_value={'valid': True}), \
             patch.object(user_service, '_check_existing_user', return_value=None), \
             patch.object(user_service, '_validate_password_strength', return_value={'valid': True}), \
             patch.object(user_service, '_log_audit_event', return_value=None), \
             patch('backend.services.user_service.secrets.token_urlsafe', return_value='mock_token'):
            
            # Mock session operations
            mock_session.add = MagicMock()
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            
            result = await user_service.create_user(
                username=username,
                email=email,
                password=password,
                first_name="Test",
                last_name="User"
            )
            
            assert result.success is True
            assert result.service_name == "UserService"
            assert "user" in result.data
            assert "verification_token" in result.data
    
    @pytest.mark.asyncio
    async def test_create_user_validation_error(self, user_service, mock_session):
        """Test user creation with validation error"""
        with patch.object(user_service, '_validate_user_data', 
                         return_value={'valid': False, 'error': 'Invalid email'}):
            
            result = await user_service.create_user(
                username="test",
                email="invalid-email",
                password="password"
            )
            
            assert result.success is False
            assert result.error_code == "VALIDATION_ERROR"
            assert "Invalid email" in result.error
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_error(self, user_service, mock_session, sample_user):
        """Test user creation with duplicate user"""
        with patch.object(user_service, '_validate_user_data', return_value={'valid': True}), \
             patch.object(user_service, '_check_existing_user', return_value=sample_user):
            
            result = await user_service.create_user(
                username="testuser",
                email="test@example.com",
                password="TestPassword123!"
            )
            
            assert result.success is False
            assert result.error_code == "DUPLICATE_USER"
    
    @pytest.mark.asyncio
    async def test_create_user_weak_password(self, user_service, mock_session):
        """Test user creation with weak password"""
        with patch.object(user_service, '_validate_user_data', return_value={'valid': True}), \
             patch.object(user_service, '_check_existing_user', return_value=None), \
             patch.object(user_service, '_validate_password_strength', 
                         return_value={'valid': False, 'error': 'Password too weak'}):
            
            result = await user_service.create_user(
                username="testuser",
                email="test@example.com",
                password="weak"
            )
            
            assert result.success is False
            # Should handle WeakPasswordException
    
    # Test get_user_by_id method
    @pytest.mark.asyncio
    async def test_get_user_by_id_success(self, user_service, mock_session, sample_user):
        """Test successful user retrieval by ID"""
        user_id = sample_user.id
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_session.execute.return_value = mock_result
        
        result = await user_service.get_user_by_id(user_id)
        
        assert result.success is True
        assert result.data["user"] == sample_user
    
    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, user_service, mock_session):
        """Test user retrieval when user not found"""
        user_id = uuid4()
        
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await user_service.get_user_by_id(user_id)
        
        assert result.success is False
        assert result.error_code == "USER_NOT_FOUND"
    
    # Test get_user_by_username method
    @pytest.mark.asyncio
    async def test_get_user_by_username_success(self, user_service, mock_session, sample_user):
        """Test successful user retrieval by username"""
        username = sample_user.username
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_session.execute.return_value = mock_result
        
        result = await user_service.get_user_by_username(username)
        
        assert result.success is True
        assert result.data["user"] == sample_user
    
    @pytest.mark.asyncio
    async def test_get_user_by_username_not_found(self, user_service, mock_session):
        """Test user retrieval by username when not found"""
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await user_service.get_user_by_username("nonexistent")
        
        assert result.success is False
        assert result.error_code == "FETCH_FAILED"
    
    # Test get_user_by_email method
    @pytest.mark.asyncio
    async def test_get_user_by_email_success(self, user_service, mock_session, sample_user):
        """Test successful user retrieval by email"""
        email = sample_user.email
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_session.execute.return_value = mock_result
        
        result = await user_service.get_user_by_email(email)
        
        assert result.success is True
        assert result.data["user"] == sample_user
    
    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, user_service, mock_session):
        """Test user retrieval by email when not found"""
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await user_service.get_user_by_email("nonexistent@example.com")
        
        assert result.success is False
        assert result.error_code == "FETCH_FAILED"
    
    # Test get_all_users method
    @pytest.mark.asyncio
    async def test_get_all_users_success(self, user_service, mock_session, sample_user):
        """Test successful retrieval of all users"""
        users = [sample_user]
        
        # Mock database queries
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = users
        mock_session.execute.return_value = mock_result
        
        # Mock count query
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 1
        
        # Set up mock to return different results for different queries
        mock_session.execute.side_effect = [mock_count_result, mock_result]
        
        result = await user_service.get_all_users(skip=0, limit=10)
        
        assert result.success is True
        assert result.data["users"] == users
        assert "pagination" in result.data
        assert result.data["pagination"]["total"] == 1
    
    @pytest.mark.asyncio
    async def test_get_all_users_with_filters(self, user_service, mock_session, sample_user):
        """Test retrieval of users with filters"""
        users = [sample_user]
        
        # Mock database queries
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = users
        mock_session.execute.return_value = mock_result
        
        # Mock count query
        mock_count_result = MagicMock()
        mock_count_result.scalar.return_value = 1
        
        mock_session.execute.side_effect = [mock_count_result, mock_result]
        
        filters = {
            "is_active": True,
            "department": "IT",
            "search": "test"
        }
        
        result = await user_service.get_all_users(
            skip=0, 
            limit=10, 
            filters=filters,
            sort_by="username",
            sort_order="asc"
        )
        
        assert result.success is True
        assert result.data["users"] == users
    
    # Test search_users method
    @pytest.mark.asyncio
    async def test_search_users_success(self, user_service, mock_session, sample_user):
        """Test successful user search"""
        users = [sample_user]
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = users
        mock_session.execute.return_value = mock_result
        
        result = await user_service.search_users("test", limit=5)
        
        assert result.success is True
        assert result.data["users"] == users
        assert result.data["count"] == 1
    
    @pytest.mark.asyncio
    async def test_search_users_no_results(self, user_service, mock_session):
        """Test user search with no results"""
        # Mock database query to return empty list
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_session.execute.return_value = mock_result
        
        result = await user_service.search_users("nonexistent")
        
        assert result.success is True
        assert result.data["users"] == []
        assert result.data["count"] == 0
    
    # Test update_user method
    @pytest.mark.asyncio
    async def test_update_user_success(self, user_service, mock_session, sample_user):
        """Test successful user update"""
        user_id = sample_user.id
        update_data = {
            "first_name": "Updated",
            "department": "Engineering"
        }
        
        # Mock get_user_by_id to return sample user
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch.object(user_service, '_log_audit_event', return_value=None):
            
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            
            result = await user_service.update_user(user_id, update_data)
            
            assert result.success is True
            assert result.data["user"] == sample_user
    
    @pytest.mark.asyncio
    async def test_update_user_not_found(self, user_service, mock_session):
        """Test update user when user not found"""
        user_id = uuid4()
        update_data = {"first_name": "Updated"}
        
        # Mock get_user_by_id to return failure
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", False, None, "User not found", "USER_NOT_FOUND")):
            
            result = await user_service.update_user(user_id, update_data)
            
            assert result.success is False
            assert result.error_code == "USER_NOT_FOUND"
    
    @pytest.mark.asyncio
    async def test_update_user_duplicate_email(self, user_service, mock_session, sample_user):
        """Test update user with duplicate email"""
        user_id = sample_user.id
        update_data = {"email": "duplicate@example.com"}
        
        # Create another user with the duplicate email
        other_user = MockUser(
            id=uuid4(),
            username="otheruser", 
            email="duplicate@example.com",
            password_hash="hash"
        )
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch.object(user_service, '_validate_email', return_value={'valid': True}), \
             patch.object(user_service, '_check_existing_user', return_value=other_user):
            
            result = await user_service.update_user(user_id, update_data)
            
            assert result.success is False
            assert result.error_code == "UPDATE_VALIDATION_ERROR"
    
    # Test update_password method
    @pytest.mark.asyncio
    async def test_update_password_success(self, user_service, mock_session, sample_user):
        """Test successful password update"""
        user_id = sample_user.id
        old_password = "OldPassword123!"
        new_password = "NewPassword456!"
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch.object(user_service, '_validate_password_strength', return_value={'valid': True}), \
             patch.object(user_service, '_is_password_in_history', return_value=False), \
             patch.object(user_service, '_add_password_to_history', return_value=None), \
             patch.object(user_service, '_log_audit_event', return_value=None), \
             patch('backend.services.user_service.pwd_context') as mock_pwd:
            
            mock_pwd.verify.return_value = True
            mock_pwd.hash.return_value = "$2b$12$new_hash"
            mock_session.commit = AsyncMock()
            
            result = await user_service.update_password(user_id, old_password, new_password)
            
            assert result.success is True
            assert "Password updated successfully" in result.data["message"]
    
    @pytest.mark.asyncio
    async def test_update_password_wrong_old_password(self, user_service, mock_session, sample_user):
        """Test password update with wrong old password"""
        user_id = sample_user.id
        old_password = "WrongPassword"
        new_password = "NewPassword456!"
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch('backend.services.user_service.pwd_context') as mock_pwd:
            
            mock_pwd.verify.return_value = False
            
            result = await user_service.update_password(user_id, old_password, new_password)
            
            assert result.success is False
            assert result.error_code == "PASSWORD_UPDATE_FAILED"
    
    @pytest.mark.asyncio
    async def test_update_password_weak_new_password(self, user_service, mock_session, sample_user):
        """Test password update with weak new password"""
        user_id = sample_user.id
        old_password = "OldPassword123!"
        new_password = "weak"
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch.object(user_service, '_validate_password_strength', 
                         return_value={'valid': False, 'error': 'Password too weak'}), \
             patch('backend.services.user_service.pwd_context') as mock_pwd:
            
            mock_pwd.verify.return_value = True
            
            result = await user_service.update_password(user_id, old_password, new_password)
            
            assert result.success is False
            assert result.error_code == "PASSWORD_UPDATE_FAILED"
    
    # Test verify_email method
    @pytest.mark.asyncio
    async def test_verify_email_success(self, user_service, mock_session, sample_user):
        """Test successful email verification"""
        token = "verification_token_123"
        sample_user.verification_token = token
        sample_user.is_verified = False
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_session.execute.return_value = mock_result
        mock_session.commit = AsyncMock()
        
        with patch.object(user_service, '_log_audit_event', return_value=None):
            result = await user_service.verify_email(token)
            
            assert result.success is True
            assert sample_user.is_verified is True
            assert sample_user.verification_token is None
    
    @pytest.mark.asyncio
    async def test_verify_email_invalid_token(self, user_service, mock_session):
        """Test email verification with invalid token"""
        token = "invalid_token"
        
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await user_service.verify_email(token)
        
        assert result.success is False
        assert result.error_code == "INVALID_TOKEN"
    
    # Test delete_user method
    @pytest.mark.asyncio
    async def test_delete_user_soft_delete(self, user_service, mock_session, sample_user):
        """Test soft delete user"""
        user_id = sample_user.id
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch.object(user_service, '_log_audit_event', return_value=None):
            
            mock_session.commit = AsyncMock()
            
            result = await user_service.delete_user(user_id, soft_delete=True)
            
            assert result.success is True
            assert sample_user.is_deleted is True
            assert sample_user.is_active is False
    
    @pytest.mark.asyncio
    async def test_delete_user_hard_delete(self, user_service, mock_session, sample_user):
        """Test hard delete user"""
        user_id = sample_user.id
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})), \
             patch.object(user_service, '_log_audit_event', return_value=None):
            
            mock_session.delete = AsyncMock()
            mock_session.commit = AsyncMock()
            
            result = await user_service.delete_user(user_id, soft_delete=False)
            
            assert result.success is True
            mock_session.delete.assert_called_once_with(sample_user)
    
    # Test restore_user method
    @pytest.mark.asyncio
    async def test_restore_user_success(self, user_service, mock_session, sample_user):
        """Test successful user restoration"""
        user_id = sample_user.id
        sample_user.is_deleted = True
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_session.execute.return_value = mock_result
        mock_session.commit = AsyncMock()
        
        with patch.object(user_service, '_log_audit_event', return_value=None):
            result = await user_service.restore_user(user_id)
            
            assert result.success is True
            assert sample_user.is_deleted is False
            assert sample_user.is_active is True
    
    @pytest.mark.asyncio
    async def test_restore_user_not_found(self, user_service, mock_session):
        """Test restore user when user not found"""
        user_id = uuid4()
        
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await user_service.restore_user(user_id)
        
        assert result.success is False
        assert result.error_code == "USER_NOT_FOUND"
    
    # Test create_bulk_users method
    @pytest.mark.asyncio
    async def test_create_bulk_users_success(self, user_service, mock_session):
        """Test successful bulk user creation"""
        users_data = [
            {
                "username": "user1",
                "email": "user1@example.com",
                "password": "Password123!"
            },
            {
                "username": "user2", 
                "email": "user2@example.com",
                "password": "Password456!"
            }
        ]
        
        # Mock create_user to succeed for all users
        mock_user1 = MockUser(id=uuid4(), username="user1", email="user1@example.com", password_hash="hash1")
        mock_user2 = MockUser(id=uuid4(), username="user2", email="user2@example.com", password_hash="hash2")
        
        create_user_results = [
            MockServiceResult("UserService", True, {"user": mock_user1}),
            MockServiceResult("UserService", True, {"user": mock_user2})
        ]
        
        with patch.object(user_service, 'create_user', side_effect=create_user_results):
            result = await user_service.create_bulk_users(users_data)
            
            assert result.success is True
            assert len(result.data["users"]) == 2
    
    @pytest.mark.asyncio
    async def test_create_bulk_users_partial_failure(self, user_service, mock_session):
        """Test bulk user creation with partial failures"""
        users_data = [
            {
                "username": "user1",
                "email": "user1@example.com", 
                "password": "Password123!"
            },
            {
                "username": "user2",
                "email": "invalid-email",
                "password": "Password456!"
            }
        ]
        
        # Mock create_user: first succeeds, second fails
        mock_user1 = MockUser(id=uuid4(), username="user1", email="user1@example.com", password_hash="hash1")
        
        create_user_results = [
            MockServiceResult("UserService", True, {"user": mock_user1}),
            MockServiceResult("UserService", False, None, "Invalid email", "VALIDATION_ERROR")
        ]
        
        with patch.object(user_service, 'create_user', side_effect=create_user_results):
            result = await user_service.create_bulk_users(users_data)
            
            assert result.success is False
            assert len(result.data["created"]) == 1
            assert len(result.data["errors"]) == 1
    
    # Test validation helper methods
    def test_validate_email_valid(self, user_service):
        """Test email validation with valid email"""
        result = user_service._validate_email("test@example.com")
        assert result["valid"] is True
    
    def test_validate_email_invalid(self, user_service):
        """Test email validation with invalid email"""
        invalid_emails = [
            "",
            "invalid-email",
            "test@",
            "@example.com",
            "test.example.com"
        ]
        
        for email in invalid_emails:
            result = user_service._validate_email(email)
            assert result["valid"] is False
    
    def test_validate_phone_valid(self, user_service):
        """Test phone validation with valid numbers"""
        valid_phones = [
            "+1234567890",
            "1234567890",
            "+44 20 7946 0958",
            "(555) 123-4567"
        ]
        
        for phone in valid_phones:
            result = user_service._validate_phone(phone)
            assert result["valid"] is True
    
    def test_validate_phone_invalid(self, user_service):
        """Test phone validation with invalid numbers"""
        invalid_phones = [
            "123",
            "abc",
            "123-456-789a",
            "++1234567890"
        ]
        
        for phone in invalid_phones:
            result = user_service._validate_phone(phone)
            assert result["valid"] is False
    
    def test_validate_password_strength_strong(self, user_service):
        """Test password strength validation with strong passwords"""
        strong_passwords = [
            "StrongPassword123!",
            "Complex@Pass2024",
            "Secure#Password456"
        ]
        
        for password in strong_passwords:
            result = user_service._validate_password_strength(password)
            assert result["valid"] is True
    
    def test_validate_password_strength_weak(self, user_service):
        """Test password strength validation with weak passwords"""
        weak_passwords = [
            "weak",
            "password",
            "123456",
            "NoNumbers!",
            "nouppercase123!",
            "NOLOWERCASE123!"
        ]
        
        for password in weak_passwords:
            result = user_service._validate_password_strength(password)
            assert result["valid"] is False
    
    def test_get_password_requirements(self, user_service):
        """Test getting password requirements"""
        requirements = user_service._get_password_requirements()
        
        assert "min_length" in requirements
        assert "require_uppercase" in requirements
        assert "require_numbers" in requirements
        assert "require_special_chars" in requirements
        assert "password_history_count" in requirements
    
    @pytest.mark.asyncio
    async def test_check_existing_user_found(self, user_service, mock_session, sample_user):
        """Test check existing user when user found"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_session.execute.return_value = mock_result
        
        result = await user_service._check_existing_user(
            username="testuser",
            email="test@example.com"
        )
        
        assert result == sample_user
    
    @pytest.mark.asyncio
    async def test_check_existing_user_not_found(self, user_service, mock_session):
        """Test check existing user when user not found"""
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await user_service._check_existing_user(
            username="nonexistent",
            email="nonexistent@example.com"
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_is_password_in_history(self, user_service):
        """Test password history check"""
        user_id = uuid4()
        password = "TestPassword123!"
        
        # Default implementation returns False
        result = await user_service._is_password_in_history(user_id, password)
        assert result is False
    
    @pytest.mark.asyncio
    async def test_add_password_to_history(self, user_service):
        """Test adding password to history"""
        user_id = uuid4()
        password_hash = "$2b$12$hash"
        
        # Should not raise exception (placeholder implementation)
        await user_service._add_password_to_history(user_id, password_hash)
    
    @pytest.mark.asyncio
    async def test_log_audit_event(self, user_service, mock_session):
        """Test audit event logging"""
        user_id = uuid4()
        action = "TEST_ACTION"
        details = {"test": "data"}
        
        # Mock audit log creation
        with patch('backend.services.user_service.AuditLog') as mock_audit:
            mock_session.add = MagicMock()
            mock_session.commit = AsyncMock()
            
            await user_service._log_audit_event(user_id, action, details)
            
            # Should attempt to create audit log
            mock_audit.assert_called_once()
    
    # Error handling tests
    @pytest.mark.asyncio
    async def test_create_user_database_error(self, user_service, mock_session):
        """Test user creation with database error"""
        with patch.object(user_service, '_validate_user_data', return_value={'valid': True}), \
             patch.object(user_service, '_check_existing_user', return_value=None), \
             patch.object(user_service, '_validate_password_strength', return_value={'valid': True}):
            
            # Mock session to raise exception
            mock_session.add.side_effect = Exception("Database error")
            mock_session.rollback = AsyncMock()
            
            result = await user_service.create_user(
                username="testuser",
                email="test@example.com",
                password="TestPassword123!"
            )
            
            assert result.success is False
            assert result.error_code == "CREATE_FAILED"
            mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_user_database_error(self, user_service, mock_session, sample_user):
        """Test user update with database error"""
        user_id = sample_user.id
        update_data = {"first_name": "Updated"}
        
        with patch.object(user_service, 'get_user_by_id', 
                         return_value=MockServiceResult("UserService", True, {"user": sample_user})):
            
            # Mock session to raise exception
            mock_session.commit.side_effect = Exception("Database error")
            mock_session.rollback = AsyncMock()
            
            result = await user_service.update_user(user_id, update_data)
            
            assert result.success is False
            assert result.error_code == "UPDATE_FAILED"
            mock_session.rollback.assert_called_once()
    
    # Integration-style test
    @pytest.mark.asyncio
    async def test_user_lifecycle_complete(self, user_service, mock_session):
        """Test complete user lifecycle: create -> get -> update -> delete -> restore"""
        # Setup mocks for complete lifecycle
        user_id = uuid4()
        created_user = MockUser(
            id=user_id,
            username="lifecycleuser",
            email="lifecycle@example.com",
            password_hash="$2b$12$hash",
            is_active=True,
            is_verified=False
        )
        
        # Mock all dependencies
        with patch.object(user_service, '_validate_user_data', return_value={'valid': True}), \
             patch.object(user_service, '_check_existing_user', return_value=None), \
             patch.object(user_service, '_validate_password_strength', return_value={'valid': True}), \
             patch.object(user_service, '_log_audit_event', return_value=None), \
             patch('backend.services.user_service.secrets.token_urlsafe', return_value='mock_token'):
            
            # Setup session mocks
            mock_session.add = MagicMock()
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            mock_session.delete = AsyncMock()
            
            # Mock database queries for different operations
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = created_user
            mock_session.execute.return_value = mock_result
            
            # 1. Create user
            create_result = await user_service.create_user(
                username="lifecycleuser",
                email="lifecycle@example.com",
                password="TestPassword123!"
            )
            assert create_result.success is True
            
            # 2. Get user
            get_result = await user_service.get_user_by_id(user_id)
            assert get_result.success is True
            
            # 3. Update user
            update_data = {"first_name": "Updated"}
            update_result = await user_service.update_user(user_id, update_data)
            assert update_result.success is True
            
            # 4. Delete user (soft)
            delete_result = await user_service.delete_user(user_id, soft_delete=True)
            assert delete_result.success is True
            
            # 5. Restore user
            restore_result = await user_service.restore_user(user_id)
            assert restore_result.success is True