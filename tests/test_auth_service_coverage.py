"""
Test auth_service.py to achieve high coverage on this critical security file
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.update({
    'TESTING': 'true',
    'DATABASE_URL': 'sqlite+aiosqlite:///:memory:',
    'JWT_SECRET_KEY': 'test-jwt-secret',
    'SECRET_KEY': 'test-secret-key',
    'DEBUG': 'true'
})

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession


class TestAuthService:
    """Test AuthService comprehensively"""
    
    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance"""
        from backend.services.auth_service import AuthService
        return AuthService()
    
    @pytest.fixture
    def mock_db(self):
        """Create mock database session"""
        mock = Mock(spec=AsyncSession)
        mock.execute = AsyncMock()
        mock.commit = AsyncMock()
        mock.refresh = AsyncMock()
        mock.rollback = AsyncMock()
        mock.close = AsyncMock()
        return mock
    
    @pytest.fixture
    def mock_user(self):
        """Create mock user"""
        from backend.models.user import User
        user = Mock(spec=User)
        user.id = 1
        user.username = "testuser"
        user.email = "test@example.com"
        user.hashed_password = "$2b$12$test_hash"
        user.is_active = True
        user.is_admin = False
        user.failed_login_attempts = 0
        user.account_locked_until = None
        user.last_login = None
        user.created_at = datetime.now()
        return user
    
    @pytest.mark.asyncio
    async def test_register_user_success(self, auth_service, mock_db):
        """Test successful user registration"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await auth_service.register_user(
            mock_db,
            username="newuser",
            email="new@example.com",
            password="SecurePass123!"
        )
        
        assert result is not None
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_register_user_duplicate(self, auth_service, mock_db, mock_user):
        """Test registration with duplicate username"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await auth_service.register_user(
            mock_db,
            username="testuser",
            email="test@example.com",
            password="SecurePass123!"
        )
        
        assert result is None
        mock_db.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service, mock_db, mock_user):
        """Test successful authentication"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        with patch('backend.services.auth_service.verify_password', return_value=True):
            result = await auth_service.authenticate_user(
                mock_db,
                username="testuser",
                password="correct_password"
            )
        
        assert result == mock_user
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, auth_service, mock_db, mock_user):
        """Test authentication with wrong password"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        with patch('backend.services.auth_service.verify_password', return_value=False):
            result = await auth_service.authenticate_user(
                mock_db,
                username="testuser",
                password="wrong_password"
            )
        
        assert result is None
        assert mock_user.failed_login_attempts == 1
    
    @pytest.mark.asyncio
    async def test_authenticate_user_locked(self, auth_service, mock_db, mock_user):
        """Test authentication with locked account"""
        mock_user.account_locked_until = datetime.now() + timedelta(minutes=5)
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        result = await auth_service.authenticate_user(
            mock_db,
            username="testuser",
            password="any_password"
        )
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service, mock_db):
        """Test authentication with non-existent user"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = None
        
        result = await auth_service.authenticate_user(
            mock_db,
            username="nonexistent",
            password="any_password"
        )
        
        assert result is None
    
    def test_create_access_token(self, auth_service):
        """Test JWT token creation"""
        data = {"sub": "testuser", "user_id": 1}
        
        token = auth_service._generate_access_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_create_refresh_token(self, auth_service):
        """Test refresh token creation"""
        data = {"sub": "testuser", "user_id": 1}
        
        token = auth_service._generate_refresh_token(data)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    
    @pytest.mark.asyncio
    async def test_verify_token_valid(self, auth_service):
        """Test valid token verification"""
        # Create a valid token
        data = {"sub": "testuser", "user_id": 1}
        token = auth_service._generate_access_token(data)
        
        # Verify it
        payload = await auth_service.verify_token(token)
        
        assert payload is not None
        assert payload.get("sub") == "testuser"
    
    @pytest.mark.asyncio
    async def test_verify_token_invalid(self, auth_service):
        """Test invalid token verification"""
        result = await auth_service.verify_token("invalid_token")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_verify_token_expired(self, auth_service):
        """Test expired token verification"""
        # Create an expired token
        data = {"sub": "testuser", "user_id": 1}
        expires_delta = timedelta(seconds=-1)  # Already expired
        
        with patch('backend.services.auth_service.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = datetime.utcnow() - timedelta(hours=1)
            token = auth_service._generate_access_token(data, expires_delta)
        
        result = await auth_service.verify_token(token)
        assert result is None
    
    @pytest.mark.asyncio
    async def test_get_current_user_valid(self, auth_service, mock_db, mock_user):
        """Test getting current user with valid token"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Create valid token
        token = auth_service._generate_access_token({"sub": "testuser"})
        
        result = await auth_service.get_current_user(token, mock_db)
        
        assert result == mock_user
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, auth_service, mock_db):
        """Test getting current user with invalid token"""
        result = await auth_service.get_current_user("invalid_token", mock_db)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_refresh_access_token_valid(self, auth_service, mock_db, mock_user):
        """Test refreshing access token"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        # Create valid refresh token
        refresh_token = auth_service._generate_refresh_token({"sub": "testuser"})
        
        result = await auth_service.refresh_access_token(refresh_token, mock_db)
        
        assert result is not None
        assert "access_token" in result
        assert "token_type" in result
    
    @pytest.mark.asyncio
    async def test_refresh_access_token_invalid(self, auth_service, mock_db):
        """Test refreshing with invalid token"""
        result = await auth_service.refresh_access_token("invalid_token", mock_db)
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_service, mock_db, mock_user):
        """Test successful password change"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        with patch('backend.services.auth_service.verify_password', return_value=True):
            with patch('backend.services.auth_service.get_password_hash', return_value="new_hash"):
                result = await auth_service.change_password(
                    mock_db,
                    user_id=1,
                    old_password="old_password",
                    new_password="NewSecurePass123!"
                )
        
        assert result is True
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_change_password_wrong_old(self, auth_service, mock_db, mock_user):
        """Test password change with wrong old password"""
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        with patch('backend.services.auth_service.verify_password', return_value=False):
            result = await auth_service.change_password(
                mock_db,
                user_id=1,
                old_password="wrong_password",
                new_password="NewSecurePass123!"
            )
        
        assert result is False
    
    def test_password_hashing(self, auth_service):
        """Test password hashing and verification"""
        from backend.services.auth_service import get_password_hash, verify_password
        
        password = "TestPassword123!"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert verify_password(password, hashed) is True
        assert verify_password("wrong_password", hashed) is False
    
    @pytest.mark.asyncio
    async def test_account_locking(self, auth_service, mock_db, mock_user):
        """Test account locking after failed attempts"""
        mock_user.failed_login_attempts = 4  # One more attempt will lock
        mock_db.execute.return_value.scalar_one_or_none.return_value = mock_user
        
        with patch('backend.services.auth_service.verify_password', return_value=False):
            result = await auth_service.authenticate_user(
                mock_db,
                username="testuser",
                password="wrong_password"
            )
        
        assert result is None
        assert mock_user.failed_login_attempts == 5
        assert mock_user.account_locked_until is not None


if __name__ == "__main__":
    pytest.main([__file__, "-xvs"])