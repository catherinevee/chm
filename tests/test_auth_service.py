"""
Tests for CHM Authentication Service
Comprehensive testing of authentication functionality
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch
import jwt

from backend.services.auth_service import auth_service, AuthService
from models.user import User, UserRole, UserStatus
from core.database import get_db

class TestAuthService:
    """Test authentication service functionality"""
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "testpassword123"
        hashed = auth_service.hash_password(password)
        
        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$2b$")
    
    def test_verify_password(self):
        """Test password verification"""
        password = "testpassword123"
        hashed = auth_service.hash_password(password)
        
        # Correct password should verify
        assert auth_service.verify_password(password, hashed) is True
        
        # Wrong password should not verify
        assert auth_service.verify_password("wrongpassword", hashed) is False
        
        # Empty password should not verify
        assert auth_service.verify_password("", hashed) is False
    
    def test_create_access_token(self):
        """Test access token creation"""
        data = {"sub": "123", "username": "testuser"}
        token = auth_service.create_access_token(data)
        
        assert token is not None
        assert len(token) > 0
        
        # Verify token can be decoded
        decoded = auth_service.verify_token(token)
        assert decoded is not None
        assert decoded["sub"] == "123"
        assert decoded["username"] == "testuser"
        assert decoded["type"] == "access"
    
    def test_create_refresh_token(self):
        """Test refresh token creation"""
        data = {"sub": "123", "username": "testuser"}
        token = auth_service.create_refresh_token(data)
        
        assert token is not None
        assert len(token) > 0
        
        # Verify token can be decoded
        decoded = auth_service.verify_token(token)
        assert decoded is not None
        assert decoded["sub"] == "123"
        assert decoded["username"] == "testuser"
        assert decoded["type"] == "refresh"
    
    def test_verify_token_valid(self):
        """Test valid token verification"""
        data = {"sub": "123", "username": "testuser"}
        token = auth_service.create_access_token(data)
        
        decoded = auth_service.verify_token(token)
        assert decoded is not None
        assert decoded["sub"] == "123"
    
    def test_verify_token_invalid(self):
        """Test invalid token verification"""
        # Invalid token
        assert auth_service.verify_token("invalid.token.here") is None
        
        # Empty token
        assert auth_service.verify_token("") is None
        
        # None token
        assert auth_service.verify_token(None) is None
    
    def test_verify_token_expired(self):
        """Test expired token verification"""
        # Create token with very short expiry
        data = {"sub": "123", "username": "testuser"}
        token = auth_service.create_access_token(data, expires_delta=timedelta(microseconds=1))
        
        # Wait for token to expire
        import time
        time.sleep(0.001)
        
        # Token should be expired
        decoded = auth_service.verify_token(token)
        assert decoded is None
    
    def test_extract_token_type(self):
        """Test token type extraction"""
        data = {"sub": "123", "username": "testuser"}
        
        # Access token
        access_token = auth_service.create_access_token(data)
        token_type = auth_service.extract_token_type(access_token)
        assert token_type == "access"
        
        # Refresh token
        refresh_token = auth_service.create_refresh_token(data)
        token_type = auth_service.extract_token_type(refresh_token)
        assert token_type == "refresh"
    
    def test_validate_password_strength(self):
        """Test password strength validation"""
        # Strong password
        result = auth_service.validate_password_strength("StrongPass123!")
        assert result["is_valid"] is True
        assert result["strength_score"] >= 8
        
        # Weak password - too short
        result = auth_service.validate_password_strength("weak")
        assert result["is_valid"] is False
        assert "8 characters" in result["errors"][0]
        
        # Weak password - no uppercase
        result = auth_service.validate_password_strength("weakpass123")
        assert result["is_valid"] is False
        assert "uppercase" in result["errors"][0]
        
        # Weak password - no digits
        result = auth_service.validate_password_strength("WeakPass")
        assert result["is_valid"] is False
        assert "digit" in result["errors"][0]
        
        # Common password
        result = auth_service.validate_password_strength("password")
        assert result["is_valid"] is False
        assert "too common" in result["errors"][0]
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, test_session, test_user):
        """Test successful user authentication"""
        user = await auth_service.authenticate_user(
            test_session, 
            "testuser", 
            "testpassword123"
        )
        
        assert user is not None
        assert user.username == "testuser"
        assert user.is_active is True
        assert user.failed_login_attempts == 0
    
    @pytest.mark.asyncio
    async def test_authenticate_user_by_email(self, test_session, test_user):
        """Test user authentication by email"""
        user = await auth_service.authenticate_user(
            test_session, 
            "test@example.com", 
            "testpassword123"
        )
        
        assert user is not None
        assert user.email == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, test_session, test_user):
        """Test authentication with wrong password"""
        user = await auth_service.authenticate_user(
            test_session, 
            "testuser", 
            "wrongpassword"
        )
        
        assert user is None
        
        # Check that failed login attempts were incremented
        await test_session.refresh(test_user)
        assert test_user.failed_login_attempts == 1
    
    @pytest.mark.asyncio
    async def test_authenticate_user_nonexistent(self, test_session):
        """Test authentication with non-existent user"""
        user = await auth_service.authenticate_user(
            test_session, 
            "nonexistent", 
            "password123"
        )
        
        assert user is None
    
    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(self, test_session):
        """Test authentication with inactive user"""
        # Create inactive user
        from models.user import User, UserRole, UserStatus
        inactive_user = User(
            username="inactive",
            email="inactive@example.com",
            hashed_password=auth_service.hash_password("password123"),
            role=UserRole.VIEWER,
            status=UserStatus.INACTIVE
        )
        
        test_session.add(inactive_user)
        await test_session.commit()
        
        user = await auth_service.authenticate_user(
            test_session, 
            "inactive", 
            "password123"
        )
        
        assert user is None
    
    @pytest.mark.asyncio
    async def test_authenticate_user_locked(self, test_session):
        """Test authentication with locked user"""
        # Create user with failed login attempts
        from models.user import User, UserRole, UserStatus
        locked_user = User(
            username="locked",
            email="locked@example.com",
            hashed_password=auth_service.hash_password("password123"),
            role=UserRole.VIEWER,
            status=UserStatus.ACTIVE,
            failed_login_attempts=5,
            account_locked_until=datetime.utcnow() + timedelta(minutes=30)
        )
        
        test_session.add(locked_user)
        await test_session.commit()
        
        user = await auth_service.authenticate_user(
            test_session, 
            "locked", 
            "password123"
        )
        
        assert user is None
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, test_session):
        """Test successful user creation"""
        user = await auth_service.create_user(
            test_session,
            username="newuser",
            email="newuser@example.com",
            password="NewPassword123!",
            full_name="New User",
            role=UserRole.OPERATOR
        )
        
        assert user is not None
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"
        assert user.full_name == "New User"
        assert user.role == UserRole.OPERATOR
        assert user.is_verified is False
        assert user.hashed_password != "NewPassword123!"
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_username(self, test_session, test_user):
        """Test user creation with duplicate username"""
        user = await auth_service.create_user(
            test_session,
            username="testuser",  # Already exists
            email="different@example.com",
            password="Password123!"
        )
        
        assert user is None
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, test_session, test_user):
        """Test user creation with duplicate email"""
        user = await auth_service.create_user(
            test_session,
            username="differentuser",
            email="test@example.com",  # Already exists
            password="Password123!"
        )
        
        assert user is None
    
    @pytest.mark.asyncio
    async def test_change_password_success(self, test_session, test_user):
        """Test successful password change"""
        success = await auth_service.change_password(
            test_session,
            test_user.id,
            "testpassword123",  # Current password
            "NewPassword456!"    # New password
        )
        
        assert success is True
        
        # Verify new password works
        user = await auth_service.authenticate_user(
            test_session,
            "testuser",
            "NewPassword456!"
        )
        
        assert user is not None
    
    @pytest.mark.asyncio
    async def test_change_password_wrong_current(self, test_session, test_user):
        """Test password change with wrong current password"""
        success = await auth_service.change_password(
            test_session,
            test_user.id,
            "wrongpassword",    # Wrong current password
            "NewPassword456!"   # New password
        )
        
        assert success is False
    
    @pytest.mark.asyncio
    async def test_change_password_nonexistent_user(self, test_session):
        """Test password change for non-existent user"""
        success = await auth_service.change_password(
            test_session,
            99999,  # Non-existent user ID
            "oldpassword",
            "newpassword"
        )
        
        assert success is False
    
    @pytest.mark.asyncio
    async def test_get_user_by_id(self, test_session, test_user):
        """Test getting user by ID"""
        user = await auth_service.get_user_by_id(test_session, test_user.id)
        
        assert user is not None
        assert user.username == "testuser"
    
    @pytest.mark.asyncio
    async def test_get_user_by_username(self, test_session, test_user):
        """Test getting user by username"""
        user = await auth_service.get_user_by_username(test_session, "testuser")
        
        assert user is not None
        assert user.id == test_user.id
    
    @pytest.mark.asyncio
    async def test_get_user_by_email(self, test_session, test_user):
        """Test getting user by email"""
        user = await auth_service.get_user_by_email(test_session, "test@example.com")
        
        assert user is not None
        assert user.id == test_user.id
    
    def test_create_tokens(self, test_user):
        """Test token creation for user"""
        tokens = auth_service.create_tokens(test_user)
        
        assert "access_token" in tokens
        assert "refresh_token" in tokens
        assert "token_type" in tokens
        assert "expires_in" in tokens
        
        assert tokens["token_type"] == "bearer"
        assert tokens["expires_in"] == auth_service.access_token_expire_minutes * 60
        
        # Verify tokens contain correct user data
        access_payload = auth_service.verify_token(tokens["access_token"])
        assert access_payload["sub"] == str(test_user.id)
        assert access_payload["username"] == test_user.username
        assert access_payload["email"] == test_user.email
        assert access_payload["role"] == test_user.role.value
    
    @pytest.mark.asyncio
    async def test_refresh_access_token_success(self, test_session, test_user):
        """Test successful access token refresh"""
        # Create refresh token
        refresh_token = auth_service.create_refresh_token({
            "sub": str(test_user.id),
            "username": test_user.username,
            "email": test_user.email,
            "role": test_user.role.value,
            "is_active": test_user.is_active
        })
        
        # Refresh access token
        new_tokens = await auth_service.refresh_access_token(test_session, refresh_token)
        
        assert new_tokens is not None
        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
    
    @pytest.mark.asyncio
    async def test_refresh_access_token_invalid(self, test_session):
        """Test access token refresh with invalid token"""
        new_tokens = await auth_service.refresh_access_token(test_session, "invalid.token")
        
        assert new_tokens is None
    
    @pytest.mark.asyncio
    async def test_refresh_access_token_wrong_type(self, test_session, test_user):
        """Test access token refresh with access token instead of refresh token"""
        # Create access token (wrong type)
        access_token = auth_service.create_access_token({
            "sub": str(test_user.id),
            "username": test_user.username
        })
        
        new_tokens = await auth_service.refresh_access_token(test_session, access_token)
        
        assert new_tokens is None

class TestAuthServiceIntegration:
    """Integration tests for authentication service"""
    
    @pytest.mark.asyncio
    async def test_full_authentication_flow(self, test_session):
        """Test complete authentication flow"""
        # 1. Create user
        user = await auth_service.create_user(
            test_session,
            username="flowuser",
            email="flow@example.com",
            password="FlowPassword123!",
            role=UserRole.OPERATOR
        )
        
        assert user is not None
        
        # 2. Authenticate user
        authenticated_user = await auth_service.authenticate_user(
            test_session,
            "flowuser",
            "FlowPassword123!"
        )
        
        assert authenticated_user is not None
        assert authenticated_user.id == user.id
        
        # 3. Create tokens
        tokens = auth_service.create_tokens(authenticated_user)
        assert tokens["access_token"] is not None
        assert tokens["refresh_token"] is not None
        
        # 4. Verify access token
        payload = auth_service.verify_token(tokens["access_token"])
        assert payload["sub"] == str(user.id)
        assert payload["username"] == "flowuser"
        
        # 5. Refresh tokens
        new_tokens = await auth_service.refresh_access_token(
            test_session, 
            tokens["refresh_token"]
        )
        
        assert new_tokens is not None
        assert new_tokens["access_token"] != tokens["access_token"]
        
        # 6. Change password
        success = await auth_service.change_password(
            test_session,
            user.id,
            "FlowPassword123!",
            "NewFlowPassword456!"
        )
        
        assert success is True
        
        # 7. Verify new password works
        new_authenticated_user = await auth_service.authenticate_user(
            test_session,
            "flowuser",
            "NewFlowPassword456!"
        )
        
        assert new_authenticated_user is not None
        assert new_authenticated_user.id == user.id
