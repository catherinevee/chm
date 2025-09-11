"""
Comprehensive Authentication Service Tests
Tests all actual methods in backend/services/auth_service.py
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import secrets
import logging

from backend.services.auth_service import AuthService, TokenData, LoginResponse
from backend.models.user import User, UserRole, UserStatus
from backend.common.exceptions import (
    AuthenticationException,
    ValidationException,
    InvalidTokenException,
    SessionExpiredException,
    AccountLockedException,
    MFARequiredException,
    PermissionDeniedException,
    UserNotFoundException,
    DuplicateUserException
)
from core.database import get_db, async_session


class TestAuthServiceComprehensive:
    """Comprehensive test coverage for AuthService - matching actual implementation"""
    
    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance for testing"""
        return AuthService()
    
    @pytest.fixture
    def mock_db(self):
        """Create mock database session"""
        return AsyncMock()
    
    @pytest.fixture
    def sample_user(self):
        """Create sample user for testing"""
        return User(
            id=1,
            username="testuser",
            email="test@test.com",
            hashed_password="$2b$12$mockhashedpassword",
            role=UserRole.VIEWER,
            status=UserStatus.ACTIVE,
            is_verified=True,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    # Core password methods tests
    def test_hash_password(self, auth_service):
        """Test password hashing"""
        password = "TestPassword123!"
        hashed = auth_service.hash_password(password)
        
        # Should return bcrypt hash
        assert hashed.startswith("$2b$")
        assert len(hashed) >= 60
        assert hashed != password
        
        # Different hashes for same password
        hashed2 = auth_service.hash_password(password)
        assert hashed != hashed2

    def test_verify_password(self, auth_service):
        """Test password verification"""
        password = "TestPassword123!"
        hashed = auth_service.hash_password(password)
        
        # Correct password should verify
        assert auth_service.verify_password(password, hashed) is True
        
        # Wrong password should not verify
        assert auth_service.verify_password("WrongPassword", hashed) is False
        
        # Empty password should not verify
        assert auth_service.verify_password("", hashed) is False

    def test_create_token(self, auth_service):
        """Test JWT token creation"""
        now = datetime.utcnow()
        token_data = TokenData(
            user_id=1,
            username="testuser",
            role=UserRole.VIEWER.value,
            permissions=["read"],
            session_id="session123",
            token_type="access",
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )
        
        token = auth_service.create_token(token_data)
        
        # Should return a JWT token string
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are fairly long
        assert token.count('.') == 2  # JWT has 3 parts separated by dots

    def test_decode_token(self, auth_service):
        """Test JWT token decoding"""
        now = datetime.utcnow()
        original_data = TokenData(
            user_id=1,
            username="testuser",
            role=UserRole.VIEWER.value,
            permissions=["read", "write"],
            session_id="session123",
            token_type="access",
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )
        
        # Create token
        token = auth_service.create_token(original_data)
        
        # Decode token
        decoded_data = auth_service.decode_token(token)
        
        # Should match original data
        assert decoded_data is not None
        assert decoded_data.user_id == original_data.user_id
        assert decoded_data.username == original_data.username
        assert decoded_data.role == original_data.role
        assert decoded_data.permissions == original_data.permissions
        assert decoded_data.session_id == original_data.session_id
        assert decoded_data.token_type == original_data.token_type

    def test_decode_token_invalid(self, auth_service):
        """Test decoding invalid tokens"""
        # Invalid token format
        assert auth_service.decode_token("invalid.token") is None
        assert auth_service.decode_token("not-a-jwt-token") is None
        assert auth_service.decode_token("") is None
        
        # Create expired token
        now = datetime.utcnow()
        expired_data = TokenData(
            user_id=1,
            username="testuser",
            role=UserRole.VIEWER.value,
            permissions=["read"],
            session_id="session123",
            token_type="access",
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1)  # Expired 1 hour ago
        )
        
        expired_token = auth_service.create_token(expired_data)
        assert auth_service.decode_token(expired_token) is None

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service, sample_user, mock_db):
        """Test successful user authentication"""
        password = "TestPassword123!"
        
        # Mock database query to return the user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_db.execute.return_value = mock_result
        
        # Mock password verification
        with patch.object(auth_service, 'verify_password', return_value=True):
            result = await auth_service.authenticate_user(mock_db, "testuser", password)
        
        assert result == sample_user
        mock_db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_password(self, auth_service, sample_user, mock_db):
        """Test authentication with invalid password"""
        password = "WrongPassword"
        
        # Mock database query to return the user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_db.execute.return_value = mock_result
        
        # Mock password verification to fail
        with patch.object(auth_service, 'verify_password', return_value=False):
            result = await auth_service.authenticate_user(mock_db, "testuser", password)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service, mock_db):
        """Test authentication when user not found"""
        # Mock database query to return None
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        result = await auth_service.authenticate_user(mock_db, "nonexistent", "password")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_authenticate_user_locked_account(self, auth_service, mock_db):
        """Test authentication with locked account"""
        # Create locked user
        locked_user = User(
            id=1,
            username="lockeduser",
            email="locked@test.com",
            hashed_password="hashed_password",
            role=UserRole.VIEWER,
            status=UserStatus.LOCKED,
            is_verified=True
        )
        
        # Mock database query
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = locked_user
        mock_db.execute.return_value = mock_result
        
        result = await auth_service.authenticate_user(mock_db, "lockeduser", "password")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_create_user_success(self, auth_service, mock_db):
        """Test successful user creation"""
        username = "newuser"
        email = "newuser@test.com"
        password = "TestPassword123!"
        
        # Mock the register method
        expected_user = User(
            id=1,
            username=username,
            email=email,
            hashed_password=auth_service.hash_password(password),
            role=UserRole.VIEWER,
            status=UserStatus.ACTIVE,
            is_verified=True
        )
        
        with patch.object(auth_service, 'register', return_value=expected_user) as mock_register:
            result = await auth_service.create_user(
                db=mock_db,
                username=username,
                email=email,
                password=password
            )
        
        assert result == expected_user
        mock_register.assert_called_once_with(
            username=username,
            email=email,
            password=password,
            full_name=None,
            role=UserRole.VIEWER,
            db=mock_db
        )

    @pytest.mark.asyncio
    async def test_get_user_by_id_success(self, auth_service, sample_user, mock_db):
        """Test successful user retrieval by ID"""
        # Mock database query
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_db.execute.return_value = mock_result
        
        result = await auth_service.get_user_by_id(mock_db, sample_user.id)
        
        assert result == sample_user
        mock_db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, auth_service, mock_db):
        """Test user retrieval when user not found"""
        # Mock database query to return None
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        result = await auth_service.get_user_by_id(mock_db, 999)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_user_by_email_success(self, auth_service, sample_user, mock_db):
        """Test successful user retrieval by email"""
        # Mock database query
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_db.execute.return_value = mock_result
        
        result = await auth_service.get_user_by_email(mock_db, sample_user.email)
        
        assert result == sample_user
        mock_db.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_user_by_email_not_found(self, auth_service, mock_db):
        """Test user retrieval when email not found"""
        # Mock database query to return None
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        result = await auth_service.get_user_by_email(mock_db, "nonexistent@test.com")
        
        assert result is None

    def test_validate_password_strength_valid(self, auth_service):
        """Test password strength validation for valid passwords"""
        valid_passwords = [
            "StrongPass123!",
            "Complex@Password2024",
            "Secure#Pass456",
            "MyPassword$789"
        ]
        
        for password in valid_passwords:
            result = auth_service.validate_password_strength(password)
            assert result["valid"] is True
            assert result["score"] == result["max_score"]
            assert len(result["errors"]) == 0
            assert result["strength"] == "Strong"

    def test_validate_password_strength_invalid(self, auth_service):
        """Test password strength validation for invalid passwords"""
        invalid_passwords = [
            ("weak", "Password must be at least"),
            ("nouppercase123!", "Password must contain uppercase letter"),
            ("NOLOWERCASE123!", "Password must contain lowercase letter"),
            ("NoNumbers!", "Password must contain number"),
            ("NoSpecial123", "Password must contain special character")
        ]
        
        for password, expected_error in invalid_passwords:
            result = auth_service.validate_password_strength(password)
            assert result["valid"] is False
            assert result["score"] < result["max_score"]
            assert len(result["errors"]) > 0
            assert any(expected_error in error for error in result["errors"])
            assert result["strength"] != "Strong"

    def test_create_tokens_success(self, auth_service, sample_user):
        """Test successful token creation"""
        result = auth_service.create_tokens(sample_user)
        
        # Should return dictionary with tokens
        assert isinstance(result, dict)
        assert "access_token" in result
        assert "refresh_token" in result
        assert "token_type" in result
        assert "expires_in" in result
        
        # Tokens should be different
        assert result["access_token"] != result["refresh_token"]
        assert result["token_type"] == "bearer"
        assert isinstance(result["expires_in"], int)
        
        # Tokens should be valid JWT format
        assert result["access_token"].count('.') == 2
        assert result["refresh_token"].count('.') == 2

    def test_create_tokens_with_permissions(self, auth_service):
        """Test token creation includes correct permissions based on user role"""
        # Test different user roles
        roles_and_permissions = [
            (UserRole.ADMIN, ['users.read', 'users.write', 'users.delete']),
            (UserRole.OPERATOR, ['devices.read', 'devices.write']),
            (UserRole.VIEWER, ['devices.read']),
        ]
        
        for role, expected_perms in roles_and_permissions:
            user = User(
                id=1,
                username="testuser",
                email="test@test.com",
                hashed_password="hashed",
                role=role,
                status=UserStatus.ACTIVE,
                is_verified=True
            )
            
            result = auth_service.create_tokens(user)
            
            # Decode access token to check permissions
            access_token_data = auth_service.decode_token(result["access_token"])
            assert access_token_data is not None
            
            # Check that expected permissions are included
            for perm in expected_perms:
                assert perm in access_token_data.permissions

    @pytest.mark.asyncio
    async def test_verify_token_valid_access_token(self, auth_service, sample_user, mock_db):
        """Test token verification with valid access token"""
        # Create access token
        tokens = auth_service.create_tokens(sample_user)
        access_token = tokens["access_token"]
        
        # Mock session manager to avoid session checks
        with patch.object(auth_service.session_manager, 'get_session', return_value=None):
            result = await auth_service.verify_token(access_token, db=mock_db)
        
        assert result is not None
        assert result.user_id == sample_user.id
        assert result.username == sample_user.username
        assert result.token_type == "access"

    @pytest.mark.asyncio
    async def test_verify_token_with_permissions(self, auth_service, sample_user, mock_db):
        """Test token verification with required permissions"""
        # Create token for user with viewer role
        tokens = auth_service.create_tokens(sample_user)
        access_token = tokens["access_token"]
        
        # Mock session manager
        with patch.object(auth_service.session_manager, 'get_session', return_value=None):
            # Should succeed with permissions user has
            result = await auth_service.verify_token(
                access_token, 
                required_permissions=["devices.read"],
                db=mock_db
            )
            assert result is not None
            
            # Should fail with permissions user doesn't have
            with pytest.raises(PermissionDeniedException):
                await auth_service.verify_token(
                    access_token,
                    required_permissions=["users.delete"],
                    db=mock_db
                )

    @pytest.mark.asyncio
    async def test_verify_token_refresh_token_invalid(self, auth_service, sample_user, mock_db):
        """Test that refresh tokens cannot be used for verification"""
        # Create tokens
        tokens = auth_service.create_tokens(sample_user)
        refresh_token = tokens["refresh_token"]
        
        # Should fail with refresh token
        result = await auth_service.verify_token(refresh_token, db=mock_db)
        assert result is None

    @pytest.mark.asyncio
    async def test_refresh_access_token_success(self, auth_service, sample_user, mock_db):
        """Test successful access token refresh"""
        # Create tokens
        tokens = auth_service.create_tokens(sample_user)
        refresh_token = tokens["refresh_token"]
        
        # Mock database query to return user
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = sample_user
        mock_db.execute.return_value = mock_result
        
        # Mock session manager
        with patch.object(auth_service.session_manager, 'get_session', return_value=None):
            result = await auth_service.refresh_access_token(mock_db, refresh_token)
        
        # Should return new token data
        assert result is not None
        assert "access_token" in result
        assert "refresh_token" in result
        assert "token_type" in result
        assert "expires_in" in result
        assert result["token_type"] == "bearer"

    @pytest.mark.asyncio
    async def test_refresh_access_token_invalid_token(self, auth_service, mock_db):
        """Test access token refresh with invalid token"""
        result = await auth_service.refresh_access_token(mock_db, "invalid-token")
        assert result is None

    # Test token generation helper methods
    def test_generate_verification_token(self, auth_service):
        """Test verification token generation"""
        token = auth_service._generate_verification_token()
        assert isinstance(token, str)
        assert len(token) >= 32

    def test_generate_reset_token(self, auth_service):
        """Test reset token generation"""
        user_id = 1
        token = auth_service._generate_reset_token(user_id)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_generate_mfa_token(self, auth_service):
        """Test MFA token generation"""
        user_id = 1
        token = auth_service._generate_mfa_token(user_id)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_verify_mfa_token_valid(self, auth_service):
        """Test MFA token verification"""
        user_id = 1
        token = auth_service._generate_mfa_token(user_id)
        
        # Verify immediately (should be valid)
        verified_user_id = auth_service._verify_mfa_token(token)
        assert verified_user_id == user_id

    def test_verify_mfa_token_invalid(self, auth_service):
        """Test MFA token verification with invalid token"""
        invalid_tokens = [
            "invalid_token",
            "",
            "wrong:format:here"
        ]
        
        for invalid_token in invalid_tokens:
            result = auth_service._verify_mfa_token(invalid_token)
            assert result is None

    # Test synchronous permission method
    def test_get_user_permissions_sync(self, auth_service):
        """Test synchronous user permission retrieval"""
        # Test different roles
        test_cases = [
            (UserRole.ADMIN, ['users.read', 'users.write', 'users.delete']),
            (UserRole.OPERATOR, ['devices.read', 'devices.write']),
            (UserRole.VIEWER, ['devices.read']),
        ]
        
        for role, expected_perms in test_cases:
            user = User(
                id=1,
                username="testuser",
                email="test@test.com",
                hashed_password="hashed",
                role=role,
                status=UserStatus.ACTIVE,
                is_verified=True
            )
            
            permissions = auth_service._get_user_permissions_sync(user)
            
            # Check that expected permissions are included
            for perm in expected_perms:
                assert perm in permissions

    # Edge cases and error handling
    def test_create_token_handles_exceptions(self, auth_service):
        """Test token creation handles exceptions gracefully"""
        # Create token data with potential issues
        now = datetime.utcnow()
        token_data = TokenData(
            user_id=1,
            username="testuser",
            role=UserRole.VIEWER.value,
            permissions=["read"],
            session_id="session123",
            token_type="access",
            issued_at=now,
            expires_at=now + timedelta(hours=1)
        )
        
        # Mock jwt.encode to raise an exception
        with patch('backend.services.auth_service.jwt.encode', side_effect=Exception("JWT error")):
            with pytest.raises(AuthenticationException):
                auth_service.create_token(token_data)

    def test_decode_token_handles_various_jwt_errors(self, auth_service):
        """Test token decoding handles various JWT errors"""
        # Test with malformed tokens that would cause different JWT exceptions
        malformed_tokens = [
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.malformed.signature",  # Invalid payload
            "not.enough.parts",  # Wrong number of parts
            "too.many.parts.here.extra",  # Too many parts
        ]
        
        for token in malformed_tokens:
            result = auth_service.decode_token(token)
            assert result is None  # Should handle gracefully

    @pytest.mark.asyncio
    async def test_verify_token_handles_session_manager_exception(self, auth_service, sample_user, mock_db):
        """Test verify_token handles session manager exceptions gracefully"""
        # Create access token
        tokens = auth_service.create_tokens(sample_user)
        access_token = tokens["access_token"]
        
        # Mock session manager to raise exception
        with patch.object(auth_service.session_manager, 'get_session', side_effect=Exception("Session error")):
            # Should still work since it handles session errors gracefully
            result = await auth_service.verify_token(access_token, db=mock_db)
            assert result is not None  # Should succeed despite session error

    def test_password_strength_edge_cases(self, auth_service):
        """Test password strength validation edge cases"""
        edge_cases = [
            ("", False),  # Empty password
            ("a", False),  # Single character
            ("12345678", False),  # Numbers only
            ("ABCDEFGH", False),  # Uppercase only
            ("abcdefgh", False),  # Lowercase only
            ("!@#$%^&*", False),  # Special characters only
        ]
        
        for password, should_be_valid in edge_cases:
            result = auth_service.validate_password_strength(password)
            assert result["valid"] == should_be_valid

    # Integration-style tests
    def test_complete_token_lifecycle(self, auth_service, sample_user):
        """Test complete token lifecycle: create -> decode -> verify format"""
        # Create tokens
        tokens = auth_service.create_tokens(sample_user)
        
        # Decode both tokens
        access_token_data = auth_service.decode_token(tokens["access_token"])
        refresh_token_data = auth_service.decode_token(tokens["refresh_token"])
        
        # Verify access token data
        assert access_token_data is not None
        assert access_token_data.user_id == sample_user.id
        assert access_token_data.username == sample_user.username
        assert access_token_data.token_type == "access"
        
        # Verify refresh token data
        assert refresh_token_data is not None
        assert refresh_token_data.user_id == sample_user.id
        assert refresh_token_data.username == sample_user.username
        assert refresh_token_data.token_type == "refresh"
        
        # Verify they have same session ID but different types
        assert access_token_data.session_id == refresh_token_data.session_id
        assert access_token_data.token_type != refresh_token_data.token_type

    def test_password_hash_verify_cycle(self, auth_service):
        """Test complete password hash and verify cycle"""
        passwords = [
            "SimplePass123!",
            "Complex@Password2024#",
            "Another$Secure^Password&456",
            "Special!@#$%^&*()_+Password123"
        ]
        
        for password in passwords:
            # Hash password
            hashed = auth_service.hash_password(password)
            
            # Verify correct password
            assert auth_service.verify_password(password, hashed) is True
            
            # Verify wrong password fails
            assert auth_service.verify_password(password + "wrong", hashed) is False
            
            # Verify different case fails
            assert auth_service.verify_password(password.upper(), hashed) is False