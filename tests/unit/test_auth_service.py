"""
Comprehensive tests for Authentication Service
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.auth_service import AuthService, TokenData
from backend.common.exceptions import (
    AuthenticationException, ValidationException, InvalidTokenException,
    SessionExpiredException, AccountLockedException, MFARequiredException,
    PermissionDeniedException, ResourceNotFoundException, DuplicateResourceException
)
from models.user import User, UserRole, UserStatus


class TestAuthService:
    """Test Authentication Service functionality"""
    
    @pytest.fixture
    def auth_service(self):
        """Create AuthService instance for testing"""
        return AuthService()
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)
    
    @pytest.fixture
    def sample_user(self):
        """Create a sample user for testing"""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            hashed_password="$2b$12$hashed_password",
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            failed_login_attempts=0,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    
    @pytest.fixture
    def token_data(self):
        """Sample token data"""
        return TokenData(
            user_id=1,
            username="testuser",
            email="test@example.com",
            role=UserRole.USER.value,
            permissions=["read"],
            exp=datetime.now() + timedelta(hours=1),
            iat=datetime.now()
        )

    def test_init(self, auth_service):
        """Test AuthService initialization"""
        assert auth_service is not None
        assert hasattr(auth_service, 'pwd_context')
        assert hasattr(auth_service, 'user_service')
        assert hasattr(auth_service, 'email_service')
        assert hasattr(auth_service, 'session_manager')

    def test_verify_password_correct(self, auth_service):
        """Test password verification with correct password"""
        password = "testpassword123"
        hashed = auth_service.get_password_hash(password)
        assert auth_service.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self, auth_service):
        """Test password verification with incorrect password"""
        password = "testpassword123"
        wrong_password = "wrongpassword"
        hashed = auth_service.get_password_hash(password)
        assert auth_service.verify_password(wrong_password, hashed) is False

    def test_get_password_hash(self, auth_service):
        """Test password hashing"""
        password = "testpassword123"
        hashed = auth_service.get_password_hash(password)
        assert hashed is not None
        assert hashed != password
        assert hashed.startswith("$2b$")

    def test_create_access_token(self, auth_service, token_data):
        """Test JWT token creation"""
        token = auth_service.create_access_token(token_data)
        assert isinstance(token, str)
        assert len(token.split('.')) == 3  # JWT has 3 parts

    def test_create_refresh_token(self, auth_service, token_data):
        """Test refresh token creation"""
        token = auth_service.create_refresh_token(token_data)
        assert isinstance(token, str)
        assert len(token.split('.')) == 3

    @pytest.mark.asyncio
    async def test_verify_token_valid(self, auth_service, token_data):
        """Test token verification with valid token"""
        token = auth_service.create_access_token(token_data)
        result = await auth_service.verify_token(token)
        assert result is not None
        assert result.user_id == token_data.user_id
        assert result.username == token_data.username

    @pytest.mark.asyncio
    async def test_verify_token_invalid(self, auth_service):
        """Test token verification with invalid token"""
        with pytest.raises(InvalidTokenException):
            await auth_service.verify_token("invalid.token.here")

    @pytest.mark.asyncio
    async def test_verify_token_expired(self, auth_service, token_data):
        """Test token verification with expired token"""
        # Create token with past expiration
        token_data.exp = datetime.now() - timedelta(hours=1)
        token = auth_service.create_access_token(token_data)
        
        with pytest.raises(SessionExpiredException):
            await auth_service.verify_token(token)

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service, mock_db_session, sample_user):
        """Test successful user authentication"""
        password = "testpassword123"
        sample_user.hashed_password = auth_service.get_password_hash(password)
        
        with patch.object(auth_service.user_service, 'get_user_by_username', return_value=sample_user):
            result = await auth_service.authenticate_user(mock_db_session, "testuser", password)
            assert result == sample_user

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self, auth_service, mock_db_session, sample_user):
        """Test authentication with wrong password"""
        password = "testpassword123"
        wrong_password = "wrongpassword"
        sample_user.hashed_password = auth_service.get_password_hash(password)
        
        with patch.object(auth_service.user_service, 'get_user_by_username', return_value=sample_user):
            with patch.object(auth_service, '_handle_failed_login') as mock_failed:
                with pytest.raises(AuthenticationException):
                    await auth_service.authenticate_user(mock_db_session, "testuser", wrong_password)
                mock_failed.assert_called_once()

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(self, auth_service, mock_db_session):
        """Test authentication with non-existent user"""
        with patch.object(auth_service.user_service, 'get_user_by_username', return_value=None):
            with pytest.raises(AuthenticationException):
                await auth_service.authenticate_user(mock_db_session, "nonexistent", "password")

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(self, auth_service, mock_db_session, sample_user):
        """Test authentication with inactive user"""
        sample_user.status = UserStatus.INACTIVE
        
        with patch.object(auth_service.user_service, 'get_user_by_username', return_value=sample_user):
            with pytest.raises(AuthenticationException):
                await auth_service.authenticate_user(mock_db_session, "testuser", "password")

    @pytest.mark.asyncio
    async def test_authenticate_user_locked(self, auth_service, mock_db_session, sample_user):
        """Test authentication with locked user"""
        sample_user.status = UserStatus.LOCKED
        
        with patch.object(auth_service.user_service, 'get_user_by_username', return_value=sample_user):
            with pytest.raises(AccountLockedException):
                await auth_service.authenticate_user(mock_db_session, "testuser", "password")

    @pytest.mark.asyncio
    async def test_register_user_success(self, auth_service, mock_db_session):
        """Test successful user registration"""
        user_data = {
            "username": "newuser",
            "email": "new@example.com",
            "password": "password123",
            "first_name": "New",
            "last_name": "User"
        }
        
        new_user = User(id=2, username="newuser", email="new@example.com")
        
        with patch.object(auth_service.user_service, 'create_user', return_value=new_user) as mock_create:
            with patch.object(auth_service.email_service, 'send_welcome_email') as mock_email:
                result = await auth_service.register_user(mock_db_session, user_data)
                assert result == new_user
                mock_create.assert_called_once()
                mock_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_register_user_duplicate(self, auth_service, mock_db_session):
        """Test user registration with duplicate username"""
        user_data = {
            "username": "existinguser",
            "email": "existing@example.com",
            "password": "password123"
        }
        
        with patch.object(auth_service.user_service, 'create_user', side_effect=DuplicateResourceException("User already exists")):
            with pytest.raises(DuplicateResourceException):
                await auth_service.register_user(mock_db_session, user_data)

    @pytest.mark.asyncio
    async def test_login_success(self, auth_service, mock_db_session, sample_user):
        """Test successful login"""
        password = "testpassword123"
        sample_user.hashed_password = auth_service.get_password_hash(password)
        
        with patch.object(auth_service, 'authenticate_user', return_value=sample_user):
            with patch.object(auth_service, '_create_user_tokens') as mock_tokens:
                mock_tokens.return_value = ("access_token", "refresh_token")
                with patch.object(auth_service.session_manager, 'create_session') as mock_session:
                    result = await auth_service.login(mock_db_session, "testuser", password)
                    assert "access_token" in result
                    assert "refresh_token" in result
                    mock_tokens.assert_called_once()
                    mock_session.assert_called_once()

    @pytest.mark.asyncio
    async def test_login_mfa_required(self, auth_service, mock_db_session, sample_user):
        """Test login when MFA is required"""
        sample_user.mfa_enabled = True
        sample_user.mfa_secret = "test_secret"
        
        with patch.object(auth_service, 'authenticate_user', return_value=sample_user):
            with pytest.raises(MFARequiredException):
                await auth_service.login(mock_db_session, "testuser", "password")

    @pytest.mark.asyncio
    async def test_logout_success(self, auth_service, mock_db_session):
        """Test successful logout"""
        token_data = TokenData(user_id=1, username="testuser")
        
        with patch.object(auth_service.session_manager, 'destroy_session') as mock_destroy:
            await auth_service.logout(mock_db_session, token_data)
            mock_destroy.assert_called_once()

    @pytest.mark.asyncio
    async def test_refresh_token_success(self, auth_service, mock_db_session, sample_user):
        """Test successful token refresh"""
        token_data = TokenData(user_id=1, username="testuser")
        refresh_token = auth_service.create_refresh_token(token_data)
        
        with patch.object(auth_service.user_service, 'get_user_by_id', return_value=sample_user):
            with patch.object(auth_service, 'verify_token', return_value=token_data):
                with patch.object(auth_service, '_create_user_tokens') as mock_tokens:
                    mock_tokens.return_value = ("new_access", "new_refresh")
                    result = await auth_service.refresh_token(mock_db_session, refresh_token)
                    assert "access_token" in result
                    assert "refresh_token" in result

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, auth_service, mock_db_session):
        """Test token refresh with invalid token"""
        with patch.object(auth_service, 'verify_token', side_effect=InvalidTokenException("Invalid token")):
            with pytest.raises(InvalidTokenException):
                await auth_service.refresh_token(mock_db_session, "invalid_token")

    @pytest.mark.asyncio
    async def test_change_password_success(self, auth_service, mock_db_session, sample_user):
        """Test successful password change"""
        old_password = "oldpassword123"
        new_password = "newpassword123"
        sample_user.hashed_password = auth_service.get_password_hash(old_password)
        
        with patch.object(auth_service.user_service, 'get_user_by_id', return_value=sample_user):
            with patch.object(auth_service.user_service, 'update_user') as mock_update:
                await auth_service.change_password(mock_db_session, 1, old_password, new_password)
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password_wrong_old(self, auth_service, mock_db_session, sample_user):
        """Test password change with wrong old password"""
        old_password = "oldpassword123"
        wrong_old = "wrongold"
        new_password = "newpassword123"
        sample_user.hashed_password = auth_service.get_password_hash(old_password)
        
        with patch.object(auth_service.user_service, 'get_user_by_id', return_value=sample_user):
            with pytest.raises(AuthenticationException):
                await auth_service.change_password(mock_db_session, 1, wrong_old, new_password)

    def test_validate_password_strength_valid(self, auth_service):
        """Test password strength validation with valid password"""
        valid_passwords = [
            "Password123!",
            "ComplexP@ssw0rd",
            "StrongP@ss1"
        ]
        
        for password in valid_passwords:
            assert auth_service.validate_password_strength(password) is True

    def test_validate_password_strength_invalid(self, auth_service):
        """Test password strength validation with invalid passwords"""
        invalid_passwords = [
            "weak",              # too short
            "password",          # no uppercase, numbers, special chars
            "PASSWORD123",       # no lowercase, special chars
            "Password",          # no numbers, special chars
            "Password123",       # no special chars
        ]
        
        for password in invalid_passwords:
            assert auth_service.validate_password_strength(password) is False

    def test_generate_mfa_secret(self, auth_service):
        """Test MFA secret generation"""
        secret = auth_service.generate_mfa_secret()
        assert isinstance(secret, str)
        assert len(secret) >= 16

    def test_verify_mfa_token_valid(self, auth_service):
        """Test MFA token verification with valid token"""
        # Mock pyotp verification
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp.return_value.verify.return_value = True
            result = auth_service.verify_mfa_token("secret", "123456")
            assert result is True

    def test_verify_mfa_token_invalid(self, auth_service):
        """Test MFA token verification with invalid token"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp.return_value.verify.return_value = False
            result = auth_service.verify_mfa_token("secret", "wrong")
            assert result is False

    @pytest.mark.asyncio
    async def test_reset_password_request(self, auth_service, mock_db_session, sample_user):
        """Test password reset request"""
        with patch.object(auth_service.user_service, 'get_user_by_email', return_value=sample_user):
            with patch.object(auth_service.user_service, 'update_user') as mock_update:
                with patch.object(auth_service.email_service, 'send_password_reset_email') as mock_email:
                    await auth_service.reset_password_request(mock_db_session, "test@example.com")
                    mock_update.assert_called_once()
                    mock_email.assert_called_once()

    @pytest.mark.asyncio
    async def test_reset_password_request_user_not_found(self, auth_service, mock_db_session):
        """Test password reset request for non-existent user"""
        with patch.object(auth_service.user_service, 'get_user_by_email', return_value=None):
            with patch.object(auth_service.email_service, 'send_password_reset_email') as mock_email:
                await auth_service.reset_password_request(mock_db_session, "nonexistent@example.com")
                # Should not send email for non-existent users
                mock_email.assert_not_called()

    @pytest.mark.asyncio
    async def test_reset_password_confirm_success(self, auth_service, mock_db_session, sample_user):
        """Test successful password reset confirmation"""
        sample_user.reset_token = "valid_token"
        sample_user.reset_token_expires = datetime.now() + timedelta(hours=1)
        
        with patch.object(auth_service.user_service, 'get_user_by_reset_token', return_value=sample_user):
            with patch.object(auth_service.user_service, 'update_user') as mock_update:
                await auth_service.reset_password_confirm(mock_db_session, "valid_token", "newpassword123")
                mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_reset_password_confirm_invalid_token(self, auth_service, mock_db_session):
        """Test password reset confirmation with invalid token"""
        with patch.object(auth_service.user_service, 'get_user_by_reset_token', return_value=None):
            with pytest.raises(InvalidTokenException):
                await auth_service.reset_password_confirm(mock_db_session, "invalid", "password")

    @pytest.mark.asyncio
    async def test_reset_password_confirm_expired_token(self, auth_service, mock_db_session, sample_user):
        """Test password reset confirmation with expired token"""
        sample_user.reset_token = "valid_token"
        sample_user.reset_token_expires = datetime.now() - timedelta(hours=1)
        
        with patch.object(auth_service.user_service, 'get_user_by_reset_token', return_value=sample_user):
            with pytest.raises(InvalidTokenException):
                await auth_service.reset_password_confirm(mock_db_session, "valid_token", "password")

    def test_check_permissions_success(self, auth_service):
        """Test permission checking with valid permissions"""
        user_permissions = ["read", "write", "delete"]
        required_permissions = ["read", "write"]
        
        result = auth_service.check_permissions(user_permissions, required_permissions)
        assert result is True

    def test_check_permissions_failure(self, auth_service):
        """Test permission checking with insufficient permissions"""
        user_permissions = ["read"]
        required_permissions = ["read", "write", "delete"]
        
        result = auth_service.check_permissions(user_permissions, required_permissions)
        assert result is False

    def test_check_permissions_empty_required(self, auth_service):
        """Test permission checking with no required permissions"""
        user_permissions = ["read"]
        required_permissions = []
        
        result = auth_service.check_permissions(user_permissions, required_permissions)
        assert result is True

    @pytest.mark.asyncio
    async def test_handle_failed_login_increment(self, auth_service, mock_db_session, sample_user):
        """Test failed login attempt handling"""
        with patch.object(auth_service.user_service, 'update_user') as mock_update:
            await auth_service._handle_failed_login(mock_db_session, sample_user)
            assert sample_user.failed_login_attempts == 1
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_failed_login_lock_account(self, auth_service, mock_db_session, sample_user):
        """Test account locking after max failed attempts"""
        sample_user.failed_login_attempts = 4  # One before max
        
        with patch.object(auth_service.user_service, 'update_user') as mock_update:
            with patch.object(auth_service.email_service, 'send_account_locked_email') as mock_email:
                await auth_service._handle_failed_login(mock_db_session, sample_user)
                assert sample_user.status == UserStatus.LOCKED
                mock_update.assert_called_once()
                mock_email.assert_called_once()

    def test_create_user_tokens(self, auth_service, sample_user):
        """Test user token creation"""
        access_token, refresh_token = auth_service._create_user_tokens(sample_user, ["read", "write"])
        
        assert isinstance(access_token, str)
        assert isinstance(refresh_token, str)
        assert len(access_token.split('.')) == 3
        assert len(refresh_token.split('.')) == 3

    @pytest.mark.asyncio
    async def test_get_current_user_success(self, auth_service, mock_db_session, sample_user, token_data):
        """Test getting current user from token"""
        with patch.object(auth_service.user_service, 'get_user_by_id', return_value=sample_user):
            result = await auth_service.get_current_user(mock_db_session, token_data)
            assert result == sample_user

    @pytest.mark.asyncio
    async def test_get_current_user_not_found(self, auth_service, mock_db_session, token_data):
        """Test getting current user when user not found"""
        with patch.object(auth_service.user_service, 'get_user_by_id', return_value=None):
            with pytest.raises(ResourceNotFoundException):
                await auth_service.get_current_user(mock_db_session, token_data)

    def test_is_token_expired_false(self, auth_service):
        """Test token expiration check with valid token"""
        future_exp = datetime.now() + timedelta(hours=1)
        assert auth_service._is_token_expired(future_exp) is False

    def test_is_token_expired_true(self, auth_service):
        """Test token expiration check with expired token"""
        past_exp = datetime.now() - timedelta(hours=1)
        assert auth_service._is_token_expired(past_exp) is True