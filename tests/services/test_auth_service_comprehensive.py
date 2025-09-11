"""
Comprehensive tests for Authentication Service
Testing all authentication, JWT, password management, and security features
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, Mock
import uuid
import jwt
from jose import JWTError
import bcrypt

# Test infrastructure imports
from tests.test_infrastructure.test_fixtures_comprehensive import (
    TestInfrastructureManager,
    TestDataFactory
)

# Service imports
from backend.services.auth_service import AuthService
from backend.database.user_models import User, Role, Permission, UserSession
from backend.config import Settings


class TestAuthServiceCore:
    """Core authentication service functionality tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance with mocked dependencies"""
        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        mock_email = AsyncMock()
        
        service = AuthService()
        service.db = mock_db
        service.redis = mock_redis
        service.email_service = mock_email
        
        return service
    
    @pytest.fixture
    def mock_settings(self):
        """Mock settings for testing"""
        settings = MagicMock(spec=Settings)
        settings.jwt_secret_key = "test_secret_key_for_testing_only"
        settings.access_token_expire_minutes = 30
        settings.refresh_token_expire_days = 7
        settings.password_min_length = 8
        settings.password_require_uppercase = True
        settings.password_require_lowercase = True
        settings.password_require_digits = True
        settings.password_require_special = True
        settings.account_lockout_threshold = 5
        settings.account_lockout_duration = 30
        return settings
    
    def test_password_hashing(self, auth_service):
        """Test password hashing functionality"""
        password = "TestPassword123!"
        
        # Hash password
        hashed = auth_service.get_password_hash(password)
        
        # Verify it's a bcrypt hash
        assert hashed.startswith("$2b$")
        assert len(hashed) == 60
        
        # Verify password
        assert auth_service.verify_password(password, hashed) is True
        assert auth_service.verify_password("WrongPassword", hashed) is False
    
    def test_password_hash_uniqueness(self, auth_service):
        """Test that same password generates different hashes"""
        password = "TestPassword123!"
        
        hash1 = auth_service.get_password_hash(password)
        hash2 = auth_service.get_password_hash(password)
        
        # Hashes should be different due to salt
        assert hash1 != hash2
        
        # But both should verify correctly
        assert auth_service.verify_password(password, hash1) is True
        assert auth_service.verify_password(password, hash2) is True
    
    def test_jwt_token_creation(self, auth_service, mock_settings):
        """Test JWT token creation"""
        with patch('backend.services.auth_service.settings', mock_settings):
            user_id = str(uuid.uuid4())
            username = "testuser"
            
            # Create access token
            access_token = auth_service.create_access_token({
                "sub": user_id,
                "username": username,
                "type": "access"
            })
            
            # Verify token structure
            assert access_token is not None
            assert len(access_token.split('.')) == 3  # JWT has 3 parts
            
            # Decode and verify payload
            payload = jwt.decode(
                access_token,
                mock_settings.jwt_secret_key,
                algorithms=["HS256"]
            )
            
            assert payload["sub"] == user_id
            assert payload["username"] == username
            assert payload["type"] == "access"
            assert "exp" in payload
            assert "iat" in payload
            assert "jti" in payload  # JWT ID for token revocation
    
    def test_jwt_token_expiration(self, auth_service, mock_settings):
        """Test JWT token expiration handling"""
        with patch('backend.services.auth_service.settings', mock_settings):
            # Create token with short expiration
            with patch('backend.services.auth_service.datetime') as mock_datetime:
                now = datetime.utcnow()
                mock_datetime.utcnow.return_value = now
                
                token = auth_service.create_access_token(
                    {"sub": "user123"},
                    expires_delta=timedelta(seconds=1)
                )
                
                # Token should be valid immediately
                payload = auth_service.verify_token(token)
                assert payload is not None
                
                # Simulate time passing
                mock_datetime.utcnow.return_value = now + timedelta(seconds=2)
                
                # Token should be expired
                with pytest.raises(JWTError):
                    auth_service.verify_token(token)
    
    def test_refresh_token_creation(self, auth_service, mock_settings):
        """Test refresh token creation and validation"""
        with patch('backend.services.auth_service.settings', mock_settings):
            user_id = str(uuid.uuid4())
            
            # Create refresh token
            refresh_token = auth_service.create_refresh_token({
                "sub": user_id,
                "type": "refresh"
            })
            
            # Verify token
            payload = auth_service.verify_token(refresh_token)
            assert payload["sub"] == user_id
            assert payload["type"] == "refresh"
            
            # Refresh token should have longer expiration
            exp_time = datetime.fromtimestamp(payload["exp"])
            now = datetime.utcnow()
            assert (exp_time - now).days >= 6  # At least 6 days
    
    @pytest.mark.asyncio
    async def test_authenticate_user_success(self, auth_service):
        """Test successful user authentication"""
        # Mock database query
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.username = "testuser"
        mock_user.hashed_password = auth_service.get_password_hash("TestPassword123!")
        mock_user.is_active = True
        mock_user.is_verified = True
        mock_user.locked_until = None
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Authenticate
        result = await auth_service.authenticate_user("testuser", "TestPassword123!")
        
        assert result == mock_user
        auth_service.db.query.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_authenticate_user_invalid_password(self, auth_service):
        """Test authentication with invalid password"""
        mock_user = MagicMock(spec=User)
        mock_user.username = "testuser"
        mock_user.hashed_password = auth_service.get_password_hash("TestPassword123!")
        mock_user.is_active = True
        mock_user.locked_until = None
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Authenticate with wrong password
        result = await auth_service.authenticate_user("testuser", "WrongPassword")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_authenticate_user_account_locked(self, auth_service):
        """Test authentication with locked account"""
        mock_user = MagicMock(spec=User)
        mock_user.username = "testuser"
        mock_user.hashed_password = auth_service.get_password_hash("TestPassword123!")
        mock_user.is_active = True
        mock_user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Attempt authentication
        with pytest.raises(Exception, match="Account is locked"):
            await auth_service.authenticate_user("testuser", "TestPassword123!")
    
    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(self, auth_service):
        """Test authentication with inactive account"""
        mock_user = MagicMock(spec=User)
        mock_user.username = "testuser"
        mock_user.hashed_password = auth_service.get_password_hash("TestPassword123!")
        mock_user.is_active = False
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Attempt authentication
        result = await auth_service.authenticate_user("testuser", "TestPassword123!")
        
        assert result is None


class TestPasswordManagement:
    """Password management and validation tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        return AuthService()
    
    def test_password_strength_validation_valid(self, auth_service):
        """Test password strength validation with valid passwords"""
        valid_passwords = [
            "TestPass123!",
            "SecureP@ssw0rd",
            "MyStr0ng!Pass",
            "C0mplex&Password"
        ]
        
        for password in valid_passwords:
            result = auth_service.validate_password_strength(password)
            assert result["valid"] is True
            assert result["score"] >= 3  # Good strength
    
    def test_password_strength_validation_invalid(self, auth_service):
        """Test password strength validation with invalid passwords"""
        invalid_passwords = [
            ("short", "too short"),
            ("alllowercase", "missing uppercase"),
            ("ALLUPPERCASE", "missing lowercase"),
            ("NoNumbers!", "missing digits"),
            ("NoSpecial123", "missing special characters"),
            ("", "empty password")
        ]
        
        for password, reason in invalid_passwords:
            result = auth_service.validate_password_strength(password)
            assert result["valid"] is False
            assert len(result["errors"]) > 0
    
    def test_password_history_check(self, auth_service):
        """Test password history validation"""
        password_history = [
            auth_service.get_password_hash("OldPassword1!"),
            auth_service.get_password_hash("OldPassword2!"),
            auth_service.get_password_hash("OldPassword3!")
        ]
        
        # Check against old password
        assert auth_service.check_password_history("OldPassword1!", password_history) is False
        
        # Check new password
        assert auth_service.check_password_history("NewPassword123!", password_history) is True
    
    @pytest.mark.asyncio
    async def test_password_reset_request(self, auth_service):
        """Test password reset request generation"""
        mock_user = MagicMock(spec=User)
        mock_user.id = uuid.uuid4()
        mock_user.email = "test@example.com"
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        auth_service.email_service.send_password_reset_email.return_value = True
        
        # Request password reset
        token = await auth_service.request_password_reset("test@example.com")
        
        assert token is not None
        assert len(token) > 20
        auth_service.email_service.send_password_reset_email.assert_called_once()
        
        # Verify token stored in database
        assert mock_user.reset_token is not None
        assert mock_user.reset_token_expires is not None
    
    @pytest.mark.asyncio
    async def test_password_reset_confirm(self, auth_service):
        """Test password reset confirmation"""
        reset_token = "valid_reset_token_123"
        new_password = "NewSecurePass123!"
        
        mock_user = MagicMock(spec=User)
        mock_user.reset_token = reset_token
        mock_user.reset_token_expires = datetime.utcnow() + timedelta(hours=1)
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Confirm password reset
        result = await auth_service.confirm_password_reset(reset_token, new_password)
        
        assert result is True
        assert mock_user.reset_token is None
        assert mock_user.reset_token_expires is None
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_password_reset_expired_token(self, auth_service):
        """Test password reset with expired token"""
        reset_token = "expired_token_123"
        
        mock_user = MagicMock(spec=User)
        mock_user.reset_token = reset_token
        mock_user.reset_token_expires = datetime.utcnow() - timedelta(hours=1)  # Expired
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Attempt reset with expired token
        result = await auth_service.confirm_password_reset(reset_token, "NewPassword123!")
        
        assert result is False


class TestSessionManagement:
    """User session management tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        service = AuthService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_create_user_session(self, auth_service):
        """Test user session creation"""
        user_id = uuid.uuid4()
        token_jti = str(uuid.uuid4())
        refresh_token = "refresh_token_123"
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0"
        
        # Create session
        session = await auth_service.create_user_session(
            user_id=user_id,
            token_jti=token_jti,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        assert session is not None
        auth_service.db.add.assert_called_once()
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_invalidate_session(self, auth_service):
        """Test session invalidation"""
        session_id = uuid.uuid4()
        
        mock_session = MagicMock(spec=UserSession)
        mock_session.id = session_id
        mock_session.is_active = True
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_session
        
        # Invalidate session
        result = await auth_service.invalidate_session(session_id)
        
        assert result is True
        assert mock_session.is_active is False
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_invalidate_all_user_sessions(self, auth_service):
        """Test invalidating all user sessions"""
        user_id = uuid.uuid4()
        
        mock_sessions = [
            MagicMock(spec=UserSession, is_active=True),
            MagicMock(spec=UserSession, is_active=True),
            MagicMock(spec=UserSession, is_active=True)
        ]
        
        auth_service.db.query.return_value.filter.return_value.all.return_value = mock_sessions
        
        # Invalidate all sessions
        count = await auth_service.invalidate_all_user_sessions(user_id)
        
        assert count == 3
        for session in mock_sessions:
            assert session.is_active is False
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self, auth_service):
        """Test cleanup of expired sessions"""
        expired_sessions = [
            MagicMock(spec=UserSession, expires_at=datetime.utcnow() - timedelta(hours=1)),
            MagicMock(spec=UserSession, expires_at=datetime.utcnow() - timedelta(days=1))
        ]
        
        auth_service.db.query.return_value.filter.return_value.all.return_value = expired_sessions
        
        # Cleanup expired sessions
        count = await auth_service.cleanup_expired_sessions()
        
        assert count == 2
        assert auth_service.db.delete.call_count == 2
        auth_service.db.commit.assert_called_once()


class TestMFAFunctionality:
    """Multi-factor authentication tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        return AuthService()
    
    def test_generate_mfa_secret(self, auth_service):
        """Test MFA secret generation"""
        secret = auth_service.generate_mfa_secret()
        
        assert secret is not None
        assert len(secret) == 32  # Base32 encoded secret
        assert secret.isupper()  # Base32 uses uppercase
    
    def test_generate_mfa_qr_code(self, auth_service):
        """Test MFA QR code generation"""
        username = "testuser"
        secret = auth_service.generate_mfa_secret()
        
        qr_code = auth_service.generate_mfa_qr_code(username, secret)
        
        assert qr_code is not None
        assert qr_code.startswith("otpauth://totp/")
        assert username in qr_code
        assert secret in qr_code
    
    def test_verify_mfa_token_valid(self, auth_service):
        """Test MFA token verification with valid token"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp_instance.verify.return_value = True
            mock_totp.return_value = mock_totp_instance
            
            secret = "TESTSECRET123456"
            token = "123456"
            
            result = auth_service.verify_mfa_token(secret, token)
            
            assert result is True
            mock_totp.assert_called_once_with(secret)
            mock_totp_instance.verify.assert_called_once_with(token, valid_window=1)
    
    def test_verify_mfa_token_invalid(self, auth_service):
        """Test MFA token verification with invalid token"""
        with patch('pyotp.TOTP') as mock_totp:
            mock_totp_instance = MagicMock()
            mock_totp_instance.verify.return_value = False
            mock_totp.return_value = mock_totp_instance
            
            secret = "TESTSECRET123456"
            token = "000000"
            
            result = auth_service.verify_mfa_token(secret, token)
            
            assert result is False
    
    @pytest.mark.asyncio
    async def test_enable_mfa_for_user(self, auth_service):
        """Test enabling MFA for a user"""
        user_id = uuid.uuid4()
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        mock_user.mfa_enabled = False
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Enable MFA
        secret = await auth_service.enable_mfa(user_id)
        
        assert secret is not None
        assert mock_user.mfa_secret is not None
        assert mock_user.mfa_enabled is True
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disable_mfa_for_user(self, auth_service):
        """Test disabling MFA for a user"""
        user_id = uuid.uuid4()
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        mock_user.mfa_enabled = True
        mock_user.mfa_secret = "OLDSECRET123"
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Disable MFA
        result = await auth_service.disable_mfa(user_id)
        
        assert result is True
        assert mock_user.mfa_secret is None
        assert mock_user.mfa_enabled is False
        auth_service.db.commit.assert_called_once()


class TestAccountSecurity:
    """Account security and lockout tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        service = AuthService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_handle_failed_login(self, auth_service):
        """Test handling failed login attempts"""
        username = "testuser"
        mock_user = MagicMock(spec=User)
        mock_user.failed_login_attempts = 2
        mock_user.locked_until = None
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Handle failed login
        await auth_service.handle_failed_login(username)
        
        assert mock_user.failed_login_attempts == 3
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_account_lockout_on_threshold(self, auth_service):
        """Test account lockout when threshold is reached"""
        username = "testuser"
        mock_user = MagicMock(spec=User)
        mock_user.failed_login_attempts = 4  # One below threshold
        mock_user.locked_until = None
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        with patch('backend.services.auth_service.settings.account_lockout_threshold', 5):
            # Handle failed login (5th attempt)
            await auth_service.handle_failed_login(username)
            
            assert mock_user.failed_login_attempts == 5
            assert mock_user.locked_until is not None
            assert mock_user.locked_until > datetime.utcnow()
    
    @pytest.mark.asyncio
    async def test_reset_failed_login_attempts(self, auth_service):
        """Test resetting failed login attempts after successful login"""
        user_id = uuid.uuid4()
        mock_user = MagicMock(spec=User)
        mock_user.id = user_id
        mock_user.failed_login_attempts = 3
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Reset failed attempts
        await auth_service.reset_failed_login_attempts(user_id)
        
        assert mock_user.failed_login_attempts == 0
        assert mock_user.last_login is not None
        auth_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_account_locked(self, auth_service):
        """Test checking if account is locked"""
        # Locked account
        mock_user_locked = MagicMock(spec=User)
        mock_user_locked.locked_until = datetime.utcnow() + timedelta(minutes=30)
        
        assert auth_service.is_account_locked(mock_user_locked) is True
        
        # Unlocked account (lock expired)
        mock_user_unlocked = MagicMock(spec=User)
        mock_user_unlocked.locked_until = datetime.utcnow() - timedelta(minutes=1)
        
        assert auth_service.is_account_locked(mock_user_unlocked) is False
        
        # Never locked account
        mock_user_never_locked = MagicMock(spec=User)
        mock_user_never_locked.locked_until = None
        
        assert auth_service.is_account_locked(mock_user_never_locked) is False


class TestTokenRevocation:
    """JWT token revocation and blacklist tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        service = AuthService()
        service.redis = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_revoke_token(self, auth_service):
        """Test token revocation"""
        token_jti = str(uuid.uuid4())
        expiry = datetime.utcnow() + timedelta(hours=1)
        
        # Revoke token
        await auth_service.revoke_token(token_jti, expiry)
        
        # Verify Redis call
        auth_service.redis.setex.assert_called_once()
        call_args = auth_service.redis.setex.call_args
        assert f"revoked_token:{token_jti}" in str(call_args)
    
    @pytest.mark.asyncio
    async def test_check_token_revoked(self, auth_service):
        """Test checking if token is revoked"""
        token_jti = str(uuid.uuid4())
        
        # Token is revoked
        auth_service.redis.exists.return_value = 1
        assert await auth_service.is_token_revoked(token_jti) is True
        
        # Token is not revoked
        auth_service.redis.exists.return_value = 0
        assert await auth_service.is_token_revoked(token_jti) is False
    
    @pytest.mark.asyncio
    async def test_revoke_all_user_tokens(self, auth_service):
        """Test revoking all tokens for a user"""
        user_id = uuid.uuid4()
        
        mock_sessions = [
            MagicMock(token_jti=str(uuid.uuid4()), expires_at=datetime.utcnow() + timedelta(hours=1)),
            MagicMock(token_jti=str(uuid.uuid4()), expires_at=datetime.utcnow() + timedelta(hours=2))
        ]
        
        auth_service.db = AsyncMock()
        auth_service.db.query.return_value.filter.return_value.all.return_value = mock_sessions
        
        # Revoke all tokens
        count = await auth_service.revoke_all_user_tokens(user_id)
        
        assert count == 2
        assert auth_service.redis.setex.call_count == 2


class TestRBACIntegration:
    """Role-based access control integration tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        service = AuthService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_check_user_permission(self, auth_service):
        """Test checking user permissions"""
        user_id = uuid.uuid4()
        
        # Setup mock user with roles and permissions
        mock_permission = MagicMock(spec=Permission)
        mock_permission.resource = "devices"
        mock_permission.action = "read"
        
        mock_role = MagicMock(spec=Role)
        mock_role.permissions = [mock_permission]
        
        mock_user = MagicMock(spec=User)
        mock_user.roles = [mock_role]
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Check permission
        has_permission = await auth_service.check_permission(user_id, "devices", "read")
        assert has_permission is True
        
        # Check missing permission
        has_permission = await auth_service.check_permission(user_id, "devices", "delete")
        assert has_permission is False
    
    @pytest.mark.asyncio
    async def test_get_user_permissions(self, auth_service):
        """Test getting all user permissions"""
        user_id = uuid.uuid4()
        
        # Setup mock permissions
        permissions = [
            MagicMock(resource="devices", action="read"),
            MagicMock(resource="devices", action="write"),
            MagicMock(resource="alerts", action="read")
        ]
        
        mock_role = MagicMock(spec=Role)
        mock_role.permissions = permissions
        
        mock_user = MagicMock(spec=User)
        mock_user.roles = [mock_role]
        
        auth_service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Get permissions
        user_permissions = await auth_service.get_user_permissions(user_id)
        
        assert len(user_permissions) == 3
        assert ("devices", "read") in [(p.resource, p.action) for p in user_permissions]


class TestAuditLogging:
    """Audit logging tests"""
    
    @pytest.fixture
    def auth_service(self):
        """Create auth service instance"""
        service = AuthService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_log_authentication_success(self, auth_service):
        """Test logging successful authentication"""
        user_id = uuid.uuid4()
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0"
        
        await auth_service.log_authentication(
            user_id=user_id,
            action="login",
            status="success",
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Verify audit log created
        auth_service.db.add.assert_called_once()
        audit_log = auth_service.db.add.call_args[0][0]
        assert audit_log.user_id == user_id
        assert audit_log.action == "login"
        assert audit_log.status == "success"
    
    @pytest.mark.asyncio
    async def test_log_authentication_failure(self, auth_service):
        """Test logging failed authentication"""
        username = "testuser"
        ip_address = "192.168.1.100"
        
        await auth_service.log_authentication_failure(
            username=username,
            reason="invalid_password",
            ip_address=ip_address
        )
        
        # Verify audit log created
        auth_service.db.add.assert_called_once()
        audit_log = auth_service.db.add.call_args[0][0]
        assert audit_log.action == "login_failed"
        assert audit_log.status == "failure"
        assert "invalid_password" in str(audit_log.details)