"""
Comprehensive Authentication Service JWT Token Tests
Covers lines 444-551, 568-643, 656-727 in backend/services/auth_service.py
"""

import pytest
import jwt
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
import secrets
import json

from backend.services.auth_service import AuthService
from backend.models.user import User, UserRole, UserStatus
from core.config import get_settings


class TestAuthServiceJWTTokens:
    """Test all JWT token functionality in AuthService"""
    
    @pytest.fixture
    async def auth_service(self):
        """Create AuthService instance for testing"""
        mock_db = AsyncMock()
        return AuthService(db_session=mock_db)
    
    @pytest.fixture
    def sample_user(self):
        """Create sample user for testing"""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    @pytest.fixture
    def admin_user(self):
        """Create admin user for testing"""
        return User(
            id=2,
            username="adminuser",
            email="admin@example.com",
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    # Token Generation Tests (Lines 444-485)
    async def test_create_access_token_basic(self, auth_service, sample_user):
        """Test basic access token creation"""
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are typically much longer
        
        # Verify token structure (header.payload.signature)
        parts = token.split('.')
        assert len(parts) == 3

    async def test_create_access_token_custom_expiry(self, auth_service, sample_user):
        """Test access token creation with custom expiry"""
        custom_expiry = timedelta(hours=2)
        
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value,
            expires_delta=custom_expiry
        )
        
        # Decode token to verify expiry
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        
        expected_exp = datetime.utcnow() + custom_expiry
        actual_exp = datetime.fromtimestamp(payload['exp'])
        
        # Allow 5 second tolerance
        assert abs((expected_exp - actual_exp).total_seconds()) < 5

    async def test_create_access_token_with_permissions(self, auth_service, admin_user):
        """Test access token creation with custom permissions"""
        permissions = ["read:devices", "write:devices", "admin:users"]
        
        token = await auth_service.create_access_token(
            user_id=admin_user.id,
            username=admin_user.username,
            role=admin_user.role.value,
            permissions=permissions
        )
        
        # Decode and verify permissions
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        
        assert "permissions" in payload
        assert set(payload["permissions"]) == set(permissions)

    async def test_create_access_token_with_claims(self, auth_service, sample_user):
        """Test access token creation with additional claims"""
        additional_claims = {
            "device_access": ["device_1", "device_2"],
            "session_id": "sess_123456",
            "login_method": "password"
        }
        
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value,
            additional_claims=additional_claims
        )
        
        # Decode and verify additional claims
        settings = get_settings()
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        
        for key, value in additional_claims.items():
            assert payload[key] == value

    # Token Validation Tests (Lines 486-551)
    async def test_verify_token_valid(self, auth_service, sample_user):
        """Test verification of valid token"""
        # Create a token first
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        # Verify the token
        payload = await auth_service.verify_token(token)
        
        assert payload is not None
        assert payload["user_id"] == sample_user.id
        assert payload["username"] == sample_user.username
        assert payload["role"] == sample_user.role.value

    async def test_verify_token_expired(self, auth_service, sample_user):
        """Test verification of expired token"""
        # Create token with very short expiry
        short_expiry = timedelta(seconds=-1)  # Already expired
        
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value,
            expires_delta=short_expiry
        )
        
        # Verify the expired token
        payload = await auth_service.verify_token(token)
        assert payload is None

    async def test_verify_token_invalid_signature(self, auth_service, sample_user):
        """Test verification of token with invalid signature"""
        # Create a valid token
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        # Tamper with the token
        parts = token.split('.')
        tampered_token = f"{parts[0]}.{parts[1]}.invalid_signature"
        
        # Verify the tampered token
        payload = await auth_service.verify_token(tampered_token)
        assert payload is None

    async def test_verify_token_malformed(self, auth_service):
        """Test verification of malformed tokens"""
        malformed_tokens = [
            "invalid_token",
            "not.a.jwt",
            "too.few.parts",
            "",
            None,
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.malformed_payload.signature"
        ]
        
        for bad_token in malformed_tokens:
            payload = await auth_service.verify_token(bad_token)
            assert payload is None

    async def test_verify_token_wrong_algorithm(self, auth_service, sample_user):
        """Test verification of token with wrong algorithm"""
        # Create token with different algorithm
        payload = {
            "user_id": sample_user.id,
            "username": sample_user.username,
            "role": sample_user.role.value,
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        
        settings = get_settings()
        token = jwt.encode(payload, settings.jwt_secret_key, algorithm="HS512")
        
        # Try to verify with expected algorithm (should fail)
        verified_payload = await auth_service.verify_token(token)
        assert verified_payload is None

    # Refresh Token Tests (Lines 552-590)
    async def test_create_refresh_token(self, auth_service, sample_user):
        """Test refresh token creation"""
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        assert refresh_token is not None
        assert isinstance(refresh_token, str)
        assert len(refresh_token) > 50
        
        # Verify token structure
        parts = refresh_token.split('.')
        assert len(parts) == 3

    async def test_create_refresh_token_longer_expiry(self, auth_service, sample_user):
        """Test refresh token has longer expiry than access token"""
        access_token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        settings = get_settings()
        
        access_payload = jwt.decode(access_token, settings.jwt_secret_key, algorithms=["HS256"])
        refresh_payload = jwt.decode(refresh_token, settings.jwt_secret_key, algorithms=["HS256"])
        
        # Refresh token should expire later than access token
        assert refresh_payload["exp"] > access_payload["exp"]

    async def test_verify_refresh_token_valid(self, auth_service, sample_user):
        """Test verification of valid refresh token"""
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        payload = await auth_service.verify_refresh_token(refresh_token)
        
        assert payload is not None
        assert payload["user_id"] == sample_user.id
        assert payload["username"] == sample_user.username
        assert payload["token_type"] == "refresh"

    async def test_verify_refresh_token_is_access_token(self, auth_service, sample_user):
        """Test rejection of access token as refresh token"""
        # Create access token
        access_token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        # Try to verify as refresh token (should fail)
        payload = await auth_service.verify_refresh_token(access_token)
        assert payload is None

    # Token Refresh Flow Tests (Lines 591-643)
    async def test_refresh_access_token_success(self, auth_service, sample_user):
        """Test successful access token refresh"""
        # Create refresh token
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            new_access_token = await auth_service.refresh_access_token(refresh_token)
            
            assert new_access_token is not None
            
            # Verify new token is valid
            payload = await auth_service.verify_token(new_access_token)
            assert payload is not None
            assert payload["user_id"] == sample_user.id

    async def test_refresh_access_token_invalid_refresh(self, auth_service):
        """Test access token refresh with invalid refresh token"""
        invalid_refresh_token = "invalid_refresh_token"
        
        new_access_token = await auth_service.refresh_access_token(invalid_refresh_token)
        assert new_access_token is None

    async def test_refresh_access_token_nonexistent_user(self, auth_service, sample_user):
        """Test access token refresh for non-existent user"""
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = None  # User not found
            
            new_access_token = await auth_service.refresh_access_token(refresh_token)
            assert new_access_token is None

    async def test_refresh_access_token_inactive_user(self, auth_service, sample_user):
        """Test access token refresh for inactive user"""
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        
        # Mark user as inactive
        sample_user.status = UserStatus.INACTIVE
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            new_access_token = await auth_service.refresh_access_token(refresh_token)
            assert new_access_token is None

    # Token Blacklisting Tests (Lines 644-700)
    async def test_blacklist_token(self, auth_service, sample_user):
        """Test token blacklisting"""
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        with patch.object(auth_service.db_session, 'add') as mock_add:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                await auth_service.blacklist_token(token)
                
                mock_add.assert_called_once()
                mock_commit.assert_called_once()

    async def test_is_token_blacklisted_true(self, auth_service, sample_user):
        """Test checking if token is blacklisted (blacklisted case)"""
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        # Mock blacklisted token found in database
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = MagicMock()
            
            is_blacklisted = await auth_service.is_token_blacklisted(token)
            assert is_blacklisted is True

    async def test_is_token_blacklisted_false(self, auth_service, sample_user):
        """Test checking if token is blacklisted (not blacklisted case)"""
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        
        # Mock no blacklisted token found
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            is_blacklisted = await auth_service.is_token_blacklisted(token)
            assert is_blacklisted is False

    async def test_cleanup_expired_blacklisted_tokens(self, auth_service):
        """Test cleanup of expired blacklisted tokens"""
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                cleaned_count = await auth_service.cleanup_expired_blacklisted_tokens()
                
                assert cleaned_count >= 0
                mock_execute.assert_called()
                mock_commit.assert_called_once()

    # Token Introspection Tests (Lines 701-727)
    async def test_get_token_info(self, auth_service, sample_user):
        """Test getting token information"""
        permissions = ["read:devices", "write:alerts"]
        additional_claims = {"session_id": "sess_123"}
        
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value,
            permissions=permissions,
            additional_claims=additional_claims
        )
        
        token_info = await auth_service.get_token_info(token)
        
        assert token_info is not None
        assert token_info["user_id"] == sample_user.id
        assert token_info["username"] == sample_user.username
        assert token_info["role"] == sample_user.role.value
        assert set(token_info["permissions"]) == set(permissions)
        assert token_info["session_id"] == "sess_123"

    async def test_get_token_info_invalid_token(self, auth_service):
        """Test getting token information for invalid token"""
        invalid_token = "invalid_token"
        
        token_info = await auth_service.get_token_info(invalid_token)
        assert token_info is None

    async def test_validate_token_permissions(self, auth_service, sample_user):
        """Test token permission validation"""
        required_permissions = ["read:devices", "write:devices"]
        granted_permissions = ["read:devices", "write:devices", "admin:users"]
        
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value,
            permissions=granted_permissions
        )
        
        has_permission = await auth_service.validate_token_permissions(
            token, required_permissions
        )
        assert has_permission is True

    async def test_validate_token_insufficient_permissions(self, auth_service, sample_user):
        """Test token permission validation with insufficient permissions"""
        required_permissions = ["admin:users", "admin:system"]
        granted_permissions = ["read:devices", "write:devices"]
        
        token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value,
            permissions=granted_permissions
        )
        
        has_permission = await auth_service.validate_token_permissions(
            token, required_permissions
        )
        assert has_permission is False

    # Integration Tests
    async def test_complete_token_lifecycle(self, auth_service, sample_user):
        """Test complete token lifecycle: create, verify, refresh, blacklist"""
        # 1. Create access token
        access_token = await auth_service.create_access_token(
            user_id=sample_user.id,
            username=sample_user.username,
            role=sample_user.role.value
        )
        assert access_token is not None
        
        # 2. Verify access token
        payload = await auth_service.verify_token(access_token)
        assert payload is not None
        
        # 3. Create refresh token
        refresh_token = await auth_service.create_refresh_token(
            user_id=sample_user.id,
            username=sample_user.username
        )
        assert refresh_token is not None
        
        # 4. Use refresh token to get new access token
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            new_access_token = await auth_service.refresh_access_token(refresh_token)
            assert new_access_token is not None
            assert new_access_token != access_token
        
        # 5. Blacklist old access token
        with patch.object(auth_service.db_session, 'add'):
            with patch.object(auth_service.db_session, 'commit'):
                await auth_service.blacklist_token(access_token)
        
        # 6. Check blacklist status
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = MagicMock()
            is_blacklisted = await auth_service.is_token_blacklisted(access_token)
            assert is_blacklisted is True

    # Error Handling Tests
    async def test_token_operations_with_missing_secret(self, auth_service, sample_user):
        """Test token operations when JWT secret is missing"""
        with patch('backend.services.auth_service.get_settings') as mock_settings:
            mock_settings.return_value.jwt_secret_key = ""
            
            with pytest.raises(Exception):
                await auth_service.create_access_token(
                    user_id=sample_user.id,
                    username=sample_user.username,
                    role=sample_user.role.value
                )

    async def test_token_operations_with_database_error(self, auth_service):
        """Test token operations when database operations fail"""
        token = "sample_token"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.side_effect = Exception("Database connection failed")
            
            with pytest.raises(Exception):
                await auth_service.is_token_blacklisted(token)

    async def test_concurrent_token_operations(self, auth_service, sample_user):
        """Test concurrent token creation and verification"""
        import asyncio
        
        async def create_and_verify_token():
            token = await auth_service.create_access_token(
                user_id=sample_user.id,
                username=sample_user.username,
                role=sample_user.role.value
            )
            payload = await auth_service.verify_token(token)
            return payload is not None
        
        # Run multiple token operations concurrently
        tasks = [create_and_verify_token() for _ in range(5)]
        results = await asyncio.gather(*tasks)
        
        # All operations should succeed
        assert all(results)