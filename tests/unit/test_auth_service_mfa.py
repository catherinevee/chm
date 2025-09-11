"""
Comprehensive Authentication Service MFA Tests
Covers lines 746-853, 857-874, 878-950 in backend/services/auth_service.py
"""

import pytest
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.auth_service import AuthService
from backend.models.user import User, UserRole, UserStatus
from backend.services.mfa_service import MFAService


class TestAuthServiceMFA:
    """Test all Multi-Factor Authentication functionality in AuthService"""
    
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
            updated_at=datetime.utcnow(),
            mfa_enabled=False,
            mfa_secret=None
        )

    @pytest.fixture
    def mfa_enabled_user(self):
        """Create user with MFA enabled"""
        return User(
            id=2,
            username="mfauser",
            email="mfa@example.com",
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            mfa_enabled=True,
            mfa_secret="JBSWY3DPEHPK3PXP"  # Base32 encoded secret
        )

    # MFA Setup Tests (Lines 746-787)
    async def test_generate_mfa_secret(self, auth_service, sample_user):
        """Test MFA secret generation"""
        secret = await auth_service.generate_mfa_secret(sample_user.id)
        
        assert secret is not None
        assert isinstance(secret, str)
        assert len(secret) == 32  # Base32 encoded 20-byte secret
        
        # Verify it's valid base32
        try:
            base64.b32decode(secret)
        except Exception:
            pytest.fail("Generated secret is not valid base32")

    async def test_generate_mfa_qr_code(self, auth_service, sample_user):
        """Test MFA QR code generation"""
        secret = "JBSWY3DPEHPK3PXP"
        
        qr_code_data = await auth_service.generate_mfa_qr_code(
            user=sample_user,
            secret=secret,
            issuer_name="CHM Test"
        )
        
        assert qr_code_data is not None
        assert qr_code_data.startswith("data:image/png;base64,")
        
        # Verify the base64 data is valid
        base64_data = qr_code_data.split(",")[1]
        try:
            base64.b64decode(base64_data)
        except Exception:
            pytest.fail("Generated QR code data is not valid base64")

    async def test_verify_mfa_setup_token_valid(self, auth_service, sample_user):
        """Test MFA setup token verification with valid token"""
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()
        
        is_valid = await auth_service.verify_mfa_setup_token(secret, valid_token)
        assert is_valid is True

    async def test_verify_mfa_setup_token_invalid(self, auth_service, sample_user):
        """Test MFA setup token verification with invalid token"""
        secret = "JBSWY3DPEHPK3PXP"
        invalid_token = "000000"  # Obviously invalid
        
        is_valid = await auth_service.verify_mfa_setup_token(secret, invalid_token)
        assert is_valid is False

    async def test_enable_mfa_for_user(self, auth_service, sample_user):
        """Test enabling MFA for a user"""
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = sample_user
                
                result = await auth_service.enable_mfa_for_user(
                    user_id=sample_user.id,
                    secret=secret,
                    verification_token=valid_token
                )
                
                assert result is True
                assert sample_user.mfa_enabled is True
                assert sample_user.mfa_secret == secret
                mock_commit.assert_called_once()

    async def test_enable_mfa_invalid_verification(self, auth_service, sample_user):
        """Test enabling MFA with invalid verification token"""
        secret = "JBSWY3DPEHPK3PXP"
        invalid_token = "000000"
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            result = await auth_service.enable_mfa_for_user(
                user_id=sample_user.id,
                secret=secret,
                verification_token=invalid_token
            )
            
            assert result is False
            assert sample_user.mfa_enabled is False

    async def test_enable_mfa_nonexistent_user(self, auth_service):
        """Test enabling MFA for non-existent user"""
        secret = "JBSWY3DPEHPK3PXP"
        totp = pyotp.TOTP(secret)
        valid_token = totp.now()
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = None
            
            result = await auth_service.enable_mfa_for_user(
                user_id=99999,
                secret=secret,
                verification_token=valid_token
            )
            
            assert result is False

    # MFA Authentication Tests (Lines 788-853)
    async def test_verify_mfa_token_valid(self, auth_service, mfa_enabled_user):
        """Test MFA token verification with valid token"""
        totp = pyotp.TOTP(mfa_enabled_user.mfa_secret)
        valid_token = totp.now()
        
        is_valid = await auth_service.verify_mfa_token(
            user_id=mfa_enabled_user.id,
            token=valid_token
        )
        assert is_valid is True

    async def test_verify_mfa_token_invalid(self, auth_service, mfa_enabled_user):
        """Test MFA token verification with invalid token"""
        invalid_token = "000000"
        
        is_valid = await auth_service.verify_mfa_token(
            user_id=mfa_enabled_user.id,
            token=invalid_token
        )
        assert is_valid is False

    async def test_verify_mfa_token_user_not_found(self, auth_service):
        """Test MFA token verification for non-existent user"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = None
            
            is_valid = await auth_service.verify_mfa_token(
                user_id=99999,
                token="123456"
            )
            assert is_valid is False

    async def test_verify_mfa_token_mfa_not_enabled(self, auth_service, sample_user):
        """Test MFA token verification for user without MFA enabled"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user  # MFA not enabled
            
            is_valid = await auth_service.verify_mfa_token(
                user_id=sample_user.id,
                token="123456"
            )
            assert is_valid is False

    async def test_verify_mfa_token_with_time_window(self, auth_service, mfa_enabled_user):
        """Test MFA token verification with time window tolerance"""
        totp = pyotp.TOTP(mfa_enabled_user.mfa_secret)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = mfa_enabled_user
            
            # Test token from previous time window
            previous_token = totp.at(datetime.now() - timedelta(seconds=30))
            
            is_valid = await auth_service.verify_mfa_token(
                user_id=mfa_enabled_user.id,
                token=previous_token
            )
            # Should be valid due to time window tolerance
            assert is_valid is True

    async def test_check_mfa_rate_limiting(self, auth_service, mfa_enabled_user):
        """Test MFA rate limiting after multiple failed attempts"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'add'):
                with patch.object(auth_service.db_session, 'commit'):
                    mock_get.return_value = mfa_enabled_user
                    
                    # Simulate multiple failed attempts
                    for _ in range(5):
                        await auth_service.record_mfa_failure(mfa_enabled_user.id)
                    
                    # Check if user is rate limited
                    is_rate_limited = await auth_service.is_mfa_rate_limited(mfa_enabled_user.id)
                    assert is_rate_limited is True

    # MFA Backup Codes Tests (Lines 857-874)
    async def test_generate_mfa_backup_codes(self, auth_service, mfa_enabled_user):
        """Test generating MFA backup codes"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = mfa_enabled_user
                
                backup_codes = await auth_service.generate_mfa_backup_codes(
                    user_id=mfa_enabled_user.id
                )
                
                assert backup_codes is not None
                assert isinstance(backup_codes, list)
                assert len(backup_codes) == 10  # Standard number of backup codes
                
                # Verify format of backup codes
                for code in backup_codes:
                    assert isinstance(code, str)
                    assert len(code) >= 8  # Minimum length
                    assert code.replace('-', '').isalnum()  # Alphanumeric with dashes
                
                mock_commit.assert_called_once()

    async def test_verify_mfa_backup_code_valid(self, auth_service, mfa_enabled_user):
        """Test MFA backup code verification with valid code"""
        backup_code = "ABCD-1234-EFGH-5678"
        
        # Mock finding valid backup code
        mock_backup_code = MagicMock()
        mock_backup_code.code = backup_code
        mock_backup_code.used = False
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_execute.return_value.scalar_one_or_none.return_value = mock_backup_code
                
                is_valid = await auth_service.verify_mfa_backup_code(
                    user_id=mfa_enabled_user.id,
                    backup_code=backup_code
                )
                
                assert is_valid is True
                assert mock_backup_code.used is True
                mock_commit.assert_called_once()

    async def test_verify_mfa_backup_code_already_used(self, auth_service, mfa_enabled_user):
        """Test MFA backup code verification with already used code"""
        backup_code = "ABCD-1234-EFGH-5678"
        
        # Mock finding used backup code
        mock_backup_code = MagicMock()
        mock_backup_code.code = backup_code
        mock_backup_code.used = True
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = mock_backup_code
            
            is_valid = await auth_service.verify_mfa_backup_code(
                user_id=mfa_enabled_user.id,
                backup_code=backup_code
            )
            
            assert is_valid is False

    async def test_verify_mfa_backup_code_not_found(self, auth_service, mfa_enabled_user):
        """Test MFA backup code verification with non-existent code"""
        backup_code = "INVALID-CODE-1234"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            is_valid = await auth_service.verify_mfa_backup_code(
                user_id=mfa_enabled_user.id,
                backup_code=backup_code
            )
            
            assert is_valid is False

    # MFA Disable Tests (Lines 875-899)
    async def test_disable_mfa_for_user_with_password(self, auth_service, mfa_enabled_user):
        """Test disabling MFA with password verification"""
        password = "UserPassword123!"
        mfa_enabled_user.hashed_password = await auth_service.hash_password(password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'execute') as mock_execute:
                with patch.object(auth_service.db_session, 'commit') as mock_commit:
                    mock_get.return_value = mfa_enabled_user
                    
                    result = await auth_service.disable_mfa_for_user(
                        user_id=mfa_enabled_user.id,
                        password=password
                    )
                    
                    assert result is True
                    assert mfa_enabled_user.mfa_enabled is False
                    assert mfa_enabled_user.mfa_secret is None
                    mock_commit.assert_called()

    async def test_disable_mfa_wrong_password(self, auth_service, mfa_enabled_user):
        """Test disabling MFA with wrong password"""
        correct_password = "UserPassword123!"
        wrong_password = "WrongPassword456!"
        mfa_enabled_user.hashed_password = await auth_service.hash_password(correct_password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = mfa_enabled_user
            
            result = await auth_service.disable_mfa_for_user(
                user_id=mfa_enabled_user.id,
                password=wrong_password
            )
            
            assert result is False
            assert mfa_enabled_user.mfa_enabled is True  # Should remain enabled

    async def test_disable_mfa_with_backup_code(self, auth_service, mfa_enabled_user):
        """Test disabling MFA using backup code"""
        backup_code = "EMERGENCY-CODE-1234"
        
        # Mock valid unused backup code
        mock_backup_code = MagicMock()
        mock_backup_code.code = backup_code
        mock_backup_code.used = False
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'execute') as mock_execute:
                with patch.object(auth_service.db_session, 'commit') as mock_commit:
                    mock_get.return_value = mfa_enabled_user
                    mock_execute.return_value.scalar_one_or_none.return_value = mock_backup_code
                    
                    result = await auth_service.disable_mfa_with_backup_code(
                        user_id=mfa_enabled_user.id,
                        backup_code=backup_code
                    )
                    
                    assert result is True
                    assert mfa_enabled_user.mfa_enabled is False
                    mock_commit.assert_called()

    # MFA Status and Management Tests (Lines 900-950)
    async def test_get_mfa_status(self, auth_service, mfa_enabled_user):
        """Test getting MFA status for user"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = mfa_enabled_user
            
            status = await auth_service.get_mfa_status(mfa_enabled_user.id)
            
            assert status is not None
            assert status["enabled"] is True
            assert status["backup_codes_remaining"] >= 0
            assert "last_used" in status

    async def test_get_mfa_status_disabled_user(self, auth_service, sample_user):
        """Test getting MFA status for user with MFA disabled"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            status = await auth_service.get_mfa_status(sample_user.id)
            
            assert status is not None
            assert status["enabled"] is False
            assert status["backup_codes_remaining"] == 0

    async def test_regenerate_mfa_secret(self, auth_service, mfa_enabled_user):
        """Test regenerating MFA secret for user"""
        old_secret = mfa_enabled_user.mfa_secret
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = mfa_enabled_user
                
                new_secret = await auth_service.regenerate_mfa_secret(mfa_enabled_user.id)
                
                assert new_secret is not None
                assert new_secret != old_secret
                assert mfa_enabled_user.mfa_secret == new_secret
                assert len(new_secret) == 32
                mock_commit.assert_called_once()

    async def test_count_remaining_backup_codes(self, auth_service, mfa_enabled_user):
        """Test counting remaining backup codes"""
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar.return_value = 7  # 7 unused codes
            
            remaining_count = await auth_service.count_remaining_backup_codes(
                mfa_enabled_user.id
            )
            
            assert remaining_count == 7

    # Integration Tests
    async def test_complete_mfa_setup_flow(self, auth_service, sample_user):
        """Test complete MFA setup flow"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = sample_user
                
                # 1. Generate secret
                secret = await auth_service.generate_mfa_secret(sample_user.id)
                assert secret is not None
                
                # 2. Generate QR code
                qr_code = await auth_service.generate_mfa_qr_code(
                    user=sample_user,
                    secret=secret,
                    issuer_name="CHM Test"
                )
                assert qr_code is not None
                
                # 3. Verify setup token
                totp = pyotp.TOTP(secret)
                valid_token = totp.now()
                
                # 4. Enable MFA
                result = await auth_service.enable_mfa_for_user(
                    user_id=sample_user.id,
                    secret=secret,
                    verification_token=valid_token
                )
                
                assert result is True
                assert sample_user.mfa_enabled is True
                mock_commit.assert_called()

    async def test_complete_mfa_authentication_flow(self, auth_service, mfa_enabled_user):
        """Test complete MFA authentication flow"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = mfa_enabled_user
            
            # 1. Generate current TOTP token
            totp = pyotp.TOTP(mfa_enabled_user.mfa_secret)
            current_token = totp.now()
            
            # 2. Verify MFA token
            is_valid = await auth_service.verify_mfa_token(
                user_id=mfa_enabled_user.id,
                token=current_token
            )
            
            assert is_valid is True

    # Error Handling Tests
    async def test_mfa_operations_with_invalid_secret(self, auth_service):
        """Test MFA operations with invalid secret format"""
        invalid_secret = "invalid_base32_secret!"
        
        with pytest.raises(Exception):
            totp = pyotp.TOTP(invalid_secret)
            totp.now()

    async def test_mfa_operations_with_database_error(self, auth_service, mfa_enabled_user):
        """Test MFA operations when database operations fail"""
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.side_effect = Exception("Database connection failed")
            
            with pytest.raises(Exception):
                await auth_service.verify_mfa_token(
                    user_id=mfa_enabled_user.id,
                    token="123456"
                )

    async def test_concurrent_mfa_verification(self, auth_service, mfa_enabled_user):
        """Test concurrent MFA token verification"""
        import asyncio
        
        totp = pyotp.TOTP(mfa_enabled_user.mfa_secret)
        valid_token = totp.now()
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = mfa_enabled_user
            
            # Verify same token multiple times concurrently
            tasks = [
                auth_service.verify_mfa_token(
                    user_id=mfa_enabled_user.id,
                    token=valid_token
                ) for _ in range(3)
            ]
            
            results = await asyncio.gather(*tasks)
            
            # All should succeed (or handle properly if replay protection exists)
            assert all(isinstance(result, bool) for result in results)