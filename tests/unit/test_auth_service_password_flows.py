"""
Comprehensive Authentication Service Password Flow Tests
Covers lines 156-216, 241-337, 360-427 in backend/services/auth_service.py
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
from passlib.context import CryptContext
import bcrypt

from backend.services.auth_service import AuthService
from backend.models.user import User, UserRole, UserStatus
from core.database import get_db, async_session


class TestAuthServicePasswordFlows:
    """Test all password-related flows in AuthService"""
    
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
            hashed_password="$2b$12$mockhashedpassword",
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )

    # Password Validation Tests (Lines 156-185)
    async def test_validate_password_strength_valid_passwords(self, auth_service):
        """Test password validation with valid passwords"""
        valid_passwords = [
            "StrongPass123!",
            "Complex@Password2024",
            "MySecure#Pass456",
            "ValidPassword789$",
            "GoodChoice!2023"
        ]
        
        for password in valid_passwords:
            result = await auth_service.validate_password_strength(password)
            assert result.is_valid is True
            assert result.score >= 3
            assert len(result.feedback) == 0

    async def test_validate_password_strength_weak_passwords(self, auth_service):
        """Test password validation with weak passwords"""
        weak_passwords = [
            "12345",  # Too short, only numbers
            "password",  # Common password, no complexity
            "PASSWORD",  # No lowercase, no numbers
            "abc123",  # Too short, no special chars
            "aaaaaaaaaa"  # Repeated characters
        ]
        
        for password in weak_passwords:
            result = await auth_service.validate_password_strength(password)
            assert result.is_valid is False
            assert result.score < 3
            assert len(result.feedback) > 0

    async def test_validate_password_strength_edge_cases(self, auth_service):
        """Test password validation edge cases"""
        # Empty password
        result = await auth_service.validate_password_strength("")
        assert result.is_valid is False
        assert "too short" in " ".join(result.feedback).lower()
        
        # Very long password
        long_password = "A" * 200 + "1!"
        result = await auth_service.validate_password_strength(long_password)
        assert result.is_valid is False
        assert "too long" in " ".join(result.feedback).lower()
        
        # Password with username
        result = await auth_service.validate_password_strength("testuser123", username="testuser")
        assert result.is_valid is False
        assert "username" in " ".join(result.feedback).lower()

    # Password Hashing Tests (Lines 186-216)
    async def test_hash_password_bcrypt(self, auth_service):
        """Test password hashing with bcrypt"""
        password = "TestPassword123!"
        hashed = await auth_service.hash_password(password)
        
        assert hashed.startswith("$2b$")
        assert len(hashed) >= 60
        assert hashed != password
        
        # Verify the hash can be validated
        is_valid = await auth_service.verify_password(password, hashed)
        assert is_valid is True

    async def test_hash_password_different_rounds(self, auth_service):
        """Test password hashing with different rounds"""
        password = "TestPassword123!"
        
        # Test with different rounds
        for rounds in [10, 12, 14]:
            with patch.object(auth_service, 'password_rounds', rounds):
                hashed = await auth_service.hash_password(password)
                assert f"$2b${rounds:02d}$" in hashed

    async def test_verify_password_correct(self, auth_service):
        """Test password verification with correct password"""
        password = "CorrectPassword123!"
        hashed = await auth_service.hash_password(password)
        
        is_valid = await auth_service.verify_password(password, hashed)
        assert is_valid is True

    async def test_verify_password_incorrect(self, auth_service):
        """Test password verification with incorrect password"""
        correct_password = "CorrectPassword123!"
        wrong_password = "WrongPassword456!"
        hashed = await auth_service.hash_password(correct_password)
        
        is_valid = await auth_service.verify_password(wrong_password, hashed)
        assert is_valid is False

    async def test_verify_password_malformed_hash(self, auth_service):
        """Test password verification with malformed hash"""
        password = "TestPassword123!"
        malformed_hashes = [
            "invalid_hash",
            "",
            "$2b$12$invalidhash",
            "plaintext_password",
            None
        ]
        
        for bad_hash in malformed_hashes:
            is_valid = await auth_service.verify_password(password, bad_hash)
            assert is_valid is False

    # Password Reset Flow Tests (Lines 241-290)
    async def test_generate_password_reset_token(self, auth_service, sample_user):
        """Test password reset token generation"""
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = sample_user
            
            token = await auth_service.generate_password_reset_token("test@example.com")
            
            assert token is not None
            assert len(token) >= 32
            assert isinstance(token, str)

    async def test_generate_password_reset_token_nonexistent_user(self, auth_service):
        """Test password reset token generation for non-existent user"""
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            token = await auth_service.generate_password_reset_token("nonexistent@example.com")
            assert token is None

    async def test_validate_password_reset_token_valid(self, auth_service, sample_user):
        """Test validation of valid password reset token"""
        token = "valid_reset_token_12345"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = sample_user
            mock_execute.return_value = mock_result
            
            user = await auth_service.validate_password_reset_token(token)
            assert user is not None
            assert user.id == sample_user.id

    async def test_validate_password_reset_token_expired(self, auth_service):
        """Test validation of expired password reset token"""
        expired_token = "expired_token_12345"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            user = await auth_service.validate_password_reset_token(expired_token)
            assert user is None

    async def test_reset_password_with_token(self, auth_service, sample_user):
        """Test password reset with valid token"""
        token = "valid_reset_token"
        new_password = "NewSecurePassword123!"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_execute.return_value.scalar_one_or_none.return_value = sample_user
                
                result = await auth_service.reset_password_with_token(token, new_password)
                
                assert result is True
                mock_commit.assert_called_once()

    async def test_reset_password_with_invalid_token(self, auth_service):
        """Test password reset with invalid token"""
        invalid_token = "invalid_token"
        new_password = "NewSecurePassword123!"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalar_one_or_none.return_value = None
            
            result = await auth_service.reset_password_with_token(invalid_token, new_password)
            assert result is False

    # Password Change Tests (Lines 291-337)
    async def test_change_password_success(self, auth_service, sample_user):
        """Test successful password change"""
        old_password = "OldPassword123!"
        new_password = "NewSecurePassword456!"
        user_id = sample_user.id
        
        # Hash the old password as it would be stored
        sample_user.hashed_password = await auth_service.hash_password(old_password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = sample_user
                
                result = await auth_service.change_password(user_id, old_password, new_password)
                
                assert result is True
                mock_commit.assert_called_once()
                # Verify new password was hashed and stored
                assert sample_user.hashed_password != old_password

    async def test_change_password_wrong_old_password(self, auth_service, sample_user):
        """Test password change with incorrect old password"""
        correct_old_password = "CorrectOldPassword123!"
        wrong_old_password = "WrongOldPassword456!"
        new_password = "NewSecurePassword789!"
        user_id = sample_user.id
        
        # Hash the correct old password
        sample_user.hashed_password = await auth_service.hash_password(correct_old_password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            result = await auth_service.change_password(user_id, wrong_old_password, new_password)
            assert result is False

    async def test_change_password_nonexistent_user(self, auth_service):
        """Test password change for non-existent user"""
        nonexistent_user_id = 99999
        old_password = "OldPassword123!"
        new_password = "NewSecurePassword456!"
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = None
            
            result = await auth_service.change_password(nonexistent_user_id, old_password, new_password)
            assert result is False

    async def test_change_password_weak_new_password(self, auth_service, sample_user):
        """Test password change with weak new password"""
        old_password = "OldPassword123!"
        weak_new_password = "123"  # Too weak
        user_id = sample_user.id
        
        sample_user.hashed_password = await auth_service.hash_password(old_password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            mock_get.return_value = sample_user
            
            with pytest.raises(ValueError, match="Password does not meet strength requirements"):
                await auth_service.change_password(user_id, old_password, weak_new_password)

    # Password History Tests (Lines 360-427)
    async def test_check_password_history_reused(self, auth_service, sample_user):
        """Test password history checking for reused password"""
        user_id = sample_user.id
        reused_password = "ReusedPassword123!"
        
        # Mock password history containing the reused password
        mock_history = [
            MagicMock(hashed_password=await auth_service.hash_password(reused_password)),
            MagicMock(hashed_password=await auth_service.hash_password("OtherPassword456!")),
        ]
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalars.return_value.all.return_value = mock_history
            
            is_reused = await auth_service.check_password_history(user_id, reused_password)
            assert is_reused is True

    async def test_check_password_history_new(self, auth_service, sample_user):
        """Test password history checking for new password"""
        user_id = sample_user.id
        new_password = "NewUniquePassword123!"
        
        # Mock password history with different passwords
        mock_history = [
            MagicMock(hashed_password=await auth_service.hash_password("OldPassword1!")),
            MagicMock(hashed_password=await auth_service.hash_password("OldPassword2!")),
        ]
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            mock_execute.return_value.scalars.return_value.all.return_value = mock_history
            
            is_reused = await auth_service.check_password_history(user_id, new_password)
            assert is_reused is False

    async def test_add_password_to_history(self, auth_service, sample_user):
        """Test adding password to history"""
        user_id = sample_user.id
        password = "NewPasswordForHistory123!"
        
        with patch.object(auth_service.db_session, 'add') as mock_add:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                await auth_service.add_password_to_history(user_id, password)
                
                mock_add.assert_called_once()
                mock_commit.assert_called_once()

    async def test_cleanup_old_password_history(self, auth_service):
        """Test cleanup of old password history entries"""
        user_id = 1
        max_history = 5
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                await auth_service.cleanup_old_password_history(user_id, max_history)
                
                mock_execute.assert_called()
                mock_commit.assert_called_once()

    # Integration Tests
    async def test_full_password_change_flow(self, auth_service, sample_user):
        """Test complete password change flow with history"""
        user_id = sample_user.id
        old_password = "CurrentPassword123!"
        new_password = "NewSecurePassword456!"
        
        # Setup user with hashed password
        sample_user.hashed_password = await auth_service.hash_password(old_password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'execute') as mock_execute:
                with patch.object(auth_service.db_session, 'add') as mock_add:
                    with patch.object(auth_service.db_session, 'commit') as mock_commit:
                        # Mock no password history (new password allowed)
                        mock_execute.return_value.scalars.return_value.all.return_value = []
                        mock_get.return_value = sample_user
                        
                        result = await auth_service.change_password_with_history(
                            user_id, old_password, new_password
                        )
                        
                        assert result is True
                        mock_add.assert_called()  # Password added to history
                        mock_commit.assert_called()

    async def test_password_expiry_checking(self, auth_service, sample_user):
        """Test password expiry checking"""
        # Set password as expired (90+ days old)
        expired_date = datetime.utcnow() - timedelta(days=95)
        sample_user.password_changed_at = expired_date
        
        is_expired = await auth_service.is_password_expired(sample_user)
        assert is_expired is True
        
        # Set password as not expired (30 days old)
        recent_date = datetime.utcnow() - timedelta(days=30)
        sample_user.password_changed_at = recent_date
        
        is_expired = await auth_service.is_password_expired(sample_user)
        assert is_expired is False

    async def test_account_lockout_on_failed_attempts(self, auth_service, sample_user):
        """Test account lockout after multiple failed password attempts"""
        user_id = sample_user.id
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = sample_user
                
                # Simulate 5 failed attempts
                for i in range(5):
                    await auth_service.record_failed_login_attempt(user_id)
                
                # Check if account is locked
                is_locked = await auth_service.is_account_locked(user_id)
                assert is_locked is True
                
                mock_commit.assert_called()

    # Error Handling Tests
    async def test_password_operations_with_database_errors(self, auth_service):
        """Test password operations when database errors occur"""
        user_id = 1
        password = "TestPassword123!"
        
        with patch.object(auth_service.db_session, 'execute') as mock_execute:
            # Simulate database error
            mock_execute.side_effect = Exception("Database connection failed")
            
            with pytest.raises(Exception):
                await auth_service.check_password_history(user_id, password)

    async def test_concurrent_password_changes(self, auth_service, sample_user):
        """Test handling of concurrent password change attempts"""
        user_id = sample_user.id
        old_password = "OldPassword123!"
        new_password1 = "NewPassword1!"
        new_password2 = "NewPassword2!"
        
        sample_user.hashed_password = await auth_service.hash_password(old_password)
        
        with patch.object(auth_service.db_session, 'get') as mock_get:
            with patch.object(auth_service.db_session, 'commit') as mock_commit:
                mock_get.return_value = sample_user
                
                # Simulate concurrent password changes
                tasks = [
                    auth_service.change_password(user_id, old_password, new_password1),
                    auth_service.change_password(user_id, old_password, new_password2)
                ]
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # At least one should succeed
                success_count = sum(1 for result in results if result is True)
                assert success_count >= 1