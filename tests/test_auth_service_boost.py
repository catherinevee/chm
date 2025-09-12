"""
Strategic auth service tests to boost coverage from 20% to 35%+
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test environment
os.environ.update({
    'TESTING': 'true',
    'DATABASE_URL': 'sqlite+aiosqlite:///:memory:',
    'JWT_SECRET_KEY': 'test-secret',
    'SECRET_KEY': 'test-secret',
    'DEBUG': 'true'
})

import pytest
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta


class TestAuthServiceBasics:
    """Strategic tests for auth service basic functionality"""
    
    def test_auth_service_import(self):
        """Test auth service can be imported"""
        from backend.services.auth_service import AuthService, auth_service
        assert AuthService is not None
        assert auth_service is not None
        
    def test_auth_service_instance(self):
        """Test AuthService instantiation"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        assert service is not None
        assert hasattr(service, 'pwd_context')
        assert hasattr(service, 'secret_key')
        
    def test_password_hashing(self):
        """Test password hashing methods"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        
        password = "TestPassword123!"
        
        # Test password hashing
        hashed = service.hash_password(password)
        assert hashed is not None
        assert hashed != password
        assert len(hashed) > 20  # bcrypt hashes are long
        
        # Test password verification
        assert service.verify_password(password, hashed) is True
        assert service.verify_password("wrong_password", hashed) is False
        
    def test_jwt_token_methods(self):
        """Test JWT token creation and verification"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        
        # Test token creation
        data = {"sub": "testuser", "user_id": 123}
        token = service.create_access_token(data)
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are long
        
        # Test token creation with expiry
        expires_delta = timedelta(hours=1)
        token_with_expiry = service.create_access_token(data, expires_delta)
        assert token_with_expiry is not None
        assert isinstance(token_with_expiry, str)
        
    @pytest.mark.asyncio
    async def test_verify_token(self):
        """Test token verification"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        
        # Create a token
        data = {"sub": "testuser"}
        token = service.create_access_token(data)
        
        # Verify the token
        payload = await service.verify_token(token)
        assert payload is not None
        assert payload.get("sub") == "testuser"
        
        # Test invalid token
        invalid_payload = await service.verify_token("invalid.token.here")
        assert invalid_payload is None
        
    def test_auth_service_properties(self):
        """Test auth service properties and configuration"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        
        # Test properties exist
        assert hasattr(service, 'algorithm')
        assert hasattr(service, 'access_token_expire_minutes')
        assert hasattr(service, 'refresh_token_expire_days')
        
        # Test some values
        assert service.algorithm == "HS256"
        assert service.access_token_expire_minutes > 0
        assert service.refresh_token_expire_days > 0


class TestAuthServiceHelpers:
    """Test helper methods in auth service"""
    
    def test_generate_password_reset_token(self):
        """Test password reset token generation"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        
        # Test token generation
        token = service.generate_password_reset_token("user@example.com")
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20
        
    def test_get_email_from_token(self):
        """Test extracting email from token"""
        from backend.services.auth_service import AuthService
        service = AuthService()
        
        email = "user@example.com"
        token = service.generate_password_reset_token(email)
        
        # Extract email from token
        extracted_email = service.get_email_from_token(token)
        assert extracted_email == email
        
        # Test invalid token
        invalid_email = service.get_email_from_token("invalid_token")
        assert invalid_email is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])