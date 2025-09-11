"""
Comprehensive tests for Authentication API endpoints
"""
import pytest
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status

from main import app
from backend.services.auth_service import AuthService, TokenData
from backend.common.exceptions import (
    AuthenticationException, ValidationException, InvalidTokenException,
    SessionExpiredException, AccountLockedException, MFARequiredException,
    DuplicateResourceException, ResourceNotFoundException
)
from models.user import User, UserRole, UserStatus


class TestAuthAPI:
    """Test Authentication API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def auth_service_mock(self):
        """Mock authentication service"""
        return AsyncMock(spec=AuthService)
    
    @pytest.fixture
    def sample_user(self):
        """Sample user for testing"""
        return User(
            id=1,
            username="testuser",
            email="test@example.com",
            first_name="Test",
            last_name="User",
            role=UserRole.USER,
            status=UserStatus.ACTIVE,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    
    @pytest.fixture
    def valid_tokens(self):
        """Valid token pair"""
        return {
            "access_token": "valid_access_token",
            "refresh_token": "valid_refresh_token",
            "token_type": "bearer",
            "expires_in": 3600
        }
    
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

    def test_register_success(self, client):
        """Test successful user registration"""
        registration_data = {
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!",
            "first_name": "New",
            "last_name": "User"
        }
        
        with patch('api.v1.auth.auth_service.register_user') as mock_register:
            new_user = User(id=2, username="newuser", email="new@example.com")
            mock_register.return_value = new_user
            
            response = client.post("/api/v1/auth/register", json=registration_data)
            
            assert response.status_code == status.HTTP_201_CREATED
            data = response.json()
            assert data["username"] == "newuser"
            assert data["email"] == "new@example.com"

    def test_register_duplicate_username(self, client):
        """Test registration with duplicate username"""
        registration_data = {
            "username": "existing",
            "email": "existing@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('api.v1.auth.auth_service.register_user') as mock_register:
            mock_register.side_effect = DuplicateResourceException("Username already exists")
            
            response = client.post("/api/v1/auth/register", json=registration_data)
            
            assert response.status_code == status.HTTP_409_CONFLICT
            assert "already exists" in response.json()["detail"]

    def test_register_invalid_data(self, client):
        """Test registration with invalid data"""
        invalid_data = {
            "username": "",  # Empty username
            "email": "invalid-email",  # Invalid email format
            "password": "weak"  # Weak password
        }
        
        response = client.post("/api/v1/auth/register", json=invalid_data)
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_login_success(self, client, valid_tokens):
        """Test successful login"""
        login_data = {
            "username": "testuser",
            "password": "password123"
        }
        
        with patch('api.v1.auth.auth_service.login') as mock_login:
            mock_login.return_value = valid_tokens
            
            response = client.post("/api/v1/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data
            assert data["token_type"] == "bearer"

    def test_login_form_data(self, client, valid_tokens):
        """Test login with form data (OAuth2 compatible)"""
        form_data = {
            "username": "testuser",
            "password": "password123"
        }
        
        with patch('api.v1.auth.auth_service.login') as mock_login:
            mock_login.return_value = valid_tokens
            
            response = client.post("/api/v1/auth/token", data=form_data)
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"

    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        login_data = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        with patch('api.v1.auth.auth_service.login') as mock_login:
            mock_login.side_effect = AuthenticationException("Invalid credentials")
            
            response = client.post("/api/v1/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED
            assert "Invalid credentials" in response.json()["detail"]

    def test_login_account_locked(self, client):
        """Test login with locked account"""
        login_data = {
            "username": "lockeduser",
            "password": "password123"
        }
        
        with patch('api.v1.auth.auth_service.login') as mock_login:
            mock_login.side_effect = AccountLockedException("Account is locked")
            
            response = client.post("/api/v1/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_423_LOCKED
            assert "locked" in response.json()["detail"]

    def test_login_mfa_required(self, client):
        """Test login when MFA is required"""
        login_data = {
            "username": "mfauser",
            "password": "password123"
        }
        
        with patch('api.v1.auth.auth_service.login') as mock_login:
            mock_login.side_effect = MFARequiredException("MFA token required")
            
            response = client.post("/api/v1/auth/login", json=login_data)
            
            assert response.status_code == status.HTTP_202_ACCEPTED
            assert "MFA" in response.json()["detail"]

    def test_logout_success(self, client):
        """Test successful logout"""
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.logout') as mock_logout:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                
                response = client.post(
                    "/api/v1/auth/logout",
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert response.json()["message"] == "Successfully logged out"

    def test_logout_invalid_token(self, client):
        """Test logout with invalid token"""
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            mock_token.side_effect = InvalidTokenException("Invalid token")
            
            response = client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": "Bearer invalid_token"}
            )
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_token_success(self, client, valid_tokens):
        """Test successful token refresh"""
        refresh_data = {
            "refresh_token": "valid_refresh_token"
        }
        
        with patch('api.v1.auth.auth_service.refresh_token') as mock_refresh:
            mock_refresh.return_value = valid_tokens
            
            response = client.post("/api/v1/auth/refresh", json=refresh_data)
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "access_token" in data
            assert "refresh_token" in data

    def test_refresh_token_invalid(self, client):
        """Test token refresh with invalid refresh token"""
        refresh_data = {
            "refresh_token": "invalid_refresh_token"
        }
        
        with patch('api.v1.auth.auth_service.refresh_token') as mock_refresh:
            mock_refresh.side_effect = InvalidTokenException("Invalid refresh token")
            
            response = client.post("/api/v1/auth/refresh", json=refresh_data)
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_refresh_token_expired(self, client):
        """Test token refresh with expired refresh token"""
        refresh_data = {
            "refresh_token": "expired_refresh_token"
        }
        
        with patch('api.v1.auth.auth_service.refresh_token') as mock_refresh:
            mock_refresh.side_effect = SessionExpiredException("Refresh token expired")
            
            response = client.post("/api/v1/auth/refresh", json=refresh_data)
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_current_user_success(self, client, sample_user):
        """Test getting current user information"""
        with patch('api.v1.auth.get_current_user') as mock_user:
            mock_user.return_value = sample_user
            
            response = client.get(
                "/api/v1/auth/me",
                headers={"Authorization": "Bearer valid_token"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["username"] == "testuser"
            assert data["email"] == "test@example.com"

    def test_get_current_user_unauthorized(self, client):
        """Test getting current user without authentication"""
        response = client.get("/api/v1/auth/me")
        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_change_password_success(self, client):
        """Test successful password change"""
        password_data = {
            "current_password": "oldpassword",
            "new_password": "NewSecurePass123!"
        }
        
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.change_password') as mock_change:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                
                response = client.put(
                    "/api/v1/auth/change-password",
                    json=password_data,
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert response.json()["message"] == "Password changed successfully"

    def test_change_password_wrong_current(self, client):
        """Test password change with wrong current password"""
        password_data = {
            "current_password": "wrongcurrent",
            "new_password": "NewSecurePass123!"
        }
        
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.change_password') as mock_change:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                mock_change.side_effect = AuthenticationException("Current password is incorrect")
                
                response = client.put(
                    "/api/v1/auth/change-password",
                    json=password_data,
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_request_password_reset_success(self, client):
        """Test successful password reset request"""
        reset_data = {
            "email": "test@example.com"
        }
        
        with patch('api.v1.auth.auth_service.reset_password_request') as mock_reset:
            response = client.post("/api/v1/auth/reset-password", json=reset_data)
            
            assert response.status_code == status.HTTP_200_OK
            assert "reset instructions" in response.json()["message"]

    def test_confirm_password_reset_success(self, client):
        """Test successful password reset confirmation"""
        confirm_data = {
            "token": "valid_reset_token",
            "new_password": "NewSecurePass123!"
        }
        
        with patch('api.v1.auth.auth_service.reset_password_confirm') as mock_confirm:
            response = client.post("/api/v1/auth/reset-password/confirm", json=confirm_data)
            
            assert response.status_code == status.HTTP_200_OK
            assert "reset successfully" in response.json()["message"]

    def test_confirm_password_reset_invalid_token(self, client):
        """Test password reset confirmation with invalid token"""
        confirm_data = {
            "token": "invalid_reset_token",
            "new_password": "NewSecurePass123!"
        }
        
        with patch('api.v1.auth.auth_service.reset_password_confirm') as mock_confirm:
            mock_confirm.side_effect = InvalidTokenException("Invalid reset token")
            
            response = client.post("/api/v1/auth/reset-password/confirm", json=confirm_data)
            
            assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_setup_mfa_success(self, client):
        """Test successful MFA setup"""
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.setup_mfa') as mock_setup:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                mock_setup.return_value = {
                    "secret": "MFASECRET123",
                    "qr_code": "data:image/png;base64,..."
                }
                
                response = client.post(
                    "/api/v1/auth/mfa/setup",
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert "secret" in data
                assert "qr_code" in data

    def test_verify_mfa_success(self, client):
        """Test successful MFA verification"""
        mfa_data = {
            "token": "123456"
        }
        
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.verify_mfa_setup') as mock_verify:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                mock_verify.return_value = True
                
                response = client.post(
                    "/api/v1/auth/mfa/verify",
                    json=mfa_data,
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert "enabled successfully" in response.json()["message"]

    def test_verify_mfa_invalid_token(self, client):
        """Test MFA verification with invalid token"""
        mfa_data = {
            "token": "invalid"
        }
        
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.verify_mfa_setup') as mock_verify:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                mock_verify.return_value = False
                
                response = client.post(
                    "/api/v1/auth/mfa/verify",
                    json=mfa_data,
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_disable_mfa_success(self, client):
        """Test successful MFA disable"""
        mfa_data = {
            "token": "123456"
        }
        
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.disable_mfa') as mock_disable:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                
                response = client.post(
                    "/api/v1/auth/mfa/disable",
                    json=mfa_data,
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert "disabled successfully" in response.json()["message"]

    def test_login_with_mfa_success(self, client, valid_tokens):
        """Test successful login with MFA token"""
        login_data = {
            "username": "mfauser",
            "password": "password123",
            "mfa_token": "123456"
        }
        
        with patch('api.v1.auth.auth_service.login_with_mfa') as mock_login:
            mock_login.return_value = valid_tokens
            
            response = client.post("/api/v1/auth/login/mfa", json=login_data)
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert "access_token" in data

    def test_login_with_mfa_invalid_token(self, client):
        """Test login with invalid MFA token"""
        login_data = {
            "username": "mfauser",
            "password": "password123",
            "mfa_token": "invalid"
        }
        
        with patch('api.v1.auth.auth_service.login_with_mfa') as mock_login:
            mock_login.side_effect = AuthenticationException("Invalid MFA token")
            
            response = client.post("/api/v1/auth/login/mfa", json=login_data)
            
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_get_user_sessions(self, client):
        """Test getting user sessions"""
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.get_user_sessions') as mock_sessions:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                mock_sessions.return_value = [
                    {
                        "session_id": "session1",
                        "created_at": datetime.now(),
                        "last_activity": datetime.now(),
                        "ip_address": "192.168.1.100",
                        "user_agent": "Mozilla/5.0..."
                    }
                ]
                
                response = client.get(
                    "/api/v1/auth/sessions",
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data) >= 1

    def test_revoke_session_success(self, client):
        """Test successful session revocation"""
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.revoke_session') as mock_revoke:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                
                response = client.delete(
                    "/api/v1/auth/sessions/session123",
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert "revoked" in response.json()["message"]

    def test_revoke_all_sessions_success(self, client):
        """Test successful revocation of all sessions"""
        with patch('api.v1.auth.get_current_token_data') as mock_token:
            with patch('api.v1.auth.auth_service.revoke_all_sessions') as mock_revoke:
                mock_token.return_value = TokenData(user_id=1, username="testuser")
                
                response = client.delete(
                    "/api/v1/auth/sessions",
                    headers={"Authorization": "Bearer valid_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert "All sessions revoked" in response.json()["message"]

    def test_validate_token_success(self, client, token_data):
        """Test successful token validation"""
        with patch('api.v1.auth.auth_service.verify_token') as mock_verify:
            mock_verify.return_value = token_data
            
            response = client.post(
                "/api/v1/auth/validate",
                headers={"Authorization": "Bearer valid_token"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["valid"] is True
            assert data["user_id"] == 1

    def test_validate_token_invalid(self, client):
        """Test token validation with invalid token"""
        with patch('api.v1.auth.auth_service.verify_token') as mock_verify:
            mock_verify.side_effect = InvalidTokenException("Invalid token")
            
            response = client.post(
                "/api/v1/auth/validate",
                headers={"Authorization": "Bearer invalid_token"}
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["valid"] is False

    def test_rate_limiting(self, client):
        """Test rate limiting on login attempts"""
        login_data = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        with patch('api.v1.auth.auth_service.login') as mock_login:
            mock_login.side_effect = AuthenticationException("Invalid credentials")
            
            # Make multiple rapid requests
            responses = []
            for _ in range(10):
                response = client.post("/api/v1/auth/login", json=login_data)
                responses.append(response)
            
            # Last few requests should be rate limited
            assert any(r.status_code == status.HTTP_429_TOO_MANY_REQUESTS for r in responses[-3:])

    def test_cors_headers(self, client):
        """Test CORS headers in response"""
        response = client.options("/api/v1/auth/login")
        # CORS headers should be present based on middleware configuration
        # Exact headers depend on CORS middleware setup