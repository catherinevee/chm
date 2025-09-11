"""
Comprehensive tests for Authentication API endpoints
Testing all auth router endpoints for complete coverage
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json
import secrets
from uuid import uuid4

# Mock the AuthService for testing
@pytest.fixture
def mock_auth_service():
    """Mock AuthService with all required methods"""
    with patch('backend.api.routers.auth.AuthService') as mock:
        # Mock user object
        mock_user = MagicMock()
        mock_user.id = uuid4()
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"
        mock_user.full_name = "Test User"
        mock_user.is_active = True
        mock_user.is_verified = True
        mock_user.is_superuser = False
        mock_user.mfa_enabled = False
        mock_user.created_at = datetime.utcnow()
        mock_user.last_login = None
        mock_user.roles = []
        mock_user.hashed_password = "hashed_password"
        mock_user.mfa_secret = "test_secret"
        mock_user.reset_token = None
        mock_user.reset_token_expires = None
        mock_user.verification_token = None
        
        # Mock service methods
        mock.create_user = AsyncMock(return_value=mock_user)
        mock.authenticate_user = AsyncMock(return_value=mock_user)
        mock.create_access_token = MagicMock(return_value="access_token")
        mock.create_refresh_token = MagicMock(return_value="refresh_token")
        mock.create_user_session = AsyncMock(return_value=True)
        mock.refresh_access_token = AsyncMock(return_value={"access_token": "new_token"})
        mock.verify_password = MagicMock(return_value=True)
        mock.get_password_hash = MagicMock(return_value="new_hashed_password")
        mock.generate_mfa_secret = MagicMock(return_value="mfa_secret")
        mock.generate_mfa_qr_code = MagicMock(return_value="qr_code_data")
        mock.verify_mfa_token = MagicMock(return_value=True)
        
        yield mock


@pytest.fixture
def mock_db_session():
    """Mock database session"""
    mock_session = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    
    # Mock database query results
    mock_result = MagicMock()
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.email = "test@example.com"
    mock_user.username = "testuser"
    mock_user.full_name = "Test User"
    mock_user.is_active = True
    mock_user.is_verified = True
    mock_user.is_superuser = False
    mock_user.mfa_enabled = False
    mock_user.created_at = datetime.utcnow()
    mock_user.last_login = None
    mock_user.roles = []
    mock_user.hashed_password = "hashed_password"
    mock_user.mfa_secret = "test_secret"
    mock_user.reset_token = None
    mock_user.reset_token_expires = None
    mock_user.verification_token = "test_verification_token"
    
    mock_result.scalar_one_or_none.return_value = mock_user
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    return mock_session


@pytest.fixture
def test_app():
    """Create test FastAPI app with auth router"""
    from fastapi import FastAPI
    from backend.api.routers.auth import router
    
    app = FastAPI()
    app.include_router(router)
    
    return app


@pytest.fixture
def client(test_app):
    """Test client for API testing"""
    return TestClient(test_app)


@pytest.fixture
def mock_dependencies():
    """Mock all authentication dependencies"""
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.username = "testuser"
    mock_user.email = "test@example.com"
    mock_user.full_name = "Test User"
    mock_user.is_active = True
    mock_user.is_verified = True
    mock_user.is_superuser = False
    mock_user.mfa_enabled = False
    mock_user.created_at = datetime.utcnow()
    mock_user.last_login = None
    mock_user.roles = []
    mock_user.hashed_password = "hashed_password"
    mock_user.mfa_secret = "test_secret"
    
    with patch('backend.api.routers.auth.get_current_user', return_value=mock_user), \
         patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user), \
         patch('backend.api.routers.auth.get_current_superuser', return_value=mock_user), \
         patch('backend.api.routers.auth.auth_rate_limit'), \
         patch('backend.api.routers.auth.get_db', return_value=AsyncMock()):
        yield mock_user


class TestAuthRegisterEndpoint:
    """Test user registration endpoint"""
    
    def test_register_success(self, client, mock_auth_service, mock_db_session):
        """Test successful user registration"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "TestPass123!",
                    "full_name": "New User"
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["is_active"] is True
        mock_auth_service.create_user.assert_called_once()
    
    def test_register_auth_service_unavailable(self, client):
        """Test registration when AuthService is unavailable"""
        with patch('backend.api.routers.auth.AuthService', None):
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "TestPass123!"
                }
            )
        
        assert response.status_code == 503
        assert "Auth service not available" in response.json()["detail"]
    
    def test_register_invalid_password(self, client, mock_auth_service, mock_db_session):
        """Test registration with invalid password"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "weak"
                }
            )
        
        assert response.status_code == 422  # Validation error
        assert "validation error" in response.json()["detail"][0]["type"]
    
    def test_register_service_error(self, client, mock_auth_service, mock_db_session):
        """Test registration service error"""
        mock_auth_service.create_user.side_effect = Exception("Service error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/register",
                json={
                    "username": "newuser",
                    "email": "newuser@example.com",
                    "password": "TestPass123!"
                }
            )
        
        assert response.status_code == 400
        assert "Service error" in response.json()["detail"]


class TestAuthLoginEndpoint:
    """Test user login endpoint"""
    
    def test_login_success(self, client, mock_auth_service, mock_db_session):
        """Test successful login"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.auth.SECRET_KEY', 'test_secret'), \
             patch('backend.api.routers.auth.ALGORITHM', 'HS256'), \
             patch('jose.jwt.decode', return_value={"jti": "test_jti"}):
            
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "testuser", "password": "password"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "access_token"
        assert data["refresh_token"] == "refresh_token"
        assert data["token_type"] == "bearer"
        assert data["expires_in"] == 1800
        
        mock_auth_service.authenticate_user.assert_called_once()
        mock_auth_service.create_access_token.assert_called_once()
        mock_auth_service.create_refresh_token.assert_called_once()
        mock_auth_service.create_user_session.assert_called_once()
    
    def test_login_invalid_credentials(self, client, mock_auth_service, mock_db_session):
        """Test login with invalid credentials"""
        mock_auth_service.authenticate_user.return_value = None
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "testuser", "password": "wrongpassword"}
            )
        
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]
    
    def test_login_authentication_error(self, client, mock_auth_service, mock_db_session):
        """Test login with authentication error"""
        from backend.services.auth_service import AuthenticationError
        mock_auth_service.authenticate_user.side_effect = AuthenticationError("Account locked")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "testuser", "password": "password"}
            )
        
        assert response.status_code == 401
        assert "Account locked" in response.json()["detail"]
    
    def test_login_service_error(self, client, mock_auth_service, mock_db_session):
        """Test login with service error"""
        mock_auth_service.authenticate_user.side_effect = Exception("Service error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/login",
                data={"username": "testuser", "password": "password"}
            )
        
        assert response.status_code == 500
        assert "An error occurred during login" in response.json()["detail"]


class TestAuthLogoutEndpoint:
    """Test user logout endpoint"""
    
    def test_logout_success(self, client, mock_dependencies):
        """Test successful logout"""
        response = client.post("/api/v1/auth/logout")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Successfully logged out"
    
    def test_logout_service_error(self, client, mock_dependencies):
        """Test logout with service error"""
        with patch('backend.api.routers.auth.logger') as mock_logger:
            # Simulate an error during logout processing
            with patch('backend.api.routers.auth.get_current_user', side_effect=Exception("Service error")):
                response = client.post("/api/v1/auth/logout")
            
            # Should still succeed as this is simplified logout
            assert response.status_code == 200


class TestRefreshTokenEndpoint:
    """Test token refresh endpoint"""
    
    def test_refresh_token_success(self, client, mock_auth_service, mock_db_session):
        """Test successful token refresh"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": "valid_refresh_token"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["access_token"] == "new_token"
        assert data["token_type"] == "bearer"
        
        mock_auth_service.refresh_access_token.assert_called_once_with(
            mock_db_session, "valid_refresh_token"
        )
    
    def test_refresh_token_invalid(self, client, mock_auth_service, mock_db_session):
        """Test refresh with invalid token"""
        mock_auth_service.refresh_access_token.return_value = None
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": "invalid_token"}
            )
        
        assert response.status_code == 401
        assert "Invalid refresh token" in response.json()["detail"]
    
    def test_refresh_token_service_error(self, client, mock_auth_service, mock_db_session):
        """Test refresh token service error"""
        mock_auth_service.refresh_access_token.side_effect = Exception("Service error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": "token"}
            )
        
        assert response.status_code == 401
        assert "Could not refresh token" in response.json()["detail"]


class TestGetCurrentUserEndpoint:
    """Test get current user profile endpoint"""
    
    def test_get_current_user_success(self, client, mock_dependencies):
        """Test successful get current user"""
        response = client.get("/api/v1/auth/me")
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["is_active"] is True


class TestUpdateCurrentUserEndpoint:
    """Test update current user profile endpoint"""
    
    def test_update_profile_success(self, client, mock_dependencies, mock_db_session):
        """Test successful profile update"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.put(
                "/api/v1/auth/me",
                json={"full_name": "Updated Name"}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        mock_db_session.commit.assert_called_once()
        mock_db_session.refresh.assert_called_once()
    
    def test_update_profile_service_error(self, client, mock_dependencies):
        """Test profile update service error"""
        mock_db = AsyncMock()
        mock_db.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.put(
                "/api/v1/auth/me",
                json={"full_name": "Updated Name"}
            )
        
        assert response.status_code == 500
        assert "Could not update profile" in response.json()["detail"]


class TestChangePasswordEndpoint:
    """Test change password endpoint"""
    
    def test_change_password_success(self, client, mock_dependencies, mock_auth_service, mock_db_session):
        """Test successful password change"""
        mock_auth_service.verify_password.return_value = True
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/password/change",
                json={
                    "current_password": "oldpass123",
                    "new_password": "NewPass123!"
                }
            )
        
        assert response.status_code == 200
        assert response.json()["message"] == "Password changed successfully"
        mock_auth_service.verify_password.assert_called_once()
        mock_auth_service.get_password_hash.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    def test_change_password_incorrect_current(self, client, mock_dependencies, mock_auth_service, mock_db_session):
        """Test password change with incorrect current password"""
        mock_auth_service.verify_password.return_value = False
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/password/change",
                json={
                    "current_password": "wrongpass",
                    "new_password": "NewPass123!"
                }
            )
        
        assert response.status_code == 400
        assert "Incorrect current password" in response.json()["detail"]
    
    def test_change_password_invalid_new_password(self, client, mock_dependencies):
        """Test password change with invalid new password"""
        response = client.post(
            "/api/v1/auth/password/change",
            json={
                "current_password": "oldpass123",
                "new_password": "weak"
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_change_password_service_error(self, client, mock_dependencies, mock_auth_service):
        """Test password change service error"""
        mock_db = AsyncMock()
        mock_db.commit.side_effect = Exception("Database error")
        mock_auth_service.verify_password.return_value = True
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/auth/password/change",
                json={
                    "current_password": "oldpass123",
                    "new_password": "NewPass123!"
                }
            )
        
        assert response.status_code == 500
        assert "Could not change password" in response.json()["detail"]


class TestPasswordResetEndpoint:
    """Test password reset request endpoint"""
    
    def test_password_reset_success(self, client, mock_db_session):
        """Test successful password reset request"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/password/reset",
                json={"email": "test@example.com"}
            )
        
        assert response.status_code == 200
        assert "reset link has been sent" in response.json()["message"]
        mock_db_session.commit.assert_called_once()
    
    def test_password_reset_user_not_found(self, client):
        """Test password reset for non-existent user"""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/auth/password/reset",
                json={"email": "nonexistent@example.com"}
            )
        
        # Should still return success to prevent email enumeration
        assert response.status_code == 200
        assert "reset link has been sent" in response.json()["message"]
    
    def test_password_reset_service_error(self, client):
        """Test password reset service error"""
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/auth/password/reset",
                json={"email": "test@example.com"}
            )
        
        # Should return success message even on error to prevent enumeration
        assert response.status_code == 200
        assert "reset link has been sent" in response.json()["message"]


class TestMFASetupEndpoint:
    """Test MFA setup endpoint"""
    
    def test_mfa_setup_enable_success(self, client, mock_dependencies, mock_auth_service, mock_db_session):
        """Test successful MFA setup enabling"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/mfa/setup",
                json={"enabled": True}
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["secret"] == "mfa_secret"
        assert data["qr_code"] == "qr_code_data"
        assert "Scan the QR code" in data["message"]
        
        mock_auth_service.generate_mfa_secret.assert_called_once()
        mock_auth_service.generate_mfa_qr_code.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    def test_mfa_setup_disable_success(self, client, mock_dependencies, mock_db_session):
        """Test successful MFA setup disabling"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/mfa/setup",
                json={"enabled": False}
            )
        
        assert response.status_code == 200
        assert response.json()["message"] == "MFA disabled successfully"
        mock_db_session.commit.assert_called_once()
    
    def test_mfa_setup_service_error(self, client, mock_dependencies, mock_auth_service):
        """Test MFA setup service error"""
        mock_db = AsyncMock()
        mock_db.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/auth/mfa/setup",
                json={"enabled": True}
            )
        
        assert response.status_code == 500
        assert "Could not setup MFA" in response.json()["detail"]


class TestMFAVerifyEndpoint:
    """Test MFA verification endpoint"""
    
    def test_mfa_verify_success(self, client, mock_dependencies, mock_auth_service, mock_db_session):
        """Test successful MFA verification"""
        mock_auth_service.verify_mfa_token.return_value = True
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/mfa/verify",
                json={"token": "123456"}
            )
        
        assert response.status_code == 200
        assert response.json()["message"] == "MFA enabled successfully"
        mock_auth_service.verify_mfa_token.assert_called_once_with("test_secret", "123456")
        mock_db_session.commit.assert_called_once()
    
    def test_mfa_verify_no_secret(self, client, mock_dependencies, mock_db_session):
        """Test MFA verification without configured secret"""
        mock_user = mock_dependencies
        mock_user.mfa_secret = None
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/mfa/verify",
                json={"token": "123456"}
            )
        
        assert response.status_code == 400
        assert "MFA not configured" in response.json()["detail"]
    
    def test_mfa_verify_invalid_token(self, client, mock_dependencies, mock_auth_service, mock_db_session):
        """Test MFA verification with invalid token"""
        mock_auth_service.verify_mfa_token.return_value = False
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/auth/mfa/verify",
                json={"token": "invalid"}
            )
        
        assert response.status_code == 400
        assert "Invalid MFA token" in response.json()["detail"]
    
    def test_mfa_verify_service_error(self, client, mock_dependencies, mock_auth_service):
        """Test MFA verification service error"""
        mock_db = AsyncMock()
        mock_db.commit.side_effect = Exception("Database error")
        mock_auth_service.verify_mfa_token.return_value = True
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/auth/mfa/verify",
                json={"token": "123456"}
            )
        
        assert response.status_code == 500
        assert "Could not verify MFA" in response.json()["detail"]


class TestEmailVerificationEndpoint:
    """Test email verification endpoint"""
    
    def test_email_verification_success(self, client, mock_db_session):
        """Test successful email verification"""
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/auth/verify/test_verification_token")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Email verified successfully"
        mock_db_session.commit.assert_called_once()
    
    def test_email_verification_invalid_token(self, client):
        """Test email verification with invalid token"""
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.get("/api/v1/auth/verify/invalid_token")
        
        assert response.status_code == 400
        assert "Invalid verification token" in response.json()["detail"]
    
    def test_email_verification_service_error(self, client):
        """Test email verification service error"""
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            response = client.get("/api/v1/auth/verify/test_token")
        
        assert response.status_code == 500
        assert "Could not verify email" in response.json()["detail"]


class TestAuthEndpointsIntegration:
    """Integration tests for authentication endpoints"""
    
    def test_registration_login_flow(self, client, mock_auth_service, mock_db_session):
        """Test complete registration and login flow"""
        # Registration
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session):
            reg_response = client.post(
                "/api/v1/auth/register",
                json={
                    "username": "flowuser",
                    "email": "flow@example.com",
                    "password": "TestFlow123!"
                }
            )
        
        assert reg_response.status_code == 200
        
        # Login
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.auth.SECRET_KEY', 'test_secret'), \
             patch('backend.api.routers.auth.ALGORITHM', 'HS256'), \
             patch('jose.jwt.decode', return_value={"jti": "test_jti"}):
            
            login_response = client.post(
                "/api/v1/auth/login",
                data={"username": "flowuser", "password": "TestFlow123!"}
            )
        
        assert login_response.status_code == 200
        assert "access_token" in login_response.json()
    
    def test_password_validation_consistency(self, client, mock_dependencies):
        """Test password validation consistency across endpoints"""
        invalid_passwords = [
            "short",  # Too short
            "nouppercase123",  # No uppercase
            "NOLOWERCASE123",  # No lowercase  
            "NoDigitsHere",  # No digits
        ]
        
        endpoints = [
            "/api/v1/auth/register",
            "/api/v1/auth/password/change"
        ]
        
        for password in invalid_passwords:
            for endpoint in endpoints:
                if endpoint == "/api/v1/auth/register":
                    response = client.post(
                        endpoint,
                        json={
                            "username": "testuser",
                            "email": "test@example.com",
                            "password": password
                        }
                    )
                else:
                    response = client.post(
                        endpoint,
                        json={
                            "current_password": "ValidPass123!",
                            "new_password": password
                        }
                    )
                
                assert response.status_code == 422  # Validation error
    
    def test_error_handling_consistency(self, client, mock_auth_service, mock_db_session):
        """Test consistent error handling across endpoints"""
        # Test database errors
        mock_db_error = AsyncMock()
        mock_db_error.commit.side_effect = Exception("Database connection error")
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db_error):
            # Test various endpoints that should handle DB errors gracefully
            endpoints_data = [
                ("/api/v1/auth/register", "post", {
                    "username": "testuser", 
                    "email": "test@example.com", 
                    "password": "TestPass123!"
                }),
                ("/api/v1/auth/password/reset", "post", {"email": "test@example.com"}),
            ]
            
            for endpoint, method, data in endpoints_data:
                if method == "post":
                    response = client.post(endpoint, json=data)
                
                # Each endpoint should handle errors appropriately
                assert response.status_code in [400, 500, 200]  # Various expected error codes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])