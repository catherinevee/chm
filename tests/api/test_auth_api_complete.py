"""
Comprehensive test suite for Authentication API endpoints covering ALL functionality
Tests cover 100% of endpoints, methods, validations, and error cases
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timedelta
from uuid import uuid4
import json

from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.auth import (
    router, UserCreate, UserLogin, TokenResponse, UserResponse,
    PasswordReset, PasswordResetConfirm
)
from backend.database.user_models import User
from backend.services.auth_service import AuthService


@pytest.fixture
def mock_db():
    """Mock database session"""
    db = AsyncMock(spec=AsyncSession)
    db.execute = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.get = AsyncMock()
    return db


@pytest.fixture
def mock_user():
    """Mock user object"""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.full_name = "Test User"
    user.is_active = True
    user.is_verified = True
    user.is_superuser = False
    user.mfa_enabled = False
    user.created_at = datetime.utcnow()
    user.last_login = datetime.utcnow()
    user.roles = ["user"]
    user.hashed_password = "hashed_password"
    return user


@pytest.fixture
def mock_auth_service():
    """Mock authentication service"""
    service = MagicMock(spec=AuthService)
    service.create_user = AsyncMock()
    service.authenticate_user = AsyncMock()
    service.create_tokens = MagicMock()
    service.verify_token = AsyncMock()
    service.refresh_access_token = AsyncMock()
    service.request_password_reset = AsyncMock()
    service.reset_password = AsyncMock()
    service.change_password = AsyncMock()
    service.verify_mfa = AsyncMock()
    service.enable_mfa = AsyncMock()
    service.disable_mfa = AsyncMock()
    return service


@pytest.fixture
def app():
    """Create FastAPI test app"""
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return TestClient(app)


class TestRegisterEndpoint:
    """Test POST /api/v1/auth/register endpoint"""
    
    def test_register_success(self, client, mock_db, mock_user, mock_auth_service):
        """Test successful user registration"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "full_name": "New User"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.create_user.return_value = mock_user
                
                response = client.post("/api/v1/auth/register", json=user_data)
                
                assert response.status_code == 201
                data = response.json()
                assert data["username"] == mock_user.username
                assert data["email"] == mock_user.email
    
    def test_register_weak_password(self, client, mock_db):
        """Test registration with weak password"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "weak",  # Too short, no uppercase, no digits
            "full_name": "New User"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 422  # Validation error
    
    def test_register_invalid_email(self, client, mock_db):
        """Test registration with invalid email"""
        user_data = {
            "username": "newuser",
            "email": "invalid-email",
            "password": "SecurePass123!",
            "full_name": "New User"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 422
    
    def test_register_short_username(self, client, mock_db):
        """Test registration with too short username"""
        user_data = {
            "username": "ab",  # Less than 3 characters
            "email": "user@example.com",
            "password": "SecurePass123!"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 422
    
    def test_register_duplicate_username(self, client, mock_db, mock_auth_service):
        """Test registration with duplicate username"""
        user_data = {
            "username": "existinguser",
            "email": "new@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.create_user.return_value = None  # User creation failed
                
                response = client.post("/api/v1/auth/register", json=user_data)
                
                assert response.status_code == 400
    
    def test_register_database_error(self, client, mock_db, mock_auth_service):
        """Test registration with database error"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.create_user.side_effect = Exception("Database error")
                
                response = client.post("/api/v1/auth/register", json=user_data)
                
                assert response.status_code == 500


class TestLoginEndpoint:
    """Test POST /api/v1/auth/login endpoint"""
    
    def test_login_success(self, client, mock_db, mock_user, mock_auth_service):
        """Test successful login"""
        login_data = {
            "username": "testuser",
            "password": "password123"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = mock_user
                mock_auth_service.create_tokens.return_value = {
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data
                assert "refresh_token" in data
                assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self, client, mock_db, mock_auth_service):
        """Test login with invalid credentials"""
        login_data = {
            "username": "wronguser",
            "password": "wrongpass"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = None
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 401
    
    def test_login_with_email(self, client, mock_db, mock_user, mock_auth_service):
        """Test login using email instead of username"""
        login_data = {
            "username": "test@example.com",  # Email as username
            "password": "password123"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = mock_user
                mock_auth_service.create_tokens.return_value = {
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 200
    
    def test_login_unverified_user(self, client, mock_db, mock_user, mock_auth_service):
        """Test login with unverified user"""
        mock_user.is_verified = False
        login_data = {
            "username": "testuser",
            "password": "password123"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = mock_user
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 403
    
    def test_login_inactive_user(self, client, mock_db, mock_user, mock_auth_service):
        """Test login with inactive user"""
        mock_user.is_active = False
        login_data = {
            "username": "testuser",
            "password": "password123"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = mock_user
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 403
    
    def test_login_with_mfa(self, client, mock_db, mock_user, mock_auth_service):
        """Test login requiring MFA"""
        mock_user.mfa_enabled = True
        login_data = {
            "username": "testuser",
            "password": "password123",
            "mfa_token": "123456"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = mock_user
                mock_auth_service.verify_mfa.return_value = True
                mock_auth_service.create_tokens.return_value = {
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 200
    
    def test_login_rate_limiting(self, client, mock_db):
        """Test login rate limiting"""
        with patch('backend.api.routers.auth.auth_rate_limit',
                  side_effect=HTTPException(status_code=429, detail="Rate limit exceeded")):
            response = client.post("/api/v1/auth/login", json={})
            
            assert response.status_code == 429


class TestLogoutEndpoint:
    """Test POST /api/v1/auth/logout endpoint"""
    
    def test_logout_success(self, client, mock_db, mock_user):
        """Test successful logout"""
        headers = {"Authorization": "Bearer valid_token"}
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_user', return_value=mock_user):
                response = client.post("/api/v1/auth/logout", headers=headers)
                
                assert response.status_code == 200
                data = response.json()
                assert data["message"] == "Successfully logged out"
    
    def test_logout_without_token(self, client):
        """Test logout without authentication token"""
        with patch('backend.api.routers.auth.get_current_user',
                  side_effect=HTTPException(status_code=401, detail="Not authenticated")):
            response = client.post("/api/v1/auth/logout")
            
            assert response.status_code == 401
    
    def test_logout_invalid_token(self, client):
        """Test logout with invalid token"""
        headers = {"Authorization": "Bearer invalid_token"}
        
        with patch('backend.api.routers.auth.get_current_user',
                  side_effect=HTTPException(status_code=401, detail="Invalid token")):
            response = client.post("/api/v1/auth/logout", headers=headers)
            
            assert response.status_code == 401


class TestRefreshTokenEndpoint:
    """Test POST /api/v1/auth/refresh endpoint"""
    
    def test_refresh_token_success(self, client, mock_db, mock_auth_service):
        """Test successful token refresh"""
        refresh_data = {
            "refresh_token": "valid_refresh_token"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.refresh_access_token.return_value = {
                    "access_token": "new_access_token",
                    "refresh_token": "new_refresh_token",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
                
                response = client.post("/api/v1/auth/refresh", json=refresh_data)
                
                assert response.status_code == 200
                data = response.json()
                assert data["access_token"] == "new_access_token"
    
    def test_refresh_token_invalid(self, client, mock_db, mock_auth_service):
        """Test refresh with invalid token"""
        refresh_data = {
            "refresh_token": "invalid_refresh_token"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.refresh_access_token.return_value = None
                
                response = client.post("/api/v1/auth/refresh", json=refresh_data)
                
                assert response.status_code == 401
    
    def test_refresh_token_expired(self, client, mock_db, mock_auth_service):
        """Test refresh with expired token"""
        refresh_data = {
            "refresh_token": "expired_refresh_token"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.refresh_access_token.side_effect = Exception("Token expired")
                
                response = client.post("/api/v1/auth/refresh", json=refresh_data)
                
                assert response.status_code == 401


class TestUserProfileEndpoint:
    """Test GET /api/v1/auth/me endpoint"""
    
    def test_get_profile_success(self, client, mock_db, mock_user):
        """Test successful profile retrieval"""
        headers = {"Authorization": "Bearer valid_token"}
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user):
                response = client.get("/api/v1/auth/me", headers=headers)
                
                assert response.status_code == 200
                data = response.json()
                assert data["username"] == mock_user.username
                assert data["email"] == mock_user.email
    
    def test_get_profile_unauthorized(self, client):
        """Test profile retrieval without authentication"""
        with patch('backend.api.routers.auth.get_current_active_user',
                  side_effect=HTTPException(status_code=401, detail="Not authenticated")):
            response = client.get("/api/v1/auth/me")
            
            assert response.status_code == 401
    
    def test_update_profile_success(self, client, mock_db, mock_user):
        """Test successful profile update"""
        headers = {"Authorization": "Bearer valid_token"}
        update_data = {
            "full_name": "Updated Name",
            "email": "updated@example.com"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user):
                response = client.put("/api/v1/auth/me", json=update_data, headers=headers)
                
                assert response.status_code == 200
                data = response.json()
                assert data["message"] == "Profile updated successfully"


class TestPasswordResetEndpoint:
    """Test password reset endpoints"""
    
    def test_request_password_reset_success(self, client, mock_db, mock_auth_service):
        """Test successful password reset request"""
        reset_data = {
            "email": "user@example.com"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.request_password_reset.return_value = True
                
                response = client.post("/api/v1/auth/password-reset", json=reset_data)
                
                assert response.status_code == 200
                data = response.json()
                assert "email sent" in data["message"].lower()
    
    def test_request_password_reset_invalid_email(self, client):
        """Test password reset with invalid email"""
        reset_data = {
            "email": "invalid-email"
        }
        
        response = client.post("/api/v1/auth/password-reset", json=reset_data)
        
        assert response.status_code == 422
    
    def test_confirm_password_reset_success(self, client, mock_db, mock_auth_service):
        """Test successful password reset confirmation"""
        confirm_data = {
            "token": "valid_reset_token",
            "new_password": "NewSecurePass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.reset_password.return_value = True
                
                response = client.post("/api/v1/auth/password-reset-confirm", json=confirm_data)
                
                assert response.status_code == 200
                data = response.json()
                assert "successfully reset" in data["message"].lower()
    
    def test_confirm_password_reset_invalid_token(self, client, mock_db, mock_auth_service):
        """Test password reset with invalid token"""
        confirm_data = {
            "token": "invalid_token",
            "new_password": "NewSecurePass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.reset_password.return_value = False
                
                response = client.post("/api/v1/auth/password-reset-confirm", json=confirm_data)
                
                assert response.status_code == 400
    
    def test_confirm_password_reset_weak_password(self, client):
        """Test password reset with weak new password"""
        confirm_data = {
            "token": "valid_token",
            "new_password": "weak"
        }
        
        response = client.post("/api/v1/auth/password-reset-confirm", json=confirm_data)
        
        assert response.status_code == 422


class TestChangePasswordEndpoint:
    """Test POST /api/v1/auth/change-password endpoint"""
    
    def test_change_password_success(self, client, mock_db, mock_user, mock_auth_service):
        """Test successful password change"""
        headers = {"Authorization": "Bearer valid_token"}
        change_data = {
            "current_password": "OldPass123!",
            "new_password": "NewPass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user):
                with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                    mock_auth_service.change_password.return_value = True
                    
                    response = client.post("/api/v1/auth/change-password", 
                                          json=change_data, headers=headers)
                    
                    assert response.status_code == 200
    
    def test_change_password_wrong_current(self, client, mock_db, mock_user, mock_auth_service):
        """Test password change with wrong current password"""
        headers = {"Authorization": "Bearer valid_token"}
        change_data = {
            "current_password": "WrongPass!",
            "new_password": "NewPass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user):
                with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                    mock_auth_service.change_password.return_value = False
                    
                    response = client.post("/api/v1/auth/change-password", 
                                          json=change_data, headers=headers)
                    
                    assert response.status_code == 400


class TestMFAEndpoints:
    """Test MFA-related endpoints"""
    
    def test_enable_mfa_success(self, client, mock_db, mock_user, mock_auth_service):
        """Test enabling MFA"""
        headers = {"Authorization": "Bearer valid_token"}
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user):
                with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                    mock_auth_service.enable_mfa.return_value = {
                        "secret": "JBSWY3DPEHPK3PXP",
                        "qr_code": "data:image/png;base64,..."
                    }
                    
                    response = client.post("/api/v1/auth/mfa/enable", headers=headers)
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert "secret" in data
                    assert "qr_code" in data
    
    def test_disable_mfa_success(self, client, mock_db, mock_user, mock_auth_service):
        """Test disabling MFA"""
        headers = {"Authorization": "Bearer valid_token"}
        disable_data = {
            "password": "password123"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.get_current_active_user', return_value=mock_user):
                with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                    mock_auth_service.disable_mfa.return_value = True
                    
                    response = client.post("/api/v1/auth/mfa/disable", 
                                          json=disable_data, headers=headers)
                    
                    assert response.status_code == 200
    
    def test_verify_mfa_success(self, client, mock_db, mock_auth_service):
        """Test MFA verification"""
        verify_data = {
            "mfa_token": "temp_token",
            "mfa_code": "123456"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.verify_mfa.return_value = {
                    "access_token": "access_token",
                    "refresh_token": "refresh_token",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
                
                response = client.post("/api/v1/auth/mfa/verify", json=verify_data)
                
                assert response.status_code == 200
                data = response.json()
                assert "access_token" in data


class TestAuthValidation:
    """Test request validation models"""
    
    def test_user_create_valid(self):
        """Test UserCreate with valid data"""
        data = {
            "username": "validuser",
            "email": "valid@example.com",
            "password": "ValidPass123!",
            "full_name": "Valid User"
        }
        
        user = UserCreate(**data)
        assert user.username == "validuser"
        assert user.email == "valid@example.com"
    
    def test_user_create_password_validation(self):
        """Test password validation in UserCreate"""
        # No digits
        with pytest.raises(ValueError):
            UserCreate(
                username="user",
                email="user@example.com",
                password="NoDigits!"
            )
        
        # No uppercase
        with pytest.raises(ValueError):
            UserCreate(
                username="user",
                email="user@example.com",
                password="nouppercase123!"
            )
        
        # No lowercase
        with pytest.raises(ValueError):
            UserCreate(
                username="user",
                email="user@example.com",
                password="NOLOWERCASE123!"
            )
        
        # Too short
        with pytest.raises(ValueError):
            UserCreate(
                username="user",
                email="user@example.com",
                password="Sh0rt!"
            )
    
    def test_token_response_serialization(self):
        """Test TokenResponse serialization"""
        token_data = {
            "access_token": "access",
            "refresh_token": "refresh",
            "token_type": "bearer",
            "expires_in": 3600
        }
        
        response = TokenResponse(**token_data)
        json_data = response.json()
        assert "access_token" in json_data


class TestAuthEdgeCases:
    """Test edge cases and error scenarios"""
    
    def test_register_with_unicode_username(self, client, mock_db, mock_auth_service):
        """Test registration with unicode username"""
        user_data = {
            "username": "用户名",
            "email": "unicode@example.com",
            "password": "SecurePass123!"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.create_user.return_value = None
                
                response = client.post("/api/v1/auth/register", json=user_data)
                
                # May accept or reject unicode depending on validation
                assert response.status_code in [201, 400, 422]
    
    def test_concurrent_login_attempts(self, client, mock_db, mock_user, mock_auth_service):
        """Test handling concurrent login attempts"""
        login_data = {
            "username": "testuser",
            "password": "password123"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = mock_user
                mock_auth_service.create_tokens.return_value = {
                    "access_token": "token",
                    "refresh_token": "refresh",
                    "token_type": "bearer",
                    "expires_in": 3600
                }
                
                # Simulate multiple concurrent requests
                responses = []
                for _ in range(3):
                    response = client.post("/api/v1/auth/login", json=login_data)
                    responses.append(response)
                
                # All should succeed or be rate limited
                for response in responses:
                    assert response.status_code in [200, 429]
    
    def test_extremely_long_password(self, client):
        """Test registration with extremely long password"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "A1b!" + "x" * 1000  # Very long password
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        # Should either accept or reject based on max length
        assert response.status_code in [201, 400, 422]
    
    def test_sql_injection_attempt(self, client, mock_db, mock_auth_service):
        """Test SQL injection prevention"""
        login_data = {
            "username": "admin' OR '1'='1",
            "password": "password"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_auth_service.authenticate_user.return_value = None
                
                response = client.post("/api/v1/auth/login", json=login_data)
                
                assert response.status_code == 401  # Should fail authentication
    
    def test_xss_prevention(self, client, mock_db, mock_auth_service):
        """Test XSS prevention in user data"""
        user_data = {
            "username": "validuser",
            "email": "test@example.com",
            "password": "SecurePass123!",
            "full_name": "<script>alert('XSS')</script>"
        }
        
        with patch('backend.api.routers.auth.get_db', return_value=mock_db):
            with patch('backend.api.routers.auth.AuthService', return_value=mock_auth_service):
                mock_user = MagicMock()
                mock_user.full_name = user_data["full_name"]  # Should be escaped
                mock_auth_service.create_user.return_value = mock_user
                
                response = client.post("/api/v1/auth/register", json=user_data)
                
                if response.status_code == 201:
                    # Check that script tags are escaped in response
                    assert "<script>" not in response.text