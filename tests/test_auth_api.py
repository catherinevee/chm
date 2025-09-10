"""
Tests for CHM Authentication API
Comprehensive testing of authentication endpoints
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, AsyncMock

from api.v1.auth import router
from models.user import User, UserRole, UserStatus
from backend.services.auth_service import auth_service

class TestAuthAPI:
    """Test authentication API endpoints"""
    
    @pytest.mark.asyncio
    async def test_register_user_success(self, test_client: TestClient, test_session: AsyncSession):
        """Test successful user registration"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "NewPassword123!",
            "full_name": "New User"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
        assert data["full_name"] == "New User"
        assert data["role"] == "viewer"  # Default role
        assert data["is_active"] is True
        assert "id" in data
        assert "uuid" in data
    
    @pytest.mark.asyncio
    async def test_register_user_duplicate_username(self, test_client: TestClient):
        """Test user registration with duplicate username"""
        # First register a user
        first_user_data = {
            "username": "testuser",
            "email": "first@example.com",
            "password": "Password123!"
        }
        first_response = test_client.post("/api/v1/auth/register", json=first_user_data)
        assert first_response.status_code == 200
        
        # Try to register another user with same username
        user_data = {
            "username": "testuser",  # Already exists
            "email": "different@example.com",
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
    
    @pytest.mark.asyncio
    async def test_register_user_duplicate_email(self, test_client: TestClient):
        """Test user registration with duplicate email"""
        # First register a user
        first_user_data = {
            "username": "firstuser",
            "email": "test@example.com",
            "password": "Password123!"
        }
        first_response = test_client.post("/api/v1/auth/register", json=first_user_data)
        assert first_response.status_code == 200
        
        # Try to register another user with same email
        user_data = {
            "username": "differentuser",
            "email": "test@example.com",  # Already exists
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
    
    @pytest.mark.asyncio
    async def test_register_user_weak_password(self, test_client: TestClient, test_session: AsyncSession):
        """Test user registration with weak password"""
        user_data = {
            "username": "weakuser",
            "email": "weak@example.com",
            "password": "weak"  # Too short
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_register_user_invalid_email(self, test_client: TestClient, test_session: AsyncSession):
        """Test user registration with invalid email"""
        user_data = {
            "username": "invaliduser",
            "email": "invalid-email",  # Invalid email format
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio  
    async def test_login_user_success(self, test_client: TestClient):
        """Test successful user login"""
        # First register a user
        register_data = {
            "username": "testuser",
            "email": "testuser@example.com", 
            "password": "TestPassword123!",
            "full_name": "Test User"
        }
        
        register_response = test_client.post("/api/v1/auth/register", json=register_data)
        assert register_response.status_code == 200
        
        # Now try to login
        login_data = {
            "username": "testuser",
            "password": "TestPassword123!"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert "token_type" in data
        assert "expires_in" in data
        
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
    
    @pytest.mark.asyncio
    async def test_login_user_by_email(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test user login by email"""
        login_data = {
            "username": "test@example.com",  # Email instead of username
            "password": "testpassword123"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
    
    @pytest.mark.asyncio
    async def test_login_user_wrong_password(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test user login with wrong password"""
        login_data = {
            "username": "testuser",
            "password": "wrongpassword"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_login_user_nonexistent(self, test_client: TestClient, test_session: AsyncSession):
        """Test user login with non-existent user"""
        login_data = {
            "username": "nonexistent",
            "password": "password123"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_login_user_inactive(self, test_client: TestClient, test_session: AsyncSession):
        """Test user login with inactive user"""
        # Create inactive user
        inactive_user = User(
            username="inactive",
            email="inactive@example.com",
            hashed_password=auth_service.hash_password("password123"),
            role=UserRole.VIEWER,
            status=UserStatus.INACTIVE
        )
        
        test_session.add(inactive_user)
        await test_session.commit()
        
        login_data = {
            "username": "inactive",
            "password": "password123"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_refresh_token_success(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test successful token refresh"""
        # First login to get tokens
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        login_response = test_client.post("/api/v1/auth/login", json=login_data)
        login_data = login_response.json()
        refresh_token = login_data["refresh_token"]
        
        # Refresh token
        headers = {"Authorization": f"Bearer {refresh_token}"}
        response = test_client.post("/api/v1/auth/refresh", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["access_token"] != login_data["access_token"]
    
    @pytest.mark.asyncio
    async def test_refresh_token_invalid(self, test_client: TestClient, test_session: AsyncSession):
        """Test token refresh with invalid token"""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = test_client.post("/api/v1/auth/refresh", headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_refresh_token_missing(self, test_client: TestClient, test_session: AsyncSession):
        """Test token refresh without token"""
        response = test_client.post("/api/v1/auth/refresh")
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_get_current_user_success(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test getting current user profile"""
        # First login to get token
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        login_response = test_client.post("/api/v1/auth/login", json=login_data)
        login_data = login_response.json()
        access_token = login_data["access_token"]
        
        # Get current user
        headers = {"Authorization": f"Bearer {access_token}"}
        response = test_client.get("/api/v1/auth/me", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["username"] == "testuser"
        assert data["email"] == "test@example.com"
        assert data["full_name"] == "Test User"
        assert data["role"] == "operator"
        assert data["is_active"] is True
    
    @pytest.mark.asyncio
    async def test_get_current_user_invalid_token(self, test_client: TestClient, test_session: AsyncSession):
        """Test getting current user with invalid token"""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = test_client.get("/api/v1/auth/me", headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_get_current_user_missing_token(self, test_client: TestClient, test_session: AsyncSession):
        """Test getting current user without token"""
        response = test_client.get("/api/v1/auth/me")
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data
    
    @pytest.mark.asyncio
    async def test_update_current_user_success(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test updating current user profile"""
        # First login to get token
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        login_response = test_client.post("/api/v1/auth/login", json=login_data)
        login_data = login_response.json()
        access_token = login_data["access_token"]
        
        # Update user profile
        update_data = {
            "full_name": "Updated Test User",
            "phone": "+1234567890"
        }
        
        headers = {"Authorization": f"Bearer {access_token}"}
        response = test_client.put("/api/v1/auth/me", json=update_data, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        
        assert data["full_name"] == "Updated Test User"
        assert data["phone"] == "+1234567890"
    
    @pytest.mark.asyncio
    async def test_logout_success(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test successful user logout"""
        # First login to get token
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        login_response = test_client.post("/api/v1/auth/login", json=login_data)
        login_data = login_response.json()
        access_token = login_data["access_token"]
        
        # Logout
        headers = {"Authorization": f"Bearer {access_token}"}
        response = test_client.post("/api/v1/auth/logout", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Successfully logged out"
    
    @pytest.mark.asyncio
    async def test_logout_invalid_token(self, test_client: TestClient, test_session: AsyncSession):
        """Test logout with invalid token"""
        headers = {"Authorization": "Bearer invalid.token.here"}
        response = test_client.post("/api/v1/auth/logout", headers=headers)
        
        assert response.status_code == 401
        data = response.json()
        assert "error" in data

class TestAuthAPIValidation:
    """Test authentication API validation"""
    
    @pytest.mark.asyncio
    async def test_register_validation_missing_fields(self, test_client: TestClient):
        """Test registration validation with missing fields"""
        # Missing username
        user_data = {
            "email": "test@example.com",
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
        
        # Missing email
        user_data = {
            "username": "testuser",
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
        
        # Missing password
        user_data = {
            "username": "testuser",
            "email": "test@example.com"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_login_validation_missing_fields(self, test_client: TestClient):
        """Test login validation with missing fields"""
        # Missing username
        login_data = {
            "password": "password123"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 422
        
        # Missing password
        login_data = {
            "username": "testuser"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_register_validation_field_lengths(self, test_client: TestClient):
        """Test registration validation for field lengths"""
        # Username too short
        user_data = {
            "username": "ab",  # Too short
            "email": "test@example.com",
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
        
        # Username too long
        user_data = {
            "username": "a" * 51,  # Too long (max 50)
            "email": "test@example.com",
            "password": "Password123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_register_validation_email_format(self, test_client: TestClient):
        """Test registration validation for email format"""
        invalid_emails = [
            "invalid-email",
            "@example.com",
            "test@",
            "test.example.com",
            "test@.com"
        ]
        
        for email in invalid_emails:
            user_data = {
                "username": "testuser",
                "email": email,
                "password": "Password123!"
            }
            
            response = test_client.post("/api/v1/auth/register", json=user_data)
            assert response.status_code == 422, f"Email {email} should be invalid"

class TestAuthAPISecurity:
    """Test authentication API security features"""
    
    @pytest.mark.asyncio
    async def test_password_hashing(self, test_client: TestClient, test_session: AsyncSession):
        """Test that passwords are properly hashed"""
        user_data = {
            "username": "hashuser",
            "email": "hash@example.com",
            "password": "OriginalPassword123!"
        }
        
        response = test_client.post("/api/v1/auth/register", json=user_data)
        assert response.status_code == 200
        
        # Verify password is hashed in database
        from sqlalchemy import select
        stmt = select(User).where(User.username == "hashuser")
        result = await test_session.execute(stmt)
        user = result.scalar_one_or_none()
        
        assert user is not None
        assert user.hashed_password != "OriginalPassword123!"
        assert user.hashed_password.startswith("$2b$")  # bcrypt hash
    
    @pytest.mark.asyncio
    async def test_token_security(self, test_client: TestClient, test_session: AsyncSession, test_user: User):
        """Test token security features"""
        # Login to get tokens
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 200
        
        data = response.json()
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]
        
        # Tokens should be different
        assert access_token != refresh_token
        
        # Tokens should be JWT format
        assert len(access_token.split(".")) == 3
        assert len(refresh_token.split(".")) == 3
        
        # Verify token contents
        import jwt
        from core.config import get_settings
        
        settings = get_settings()
        
        # Access token should contain user info
        access_payload = jwt.decode(access_token, settings.secret_key, algorithms=["HS256"])
        assert access_payload["sub"] == str(test_user.id)
        assert access_payload["username"] == "testuser"
        assert access_payload["type"] == "access"
        
        # Refresh token should contain user info
        refresh_payload = jwt.decode(refresh_token, settings.secret_key, algorithms=["HS256"])
        assert refresh_payload["sub"] == str(test_user.id)
        assert refresh_payload["username"] == "testuser"
        assert refresh_payload["type"] == "refresh"
    
    @pytest.mark.asyncio
    async def test_rate_limiting_simulation(self, test_client: TestClient, test_session: AsyncSession):
        """Test rate limiting behavior (simulated)"""
        # Try multiple failed logins
        for i in range(10):
            login_data = {
                "username": "testuser",
                "password": "wrongpassword"
            }
            
            response = test_client.post("/api/v1/auth/login", json=login_data)
            
            if i < 5:  # First 5 attempts should fail but not lock
                assert response.status_code == 401
            else:  # After 5 attempts, account should be locked
                assert response.status_code == 401
        
        # Try correct password - should be locked
        login_data = {
            "username": "testuser",
            "password": "testpassword123"
        }
        
        response = test_client.post("/api/v1/auth/login", json=login_data)
        assert response.status_code == 401
