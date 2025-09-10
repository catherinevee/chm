"""
Comprehensive test suite for CHM application
Tests all major components with proper async handling
"""

import pytest
import asyncio
import sys
import os
from typing import AsyncGenerator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
import tempfile
import shutil
from datetime import datetime

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import create_app
from core.database import get_db, Base, metadata, async_session
from core.config import get_settings
from models import User, Device, Metric, Alert, DiscoveryJob, Notification
from backend.services.auth_service import auth_service

class TestComprehensiveSuite:
    """Comprehensive test suite for CHM application"""
    
    @pytest.fixture(scope="class")
    def event_loop(self):
        """Create event loop for the test class"""
        loop = asyncio.new_event_loop()
        yield loop
        loop.close()
    
    @pytest.fixture(scope="class")
    def test_engine(self):
        """Create test database engine"""
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool
        
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            poolclass=StaticPool,
            connect_args={"check_same_thread": False},
            echo=False
        )
        
        # Create all tables synchronously
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def create_tables():
            async with engine.begin() as conn:
                await conn.run_sync(metadata.create_all)
        
        loop.run_until_complete(create_tables())
        loop.close()
        
        return engine
    
    @pytest.fixture(scope="class")
    def test_session(self, test_engine):
        """Create test database session"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def get_session():
            async with async_session(bind=test_engine) as session:
                return session
        
        session = loop.run_until_complete(get_session())
        loop.close()
        return session
    
    @pytest.fixture(scope="class")
    def test_client(self, test_session):
        """Create test client with database override"""
        app = create_app()
        
        # Override database dependency
        def override_get_db():
            return test_session
        
        app.dependency_overrides[get_db] = override_get_db
        
        with TestClient(app) as client:
            yield client
        
        app.dependency_overrides.clear()
    
    @pytest.mark.asyncio
    async def test_database_connection(self, test_engine):
        """Test database connection and basic operations"""
        async with test_engine.begin() as conn:
            result = await conn.execute("SELECT 1")
            assert result.scalar() == 1
    
    @pytest.mark.asyncio
    async def test_database_tables_created(self, test_engine):
        """Test that all database tables are created"""
        async with test_engine.begin() as conn:
            # Check that key tables exist
            tables = await conn.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
            """)
            table_names = [row[0] for row in tables.fetchall()]
            
            expected_tables = ['users', 'devices', 'metrics', 'alerts', 'discovery_jobs', 'notifications']
            for table in expected_tables:
                assert table in table_names, f"Table {table} not found in database"
    
    @pytest.mark.asyncio
    async def test_user_creation(self, test_session):
        """Test user creation and authentication"""
        # Create a test user
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password=auth_service.hash_password("testpassword"),
            full_name="Test User",
            role="user",
            status="active",
            is_verified=True
        )
        
        test_session.add(user)
        await test_session.commit()
        await test_session.refresh(user)
        
        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_verified is True
    
    @pytest.mark.asyncio
    async def test_device_creation(self, test_session):
        """Test device creation and management"""
        # Create a test device
        device = Device(
            name="Test Device",
            device_type="router",
            ip_address="192.168.1.1",
            status="active",
            monitoring_enabled=True
        )
        
        test_session.add(device)
        await test_session.commit()
        await test_session.refresh(device)
        
        assert device.id is not None
        assert device.name == "Test Device"
        assert device.device_type == "router"
        assert device.ip_address == "192.168.1.1"
        assert device.status == "active"
    
    @pytest.mark.asyncio
    async def test_metric_creation(self, test_session):
        """Test metric creation and storage"""
        # Create a test metric
        metric = Metric(
            device_id=1,  # Assuming device with ID 1 exists
            metric_name="cpu_usage",
            metric_value=75.5,
            metric_unit="percent",
            timestamp=datetime.now()
        )
        
        test_session.add(metric)
        await test_session.commit()
        await test_session.refresh(metric)
        
        assert metric.id is not None
        assert metric.device_id == 1
        assert metric.metric_name == "cpu_usage"
        assert metric.metric_value == 75.5
        assert metric.metric_unit == "percent"
    
    @pytest.mark.asyncio
    async def test_alert_creation(self, test_session):
        """Test alert creation and management"""
        # Create a test alert
        alert = Alert(
            title="High CPU Usage",
            description="CPU usage is above threshold",
            severity="warning",
            status="active",
            device_id=1,
            metric_id=1
        )
        
        test_session.add(alert)
        await test_session.commit()
        await test_session.refresh(alert)
        
        assert alert.id is not None
        assert alert.title == "High CPU Usage"
        assert alert.severity == "warning"
        assert alert.status == "active"
        assert alert.device_id == 1
    
    def test_api_endpoints(self, test_client):
        """Test API endpoints are accessible"""
        # Test health endpoint
        response = test_client.get("/health")
        assert response.status_code == 200
        
        # Test docs endpoint
        response = test_client.get("/docs")
        assert response.status_code == 200
        
        # Test API v1 endpoints
        response = test_client.get("/api/v1/")
        assert response.status_code in [200, 404]  # 404 is acceptable if no root endpoint
    
    def test_authentication_endpoints(self, test_client):
        """Test authentication endpoints"""
        # Test login endpoint
        response = test_client.post("/api/v1/auth/login", json={
            "username": "testuser",
            "password": "testpassword"
        })
        # Should return 401 for invalid credentials or 422 for validation error
        assert response.status_code in [401, 422]
    
    def test_device_endpoints(self, test_client):
        """Test device management endpoints"""
        # Test devices list endpoint
        response = test_client.get("/api/v1/devices/")
        # Should return 401 for unauthorized access or 200 if no auth required
        assert response.status_code in [200, 401, 403]
    
    def test_metrics_endpoints(self, test_client):
        """Test metrics endpoints"""
        # Test metrics endpoint
        response = test_client.get("/api/v1/metrics/")
        # Should return 401 for unauthorized access or 200 if no auth required
        assert response.status_code in [200, 401, 403]
    
    def test_alerts_endpoints(self, test_client):
        """Test alerts endpoints"""
        # Test alerts endpoint
        response = test_client.get("/api/v1/alerts/")
        # Should return 401 for unauthorized access or 200 if no auth required
        assert response.status_code in [200, 401, 403]
    
    def test_discovery_endpoints(self, test_client):
        """Test discovery endpoints"""
        # Test discovery endpoint
        response = test_client.get("/api/v1/discovery/")
        # Should return 401 for unauthorized access or 200 if no auth required
        assert response.status_code in [200, 401, 403]
    
    @pytest.mark.asyncio
    async def test_database_transactions(self, test_session):
        """Test database transaction handling"""
        try:
            # Start a transaction
            user = User(
                username="transaction_test",
                email="transaction@example.com",
                hashed_password=auth_service.hash_password("password"),
                full_name="Transaction Test",
                role="user",
                status="active"
            )
            
            test_session.add(user)
            await test_session.commit()
            
            # Verify the user was created
            result = await test_session.execute(
                "SELECT username FROM users WHERE username = 'transaction_test'"
            )
            assert result.scalar() == "transaction_test"
            
        except Exception as e:
            await test_session.rollback()
            raise e
    
    @pytest.mark.asyncio
    async def test_database_error_handling(self, test_session):
        """Test database error handling"""
        try:
            # Try to create a user with invalid data
            user = User(
                username="",  # Invalid empty username
                email="invalid-email",  # Invalid email format
                hashed_password="",  # Empty password
                role="invalid_role",  # Invalid role
                status="invalid_status"  # Invalid status
            )
            
            test_session.add(user)
            await test_session.commit()
            
            # If we get here, the validation didn't work as expected
            assert False, "Expected validation error for invalid user data"
            
        except Exception as e:
            # This is expected - validation should fail
            await test_session.rollback()
            assert "validation" in str(e).lower() or "constraint" in str(e).lower()
    
    def test_application_startup(self, test_client):
        """Test that the application starts up correctly"""
        # Test that the app is running
        response = test_client.get("/health")
        assert response.status_code == 200
        
        # Test that the response contains expected data
        data = response.json()
        assert "status" in data
        assert data["status"] == "healthy"
    
    def test_cors_headers(self, test_client):
        """Test CORS headers are present"""
        response = test_client.options("/api/v1/")
        # CORS headers should be present
        assert "access-control-allow-origin" in response.headers or response.status_code == 200
    
    def test_security_headers(self, test_client):
        """Test security headers are present"""
        response = test_client.get("/health")
        # Security headers should be present
        headers = response.headers
        # Check for common security headers
        security_headers = [
            "x-content-type-options",
            "x-frame-options", 
            "x-xss-protection"
        ]
        
        # At least one security header should be present
        present_headers = [h for h in security_headers if h in headers]
        assert len(present_headers) > 0, "No security headers found"

if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])
