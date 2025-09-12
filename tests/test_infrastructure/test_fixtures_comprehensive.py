"""
Comprehensive Test Fixtures and Infrastructure
Advanced pytest fixtures for reliable and scalable testing
"""

import pytest
import asyncio
import tempfile
import uuid
from datetime import datetime, timedelta
from typing import AsyncGenerator, Generator, Dict, Any
from unittest.mock import AsyncMock, MagicMock, patch

# Database and async imports
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
import redis.asyncio as redis

# CHM imports
from backend.database.base import Base
from backend.database.user_models import User, Role, Permission, UserSession, AuditLog
from backend.database.models import Device, Alert, NetworkInterface, DeviceMetric
from backend.config import Settings
from backend.services.auth_service import AuthService


class TestInfrastructureManager:
    """Advanced test infrastructure management"""
    
    def __init__(self):
        self.temp_files = []
        self.mock_services = {}
        self.test_databases = {}
        self.redis_instances = {}
        
    async def setup_test_database(self, test_id: str) -> AsyncSession:
        """Create isolated test database for each test"""
        database_url = f"sqlite+aiosqlite:///:memory:"
        
        engine = create_async_engine(
            database_url,
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        session = session_factory()
        
        self.test_databases[test_id] = {"engine": engine, "session": session}
        return session
    
    async def cleanup_test_database(self, test_id: str):
        """Clean up test database resources"""
        if test_id in self.test_databases:
            db_info = self.test_databases[test_id]
            await db_info["session"].close()
            await db_info["engine"].dispose()
            del self.test_databases[test_id]
    
    def create_mock_redis(self, test_id: str) -> AsyncMock:
        """Create mock Redis instance for testing"""
        mock_redis = AsyncMock(spec=redis.Redis)
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        mock_redis.delete.return_value = 1
        mock_redis.exists.return_value = 0
        mock_redis.expire.return_value = True
        mock_redis.flushdb.return_value = True
        
        self.redis_instances[test_id] = mock_redis
        return mock_redis
    
    def cleanup_mock_redis(self, test_id: str):
        """Clean up mock Redis instance"""
        if test_id in self.redis_instances:
            del self.redis_instances[test_id]
    
    async def create_test_user(self, session: AsyncSession, **kwargs) -> User:
        """Create a test user with default values"""
        defaults = {
            "username": f"testuser_{uuid.uuid4().hex[:8]}",
            "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
            "hashed_password": "hashed_password_here",
            "full_name": "Test User",
            "is_active": True,
            "is_verified": True
        }
        defaults.update(kwargs)
        
        user = User(**defaults)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user
    
    async def create_test_role(self, session: AsyncSession, **kwargs) -> Role:
        """Create a test role with default values"""
        defaults = {
            "name": f"test_role_{uuid.uuid4().hex[:8]}",
            "description": "Test role description"
        }
        defaults.update(kwargs)
        
        role = Role(**defaults)
        session.add(role)
        await session.commit()
        await session.refresh(role)
        return role
    
    async def create_test_device(self, session: AsyncSession, **kwargs) -> Device:
        """Create a test device with default values"""
        defaults = {
            "name": f"test_device_{uuid.uuid4().hex[:8]}",
            "ip_address": "192.168.1.100",
            "device_type": "router",
            "vendor": "cisco",
            "model": "ISR4321",
            "status": "active",
            "snmp_community": "public",
            "snmp_version": "2c"
        }
        defaults.update(kwargs)
        
        device = Device(**defaults)
        session.add(device)
        await session.commit()
        await session.refresh(device)
        return device
    
    async def create_test_alert(self, session: AsyncSession, device: Device = None, **kwargs) -> Alert:
        """Create a test alert with default values"""
        if device is None:
            device = await self.create_test_device(session)
        
        defaults = {
            "device_id": device.id,
            "alert_type": "connectivity",
            "severity": "warning",
            "message": "Test alert message",
            "status": "open",
            "details": {"test": "details"}
        }
        defaults.update(kwargs)
        
        alert = Alert(**defaults)
        session.add(alert)
        await session.commit()
        await session.refresh(alert)
        return alert
    
    def cleanup_all(self):
        """Clean up all test resources"""
        for temp_file in self.temp_files:
            try:
                temp_file.unlink()
            except Exception as e:
                logger.debug(f"Exception caught: {e}")
        self.temp_files.clear()
        self.mock_services.clear()


@pytest.fixture(scope="session")
def test_infrastructure_manager():
    """Session-scoped test infrastructure manager"""
    manager = TestInfrastructureManager()
    yield manager
    manager.cleanup_all()


@pytest.fixture
async def test_db_session(test_infrastructure_manager):
    """Isolated database session for each test"""
    test_id = f"test_{uuid.uuid4().hex}"
    session = await test_infrastructure_manager.setup_test_database(test_id)
    
    try:
        yield session
    finally:
        await test_infrastructure_manager.cleanup_test_database(test_id)


@pytest.fixture
def mock_redis(test_infrastructure_manager):
    """Mock Redis instance for testing"""
    test_id = f"redis_{uuid.uuid4().hex}"
    mock_redis = test_infrastructure_manager.create_mock_redis(test_id)
    
    try:
        yield mock_redis
    finally:
        test_infrastructure_manager.cleanup_mock_redis(test_id)


@pytest.fixture
async def sample_user(test_db_session):
    """Sample user for testing"""
    manager = TestInfrastructureManager()
    return await manager.create_test_user(test_db_session)


@pytest.fixture
async def sample_admin_user(test_db_session):
    """Sample admin user for testing"""
    manager = TestInfrastructureManager()
    return await manager.create_test_user(
        test_db_session,
        username="admin_user",
        is_superuser=True
    )


@pytest.fixture
async def sample_role(test_db_session):
    """Sample role for testing"""
    manager = TestInfrastructureManager()
    return await manager.create_test_role(test_db_session)


@pytest.fixture
async def sample_device(test_db_session):
    """Sample device for testing"""
    manager = TestInfrastructureManager()
    return await manager.create_test_device(test_db_session)


@pytest.fixture
async def sample_alert(test_db_session, sample_device):
    """Sample alert for testing"""
    manager = TestInfrastructureManager()
    return await manager.create_test_alert(test_db_session, sample_device)


@pytest.fixture
def mock_auth_service():
    """Mock authentication service for testing"""
    mock_service = AsyncMock(spec=AuthService)
    
    # Configure common return values
    mock_service.verify_password.return_value = True
    mock_service.get_password_hash.return_value = "hashed_password"
    mock_service.create_access_token.return_value = "mock_access_token"
    mock_service.create_refresh_token.return_value = "mock_refresh_token"
    mock_service.verify_token.return_value = {"user_id": "mock_user_id"}
    
    return mock_service


@pytest.fixture
def mock_settings():
    """Mock settings for testing"""
    settings = MagicMock(spec=Settings)
    settings.database_url = "sqlite+aiosqlite:///:memory:"
    settings.secret_key = "test_secret"
    settings.jwt_secret_key = "test_jwt_secret"
    settings.access_token_expire_minutes = 30
    settings.refresh_token_expire_days = 7
    settings.cors_origins = ["http://localhost:3000"]
    return settings


class MockEmailService:
    """Mock email service for testing"""
    
    def __init__(self):
        self.sent_emails = []
        self.should_fail = False
        
    async def send_email(self, to: str, subject: str, body: str) -> bool:
        """Mock send email"""
        if self.should_fail:
            return False
        
        self.sent_emails.append({
            "to": to,
            "subject": subject,
            "body": body,
            "sent_at": datetime.utcnow()
        })
        return True
    
    def get_sent_emails(self):
        """Get list of sent emails"""
        return self.sent_emails.copy()
    
    def clear_sent_emails(self):
        """Clear sent emails list"""
        self.sent_emails.clear()


@pytest.fixture
def mock_email_service():
    """Mock email service for testing"""
    return MockEmailService()


class AsyncContextManagerMock:
    """Helper for mocking async context managers"""
    
    def __init__(self, return_value):
        self.return_value = return_value
    
    async def __aenter__(self):
        return self.return_value
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def async_context_mock():
    """Factory for creating async context manager mocks"""
    return AsyncContextManagerMock


class TestDataFactory:
    """Factory for creating test data"""
    
    @staticmethod
    def create_user_data(**overrides):
        """Create user data for testing"""
        defaults = {
            "username": f"user_{uuid.uuid4().hex[:8]}",
            "email": f"user_{uuid.uuid4().hex[:8]}@example.com",
            "password": "TestPassword123!",
            "full_name": "Test User"
        }
        defaults.update(overrides)
        return defaults
    
    @staticmethod
    def create_device_data(**overrides):
        """Create device data for testing"""
        defaults = {
            "name": f"device_{uuid.uuid4().hex[:8]}",
            "ip_address": "192.168.1.100",
            "device_type": "router",
            "vendor": "cisco",
            "model": "ISR4321"
        }
        defaults.update(overrides)
        return defaults
    
    @staticmethod
    def create_alert_data(**overrides):
        """Create alert data for testing"""
        defaults = {
            "alert_type": "connectivity",
            "severity": "warning",
            "message": "Test alert message",
            "status": "open"
        }
        defaults.update(overrides)
        return defaults


@pytest.fixture
def test_data_factory():
    """Test data factory for creating test objects"""
    return TestDataFactory


@pytest.fixture(autouse=True)
def setup_test_environment():
    """Auto-use fixture to set up test environment"""
    # Mock external dependencies
    with patch('backend.services.email_service.EmailService') as mock_email, \
         patch('redis.asyncio.from_url') as mock_redis_connection:
        
        mock_email_instance = AsyncMock()
        mock_email.return_value = mock_email_instance
        mock_email_instance.send_email.return_value = True
        
        mock_redis_instance = AsyncMock()
        mock_redis_connection.return_value = mock_redis_instance
        
        yield {
            'mock_email': mock_email_instance,
            'mock_redis': mock_redis_instance
        }


class TestMetrics:
    """Test metrics collection and reporting"""
    
    def __init__(self):
        self.test_results = []
        self.performance_metrics = []
    
    def record_test_result(self, test_name: str, status: str, duration: float):
        """Record test result"""
        self.test_results.append({
            "test_name": test_name,
            "status": status,
            "duration": duration,
            "timestamp": datetime.utcnow()
        })
    
    def record_performance_metric(self, operation: str, duration: float):
        """Record performance metric"""
        self.performance_metrics.append({
            "operation": operation,
            "duration": duration,
            "timestamp": datetime.utcnow()
        })
    
    def get_test_summary(self):
        """Get test execution summary"""
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r["status"] == "passed"])
        failed_tests = total_tests - passed_tests
        avg_duration = sum(r["duration"] for r in self.test_results) / total_tests if total_tests > 0 else 0
        
        return {
            "total_tests": total_tests,
            "passed_tests": passed_tests,
            "failed_tests": failed_tests,
            "pass_rate": (passed_tests / total_tests) * 100 if total_tests > 0 else 0,
            "average_duration": avg_duration
        }


@pytest.fixture(scope="session")
def test_metrics():
    """Session-scoped test metrics collection"""
    return TestMetrics()


@pytest.fixture(autouse=True)
def record_test_metrics(request, test_metrics):
    """Auto-record test metrics"""
    start_time = datetime.utcnow()
    
    yield
    
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()
    
    # Determine test status from pytest
    status = "passed"
    if hasattr(request.node, "rep_call"):
        if request.node.rep_call.failed:
            status = "failed"
        elif request.node.rep_call.skipped:
            status = "skipped"
    
    test_metrics.record_test_result(
        test_name=request.node.name,
        status=status,
        duration=duration
    )


class DatabaseTestUtils:
    """Utilities for database testing"""
    
    @staticmethod
    async def count_records(session: AsyncSession, model_class):
        """Count records in a table"""
        from sqlalchemy import select, func
        result = await session.execute(select(func.count(model_class.id)))
        return result.scalar()
    
    @staticmethod
    async def clear_table(session: AsyncSession, model_class):
        """Clear all records from a table"""
        from sqlalchemy import delete
        await session.execute(delete(model_class))
        await session.commit()
    
    @staticmethod
    async def verify_foreign_key_constraint(session: AsyncSession, parent_model, child_model, parent_id):
        """Verify foreign key constraint enforcement"""
        from sqlalchemy import select
        
        # Try to create child without valid parent
        try:
            child = child_model(foreign_key_field=parent_id)
            session.add(child)
            await session.commit()
            return False  # Should have failed
        except Exception:
            await session.rollback()
            return True  # Correctly enforced


@pytest.fixture
def db_test_utils():
    """Database testing utilities"""
    return DatabaseTestUtils