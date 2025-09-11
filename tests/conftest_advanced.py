"""
Advanced Test Configuration for CHM
Comprehensive pytest configuration with optimized fixtures and infrastructure
"""

import pytest
import asyncio
import os
import sys
import tempfile
import uuid
from pathlib import Path
from datetime import datetime, timedelta
from typing import AsyncGenerator, Generator, Dict, Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Database and async imports
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event

# CHM imports  
from backend.database.base import Base
from backend.database.user_models import User, Role, Permission, UserSession, AuditLog
from backend.database.models import Device, Alert, NetworkInterface, DeviceMetric
from backend.config import Settings
from backend.services.auth_service import AuthService

# Import comprehensive fixtures
from tests.test_infrastructure.test_fixtures_comprehensive import (
    TestInfrastructureManager,
    TestDataFactory,
    MockEmailService,
    AsyncContextManagerMock,
    TestMetrics,
    DatabaseTestUtils
)

# ============================================================================
# PYTEST CONFIGURATION
# ============================================================================

def pytest_configure(config):
    """Configure pytest with custom markers and settings"""
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )
    config.addinivalue_line(
        "markers", "database: mark test as requiring database"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "redis: mark test as requiring Redis"
    )
    config.addinivalue_line(
        "markers", "external: mark test as requiring external services"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test paths"""
    for item in items:
        # Add markers based on file path
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "database" in str(item.fspath):
            item.add_marker(pytest.mark.database)
        
        # Add async marker for async test functions
        if asyncio.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)


# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

# Set test environment variables
os.environ.update({
    "TESTING": "true",
    "LOG_LEVEL": "ERROR",  # Reduce noise during testing
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
    "SECRET_KEY": "test-secret-key-for-testing-do-not-use-in-production",
    "JWT_SECRET_KEY": "test-jwt-secret-key-for-testing-do-not-use-in-production",
    "ENCRYPTION_KEY": "dGVzdC1lbmNyeXB0aW9uLWtleS1mb3ItdGVzdGluZy0zMi1jaGFycw==",
    "SNMP_ENCRYPTION_KEY": "dGVzdC1zbm1wLWVuY3J5cHRpb24ta2V5LWZvci10ZXN0aW5nLTMyLWNoYXJz",
    "ACCESS_TOKEN_EXPIRE_MINUTES": "30",
    "REFRESH_TOKEN_EXPIRE_DAYS": "7",
    "CORS_ORIGINS": "http://localhost:3000,http://localhost:8000",
    "REDIS_URL": "redis://localhost:6379/1",  # Use test database
    "EMAIL_ENABLED": "false",  # Disable email in tests
    "PROMETHEUS_ENABLED": "false",  # Disable Prometheus in tests
    "RATE_LIMIT_ENABLED": "false"  # Disable rate limiting in tests
})


# ============================================================================
# SESSION-SCOPED FIXTURES
# ============================================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Test-specific settings configuration"""
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        secret_key="test-secret-key",
        jwt_secret_key="test-jwt-secret",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        testing=True,
        log_level="ERROR"
    )


@pytest.fixture(scope="session")
def infrastructure_manager():
    """Session-scoped infrastructure manager"""
    manager = TestInfrastructureManager()
    yield manager
    manager.cleanup_all()


@pytest.fixture(scope="session")
def session_metrics():
    """Session-scoped test metrics"""
    return TestMetrics()


# ============================================================================
# FUNCTION-SCOPED DATABASE FIXTURES
# ============================================================================

@pytest.fixture
async def test_engine():
    """Create test database engine for each test"""
    database_url = "sqlite+aiosqlite:///:memory:"
    
    engine = create_async_engine(
        database_url,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False  # Set to True for SQL debugging
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine):
    """Create database session for each test"""
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with session_factory() as session:
        yield session


@pytest.fixture
async def db_session_with_rollback(test_engine):
    """Create database session with automatic rollback"""
    session_factory = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with session_factory() as session:
        # Start a transaction
        transaction = await session.begin()
        
        try:
            yield session
        finally:
            # Always rollback to ensure clean state
            await transaction.rollback()


# ============================================================================
# MODEL FACTORY FIXTURES
# ============================================================================

@pytest.fixture
def data_factory():
    """Test data factory"""
    return TestDataFactory()


@pytest.fixture
async def sample_user(db_session):
    """Create sample user for testing"""
    user_data = {
        "username": f"testuser_{uuid.uuid4().hex[:8]}",
        "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "full_name": "Test User",
        "is_active": True,
        "is_verified": True
    }
    
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def admin_user(db_session):
    """Create admin user for testing"""
    user_data = {
        "username": f"admin_{uuid.uuid4().hex[:8]}",
        "email": f"admin_{uuid.uuid4().hex[:8]}@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        "full_name": "Admin User",
        "is_active": True,
        "is_verified": True,
        "is_superuser": True
    }
    
    user = User(**user_data)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
async def sample_role(db_session):
    """Create sample role for testing"""
    role_data = {
        "name": f"test_role_{uuid.uuid4().hex[:8]}",
        "description": "Test role for testing purposes"
    }
    
    role = Role(**role_data)
    db_session.add(role)
    await db_session.commit()
    await db_session.refresh(role)
    return role


@pytest.fixture
async def sample_permission(db_session):
    """Create sample permission for testing"""
    permission_data = {
        "resource": "devices",
        "action": "read",
        "description": "Read access to devices"
    }
    
    permission = Permission(**permission_data)
    db_session.add(permission)
    await db_session.commit()
    await db_session.refresh(permission)
    return permission


@pytest.fixture
async def sample_device(db_session):
    """Create sample device for testing"""
    device_data = {
        "name": f"test_device_{uuid.uuid4().hex[:8]}",
        "ip_address": "192.168.1.100",
        "device_type": "router",
        "vendor": "cisco",
        "model": "ISR4321",
        "status": "active",
        "snmp_community": "public",
        "snmp_version": "2c"
    }
    
    device = Device(**device_data)
    db_session.add(device)
    await db_session.commit()
    await db_session.refresh(device)
    return device


@pytest.fixture
async def sample_alert(db_session, sample_device):
    """Create sample alert for testing"""
    alert_data = {
        "device_id": sample_device.id,
        "alert_type": "connectivity",
        "severity": "warning",
        "message": "Test alert message",
        "status": "open",
        "details": {"test_key": "test_value"}
    }
    
    alert = Alert(**alert_data)
    db_session.add(alert)
    await db_session.commit()
    await db_session.refresh(alert)
    return alert


# ============================================================================
# SERVICE MOCK FIXTURES
# ============================================================================

@pytest.fixture
def mock_auth_service():
    """Mock authentication service"""
    mock = AsyncMock(spec=AuthService)
    
    # Configure common return values
    mock.verify_password.return_value = True
    mock.get_password_hash.return_value = "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
    mock.create_access_token.return_value = "mock_access_token"
    mock.create_refresh_token.return_value = "mock_refresh_token"
    mock.verify_token.return_value = {"user_id": "mock_user_id", "exp": 9999999999}
    mock.authenticate_user.return_value = MagicMock(id="mock_user_id", username="testuser")
    
    return mock


@pytest.fixture
def mock_email_service():
    """Mock email service"""
    return MockEmailService()


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    mock_redis = AsyncMock()
    mock_redis.get.return_value = None
    mock_redis.set.return_value = True
    mock_redis.delete.return_value = 1
    mock_redis.exists.return_value = 0
    mock_redis.expire.return_value = True
    mock_redis.flushdb.return_value = True
    mock_redis.ping.return_value = True
    
    return mock_redis


# ============================================================================
# UTILITY FIXTURES
# ============================================================================

@pytest.fixture
def temp_directory():
    """Create temporary directory for test files"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield Path(temp_dir)


@pytest.fixture
def db_utils():
    """Database testing utilities"""
    return DatabaseTestUtils()


@pytest.fixture
def async_context_factory():
    """Factory for creating async context manager mocks"""
    return AsyncContextManagerMock


# ============================================================================
# AUTO-USE FIXTURES
# ============================================================================

@pytest.fixture(autouse=True)
def isolate_tests():
    """Isolate tests by mocking external dependencies"""
    with patch.multiple(
        'backend.services.email_service',
        EmailService=lambda: MockEmailService()
    ), patch.multiple(
        'backend.services.redis_cache_service',
        redis=AsyncMock()
    ), patch('backend.services.notification_service.NotificationService') as mock_notif:
        
        # Configure notification service mock
        mock_notif_instance = AsyncMock()
        mock_notif.return_value = mock_notif_instance
        mock_notif_instance.send_notification.return_value = True
        
        yield {
            'mock_notification': mock_notif_instance
        }


@pytest.fixture(autouse=True)
def setup_test_logging():
    """Configure logging for tests"""
    import logging
    
    # Set logging levels for test environment
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.dialects").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)
    
    yield
    
    # Reset logging after test
    logging.getLogger().handlers = []


# ============================================================================
# PERFORMANCE MONITORING FIXTURES
# ============================================================================

@pytest.fixture(autouse=True)
def monitor_test_performance(request, session_metrics):
    """Monitor individual test performance"""
    start_time = datetime.utcnow()
    
    yield
    
    end_time = datetime.utcnow()
    duration = (end_time - start_time).total_seconds()
    
    # Record test performance
    session_metrics.record_test_result(
        test_name=request.node.name,
        status="unknown",  # Will be updated by pytest hooks
        duration=duration
    )


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Hook to capture test results"""
    outcome = yield
    report = outcome.get_result()
    
    # Store the report in the item for later use
    setattr(item, f"rep_{report.when}", report)


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

async def create_test_data_set(session: AsyncSession, count: int = 5) -> Dict[str, Any]:
    """Create a complete set of test data"""
    # Create users
    users = []
    for i in range(count):
        user_data = {
            "username": f"testuser{i}",
            "email": f"test{i}@example.com",
            "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
            "full_name": f"Test User {i}",
            "is_active": True,
            "is_verified": True
        }
        user = User(**user_data)
        session.add(user)
        users.append(user)
    
    # Create devices
    devices = []
    for i in range(count):
        device_data = {
            "name": f"device{i}",
            "ip_address": f"192.168.1.{100 + i}",
            "device_type": "router" if i % 2 == 0 else "switch",
            "vendor": "cisco",
            "model": f"ISR432{i}",
            "status": "active"
        }
        device = Device(**device_data)
        session.add(device)
        devices.append(device)
    
    await session.commit()
    
    # Create alerts
    alerts = []
    for i, device in enumerate(devices):
        await session.refresh(device)
        alert_data = {
            "device_id": device.id,
            "alert_type": "connectivity",
            "severity": "warning" if i % 2 == 0 else "critical",
            "message": f"Test alert for {device.name}",
            "status": "open"
        }
        alert = Alert(**alert_data)
        session.add(alert)
        alerts.append(alert)
    
    await session.commit()
    
    return {
        "users": users,
        "devices": devices,
        "alerts": alerts
    }


@pytest.fixture
async def test_data_set(db_session):
    """Create comprehensive test data set"""
    return await create_test_data_set(db_session)