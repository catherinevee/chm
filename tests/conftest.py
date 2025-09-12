"""
Real test configuration for actual code coverage
This replaces mock-based testing with real execution
"""

import pytest
import pytest_asyncio
import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta
from typing import AsyncGenerator, Generator
import tempfile

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# UUID patching removed - not needed for current tests

# Set test environment
os.environ.update({
    "TESTING": "true",
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
    "SECRET_KEY": "test-secret-key-for-testing",
    "JWT_SECRET_KEY": "test-jwt-secret",
    "LOG_LEVEL": "DEBUG",
    "EMAIL_ENABLED": "false",  # Only mock external services
    "SMS_ENABLED": "false",
    "REDIS_URL": "redis://localhost:6379/15"  # Test database
})

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy import event
from fastapi.testclient import TestClient
from httpx import AsyncClient
import redis.asyncio as redis

# Import Base here after environment setup but before fixtures
from backend.database.base import Base


# ============================================================================
# REAL DATABASE FIXTURES
# ============================================================================

@pytest_asyncio.fixture(scope="function")
async def real_engine():
    """Create real async SQLite engine for testing"""
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    
    engine = create_async_engine(
        DATABASE_URL,
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


@pytest_asyncio.fixture(scope="function")
async def real_db_session(real_engine):
    """Create real database session that executes actual queries"""
    async_session = async_sessionmaker(
        real_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture(scope="function")
async def real_db_with_data(real_db_session):
    """Real database with test data"""
    # Import models locally after patching
    from backend.database.user_models import User, Role, Permission
    from backend.database.models import Device, Alert, DeviceMetric
    
    # Create test user
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
        full_name="Test User",
        is_active=True,
        is_verified=True
    )
    real_db_session.add(user)
    
    # Create admin user
    admin = User(
        username="admin",
        email="admin@example.com",
        hashed_password="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        full_name="Admin User",
        is_active=True,
        is_verified=True,
        is_superuser=True
    )
    real_db_session.add(admin)
    
    # Create roles
    admin_role = Role(name="admin", description="Administrator role")
    user_role = Role(name="user", description="Regular user role")
    real_db_session.add(admin_role)
    real_db_session.add(user_role)
    
    # Create permissions
    read_perm = Permission(resource="devices", action="read")
    write_perm = Permission(resource="devices", action="write")
    delete_perm = Permission(resource="devices", action="delete")
    real_db_session.add_all([read_perm, write_perm, delete_perm])
    
    await real_db_session.commit()
    
    # Assign roles
    admin.roles.append(admin_role)
    user.roles.append(user_role)
    admin_role.permissions.extend([read_perm, write_perm, delete_perm])
    user_role.permissions.append(read_perm)
    
    await real_db_session.commit()
    
    # Create test devices
    device1 = Device(
        name="test-router-01",
        ip_address="192.168.1.1",
        device_type="router",
        vendor="cisco",
        model="ISR4321",
        status="active",
        snmp_community="public",
        snmp_version="2c"
    )
    device2 = Device(
        name="test-switch-01",
        ip_address="192.168.1.2",
        device_type="switch",
        vendor="cisco",
        model="Catalyst 2960",
        status="active"
    )
    real_db_session.add_all([device1, device2])
    await real_db_session.commit()
    
    # Create test alerts
    alert1 = Alert(
        device_id=device1.id,
        alert_type="cpu_high",
        severity="warning",
        message="CPU usage above 80%",
        status="open",
        details={"cpu_usage": 85}
    )
    alert2 = Alert(
        device_id=device2.id,
        alert_type="interface_down",
        severity="critical",
        message="Interface GigabitEthernet0/1 is down",
        status="open"
    )
    real_db_session.add_all([alert1, alert2])
    await real_db_session.commit()
    
    # Create test metrics
    for i in range(10):
        metric = DeviceMetric(
            device_id=device1.id,
            metric_type="cpu_usage",
            value=70 + i,
            unit="percent",
            timestamp=datetime.utcnow() - timedelta(minutes=10-i)
        )
        real_db_session.add(metric)
    
    await real_db_session.commit()
    
    return {
        "users": [user, admin],
        "roles": [admin_role, user_role],
        "permissions": [read_perm, write_perm, delete_perm],
        "devices": [device1, device2],
        "alerts": [alert1, alert2]
    }


# ============================================================================
# REAL TEST CLIENT FIXTURES
# ============================================================================

@pytest.fixture(scope="function")
def real_test_client():
    """Create TestClient that executes real API endpoints"""
    from core.database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    
    # Create engine for SQLite testing
    from sqlalchemy.pool import StaticPool
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    
    engine = create_async_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
    
    # Create a session factory for the test
    async_session = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    # Create tables once
    import asyncio
    
    async def create_tables():
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    asyncio.run(create_tables())
    
    # Import app after patching and table creation
    from main import app
    
    # Override database dependency with real test database
    async def override_get_db():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[get_db] = override_get_db
    
    # Only mock external services
    from unittest.mock import patch, AsyncMock
    
    with patch('backend.services.email_service.EmailService') as mock_email:
        mock_email_instance = AsyncMock()
        mock_email_instance.send_email.return_value = True
        mock_email.return_value = mock_email_instance
        
        with TestClient(app) as client:
            yield client
    
    # Clear overrides
    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def async_test_client(real_db_session):
    """Async test client for async endpoint testing"""
    from core.database import get_db
    
    async def override_get_db():
        yield real_db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    
    app.dependency_overrides.clear()


# ============================================================================
# REAL AUTHENTICATION FIXTURES
# ============================================================================

@pytest.fixture
def real_auth_headers(real_test_client, real_db_with_data):
    """Get real authentication headers by actually logging in"""
    # Perform real login
    response = real_test_client.post(
        "/api/v1/auth/login",
        data={
            "username": "testuser",
            "password": "secret"
        }
    )
    
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def real_admin_headers(real_test_client, real_db_with_data):
    """Get real admin authentication headers"""
    response = real_test_client.post(
        "/api/v1/auth/login",
        data={
            "username": "admin",
            "password": "secret"
        }
    )
    
    assert response.status_code == 200
    token = response.json()["access_token"]
    
    return {"Authorization": f"Bearer {token}"}


# ============================================================================
# REAL SERVICE FIXTURES
# ============================================================================

@pytest_asyncio.fixture
async def real_auth_service(real_db_session):
    """Create real AuthService that executes actual authentication logic"""
    from backend.services.auth_service import AuthService
    service = AuthService()
    service.db = real_db_session
    
    # Only mock external email service
    from unittest.mock import AsyncMock
    service.email_service = AsyncMock()
    service.email_service.send_email.return_value = True
    
    return service


@pytest_asyncio.fixture
async def real_device_service(real_db_session):
    """Create real DeviceService that executes actual device operations"""
    from backend.services.device_service import DeviceService
    
    service = DeviceService()
    service.db = real_db_session
    
    # Mock only external SNMP/SSH connections
    from unittest.mock import AsyncMock
    service.snmp_service = AsyncMock()
    service.ssh_service = AsyncMock()
    
    # Configure mock responses for external services
    service.snmp_service.get_device_info.return_value = {
        "sysName": "test-device",
        "sysDescr": "Cisco IOS",
        "uptime": 1000000
    }
    service.ssh_service.execute_command.return_value = "Command output"
    
    return service


@pytest_asyncio.fixture
async def real_alert_service(real_db_session):
    """Create real AlertService that executes actual alert logic"""
    from backend.services.alert_service import AlertService
    
    service = AlertService()
    service.db = real_db_session
    
    # Mock only notification sending
    from unittest.mock import AsyncMock
    service.notification_service = AsyncMock()
    service.notification_service.send_notification.return_value = True
    
    return service


@pytest_asyncio.fixture
async def real_metrics_service(real_db_session):
    """Create real MetricsService that executes actual metrics operations"""
    from backend.services.metrics_service import MetricsService
    
    service = MetricsService()
    service.db = real_db_session
    
    # Mock only external time-series database
    from unittest.mock import AsyncMock
    service.time_series_db = AsyncMock()
    service.time_series_db.write.return_value = True
    
    return service


# ============================================================================
# REAL REDIS FIXTURES (Optional - can use real Redis for testing)
# ============================================================================

@pytest_asyncio.fixture
async def real_redis_client():
    """Create real Redis client for testing caching"""
    try:
        client = await redis.from_url(
            "redis://localhost:6379/15",  # Use test database 15
            encoding="utf-8",
            decode_responses=True
        )
        
        # Clear test database
        await client.flushdb()
        
        yield client
        
        # Cleanup
        await client.flushdb()
        await client.close()
    except Exception as e:

        logger.debug(f"Exception: {e}")
        # If Redis not available, provide mock
        from unittest.mock import AsyncMock
        mock_redis = AsyncMock()
        mock_redis.get.return_value = None
        mock_redis.set.return_value = True
        mock_redis.delete.return_value = 1
        yield mock_redis


# ============================================================================
# REAL WEBSOCKET FIXTURES
# ============================================================================

@pytest.fixture
def real_websocket_client(real_test_client):
    """Create real WebSocket test client"""
    return real_test_client


# ============================================================================
# REAL BACKGROUND TASK FIXTURES
# ============================================================================

@pytest.fixture
def real_task_runner():
    """Create real task runner for background tasks"""
    from backend.tasks.celery_app import celery_app
    
    # Configure Celery for testing
    celery_app.conf.update(
        task_always_eager=True,  # Execute tasks synchronously
        task_eager_propagates=True,
        broker_url='memory://',
        result_backend='cache+memory://'
    )
    
    return celery_app


# ============================================================================
# TEST DATA GENERATORS
# ============================================================================

@pytest.fixture
def generate_test_devices():
    """Generate test device data"""
    def _generate(count=5):
        devices = []
        for i in range(count):
            devices.append({
                "name": f"device-{i:03d}",
                "ip_address": f"192.168.1.{100 + i}",
                "device_type": "router" if i % 2 == 0 else "switch",
                "vendor": "cisco",
                "model": "ISR4321" if i % 2 == 0 else "Catalyst 2960",
                "status": "active",
                "snmp_community": "public",
                "snmp_version": "2c"
            })
        return devices
    return _generate


@pytest.fixture
def generate_test_metrics():
    """Generate test metrics data"""
    def _generate(device_id, count=100):
        metrics = []
        for i in range(count):
            metrics.append({
                "device_id": device_id,
                "metric_type": "cpu_usage",
                "value": 50 + (i % 50),  # Varying between 50-100
                "unit": "percent",
                "timestamp": datetime.utcnow() - timedelta(minutes=count-i)
            })
        return metrics
    return _generate


@pytest.fixture
def generate_test_alerts():
    """Generate test alerts data"""
    def _generate(device_id, count=10):
        alerts = []
        severities = ["info", "warning", "error", "critical"]
        types = ["cpu_high", "memory_high", "disk_full", "interface_down"]
        
        for i in range(count):
            alerts.append({
                "device_id": device_id,
                "alert_type": types[i % len(types)],
                "severity": severities[i % len(severities)],
                "message": f"Test alert {i}",
                "status": "open" if i < count // 2 else "resolved",
                "details": {"index": i}
            })
        return alerts
    return _generate


# ============================================================================
# ERROR INJECTION FIXTURES
# ============================================================================

@pytest.fixture
def inject_database_error(real_db_session):
    """Inject database errors for testing error handling"""
    from sqlalchemy.exc import IntegrityError, OperationalError
    from unittest.mock import patch
    
    def _inject(error_type="integrity"):
        if error_type == "integrity":
            error = IntegrityError("", "", "")
        elif error_type == "operational":
            error = OperationalError("", "", "")
        else:
            error = Exception("Database error")
        
        return patch.object(real_db_session, 'commit', side_effect=error)
    
    return _inject


@pytest.fixture
def inject_network_error():
    """Inject network errors for testing resilience"""
    from unittest.mock import patch
    import aiohttp
    
    def _inject(error_type="timeout"):
        if error_type == "timeout":
            error = asyncio.TimeoutError()
        elif error_type == "connection":
            error = aiohttp.ClientConnectionError("Connection failed")
        else:
            error = Exception("Network error")
        
        return patch('aiohttp.ClientSession.get', side_effect=error)
    
    return _inject


# ============================================================================
# PERFORMANCE MONITORING
# ============================================================================

@pytest.fixture
def performance_monitor():
    """Monitor test performance"""
    import time
    
    class PerformanceMonitor:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            
        def start(self):
            self.start_time = time.time()
            
        def stop(self):
            self.end_time = time.time()
            return self.end_time - self.start_time
    
    return PerformanceMonitor()


# ============================================================================
# CLEANUP FIXTURES
# ============================================================================

# @pytest.fixture(autouse=True)
# async def cleanup_after_test():
#     """Automatic cleanup after each test"""
#     yield
#     
#     # Close any open database connections
#     from sqlalchemy.pool import QueuePool
#     QueuePool.dispose()
#     
#     # Clear any caches
#     from functools import lru_cache
#     lru_cache.cache_clear()
#     
#     # Reset any global state
#     import gc
#     gc.collect()