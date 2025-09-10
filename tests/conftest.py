"""
CHM Test Configuration
Test fixtures and configuration for CHM application
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import StaticPool
import os
import tempfile
import shutil
from datetime import datetime

from core.database import get_db, Base, metadata
from core.config import get_settings
from main import create_app
from models import User, Device, Metric, Alert, DiscoveryJob, Notification
from models.user import UserRole, UserStatus
from backend.services.auth_service import auth_service

# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

# Test settings
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def test_settings():
    """Get test settings"""
    settings = get_settings()
    settings.database_url = TEST_DATABASE_URL
    settings.debug = True
    settings.secret_key = "test-secret-key-for-testing-only"
    return settings

@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine"""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
        echo=False
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    
    yield engine
    
    async with engine.begin() as conn:
        await conn.run_sync(metadata.drop_all)
    
    await engine.dispose()

@pytest.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session"""
    async_session = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
def test_client(test_session) -> Generator[TestClient, None, None]:
    """Create test client"""
    app = create_app()
    
    # Override database dependency
    def override_get_db():
        yield test_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as client:
        yield client
    
    app.dependency_overrides.clear()

# User fixtures
@pytest.fixture
async def test_user(test_session) -> User:
    """Create a test user"""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=auth_service.hash_password("testpassword123"),
        full_name="Test User",
        role=UserRole.OPERATOR,
        status=UserStatus.ACTIVE,
        is_verified=True
    )
    
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    
    return user

@pytest.fixture
async def test_admin_user(test_session) -> User:
    """Create a test admin user"""
    user = User(
        username="admin",
        email="admin@example.com",
        hashed_password=auth_service.hash_password("adminpassword123"),
        full_name="Admin User",
        role=UserRole.ADMIN,
        status=UserStatus.ACTIVE,
        is_verified=True
    )
    
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    
    return user

@pytest.fixture
async def test_viewer_user(test_session) -> User:
    """Create a test viewer user"""
    user = User(
        username="viewer",
        email="viewer@example.com",
        hashed_password=auth_service.hash_password("viewerpassword123"),
        full_name="Viewer User",
        role=UserRole.VIEWER,
        status=UserStatus.ACTIVE,
        is_verified=True
    )
    
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    
    return user

# Device fixtures
@pytest.fixture
async def test_device(test_session, test_user) -> Device:
    """Create a test device"""
    from models.device import Device, DeviceType, DeviceStatus, DeviceProtocol
    
    device = Device(
        name="Test Router",
        hostname="router1.example.com",
        description="Test network router",
        device_type=DeviceType.ROUTER,
        manufacturer="Cisco",
        model="ISR4321",
        serial_number="TEST123456",
        ip_address="192.168.1.1",
        mac_address="00:11:22:33:44:55",
        status=DeviceStatus.ONLINE,
        protocol=DeviceProtocol.SNMP,
        port=161,
        community_string="public",
        is_monitored=True,
        poll_interval=300,
        owner_id=test_user.id
    )
    
    test_session.add(device)
    await test_session.commit()
    await test_session.refresh(device)
    
    return device

@pytest.fixture
async def test_switch(test_session, test_user) -> Device:
    """Create a test switch device"""
    from models.device import Device, DeviceType, DeviceStatus, DeviceProtocol
    
    device = Device(
        name="Test Switch",
        hostname="switch1.example.com",
        description="Test network switch",
        device_type=DeviceType.SWITCH,
        manufacturer="HP",
        model="ProCurve 2920",
        serial_number="TEST789012",
        ip_address="192.168.1.2",
        mac_address="00:11:22:33:44:66",
        status=DeviceStatus.ONLINE,
        protocol=DeviceProtocol.SNMP,
        port=161,
        community_string="public",
        is_monitored=True,
        poll_interval=300,
        owner_id=test_user.id
    )
    
    test_session.add(device)
    await test_session.commit()
    await test_session.refresh(device)
    
    return device

# Metric fixtures
@pytest.fixture
async def test_metric(test_session, test_device) -> Metric:
    """Create a test metric"""
    from models.metric import Metric, MetricType, MetricCategory
    
    metric = Metric(
        name="cpu_usage",
        description="CPU usage percentage",
        metric_type=MetricType.GAUGE,
        category=MetricCategory.SYSTEM,
        device_id=test_device.id,
        value=75.5,
        unit="percent",
        labels={"core": "all"},
        timestamp=datetime.now()
    )
    
    test_session.add(metric)
    await test_session.commit()
    await test_session.refresh(metric)
    
    return metric

# Alert fixtures
@pytest.fixture
async def test_alert(test_session, test_device, test_user) -> Alert:
    """Create a test alert"""
    from models.alert import Alert, AlertSeverity, AlertStatus, AlertCategory
    
    alert = Alert(
        title="High CPU Usage",
        message="CPU usage is above threshold",
        category=AlertCategory.PERFORMANCE,
        severity=AlertSeverity.WARNING,
        status=AlertStatus.OPEN,
        source="device_monitor",
        device_id=test_device.id,
        assigned_user_id=test_user.id
    )
    
    test_session.add(alert)
    await test_session.commit()
    await test_session.refresh(alert)
    
    return alert

# Discovery job fixtures
@pytest.fixture
async def test_discovery_job(test_session, test_user) -> DiscoveryJob:
    """Create a test discovery job"""
    from models.discovery_job import DiscoveryJob, DiscoveryType, DiscoveryStatus
    
    job = DiscoveryJob(
        name="Network Scan",
        description="Scan network for devices",
        job_type=DiscoveryType.NETWORK_SCAN,
        status=DiscoveryStatus.COMPLETED,
        target_networks=["192.168.1.0/24"],
        total_targets=254,
        completed_targets=254,
        failed_targets=0,
        progress_percentage=100,
        created_by=test_user.id
    )
    
    test_session.add(job)
    await test_session.commit()
    await test_session.refresh(job)
    
    return job

# Notification fixtures
@pytest.fixture
async def test_notification(test_session, test_user) -> Notification:
    """Create a test notification"""
    from models.notification import Notification, NotificationType, NotificationPriority, NotificationStatus
    
    notification = Notification(
        title="System Update",
        message="System has been updated successfully",
        notification_type=NotificationType.SYSTEM,
        priority=NotificationPriority.NORMAL,
        status=NotificationStatus.UNREAD,
        user_id=test_user.id
    )
    
    test_session.add(notification)
    await test_session.commit()
    await test_session.refresh(notification)
    
    return notification

# Authentication fixtures
@pytest.fixture
async def test_user_token(test_session, test_user) -> str:
    """Create a test user access token"""
    tokens = auth_service.create_tokens(test_user)
    return tokens["access_token"]

@pytest.fixture
async def test_admin_token(test_session, test_admin_user) -> str:
    """Create a test admin access token"""
    tokens = auth_service.create_tokens(test_admin_user)
    return tokens["access_token"]

@pytest.fixture
async def test_viewer_token(test_session, test_viewer_user) -> str:
    """Create a test viewer access token"""
    tokens = auth_service.create_tokens(test_viewer_user)
    return tokens["access_token"]

# Test data fixtures
@pytest.fixture
def sample_device_data():
    """Sample device data for testing"""
    return {
        "name": "Test Device",
        "hostname": "test.example.com",
        "description": "A test device",
        "device_type": "router",
        "manufacturer": "Test Corp",
        "model": "Test Model",
        "ip_address": "192.168.1.100",
        "protocol": "snmp",
        "port": 161,
        "community_string": "public",
        "is_monitored": True,
        "poll_interval": 300
    }

@pytest.fixture
def sample_user_data():
    """Sample user data for testing"""
    return {
        "username": "newuser",
        "email": "newuser@example.com",
        "password": "NewPassword123!",
        "full_name": "New User",
        "role": "operator"
    }

@pytest.fixture
def sample_metric_data():
    """Sample metric data for testing"""
    return {
        "name": "memory_usage",
        "description": "Memory usage percentage",
        "metric_type": "gauge",
        "category": "system",
        "value": 65.2,
        "unit": "percent",
        "labels": {"component": "memory"}
    }

# Utility fixtures
@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing"""
    temp_dir = tempfile.mkdtemp()
    yield temp_dir
    shutil.rmtree(temp_dir)

@pytest.fixture
def mock_settings():
    """Mock settings for testing"""
    return {
        "app_name": "CHM Test",
        "version": "2.0.0",
        "debug": True,
        "secret_key": "test-secret-key",
        "database_url": TEST_DATABASE_URL,
        "redis_url": "redis://localhost:6379/1"
    }

# Async test utilities
@pytest.fixture
async def async_client(test_session):
    """Create async test client"""
    app = create_app()
    
    def override_get_db():
        yield test_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    return app

# Cleanup fixtures
@pytest.fixture(autouse=True)
async def cleanup_test_data(test_session):
    """Clean up test data after each test"""
    yield
    
    # Clean up all test data
    try:
        await test_session.rollback()
    except:
        pass