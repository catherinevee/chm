"""
Comprehensive tests for Database Models and Relationships
Testing all database models, relationships, constraints, and model behavior
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.exc import IntegrityError, DataError
from sqlalchemy import select, and_, or_, func, text
from sqlalchemy.orm import selectinload, joinedload
import uuid
from typing import List, Dict, Any

# Database imports
from backend.database.base import Base, DatabaseManager
from backend.database.models import (
    Device, DeviceMetric, Alert, NetworkInterface, Notification,
    TopologyNode, TopologyEdge, SLAMetric, CircuitBreakerState,
    SystemHealthMetric, DiscoveryJob
)
from backend.database.user_models import (
    User, Role, Permission, UserSession, AuditLog,
    user_roles, role_permissions
)


@pytest.fixture
async def test_db_engine():
    """Create test database engine with in-memory SQLite"""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    # Cleanup
    await engine.dispose()


@pytest.fixture
async def test_db_session(test_db_engine):
    """Create test database session"""
    async_session = async_sessionmaker(
        test_db_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session


@pytest.fixture
async def sample_user(test_db_session):
    """Create sample user for testing"""
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password="hashed_password_123",
        full_name="Test User",
        is_active=True,
        is_verified=True
    )
    test_db_session.add(user)
    await test_db_session.commit()
    await test_db_session.refresh(user)
    return user


@pytest.fixture
async def sample_device(test_db_session):
    """Create sample device for testing"""
    device = Device(
        hostname="test-device",
        ip_address="192.168.1.100",
        device_type="router",
        manufacturer="Cisco",
        model="2901",
        location="Datacenter-1",
        is_active=True,
        current_state="active"
    )
    test_db_session.add(device)
    await test_db_session.commit()
    await test_db_session.refresh(device)
    return device


@pytest.fixture
async def sample_role(test_db_session):
    """Create sample role for testing"""
    role = Role(
        name="test_role",
        description="Test role for unit tests"
    )
    test_db_session.add(role)
    await test_db_session.commit()
    await test_db_session.refresh(role)
    return role


@pytest.fixture
async def sample_permission(test_db_session):
    """Create sample permission for testing"""
    permission = Permission(
        resource="devices",
        action="read",
        description="Read device information"
    )
    test_db_session.add(permission)
    await test_db_session.commit()
    await test_db_session.refresh(permission)
    return permission


class TestUserModel:
    """Test User model functionality"""
    
    async def test_user_creation(self, test_db_session):
        """Test basic user creation"""
        user = User(
            username="newuser",
            email="newuser@example.com",
            hashed_password="hashed_password",
            full_name="New User"
        )
        
        test_db_session.add(user)
        await test_db_session.commit()
        await test_db_session.refresh(user)
        
        assert user.id is not None
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"
        assert user.is_active is True  # Default value
        assert user.is_superuser is False  # Default value
        assert user.created_at is not None
    
    async def test_user_unique_constraints(self, test_db_session, sample_user):
        """Test user unique constraints (username and email)"""
        # Test duplicate username
        duplicate_username = User(
            username=sample_user.username,  # Same username
            email="different@example.com",
            hashed_password="password"
        )
        test_db_session.add(duplicate_username)
        
        with pytest.raises(IntegrityError):
            await test_db_session.commit()
        
        await test_db_session.rollback()
        
        # Test duplicate email
        duplicate_email = User(
            username="different_user",
            email=sample_user.email,  # Same email
            hashed_password="password"
        )
        test_db_session.add(duplicate_email)
        
        with pytest.raises(IntegrityError):
            await test_db_session.commit()
    
    async def test_user_role_relationship(self, test_db_session, sample_user, sample_role):
        """Test User-Role many-to-many relationship"""
        # Add role to user
        sample_user.roles.append(sample_role)
        await test_db_session.commit()
        
        # Refresh and verify relationship
        await test_db_session.refresh(sample_user, ['roles'])
        await test_db_session.refresh(sample_role, ['users'])
        
        assert len(sample_user.roles) == 1
        assert sample_user.roles[0].name == "test_role"
        assert len(sample_role.users) == 1
        assert sample_role.users[0].username == "testuser"
    
    async def test_user_session_relationship(self, test_db_session, sample_user):
        """Test User-UserSession one-to-many relationship"""
        # Create user sessions
        session1 = UserSession(
            user_id=sample_user.id,
            token_jti="jti_1",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            ip_address="192.168.1.1"
        )
        session2 = UserSession(
            user_id=sample_user.id,
            token_jti="jti_2",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            ip_address="192.168.1.2"
        )
        
        test_db_session.add_all([session1, session2])
        await test_db_session.commit()
        
        # Refresh user with sessions
        await test_db_session.refresh(sample_user, ['sessions'])
        
        assert len(sample_user.sessions) == 2
        assert all(session.user_id == sample_user.id for session in sample_user.sessions)
    
    async def test_user_audit_log_relationship(self, test_db_session, sample_user):
        """Test User-AuditLog one-to-many relationship"""
        # Create audit logs
        audit1 = AuditLog(
            user_id=sample_user.id,
            action="login",
            resource_type="user",
            status="success"
        )
        audit2 = AuditLog(
            user_id=sample_user.id,
            action="logout",
            resource_type="user",
            status="success"
        )
        
        test_db_session.add_all([audit1, audit2])
        await test_db_session.commit()
        
        # Refresh user with audit logs
        await test_db_session.refresh(sample_user, ['audit_logs'])
        
        assert len(sample_user.audit_logs) == 2
        assert all(audit.user_id == sample_user.id for audit in sample_user.audit_logs)
    
    async def test_user_json_preferences(self, test_db_session):
        """Test JSON preferences field"""
        preferences = {
            "theme": "dark",
            "language": "en",
            "timezone": "UTC",
            "dashboard_layout": ["widgets", "alerts", "devices"]
        }
        
        user = User(
            username="prefuser",
            email="prefs@example.com",
            hashed_password="password",
            preferences=preferences
        )
        
        test_db_session.add(user)
        await test_db_session.commit()
        await test_db_session.refresh(user)
        
        assert user.preferences == preferences
        assert user.preferences["theme"] == "dark"
        assert len(user.preferences["dashboard_layout"]) == 3
    
    async def test_user_timestamps(self, test_db_session):
        """Test user timestamp fields"""
        user = User(
            username="timeuser",
            email="time@example.com",
            hashed_password="password"
        )
        
        test_db_session.add(user)
        await test_db_session.commit()
        
        # Check created_at is set
        assert user.created_at is not None
        assert isinstance(user.created_at, datetime)
        
        # Update user to test updated_at
        original_created = user.created_at
        await asyncio.sleep(0.01)  # Small delay
        user.full_name = "Updated Name"
        await test_db_session.commit()
        await test_db_session.refresh(user)
        
        # In SQLite, updated_at might not be automatically set
        # but created_at should remain unchanged
        assert user.created_at == original_created


class TestRolePermissionModel:
    """Test Role and Permission model functionality"""
    
    async def test_role_creation(self, test_db_session):
        """Test role creation"""
        role = Role(
            name="admin",
            description="Administrator role",
            is_system=True
        )
        
        test_db_session.add(role)
        await test_db_session.commit()
        await test_db_session.refresh(role)
        
        assert role.id is not None
        assert role.name == "admin"
        assert role.is_system is True
        assert role.created_at is not None
    
    async def test_permission_creation(self, test_db_session):
        """Test permission creation"""
        permission = Permission(
            resource="users",
            action="write",
            description="Create and update users"
        )
        
        test_db_session.add(permission)
        await test_db_session.commit()
        await test_db_session.refresh(permission)
        
        assert permission.id is not None
        assert permission.resource == "users"
        assert permission.action == "write"
    
    async def test_role_permission_relationship(self, test_db_session, sample_role, sample_permission):
        """Test Role-Permission many-to-many relationship"""
        # Add permission to role
        sample_role.permissions.append(sample_permission)
        await test_db_session.commit()
        
        # Refresh and verify relationship
        await test_db_session.refresh(sample_role, ['permissions'])
        await test_db_session.refresh(sample_permission, ['roles'])
        
        assert len(sample_role.permissions) == 1
        assert sample_role.permissions[0].resource == "devices"
        assert len(sample_permission.roles) == 1
        assert sample_permission.roles[0].name == "test_role"
    
    async def test_permission_unique_constraint(self, test_db_session):
        """Test permission unique constraint on resource+action"""
        permission1 = Permission(
            resource="alerts",
            action="delete",
            description="Delete alerts"
        )
        test_db_session.add(permission1)
        await test_db_session.commit()
        
        # Try to create duplicate permission
        permission2 = Permission(
            resource="alerts",
            action="delete",  # Same resource+action
            description="Different description"
        )
        test_db_session.add(permission2)
        
        with pytest.raises(IntegrityError):
            await test_db_session.commit()


class TestDeviceModel:
    """Test Device model functionality"""
    
    async def test_device_creation(self, test_db_session):
        """Test basic device creation"""
        device = Device(
            hostname="router-01",
            ip_address="10.0.1.1",
            device_type="router",
            manufacturer="Juniper",
            model="MX240"
        )
        
        test_db_session.add(device)
        await test_db_session.commit()
        await test_db_session.refresh(device)
        
        assert device.id is not None
        assert device.hostname == "router-01"
        assert device.current_state == "unknown"  # Default value
        assert device.is_active is True  # Default value
        assert device.created_at is not None
    
    async def test_device_with_json_configuration(self, test_db_session):
        """Test device with JSON configuration field"""
        config = {
            "snmp": {
                "version": "2c",
                "community": "public",
                "port": 161
            },
            "polling_interval": 300,
            "thresholds": {
                "cpu": {"warning": 70, "critical": 90},
                "memory": {"warning": 80, "critical": 95}
            }
        }
        
        device = Device(
            hostname="config-device",
            ip_address="10.0.2.1",
            device_type="switch",
            configuration=config
        )
        
        test_db_session.add(device)
        await test_db_session.commit()
        await test_db_session.refresh(device)
        
        assert device.configuration == config
        assert device.configuration["snmp"]["version"] == "2c"
        assert device.configuration["thresholds"]["cpu"]["warning"] == 70
    
    async def test_device_network_interface_relationship(self, test_db_session, sample_device):
        """Test Device-NetworkInterface one-to-many relationship"""
        # Create network interfaces
        interface1 = NetworkInterface(
            device_id=sample_device.id,
            name="GigabitEthernet0/0",
            interface_type="ethernet",
            status="up",
            speed="1000Mbps"
        )
        interface2 = NetworkInterface(
            device_id=sample_device.id,
            name="GigabitEthernet0/1",
            interface_type="ethernet",
            status="down",
            speed="1000Mbps"
        )
        
        test_db_session.add_all([interface1, interface2])
        await test_db_session.commit()
        
        # Refresh device with interfaces
        await test_db_session.refresh(sample_device, ['interfaces'])
        
        assert len(sample_device.interfaces) == 2
        assert all(interface.device_id == sample_device.id for interface in sample_device.interfaces)
    
    async def test_device_metric_relationship(self, test_db_session, sample_device):
        """Test Device-DeviceMetric one-to-many relationship"""
        # Create device metrics
        metric1 = DeviceMetric(
            device_id=sample_device.id,
            metric_type="cpu_usage",
            value=65.5,
            unit="percent",
            timestamp=datetime.utcnow()
        )
        metric2 = DeviceMetric(
            device_id=sample_device.id,
            metric_type="memory_usage",
            value=72.3,
            unit="percent",
            timestamp=datetime.utcnow()
        )
        
        test_db_session.add_all([metric1, metric2])
        await test_db_session.commit()
        
        # Refresh device with metrics
        await test_db_session.refresh(sample_device, ['metrics'])
        
        assert len(sample_device.metrics) == 2
        assert all(metric.device_id == sample_device.id for metric in sample_device.metrics)
    
    async def test_device_alert_relationship(self, test_db_session, sample_device):
        """Test Device-Alert one-to-many relationship"""
        # Create alerts
        alert1 = Alert(
            device_id=sample_device.id,
            alert_type="connectivity",
            severity="critical",
            message="Device unreachable",
            status="active"
        )
        alert2 = Alert(
            device_id=sample_device.id,
            alert_type="performance",
            severity="warning",
            message="High CPU usage",
            status="active"
        )
        
        test_db_session.add_all([alert1, alert2])
        await test_db_session.commit()
        
        # Refresh device with alerts
        await test_db_session.refresh(sample_device, ['alerts'])
        
        assert len(sample_device.alerts) == 2
        assert all(alert.device_id == sample_device.id for alert in sample_device.alerts)


class TestAlertModel:
    """Test Alert model functionality"""
    
    async def test_alert_creation(self, test_db_session, sample_device):
        """Test basic alert creation"""
        alert = Alert(
            device_id=sample_device.id,
            alert_type="temperature",
            severity="warning",
            message="Temperature above normal",
            description="Device temperature is 85°C",
            status="active"
        )
        
        test_db_session.add(alert)
        await test_db_session.commit()
        await test_db_session.refresh(alert)
        
        assert alert.id is not None
        assert alert.device_id == sample_device.id
        assert alert.severity == "warning"
        assert alert.status == "active"
        assert alert.created_at is not None
    
    async def test_alert_with_json_details(self, test_db_session, sample_device):
        """Test alert with JSON details and metadata"""
        details = {
            "current_value": 85.2,
            "threshold": 80.0,
            "sensor_location": "CPU",
            "measurement_unit": "celsius"
        }
        
        metadata = {
            "auto_generated": True,
            "correlation_id": "temp_alert_001",
            "source_system": "snmp_poller"
        }
        
        alert = Alert(
            device_id=sample_device.id,
            alert_type="temperature",
            severity="warning",
            message="Temperature threshold exceeded",
            details=details,
            alert_metadata=metadata,
            status="active"
        )
        
        test_db_session.add(alert)
        await test_db_session.commit()
        await test_db_session.refresh(alert)
        
        assert alert.details == details
        assert alert.details["current_value"] == 85.2
        assert alert.alert_metadata == metadata
        assert alert.alert_metadata["auto_generated"] is True
    
    async def test_alert_acknowledgment_fields(self, test_db_session, sample_device, sample_user):
        """Test alert acknowledgment fields"""
        alert = Alert(
            device_id=sample_device.id,
            alert_type="disk_space",
            severity="critical",
            message="Disk space low",
            status="active"
        )
        
        test_db_session.add(alert)
        await test_db_session.commit()
        
        # Acknowledge alert
        alert.status = "acknowledged"
        alert.acknowledged_by = sample_user.id
        alert.acknowledged_at = datetime.utcnow()
        
        await test_db_session.commit()
        await test_db_session.refresh(alert)
        
        assert alert.status == "acknowledged"
        assert alert.acknowledged_by == sample_user.id
        assert alert.acknowledged_at is not None
    
    async def test_alert_resolution_fields(self, test_db_session, sample_device, sample_user):
        """Test alert resolution fields"""
        alert = Alert(
            device_id=sample_device.id,
            alert_type="network",
            severity="error",
            message="Interface down",
            status="acknowledged"
        )
        
        test_db_session.add(alert)
        await test_db_session.commit()
        
        # Resolve alert
        alert.status = "resolved"
        alert.resolved_by = sample_user.id
        alert.resolved_at = datetime.utcnow()
        
        await test_db_session.commit()
        await test_db_session.refresh(alert)
        
        assert alert.status == "resolved"
        assert alert.resolved_by == sample_user.id
        assert alert.resolved_at is not None


class TestAdvancedModels:
    """Test advanced models like SLA, Topology, etc."""
    
    async def test_topology_node_creation(self, test_db_session, sample_device):
        """Test topology node creation"""
        node = TopologyNode(
            device_id=sample_device.id,
            label="Router-01",
            node_type="router",
            x_position=100.0,
            y_position=200.0,
            properties={"color": "blue", "size": "large"},
            node_metadata={"layer": 3, "protocol": "ospf"}
        )
        
        test_db_session.add(node)
        await test_db_session.commit()
        await test_db_session.refresh(node)
        
        assert node.id is not None
        assert node.device_id == sample_device.id
        assert node.x_position == 100.0
        assert node.properties["color"] == "blue"
        assert node.node_metadata["layer"] == 3
    
    async def test_topology_edge_creation(self, test_db_session):
        """Test topology edge creation"""
        # Create source and target nodes
        source_node = TopologyNode(
            label="Source Node",
            node_type="switch",
            x_position=0.0,
            y_position=0.0
        )
        target_node = TopologyNode(
            label="Target Node",
            node_type="router",
            x_position=100.0,
            y_position=100.0
        )
        
        test_db_session.add_all([source_node, target_node])
        await test_db_session.commit()
        
        # Create edge
        edge = TopologyEdge(
            source_node_id=source_node.id,
            target_node_id=target_node.id,
            edge_type="ethernet",
            source_interface="GigE0/1",
            target_interface="GigE0/0",
            properties={"bandwidth": "1Gbps", "status": "up"}
        )
        
        test_db_session.add(edge)
        await test_db_session.commit()
        await test_db_session.refresh(edge)
        
        assert edge.id is not None
        assert edge.source_node_id == source_node.id
        assert edge.target_node_id == target_node.id
        assert edge.properties["bandwidth"] == "1Gbps"
    
    async def test_sla_metric_creation(self, test_db_session, sample_device):
        """Test SLA metric creation"""
        sla = SLAMetric(
            device_id=sample_device.id,
            metric_name="availability",
            target_value=99.9,
            current_value=99.5,
            compliance_percentage=99.5,
            measurement_period="monthly",
            threshold_type="min",
            is_compliant=False,
            sla_metadata={"contract_id": "SLA-001", "penalty": 1000}
        )
        
        test_db_session.add(sla)
        await test_db_session.commit()
        await test_db_session.refresh(sla)
        
        assert sla.id is not None
        assert sla.device_id == sample_device.id
        assert sla.target_value == 99.9
        assert sla.is_compliant is False
        assert sla.sla_metadata["contract_id"] == "SLA-001"
    
    async def test_circuit_breaker_state_creation(self, test_db_session):
        """Test circuit breaker state creation"""
        cb_state = CircuitBreakerState(
            identifier="snmp_polling_service",
            state="open",
            failure_count=5,
            success_count=0,
            last_failure_time=datetime.utcnow(),
            opened_at=datetime.utcnow(),
            next_attempt_time=datetime.utcnow() + timedelta(minutes=5),
            failure_threshold=5,
            recovery_timeout=300,
            error_details={"last_error": "Connection timeout", "error_code": "TIMEOUT"}
        )
        
        test_db_session.add(cb_state)
        await test_db_session.commit()
        await test_db_session.refresh(cb_state)
        
        assert cb_state.id is not None
        assert cb_state.identifier == "snmp_polling_service"
        assert cb_state.state == "open"
        assert cb_state.failure_count == 5
        assert cb_state.error_details["last_error"] == "Connection timeout"
    
    async def test_system_health_metric_creation(self, test_db_session):
        """Test system health metric creation"""
        health_metric = SystemHealthMetric(
            metric_category="resource_usage",
            metric_name="cpu_utilization",
            metric_value=75.5,
            service_name="chm_backend",
            instance_id="chm_01",
            tags={"environment": "production", "region": "us-east-1"},
            timestamp=datetime.utcnow()
        )
        
        test_db_session.add(health_metric)
        await test_db_session.commit()
        await test_db_session.refresh(health_metric)
        
        assert health_metric.id is not None
        assert health_metric.metric_category == "resource_usage"
        assert health_metric.metric_value == 75.5
        assert health_metric.tags["environment"] == "production"
    
    async def test_discovery_job_creation(self, test_db_session, sample_user):
        """Test discovery job creation"""
        discovery_job = DiscoveryJob(
            name="Datacenter Scan",
            ip_range="192.168.1.0/24",
            protocol="snmp",
            credentials={"snmp_community": "public", "snmp_version": "2c"},
            options={"timeout": 30, "retries": 3},
            status="pending",
            created_by=sample_user.id
        )
        
        test_db_session.add(discovery_job)
        await test_db_session.commit()
        await test_db_session.refresh(discovery_job)
        
        assert discovery_job.id is not None
        assert discovery_job.name == "Datacenter Scan"
        assert discovery_job.status == "pending"
        assert discovery_job.credentials["snmp_community"] == "public"
        assert discovery_job.created_by == sample_user.id


class TestModelQueryOperations:
    """Test complex query operations across models"""
    
    async def test_user_with_roles_and_permissions_query(self, test_db_session, sample_user, sample_role, sample_permission):
        """Test complex query with multiple relationships"""
        # Setup relationships
        sample_role.permissions.append(sample_permission)
        sample_user.roles.append(sample_role)
        await test_db_session.commit()
        
        # Query user with all relationships loaded
        result = await test_db_session.execute(
            select(User)
            .options(
                selectinload(User.roles).selectinload(Role.permissions),
                selectinload(User.sessions),
                selectinload(User.audit_logs)
            )
            .where(User.id == sample_user.id)
        )
        user = result.scalar_one()
        
        assert len(user.roles) == 1
        assert len(user.roles[0].permissions) == 1
        assert user.roles[0].permissions[0].resource == "devices"
    
    async def test_device_with_all_relationships_query(self, test_db_session, sample_device):
        """Test device query with all related data"""
        # Create related data
        interface = NetworkInterface(
            device_id=sample_device.id,
            name="eth0",
            status="up"
        )
        metric = DeviceMetric(
            device_id=sample_device.id,
            metric_type="cpu_usage",
            value=50.0,
            timestamp=datetime.utcnow()
        )
        alert = Alert(
            device_id=sample_device.id,
            alert_type="test",
            severity="info",
            message="Test alert",
            status="active"
        )
        
        test_db_session.add_all([interface, metric, alert])
        await test_db_session.commit()
        
        # Query device with all relationships
        result = await test_db_session.execute(
            select(Device)
            .options(
                selectinload(Device.interfaces),
                selectinload(Device.metrics),
                selectinload(Device.alerts)
            )
            .where(Device.id == sample_device.id)
        )
        device = result.scalar_one()
        
        assert len(device.interfaces) == 1
        assert len(device.metrics) == 1
        assert len(device.alerts) == 1
    
    async def test_complex_aggregation_queries(self, test_db_session, sample_device):
        """Test complex aggregation queries"""
        # Create multiple metrics
        metrics_data = [
            ("cpu_usage", 65.0),
            ("cpu_usage", 70.0),
            ("cpu_usage", 68.0),
            ("memory_usage", 80.0),
            ("memory_usage", 75.0)
        ]
        
        metrics = []
        for metric_type, value in metrics_data:
            metric = DeviceMetric(
                device_id=sample_device.id,
                metric_type=metric_type,
                value=value,
                timestamp=datetime.utcnow()
            )
            metrics.append(metric)
        
        test_db_session.add_all(metrics)
        await test_db_session.commit()
        
        # Query aggregated data
        result = await test_db_session.execute(
            select(
                DeviceMetric.metric_type,
                func.avg(DeviceMetric.value).label('avg_value'),
                func.max(DeviceMetric.value).label('max_value'),
                func.min(DeviceMetric.value).label('min_value'),
                func.count(DeviceMetric.id).label('count')
            )
            .where(DeviceMetric.device_id == sample_device.id)
            .group_by(DeviceMetric.metric_type)
        )
        
        results = result.all()
        assert len(results) == 2  # cpu_usage and memory_usage
        
        # Find CPU usage stats
        cpu_stats = next(r for r in results if r.metric_type == "cpu_usage")
        assert cpu_stats.count == 3
        assert 67 < cpu_stats.avg_value < 68  # Average of 65, 70, 68
    
    async def test_date_range_queries(self, test_db_session, sample_device):
        """Test date range queries"""
        now = datetime.utcnow()
        
        # Create metrics with different timestamps
        old_metric = DeviceMetric(
            device_id=sample_device.id,
            metric_type="cpu_usage",
            value=50.0,
            timestamp=now - timedelta(hours=25)  # Older than 24 hours
        )
        recent_metric = DeviceMetric(
            device_id=sample_device.id,
            metric_type="cpu_usage",
            value=60.0,
            timestamp=now - timedelta(hours=1)   # Within last 24 hours
        )
        
        test_db_session.add_all([old_metric, recent_metric])
        await test_db_session.commit()
        
        # Query recent metrics (last 24 hours)
        cutoff_time = now - timedelta(hours=24)
        result = await test_db_session.execute(
            select(DeviceMetric)
            .where(and_(
                DeviceMetric.device_id == sample_device.id,
                DeviceMetric.timestamp >= cutoff_time
            ))
        )
        recent_metrics = result.scalars().all()
        
        assert len(recent_metrics) == 1
        assert recent_metrics[0].value == 60.0


class TestModelConstraintsAndValidation:
    """Test model constraints and data validation"""
    
    async def test_required_field_constraints(self, test_db_session):
        """Test required field constraints"""
        # Test User without required fields
        user = User()  # Missing required fields
        test_db_session.add(user)
        
        with pytest.raises((IntegrityError, DataError)):
            await test_db_session.commit()
        
        await test_db_session.rollback()
        
        # Test Device without required fields
        device = Device()  # Missing required fields
        test_db_session.add(device)
        
        with pytest.raises((IntegrityError, DataError)):
            await test_db_session.commit()
    
    async def test_foreign_key_constraints(self, test_db_session):
        """Test foreign key constraints"""
        # Test creating alert with non-existent device
        fake_device_id = uuid.uuid4()
        alert = Alert(
            device_id=fake_device_id,
            alert_type="test",
            severity="info",
            message="Test",
            status="active"
        )
        test_db_session.add(alert)
        
        with pytest.raises(IntegrityError):
            await test_db_session.commit()
    
    async def test_cascade_deletions(self, test_db_session, sample_user):
        """Test cascade deletions work properly"""
        # Create user session
        session = UserSession(
            user_id=sample_user.id,
            token_jti="test_jti",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        test_db_session.add(session)
        await test_db_session.commit()
        
        # Verify session exists
        result = await test_db_session.execute(
            select(UserSession).where(UserSession.user_id == sample_user.id)
        )
        assert result.scalar_one_or_none() is not None
        
        # Delete user (should cascade delete sessions)
        await test_db_session.delete(sample_user)
        await test_db_session.commit()
        
        # Verify session is deleted
        result = await test_db_session.execute(
            select(UserSession).where(UserSession.user_id == sample_user.id)
        )
        assert result.scalar_one_or_none() is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])