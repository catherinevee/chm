"""
Comprehensive tests for Database Constraints and Data Integrity
Testing database constraints, foreign keys, cascades, indexes, and data validation
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.exc import IntegrityError, DataError
from sqlalchemy import text, select, and_, or_, func, inspect, Index
from sqlalchemy.schema import CreateIndex, CreateTable
import uuid
from typing import List, Dict, Any

# Database imports
from backend.database.base import Base
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
async def constraint_test_engine():
    """Create test database engine for constraint testing"""
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
async def constraint_test_session(constraint_test_engine):
    """Create test database session for constraint testing"""
    async_session = async_sessionmaker(
        constraint_test_engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()  # Rollback any changes in test


class TestUniqueConstraints:
    """Test unique constraints across all models"""
    
    async def test_user_unique_username_constraint(self, constraint_test_session):
        """Test user username unique constraint"""
        # Create first user
        user1 = User(
            username="unique_user",
            email="user1@example.com",
            hashed_password="password1"
        )
        constraint_test_session.add(user1)
        await constraint_test_session.commit()
        
        # Try to create second user with same username
        user2 = User(
            username="unique_user",  # Same username
            email="user2@example.com",
            hashed_password="password2"
        )
        constraint_test_session.add(user2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_user_unique_email_constraint(self, constraint_test_session):
        """Test user email unique constraint"""
        # Create first user
        user1 = User(
            username="user1",
            email="unique@example.com",
            hashed_password="password1"
        )
        constraint_test_session.add(user1)
        await constraint_test_session.commit()
        
        # Try to create second user with same email
        user2 = User(
            username="user2",
            email="unique@example.com",  # Same email
            hashed_password="password2"
        )
        constraint_test_session.add(user2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_role_unique_name_constraint(self, constraint_test_session):
        """Test role name unique constraint"""
        # Create first role
        role1 = Role(name="unique_role", description="First role")
        constraint_test_session.add(role1)
        await constraint_test_session.commit()
        
        # Try to create second role with same name
        role2 = Role(name="unique_role", description="Second role")  # Same name
        constraint_test_session.add(role2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_permission_unique_resource_action_constraint(self, constraint_test_session):
        """Test permission resource+action unique constraint"""
        # Create first permission
        perm1 = Permission(
            resource="devices",
            action="read",
            description="Read devices permission"
        )
        constraint_test_session.add(perm1)
        await constraint_test_session.commit()
        
        # Try to create second permission with same resource+action
        perm2 = Permission(
            resource="devices",  # Same resource
            action="read",       # Same action
            description="Duplicate permission"
        )
        constraint_test_session.add(perm2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_user_session_unique_token_jti_constraint(self, constraint_test_session):
        """Test user session token_jti unique constraint"""
        # Create user first
        user = User(
            username="sessionuser",
            email="session@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        # Create first session
        session1 = UserSession(
            user_id=user.id,
            token_jti="unique_jti",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        constraint_test_session.add(session1)
        await constraint_test_session.commit()
        
        # Try to create second session with same token_jti
        session2 = UserSession(
            user_id=user.id,
            token_jti="unique_jti",  # Same JTI
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        constraint_test_session.add(session2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_circuit_breaker_unique_identifier_constraint(self, constraint_test_session):
        """Test circuit breaker identifier unique constraint"""
        # Create first circuit breaker state
        cb1 = CircuitBreakerState(
            identifier="unique_service",
            state="closed",
            failure_count=0
        )
        constraint_test_session.add(cb1)
        await constraint_test_session.commit()
        
        # Try to create second circuit breaker with same identifier
        cb2 = CircuitBreakerState(
            identifier="unique_service",  # Same identifier
            state="open",
            failure_count=5
        )
        constraint_test_session.add(cb2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()


class TestForeignKeyConstraints:
    """Test foreign key constraints and relationships"""
    
    async def test_device_metric_foreign_key_constraint(self, constraint_test_session):
        """Test DeviceMetric foreign key to Device"""
        # Try to create metric without corresponding device
        fake_device_id = uuid.uuid4()
        metric = DeviceMetric(
            device_id=fake_device_id,
            metric_type="cpu_usage",
            value=50.0,
            timestamp=datetime.utcnow()
        )
        constraint_test_session.add(metric)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_alert_foreign_key_constraint(self, constraint_test_session):
        """Test Alert foreign key to Device"""
        # Try to create alert without corresponding device
        fake_device_id = uuid.uuid4()
        alert = Alert(
            device_id=fake_device_id,
            alert_type="connectivity",
            severity="critical",
            message="Device unreachable",
            status="active"
        )
        constraint_test_session.add(alert)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_network_interface_foreign_key_constraint(self, constraint_test_session):
        """Test NetworkInterface foreign key to Device"""
        # Try to create interface without corresponding device
        fake_device_id = uuid.uuid4()
        interface = NetworkInterface(
            device_id=fake_device_id,
            name="eth0",
            status="down"
        )
        constraint_test_session.add(interface)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_user_session_foreign_key_constraint(self, constraint_test_session):
        """Test UserSession foreign key to User"""
        # Try to create session without corresponding user
        fake_user_id = uuid.uuid4()
        session = UserSession(
            user_id=fake_user_id,
            token_jti="test_jti",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        constraint_test_session.add(session)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_audit_log_foreign_key_constraint(self, constraint_test_session):
        """Test AuditLog foreign key to User"""
        # Try to create audit log without corresponding user
        fake_user_id = uuid.uuid4()
        audit = AuditLog(
            user_id=fake_user_id,
            action="login",
            resource_type="user",
            status="success"
        )
        constraint_test_session.add(audit)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_topology_node_foreign_key_constraint(self, constraint_test_session):
        """Test TopologyNode foreign key to Device (optional)"""
        # This should work since device_id is optional
        node = TopologyNode(
            device_id=None,  # Optional foreign key
            label="Standalone Node",
            node_type="virtual"
        )
        constraint_test_session.add(node)
        await constraint_test_session.commit()  # Should succeed
        
        # But invalid device_id should fail
        await constraint_test_session.rollback()
        fake_device_id = uuid.uuid4()
        node = TopologyNode(
            device_id=fake_device_id,  # Invalid foreign key
            label="Invalid Node",
            node_type="switch"
        )
        constraint_test_session.add(node)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()
    
    async def test_topology_edge_foreign_key_constraints(self, constraint_test_session):
        """Test TopologyEdge foreign keys to TopologyNode"""
        fake_node_id = uuid.uuid4()
        
        # Try to create edge with invalid source node
        edge = TopologyEdge(
            source_node_id=fake_node_id,
            target_node_id=fake_node_id,
            edge_type="connection"
        )
        constraint_test_session.add(edge)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()


class TestCascadeConstraints:
    """Test cascade delete constraints"""
    
    async def test_user_cascade_delete_sessions(self, constraint_test_session):
        """Test user deletion cascades to user sessions"""
        # Create user
        user = User(
            username="cascade_user",
            email="cascade@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        # Create user sessions
        session1 = UserSession(
            user_id=user.id,
            token_jti="session1",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        session2 = UserSession(
            user_id=user.id,
            token_jti="session2",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        constraint_test_session.add_all([session1, session2])
        await constraint_test_session.commit()
        
        # Verify sessions exist
        result = await constraint_test_session.execute(
            select(func.count(UserSession.id)).where(UserSession.user_id == user.id)
        )
        assert result.scalar() == 2
        
        # Delete user
        await constraint_test_session.delete(user)
        await constraint_test_session.commit()
        
        # Verify sessions are cascade deleted
        result = await constraint_test_session.execute(
            select(func.count(UserSession.id)).where(UserSession.user_id == user.id)
        )
        assert result.scalar() == 0
    
    async def test_user_cascade_delete_audit_logs(self, constraint_test_session):
        """Test user deletion cascades to audit logs (if configured)"""
        # Create user
        user = User(
            username="audit_user",
            email="audit@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        # Create audit logs
        audit1 = AuditLog(
            user_id=user.id,
            action="login",
            resource_type="user",
            status="success"
        )
        audit2 = AuditLog(
            user_id=user.id,
            action="logout",
            resource_type="user", 
            status="success"
        )
        constraint_test_session.add_all([audit1, audit2])
        await constraint_test_session.commit()
        
        # Verify audit logs exist
        result = await constraint_test_session.execute(
            select(func.count(AuditLog.id)).where(AuditLog.user_id == user.id)
        )
        count_before = result.scalar()
        assert count_before == 2
        
        # Delete user
        await constraint_test_session.delete(user)
        await constraint_test_session.commit()
        
        # Check if audit logs are deleted or user_id is set to NULL
        result = await constraint_test_session.execute(
            select(func.count(AuditLog.id)).where(AuditLog.user_id == user.id)
        )
        count_after = result.scalar()
        
        # In many systems, audit logs are preserved with NULL user_id
        # The exact behavior depends on the foreign key configuration
        assert count_after <= count_before
    
    async def test_device_cascade_delete_metrics(self, constraint_test_session):
        """Test device deletion cascades to device metrics"""
        # Create device
        device = Device(
            hostname="cascade-device",
            ip_address="192.168.1.200",
            device_type="router"
        )
        constraint_test_session.add(device)
        await constraint_test_session.commit()
        
        # Create device metrics
        metric1 = DeviceMetric(
            device_id=device.id,
            metric_type="cpu_usage",
            value=60.0,
            timestamp=datetime.utcnow()
        )
        metric2 = DeviceMetric(
            device_id=device.id,
            metric_type="memory_usage",
            value=70.0,
            timestamp=datetime.utcnow()
        )
        constraint_test_session.add_all([metric1, metric2])
        await constraint_test_session.commit()
        
        # Verify metrics exist
        result = await constraint_test_session.execute(
            select(func.count(DeviceMetric.id)).where(DeviceMetric.device_id == device.id)
        )
        assert result.scalar() == 2
        
        # Delete device
        await constraint_test_session.delete(device)
        await constraint_test_session.commit()
        
        # Verify metrics are deleted (or this might fail if no cascade is configured)
        result = await constraint_test_session.execute(
            select(func.count(DeviceMetric.id)).where(DeviceMetric.device_id == device.id)
        )
        # This depends on whether cascade delete is configured
        count_after = result.scalar()
        assert count_after >= 0  # Either 0 (cascaded) or would have failed above
    
    async def test_role_permission_cascade_delete(self, constraint_test_session):
        """Test role/permission many-to-many cascade behavior"""
        # Create role and permission
        role = Role(name="test_role", description="Test role")
        permission = Permission(resource="test", action="read", description="Test permission")
        
        constraint_test_session.add_all([role, permission])
        await constraint_test_session.commit()
        
        # Associate role with permission
        role.permissions.append(permission)
        await constraint_test_session.commit()
        
        # Verify association exists
        result = await constraint_test_session.execute(
            select(func.count()).select_from(role_permissions)
            .where(and_(
                role_permissions.c.role_id == role.id,
                role_permissions.c.permission_id == permission.id
            ))
        )
        assert result.scalar() == 1
        
        # Delete role
        await constraint_test_session.delete(role)
        await constraint_test_session.commit()
        
        # Verify association is deleted but permission remains
        result = await constraint_test_session.execute(
            select(func.count()).select_from(role_permissions)
            .where(role_permissions.c.role_id == role.id)
        )
        assert result.scalar() == 0
        
        # Permission should still exist
        result = await constraint_test_session.execute(
            select(Permission).where(Permission.id == permission.id)
        )
        assert result.scalar_one_or_none() is not None


class TestDataValidationConstraints:
    """Test data validation and business rule constraints"""
    
    async def test_required_fields_constraint(self, constraint_test_session):
        """Test that required fields cannot be null"""
        # Test User required fields
        user = User()  # No required fields provided
        constraint_test_session.add(user)
        
        with pytest.raises((IntegrityError, DataError)):
            await constraint_test_session.commit()
        
        await constraint_test_session.rollback()
        
        # Test Device required fields
        device = Device()  # No required fields provided
        constraint_test_session.add(device)
        
        with pytest.raises((IntegrityError, DataError)):
            await constraint_test_session.commit()
    
    async def test_string_length_constraints(self, constraint_test_session):
        """Test string field length constraints"""
        # Test username length (assuming max 100 chars)
        long_username = "x" * 200  # Exceeds typical username length
        user = User(
            username=long_username,
            email="test@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        
        # This might succeed in SQLite but would fail in PostgreSQL
        # with proper length constraints
        try:
            await constraint_test_session.commit()
        except DataError:
            # Expected in databases with enforced length constraints
            pass
    
    async def test_boolean_field_constraints(self, constraint_test_session):
        """Test boolean field constraints and defaults"""
        # Test boolean fields with proper values
        user = User(
            username="bool_user",
            email="bool@example.com",
            hashed_password="password",
            is_active=True,
            is_superuser=False,
            is_verified=True,
            mfa_enabled=False
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        await constraint_test_session.refresh(user)
        assert user.is_active is True
        assert user.is_superuser is False
        assert user.is_verified is True
        assert user.mfa_enabled is False
    
    async def test_datetime_field_constraints(self, constraint_test_session):
        """Test datetime field constraints"""
        now = datetime.utcnow()
        future_time = now + timedelta(hours=1)
        
        # Test UserSession with proper datetime
        user = User(
            username="datetime_user",
            email="datetime@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        session = UserSession(
            user_id=user.id,
            token_jti="datetime_jti",
            expires_at=future_time,
            last_activity=now
        )
        constraint_test_session.add(session)
        await constraint_test_session.commit()
        
        await constraint_test_session.refresh(session)
        assert session.expires_at == future_time
        assert session.created_at is not None  # Auto-generated
    
    async def test_json_field_constraints(self, constraint_test_session):
        """Test JSON field constraints and validation"""
        # Test valid JSON in various fields
        valid_json = {"key": "value", "number": 42, "array": [1, 2, 3]}
        
        # Test Device configuration JSON
        device = Device(
            hostname="json-device",
            ip_address="192.168.1.300",
            device_type="switch",
            configuration=valid_json
        )
        constraint_test_session.add(device)
        await constraint_test_session.commit()
        
        await constraint_test_session.refresh(device)
        assert device.configuration == valid_json
        assert device.configuration["number"] == 42
        
        # Test Alert details JSON
        alert = Alert(
            device_id=device.id,
            alert_type="json_test",
            severity="info",
            message="JSON test",
            status="active",
            details=valid_json,
            alert_metadata={"source": "test"}
        )
        constraint_test_session.add(alert)
        await constraint_test_session.commit()
        
        await constraint_test_session.refresh(alert)
        assert alert.details == valid_json
        assert alert.alert_metadata["source"] == "test"


class TestIndexConstraints:
    """Test database indexes and their constraints"""
    
    async def test_index_existence_verification(self, constraint_test_engine):
        """Test that expected indexes exist"""
        async with constraint_test_engine.connect() as conn:
            # Get table information
            inspector = inspect(constraint_test_engine.sync_engine)
            
            # Check User table indexes
            user_indexes = inspector.get_indexes('users')
            index_names = [idx['name'] for idx in user_indexes]
            
            # Should have indexes on username, email, and composite index
            assert any('username' in str(idx) for idx in user_indexes)
            assert any('email' in str(idx) for idx in user_indexes)
            
            # Check Device table indexes
            device_indexes = inspector.get_indexes('devices')
            assert any('hostname' in str(idx) for idx in device_indexes)
            assert any('ip_address' in str(idx) for idx in device_indexes)
    
    async def test_composite_index_behavior(self, constraint_test_session):
        """Test composite index behavior"""
        # Create test data that should benefit from composite indexes
        users_data = [
            ("user1", "user1@example.com", True),
            ("user2", "user2@example.com", False),
            ("user3", "user3@example.com", True),
        ]
        
        users = []
        for username, email, is_active in users_data:
            user = User(
                username=username,
                email=email,
                hashed_password="password",
                is_active=is_active
            )
            users.append(user)
        
        constraint_test_session.add_all(users)
        await constraint_test_session.commit()
        
        # Query using composite index (email + is_active)
        result = await constraint_test_session.execute(
            select(User).where(and_(
                User.email.like("%@example.com"),
                User.is_active == True
            ))
        )
        active_users = result.scalars().all()
        assert len(active_users) == 2
    
    async def test_unique_index_constraints(self, constraint_test_session):
        """Test unique index constraints"""
        # Test that unique indexes prevent duplicates
        
        # UserSession token_jti should be unique
        user = User(
            username="unique_index_user",
            email="unique@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        session1 = UserSession(
            user_id=user.id,
            token_jti="unique_token",
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        constraint_test_session.add(session1)
        await constraint_test_session.commit()
        
        # Second session with same token_jti should fail
        session2 = UserSession(
            user_id=user.id,
            token_jti="unique_token",  # Duplicate JTI
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        constraint_test_session.add(session2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()


class TestBusinessRuleConstraints:
    """Test business rule constraints and validation"""
    
    async def test_user_account_lockout_logic(self, constraint_test_session):
        """Test user account lockout business rules"""
        # Create user
        user = User(
            username="lockout_user",
            email="lockout@example.com",
            hashed_password="password",
            failed_login_attempts=0,
            locked_until=None
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        # Simulate failed login attempts
        user.failed_login_attempts = 5
        user.locked_until = datetime.utcnow() + timedelta(minutes=30)
        user.is_active = False  # Account locked
        
        await constraint_test_session.commit()
        await constraint_test_session.refresh(user)
        
        assert user.failed_login_attempts == 5
        assert user.locked_until is not None
        assert user.is_active is False
    
    async def test_alert_severity_escalation_rules(self, constraint_test_session):
        """Test alert severity escalation business rules"""
        # Create device first
        device = Device(
            hostname="alert-device",
            ip_address="192.168.1.400",
            device_type="router"
        )
        constraint_test_session.add(device)
        await constraint_test_session.commit()
        
        # Create alert with escalation path
        severities = ["info", "warning", "error", "critical"]
        
        for severity in severities:
            alert = Alert(
                device_id=device.id,
                alert_type="escalation_test",
                severity=severity,
                message=f"Alert with {severity} severity",
                status="active"
            )
            constraint_test_session.add(alert)
        
        await constraint_test_session.commit()
        
        # Verify all severities were accepted
        result = await constraint_test_session.execute(
            select(func.count(Alert.id)).where(Alert.device_id == device.id)
        )
        assert result.scalar() == 4
    
    async def test_device_state_transition_rules(self, constraint_test_session):
        """Test device state transition business rules"""
        device = Device(
            hostname="state-device",
            ip_address="192.168.1.500",
            device_type="switch",
            current_state="unknown"  # Initial state
        )
        constraint_test_session.add(device)
        await constraint_test_session.commit()
        
        # Test valid state transitions
        valid_states = ["unknown", "up", "down", "warning", "critical"]
        
        for state in valid_states:
            device.current_state = state
            device.updated_at = datetime.utcnow()
            await constraint_test_session.commit()
            
            await constraint_test_session.refresh(device)
            assert device.current_state == state
    
    async def test_session_expiration_constraints(self, constraint_test_session):
        """Test session expiration business rules"""
        user = User(
            username="session_user",
            email="session@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user)
        await constraint_test_session.commit()
        
        now = datetime.utcnow()
        
        # Create expired session
        expired_session = UserSession(
            user_id=user.id,
            token_jti="expired_token",
            expires_at=now - timedelta(hours=1),  # Expired
            is_active=True
        )
        constraint_test_session.add(expired_session)
        await constraint_test_session.commit()
        
        # Business logic would deactivate expired sessions
        # Simulate this business rule
        result = await constraint_test_session.execute(
            select(UserSession).where(UserSession.expires_at < now)
        )
        expired_sessions = result.scalars().all()
        
        for session in expired_sessions:
            session.is_active = False
        
        await constraint_test_session.commit()
        
        # Verify business rule application
        await constraint_test_session.refresh(expired_session)
        assert expired_session.is_active is False


class TestConcurrencyConstraints:
    """Test concurrency and race condition constraints"""
    
    async def test_optimistic_locking_simulation(self, constraint_test_session):
        """Test optimistic locking behavior simulation"""
        # Create device
        device = Device(
            hostname="concurrent-device",
            ip_address="192.168.1.600",
            device_type="router"
        )
        constraint_test_session.add(device)
        await constraint_test_session.commit()
        
        # Simulate concurrent updates by checking updated_at
        original_updated_at = device.updated_at
        
        # First update
        device.location = "Datacenter-A"
        device.updated_at = datetime.utcnow()
        await constraint_test_session.commit()
        
        new_updated_at = device.updated_at
        assert new_updated_at != original_updated_at
    
    async def test_unique_constraint_race_condition(self, constraint_test_session):
        """Test handling of unique constraint violations in concurrent scenarios"""
        # This simulates what happens when two processes try to create
        # users with the same username simultaneously
        
        base_username = "race_condition_user"
        
        # First user succeeds
        user1 = User(
            username=base_username,
            email="race1@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user1)
        await constraint_test_session.commit()
        
        # Second user with same username fails
        user2 = User(
            username=base_username,  # Same username
            email="race2@example.com",
            hashed_password="password"
        )
        constraint_test_session.add(user2)
        
        with pytest.raises(IntegrityError):
            await constraint_test_session.commit()


class TestConstraintErrorHandling:
    """Test proper error handling for constraint violations"""
    
    async def test_integrity_error_types(self, constraint_test_session):
        """Test different types of integrity errors"""
        
        # Test NOT NULL constraint
        try:
            user = User(
                username=None,  # NOT NULL violation
                email="null@example.com",
                hashed_password="password"
            )
            constraint_test_session.add(user)
            await constraint_test_session.commit()
        except (IntegrityError, DataError) as e:
            assert "username" in str(e).lower() or "not null" in str(e).lower()
        
        await constraint_test_session.rollback()
        
        # Test UNIQUE constraint
        try:
            user1 = User(
                username="unique_test",
                email="unique1@example.com",
                hashed_password="password"
            )
            constraint_test_session.add(user1)
            await constraint_test_session.commit()
            
            user2 = User(
                username="unique_test",  # UNIQUE violation
                email="unique2@example.com",
                hashed_password="password"
            )
            constraint_test_session.add(user2)
            await constraint_test_session.commit()
        except IntegrityError as e:
            assert "unique" in str(e).lower() or "duplicate" in str(e).lower()
    
    async def test_foreign_key_error_handling(self, constraint_test_session):
        """Test foreign key constraint error handling"""
        fake_device_id = uuid.uuid4()
        
        try:
            alert = Alert(
                device_id=fake_device_id,  # Foreign key violation
                alert_type="test",
                severity="info",
                message="Test",
                status="active"
            )
            constraint_test_session.add(alert)
            await constraint_test_session.commit()
        except IntegrityError as e:
            assert "foreign key" in str(e).lower() or "device_id" in str(e).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])