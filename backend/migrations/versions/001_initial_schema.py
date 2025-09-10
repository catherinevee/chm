"""
Initial database schema

Revision ID: 001
Revises: 
Create Date: 2024-12-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create initial database schema"""
    
    # Create UUID extension
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    
    # Create users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('username', sa.String(50), unique=True, nullable=False, index=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('full_name', sa.String(255)),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('is_superuser', sa.Boolean(), default=False),
        sa.Column('is_verified', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('last_login', sa.DateTime(timezone=True)),
        sa.Column('failed_login_attempts', sa.Integer(), default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True)),
        sa.Column('password_changed_at', sa.DateTime(timezone=True)),
        sa.Column('verification_token', sa.String(255)),
        sa.Column('reset_token', sa.String(255)),
        sa.Column('reset_token_expires', sa.DateTime(timezone=True)),
        sa.Column('settings', sa.JSON()),
        sa.Column('preferences', sa.JSON()),
        sa.Column('metadata', sa.JSON())
    )
    
    # Create roles table
    op.create_table('roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(50), unique=True, nullable=False),
        sa.Column('description', sa.String(255)),
        sa.Column('permissions', sa.JSON()),
        sa.Column('is_system', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now())
    )
    
    # Create user_roles junction table
    op.create_table('user_roles',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE')),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE')),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    
    # Create devices table
    op.create_table('devices',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('hostname', sa.String(255), nullable=False, index=True),
        sa.Column('ip_address', sa.String(45), nullable=False, unique=True, index=True),
        sa.Column('mac_address', sa.String(17)),
        sa.Column('device_type', sa.String(50), index=True),
        sa.Column('manufacturer', sa.String(100)),
        sa.Column('model', sa.String(100)),
        sa.Column('serial_number', sa.String(100)),
        sa.Column('firmware_version', sa.String(100)),
        sa.Column('location', sa.String(255)),
        sa.Column('department', sa.String(100)),
        sa.Column('description', sa.Text()),
        sa.Column('notes', sa.Text()),
        sa.Column('discovery_protocol', sa.String(50)),
        sa.Column('device_group', sa.String(100)),
        sa.Column('snmp_community_encrypted', sa.Text()),
        sa.Column('snmp_version', sa.String(10)),
        sa.Column('snmp_port', sa.Integer(), default=161),
        sa.Column('ssh_username', sa.String(100)),
        sa.Column('ssh_password_encrypted', sa.Text()),
        sa.Column('ssh_key_encrypted', sa.Text()),
        sa.Column('ssh_port', sa.Integer(), default=22),
        sa.Column('api_key_encrypted', sa.Text()),
        sa.Column('api_endpoint', sa.String(255)),
        sa.Column('current_state', sa.String(50), default='unknown', index=True),
        sa.Column('last_poll_time', sa.DateTime(timezone=True)),
        sa.Column('next_poll_time', sa.DateTime(timezone=True)),
        sa.Column('poll_interval', sa.Integer(), default=300),
        sa.Column('consecutive_failures', sa.Integer(), default=0),
        sa.Column('circuit_breaker_trips', sa.Integer(), default=0),
        sa.Column('discovery_status', sa.String(50)),
        sa.Column('discovery_data', sa.JSON()),
        sa.Column('configuration', sa.JSON()),
        sa.Column('capabilities', sa.JSON()),
        sa.Column('is_active', sa.Boolean(), default=True, index=True),
        sa.Column('is_monitored', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('updated_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'))
    )
    
    # Create device_metrics table
    op.create_table('device_metrics',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('metric_type', sa.String(50), nullable=False, index=True),
        sa.Column('metric_name', sa.String(100), index=True),
        sa.Column('value', sa.Float(), nullable=False),
        sa.Column('unit', sa.String(20)),
        sa.Column('threshold_warning', sa.Float()),
        sa.Column('threshold_critical', sa.Float()),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column('metadata', sa.JSON()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    
    # Create index for time-series queries
    op.create_index('idx_device_metrics_device_time', 'device_metrics', ['device_id', 'timestamp'])
    op.create_index('idx_device_metrics_type_time', 'device_metrics', ['metric_type', 'timestamp'])
    
    # Create alerts table
    op.create_table('alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), index=True),
        sa.Column('alert_type', sa.String(50), nullable=False, index=True),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('message', sa.String(500), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('status', sa.String(20), default='active', index=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True)),
        sa.Column('acknowledged_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('resolved_at', sa.DateTime(timezone=True)),
        sa.Column('resolved_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('escalation_level', sa.Integer(), default=0),
        sa.Column('alert_metadata', sa.JSON()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), index=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'))
    )
    
    # Create network_interfaces table
    op.create_table('network_interfaces',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.String(255)),
        sa.Column('interface_type', sa.String(50)),
        sa.Column('mac_address', sa.String(17)),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('subnet_mask', sa.String(45)),
        sa.Column('vlan_id', sa.Integer()),
        sa.Column('speed', sa.BigInteger()),
        sa.Column('duplex', sa.String(20)),
        sa.Column('mtu', sa.Integer()),
        sa.Column('admin_status', sa.String(20)),
        sa.Column('operational_status', sa.String(20), index=True),
        sa.Column('last_change', sa.DateTime(timezone=True)),
        sa.Column('in_octets', sa.BigInteger()),
        sa.Column('out_octets', sa.BigInteger()),
        sa.Column('in_errors', sa.BigInteger()),
        sa.Column('out_errors', sa.BigInteger()),
        sa.Column('in_discards', sa.BigInteger()),
        sa.Column('out_discards', sa.BigInteger()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now())
    )
    
    # Create discovery_jobs table
    op.create_table('discovery_jobs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('ip_range', sa.String(255), nullable=False),
        sa.Column('protocol', sa.String(50)),
        sa.Column('credentials', sa.JSON()),
        sa.Column('options', sa.JSON()),
        sa.Column('status', sa.String(50), default='pending', index=True),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('devices_found', sa.Integer(), default=0),
        sa.Column('devices_added', sa.Integer(), default=0),
        sa.Column('error_message', sa.Text()),
        sa.Column('results', sa.JSON()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'))
    )
    
    # Create notifications table
    op.create_table('notifications',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('message', sa.Text(), nullable=False),
        sa.Column('notification_type', sa.String(50), index=True),
        sa.Column('severity', sa.String(20)),
        sa.Column('read', sa.Boolean(), default=False, index=True),
        sa.Column('read_at', sa.DateTime(timezone=True)),
        sa.Column('notification_metadata', sa.JSON()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), index=True)
    )
    
    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), index=True),
        sa.Column('action', sa.String(100), nullable=False, index=True),
        sa.Column('resource_type', sa.String(50), index=True),
        sa.Column('resource_id', sa.String(100)),
        sa.Column('details', sa.JSON()),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.String(255)),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now(), index=True)
    )
    
    # Create maintenance_windows table
    op.create_table('maintenance_windows',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('device_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('devices.id'), index=True),
        sa.Column('device_group', sa.String(100)),
        sa.Column('start_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('end_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('recurring', sa.Boolean(), default=False),
        sa.Column('recurrence_pattern', sa.JSON()),
        sa.Column('suppress_alerts', sa.Boolean(), default=True),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('created_by', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'))
    )
    
    # Insert default roles
    op.execute("""
        INSERT INTO roles (id, name, description, permissions, is_system)
        VALUES 
        (gen_random_uuid(), 'admin', 'Administrator role with full access', 
         '{"all": true}', true),
        (gen_random_uuid(), 'operator', 'Operator role with monitoring access', 
         '{"view": true, "acknowledge": true, "poll": true}', true),
        (gen_random_uuid(), 'viewer', 'Read-only viewer role', 
         '{"view": true}', true)
    """)


def downgrade() -> None:
    """Drop all tables"""
    op.drop_table('maintenance_windows')
    op.drop_table('audit_logs')
    op.drop_table('notifications')
    op.drop_table('discovery_jobs')
    op.drop_table('network_interfaces')
    op.drop_table('alerts')
    op.drop_index('idx_device_metrics_type_time')
    op.drop_index('idx_device_metrics_device_time')
    op.drop_table('device_metrics')
    op.drop_table('devices')
    op.drop_table('user_roles')
    op.drop_table('roles')
    op.drop_table('users')