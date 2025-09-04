"""
Database migration to add user authentication and encrypted credential fields
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import uuid

# Revision identifiers
revision = '001_add_user_and_credentials'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    """Add user tables and encrypted credential fields to devices"""
    
    # Create users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('username', sa.String(100), nullable=False, unique=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('full_name', sa.String(255)),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('is_superuser', sa.Boolean(), default=False),
        sa.Column('is_verified', sa.Boolean(), default=False),
        sa.Column('verification_token', sa.String(255)),
        sa.Column('reset_token', sa.String(255)),
        sa.Column('reset_token_expires', sa.DateTime(timezone=True)),
        sa.Column('last_login', sa.DateTime(timezone=True)),
        sa.Column('failed_login_attempts', sa.Integer(), default=0),
        sa.Column('locked_until', sa.DateTime(timezone=True)),
        sa.Column('mfa_secret', sa.String(255)),
        sa.Column('mfa_enabled', sa.Boolean(), default=False),
        sa.Column('api_key', sa.String(255), unique=True),
        sa.Column('preferences', sa.JSON()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now())
    )
    
    # Create indexes for users table
    op.create_index('idx_user_username', 'users', ['username'])
    op.create_index('idx_user_email', 'users', ['email'])
    op.create_index('idx_user_email_active', 'users', ['email', 'is_active'])
    
    # Create roles table
    op.create_table('roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.Text()),
        sa.Column('is_system', sa.Boolean(), default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), onupdate=sa.func.now())
    )
    
    # Create permissions table
    op.create_table('permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('resource', sa.String(100), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),
        sa.Column('description', sa.Text()),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    
    # Create unique index for permissions
    op.create_index('idx_permission_resource_action', 'permissions', ['resource', 'action'], unique=True)
    
    # Create user_roles association table
    op.create_table('user_roles',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id', ondelete='CASCADE')),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    
    # Create role_permissions association table
    op.create_table('role_permissions',
        sa.Column('role_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('roles.id', ondelete='CASCADE')),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('permissions.id', ondelete='CASCADE')),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )
    
    # Create user_sessions table
    op.create_table('user_sessions',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_jti', sa.String(255), nullable=False, unique=True),
        sa.Column('refresh_token', sa.String(500), unique=True),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column('last_activity', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    
    # Create indexes for user_sessions
    op.create_index('idx_session_user_active', 'user_sessions', ['user_id', 'is_active'])
    op.create_index('idx_session_token_jti', 'user_sessions', ['token_jti'])
    
    # Create audit_logs table
    op.create_table('audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True, default=uuid.uuid4),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id')),
        sa.Column('action', sa.String(100), nullable=False),
        sa.Column('resource_type', sa.String(100)),
        sa.Column('resource_id', sa.String(255)),
        sa.Column('details', sa.JSON()),
        sa.Column('ip_address', sa.String(45)),
        sa.Column('user_agent', sa.Text()),
        sa.Column('status', sa.String(20)),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now())
    )
    
    # Create indexes for audit_logs
    op.create_index('idx_audit_user_created', 'audit_logs', ['user_id', 'created_at'])
    op.create_index('idx_audit_resource_action', 'audit_logs', ['resource_type', 'action'])
    
    # Add encrypted credential fields to devices table
    op.add_column('devices', sa.Column('snmp_community_encrypted', sa.Text()))
    op.add_column('devices', sa.Column('snmp_v3_auth_encrypted', sa.Text()))
    op.add_column('devices', sa.Column('snmp_v3_priv_encrypted', sa.Text()))
    op.add_column('devices', sa.Column('ssh_username', sa.String(100)))
    op.add_column('devices', sa.Column('ssh_password_encrypted', sa.Text()))
    op.add_column('devices', sa.Column('ssh_key_encrypted', sa.Text()))
    op.add_column('devices', sa.Column('api_key_encrypted', sa.Text()))
    op.add_column('devices', sa.Column('api_secret_encrypted', sa.Text()))
    
    # Add user_id field to notifications table
    op.add_column('notifications', sa.Column('user_id', postgresql.UUID(as_uuid=True)))

def downgrade():
    """Remove user tables and encrypted credential fields"""
    
    # Remove encrypted credential fields from devices table
    op.drop_column('devices', 'snmp_community_encrypted')
    op.drop_column('devices', 'snmp_v3_auth_encrypted')
    op.drop_column('devices', 'snmp_v3_priv_encrypted')
    op.drop_column('devices', 'ssh_username')
    op.drop_column('devices', 'ssh_password_encrypted')
    op.drop_column('devices', 'ssh_key_encrypted')
    op.drop_column('devices', 'api_key_encrypted')
    op.drop_column('devices', 'api_secret_encrypted')
    
    # Remove user_id from notifications
    op.drop_column('notifications', 'user_id')
    
    # Drop tables in reverse order
    op.drop_table('audit_logs')
    op.drop_table('user_sessions')
    op.drop_table('role_permissions')
    op.drop_table('user_roles')
    op.drop_table('permissions')
    op.drop_table('roles')
    op.drop_table('users')