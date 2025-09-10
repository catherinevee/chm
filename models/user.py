"""
CHM User Model
User authentication and authorization model
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime, timedelta
from typing import Optional, List

from core.database import Base
import enum

class UserRole(str, enum.Enum):
    """User role enumeration"""
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
    GUEST = "guest"

class UserStatus(str, enum.Enum):
    """User status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"

class User(Base):
    """User model for authentication and authorization"""
    
    __tablename__ = "users"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Authentication fields
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    
    # Profile fields
    full_name = Column(String(100), nullable=True)
    phone = Column(String(20), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    
    # Status and role
    role = Column(Enum(UserRole), default=UserRole.VIEWER, nullable=False)
    status = Column(Enum(UserStatus), default=UserStatus.ACTIVE, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    is_mfa_enabled = Column(Boolean, default=False, nullable=False)
    mfa_secret = Column(String(255), nullable=True)
    
    # Security fields
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    last_failed_login = Column(DateTime, nullable=True)
    account_locked_until = Column(DateTime, nullable=True)
    password_changed_at = Column(DateTime, default=func.now(), nullable=False)
    password_expires_at = Column(DateTime, nullable=True)
    
    # Session management
    last_login = Column(DateTime, nullable=True)
    last_activity = Column(DateTime, nullable=True)
    session_timeout = Column(Integer, default=1800, nullable=False)  # 30 minutes
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, nullable=True)
    updated_by = Column(Integer, nullable=True)
    
    # Soft delete
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, nullable=True)
    
    # Relationships
    devices = relationship("Device", foreign_keys="Device.created_by", back_populates="owner")
    alerts = relationship("Alert", foreign_keys="Alert.assigned_to", back_populates="assigned_user")
    notifications = relationship("Notification", foreign_keys="Notification.user_id", back_populates="user")
    security_roles = relationship("SecurityRole", secondary="user_roles", foreign_keys="[UserRole.user_id, UserRole.role_id]", back_populates="users")
    
    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"
    
    @property
    def is_active(self) -> bool:
        """Check if user is active"""
        return (
            self.status == UserStatus.ACTIVE and 
            not self.is_deleted and
            (self.account_locked_until is None or self.account_locked_until < datetime.utcnow())
        )
    
    @property
    def is_admin(self) -> bool:
        """Check if user is admin"""
        return self.role == UserRole.ADMIN
    
    @property
    def is_operator(self) -> bool:
        """Check if user is operator or admin"""
        return self.role in [UserRole.ADMIN, UserRole.OPERATOR]
    
    @property
    def can_view(self) -> bool:
        """Check if user can view data"""
        return self.is_active
    
    @property
    def can_edit(self) -> bool:
        """Check if user can edit data"""
        return self.is_active and self.is_operator
    
    @property
    def can_delete(self) -> bool:
        """Check if user can delete data"""
        return self.is_active and self.is_admin
    
    @property
    def is_locked(self) -> bool:
        """Check if user account is locked"""
        return (
            self.account_locked_until is not None and 
            self.account_locked_until > datetime.utcnow()
        )
    
    @property
    def password_expired(self) -> bool:
        """Check if password has expired"""
        if self.password_expires_at is None:
            return False
        return datetime.utcnow() > self.password_expires_at
    
    def increment_failed_login(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        
        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
    
    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.last_failed_login = None
        self.account_locked_until = None
    
    def update_last_login(self):
        """Update last login timestamp"""
        self.last_login = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        self.reset_failed_login()
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.utcnow()
    
    def set_password_expiry(self, days: int = 90):
        """Set password expiry date"""
        self.password_expires_at = datetime.utcnow() + timedelta(days=days)
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert user to dictionary"""
        data = {
            "id": self.id,
            "uuid": str(self.uuid),
            "username": self.username,
            "email": self.email,
            "full_name": self.full_name,
            "phone": self.phone,
            "avatar_url": self.avatar_url,
            "role": self.role.value,
            "status": self.status.value,
            "is_verified": self.is_verified,
            "is_mfa_enabled": self.is_mfa_enabled,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "is_active": self.is_active,
            "is_locked": self.is_locked,
            "password_expired": self.password_expired
        }
        
        if include_sensitive:
            data.update({
                "failed_login_attempts": self.failed_login_attempts,
                "last_failed_login": self.last_failed_login.isoformat() if self.last_failed_login else None,
                "account_locked_until": self.account_locked_until.isoformat() if self.account_locked_until else None,
                "password_changed_at": self.password_changed_at.isoformat(),
                "password_expires_at": self.password_expires_at.isoformat() if self.password_expires_at else None
            })
        
        return data
