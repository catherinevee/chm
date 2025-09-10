"""
CHM Device Credentials Model
Secure storage of device access credentials with encryption
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
import enum

from core.database import Base

class CredentialType(str, enum.Enum):
    """Types of device credentials"""
    SNMP = "SNMP"
    SSH = "SSH"
    HTTP = "HTTP"
    TELNET = "TELNET"

class CredentialStatus(str, enum.Enum):
    """Credential status"""
    ACTIVE = "active"
    EXPIRED = "expired"
    LOCKED = "locked"
    ROTATING = "rotating"

class DeviceCredentials(Base):
    """Secure storage for device access credentials"""
    __tablename__ = "device_credentials"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Device relationship
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    device = relationship("Device", back_populates="credentials")
    
    # Credential details
    credential_type = Column(Enum(CredentialType), nullable=False, index=True)
    name = Column(String(100), nullable=False)  # e.g., "Primary SNMP", "SSH Admin"
    description = Column(Text, nullable=True)
    
    # Encrypted credential data
    encrypted_data = Column(Text, nullable=False)  # AES-256 encrypted
    key_id = Column(String(100), nullable=False)  # KMS key reference
    encryption_algorithm = Column(String(50), default="AES-256-GCM")
    
    # Security settings
    status = Column(Enum(CredentialStatus), default=CredentialStatus.ACTIVE, nullable=False)
    is_primary = Column(Boolean, default=False, nullable=False)  # Primary credential for device
    
    # Access control
    allowed_users = Column(Text, nullable=True)  # JSON array of user IDs
    allowed_actions = Column(Text, nullable=True)  # JSON array of allowed actions
    
    # Rotation and expiry
    created_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=True, index=True)
    last_rotated = Column(DateTime, nullable=True)
    rotation_interval_days = Column(Integer, nullable=True)
    
    # Audit fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0)
    
    # Soft delete
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    def __repr__(self):
        return f"<DeviceCredentials(id={self.id}, type={self.credential_type}, device_id={self.device_id})>"
    
    @property
    def is_expired(self) -> bool:
        """Check if credential has expired"""
        if not self.expires_at:
            return False
        return func.now() > self.expires_at
    
    @property
    def needs_rotation(self) -> bool:
        """Check if credential needs rotation"""
        if not self.rotation_interval_days or not self.last_rotated:
            return False
        from datetime import datetime, timedelta
        return datetime.utcnow() > (self.last_rotated + timedelta(days=self.rotation_interval_days))
    
    @property
    def is_usable(self) -> bool:
        """Check if credential can be used"""
        if self.expires_at is None:
            # No expiration date, so not expired
            return (
                self.status == CredentialStatus.ACTIVE and
                not self.is_deleted
            )
        else:
            # Has expiration date, so is_expired returns a SQLAlchemy expression
            # We can't evaluate this in Python, so we return the expression
            # This will be evaluated by the database
            return (
                self.status == CredentialStatus.ACTIVE and
                not self.is_expired and
                not self.is_deleted
            )
    
    def mark_used(self):
        """Mark credential as used"""
        self.last_used = func.now()
        self.usage_count += 1
    
    def rotate(self, new_encrypted_data: str, new_key_id: str):
        """Rotate credential with new encrypted data"""
        self.encrypted_data = new_encrypted_data
        self.key_id = new_key_id
        self.last_rotated = func.now()
        self.usage_count = 0
    
    def lock(self):
        """Lock credential"""
        self.status = CredentialStatus.LOCKED
    
    def unlock(self):
        """Unlock credential"""
        self.status = CredentialStatus.ACTIVE
    
    def expire(self):
        """Mark credential as expired"""
        self.status = CredentialStatus.EXPIRED
