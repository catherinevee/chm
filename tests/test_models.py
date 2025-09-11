"""
Test models with String IDs for SQLite compatibility
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from datetime import datetime
import uuid

from backend.database.base import Base


class TestDevice(Base):
    """Device model for testing with String ID"""
    __tablename__ = "test_devices"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True) 
    device_type = Column(String(50), nullable=False, index=True)
    current_state = Column(String(20), nullable=False, default="unknown")
    manufacturer = Column(String(100))
    model = Column(String(100))
    serial_number = Column(String(100))
    firmware_version = Column(String(100))
    location = Column(String(255))
    description = Column(Text)
    
    # Monitoring configuration
    snmp_enabled = Column(Boolean, default=False)
    snmp_community = Column(String(100))
    snmp_version = Column(String(10), default="2c")
    snmp_port = Column(Integer, default=161)
    
    ssh_enabled = Column(Boolean, default=False)
    ssh_username = Column(String(100))
    ssh_port = Column(Integer, default=22)
    
    # Monitoring intervals
    polling_interval = Column(Integer, default=300)  # seconds
    last_polled = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    
    # Status fields
    is_active = Column(Boolean, default=True)
    is_monitored = Column(Boolean, default=True)
    uptime = Column(Integer)  # seconds
    
    # Additional metadata
    tags = Column(JSON)
    custom_fields = Column(JSON)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


class TestUser(Base):
    """User model for testing with String ID"""
    __tablename__ = "test_users"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255))
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())