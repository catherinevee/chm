"""
CHM Device Model
Network device management and monitoring
"""

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum, ForeignKey, JSON
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
import enum
from typing import Any

from core.database import Base

class DeviceStatus(str, enum.Enum):
    """Device operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"
    ERROR = "error"

class DeviceProtocol(str, enum.Enum):
    """Device communication protocol"""
    SNMP = "SNMP"
    SSH = "SSH"
    HTTP = "HTTP"
    TELNET = "TELNET"
    ICMP = "ICMP"

class DeviceType(str, enum.Enum):
    """Device type classification"""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    PRINTER = "printer"
    CAMERA = "camera"
    SENSOR = "sensor"
    OTHER = "other"

class Device(Base):
    """Network device model"""
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Basic device information
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    device_type = Column(Enum(DeviceType), default=DeviceType.OTHER, nullable=False, index=True)
    vendor = Column(String(100), nullable=True, index=True)
    model = Column(String(100), nullable=True, index=True)
    serial_number = Column(String(100), nullable=True, unique=True)
    
    # Network information
    ip_address = Column(String(45), nullable=False, index=True)  # IPv4 or IPv6
    mac_address = Column(String(17), nullable=True, index=True)  # XX:XX:XX:XX:XX:XX format
    hostname = Column(String(255), nullable=True, index=True)
    domain = Column(String(255), nullable=True)
    
    # Communication protocol
    protocol = Column(Enum(DeviceProtocol), default=DeviceProtocol.SNMP, nullable=False, index=True)
    port = Column(Integer, nullable=True)  # Protocol-specific port
    
    # SSH-specific fields
    ssh_username = Column(String(100), nullable=True)
    ssh_key_path = Column(String(255), nullable=True)
    
    # SNMP-specific fields
    snmp_community = Column(String(100), nullable=True)
    snmp_version = Column(String(10), default="2c", nullable=True)  # 1, 2c, 3
    
    # Device status and monitoring
    status = Column(Enum(DeviceStatus), default=DeviceStatus.UNKNOWN, nullable=False, index=True)
    last_seen = Column(DateTime, nullable=True, index=True)
    last_poll = Column(DateTime, nullable=True, index=True)
    response_time_ms = Column(Integer, nullable=True)  # Last response time in milliseconds
    
    # Monitoring configuration
    monitoring_enabled = Column(Boolean, default=True, nullable=False)
    poll_interval_seconds = Column(Integer, default=300, nullable=False)  # 5 minutes default
    timeout_seconds = Column(Integer, default=30, nullable=False)
    retry_count = Column(Integer, default=3, nullable=False)
    
    # Device capabilities and features
    capabilities = Column(JSON, nullable=True)  # JSON object of device capabilities
    interfaces = Column(JSON, nullable=True)  # JSON array of interface names
    services = Column(JSON, nullable=True)  # JSON array of running services
    
    # Location and organization
    location = Column(String(255), nullable=True, index=True)
    department = Column(String(100), nullable=True, index=True)
    owner = Column(String(100), nullable=True)
    tags = Column(JSON, nullable=True)  # JSON array of tags
    
    # Security and access control
    access_level = Column(String(50), default="read", nullable=False)  # read, write, admin
    allowed_users = Column(JSON, nullable=True)  # JSON array of user IDs
    allowed_actions = Column(JSON, nullable=True)  # JSON array of allowed actions
    
    # Audit and tracking
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Soft delete
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    owner = relationship("User", foreign_keys=[created_by], back_populates="devices")
    credentials = relationship("DeviceCredentials", back_populates="device", cascade="all, delete-orphan")
    metrics = relationship("Metric", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="device")
    interfaces = relationship("NetworkInterface", foreign_keys="NetworkInterface.device_id", back_populates="device")
    performance_analyses = relationship("PerformanceAnalysis", back_populates="device")
    anomaly_detections = relationship("AnomalyDetection", back_populates="device")
    capacity_planning = relationship("CapacityPlanning", back_populates="device")
    trend_forecasts = relationship("TrendForecast", back_populates="device")
    
    def __repr__(self):
        return f"<Device(id={self.id}, name='{self.name}', ip='{self.ip_address}', status='{self.status}')>"
    
    @property
    def is_online(self) -> bool:
        """Check if device is currently online"""
        return self.status == DeviceStatus.ONLINE
    
    @property
    def is_monitored(self) -> bool:
        """Check if device is being monitored"""
        return self.monitoring_enabled and not self.is_deleted
    
    @property
    def needs_polling(self) -> bool:
        """Check if device needs to be polled"""
        if not self.is_monitored:
            return False
        
        if not self.last_poll:
            return True
        
        from datetime import datetime, timedelta
        return datetime.now() > (self.last_poll + timedelta(seconds=self.poll_interval_seconds))
    
    @property
    def is_accessible(self) -> bool:
        """Check if device is accessible for operations"""
        return (
            self.is_monitored and
            self.status != DeviceStatus.MAINTENANCE and
            not self.is_deleted
        )
    
    def update_status(self, new_status: DeviceStatus, response_time_ms: int = None):
        """Update device status and monitoring data"""
        self.status = new_status
        self.last_seen = func.now()
        self.last_poll = func.now()
        
        if response_time_ms is not None:
            self.response_time_ms = response_time_ms
        
        # Update status change timestamp
        self.updated_at = func.now()
    
    def enable_monitoring(self):
        """Enable device monitoring"""
        self.monitoring_enabled = True
        self.updated_at = func.now()
    
    def disable_monitoring(self):
        """Disable device monitoring"""
        self.monitoring_enabled = False
        self.updated_at = func.now()
    
    def add_tag(self, tag: str):
        """Add a tag to the device"""
        if not self.tags:
            self.tags = []
        
        if tag not in self.tags:
            self.tags.append(tag)
            self.updated_at = func.now()
    
    def remove_tag(self, tag: str):
        """Remove a tag from the device"""
        if self.tags and tag in self.tags:
            self.tags.remove(tag)
            self.updated_at = func.now()
    
    def set_capability(self, capability: str, value: Any):
        """Set a device capability"""
        if not self.capabilities:
            self.capabilities = {}
        
        self.capabilities[capability] = value
        self.updated_at = func.now()
    
    def get_capability(self, capability: str, default: Any = None) -> Any:
        """Get a device capability"""
        if not self.capabilities:
            return default
        
        return self.capabilities.get(capability, default)
    
    def soft_delete(self, deleted_by: int):
        """Soft delete the device"""
        self.is_deleted = True
        self.deleted_at = func.now()
        self.deleted_by = deleted_by
        self.monitoring_enabled = False  # Disable monitoring for deleted devices
    
    def restore(self):
        """Restore a soft-deleted device"""
        self.is_deleted = False
        self.deleted_at = None
        self.deleted_by = None
        self.monitoring_enabled = True  # Re-enable monitoring
        self.updated_at = func.now()
