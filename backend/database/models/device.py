"""
Device model for CHM
"""
from sqlalchemy import Column, String, Boolean, DateTime, Integer, Float, JSON, Enum, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from database.base import Base


class DeviceStatus(enum.Enum):
    """Device status enumeration"""
    UP = "up"
    DOWN = "down"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class DeviceType(enum.Enum):
    """Device type enumeration"""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    ACCESS_POINT = "access_point"
    LOAD_BALANCER = "load_balancer"
    STORAGE = "storage"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    OTHER = "other"


class Device(Base):
    """Device model with comprehensive monitoring capabilities"""
    __tablename__ = "devices"
    
    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(INET, nullable=False, unique=True, index=True)
    mac_address = Column(String(17))
    
    # Device classification
    device_type = Column(Enum(DeviceType), default=DeviceType.OTHER)
    vendor = Column(String(100), index=True)
    model = Column(String(100))
    serial_number = Column(String(100), unique=True, sparse=True)
    firmware_version = Column(String(100))
    hardware_version = Column(String(100))
    
    # Location and organization
    location = Column(String(255))
    site_id = Column(UUID(as_uuid=True), ForeignKey("sites.id"))
    department = Column(String(100))
    asset_tag = Column(String(100), unique=True, sparse=True)
    
    # SNMP configuration
    snmp_enabled = Column(Boolean, default=True)
    snmp_version = Column(String(10), default="2c")
    snmp_community = Column(String(255))  # Encrypted
    snmp_v3_username = Column(String(100))
    snmp_v3_auth_protocol = Column(String(10))  # MD5, SHA
    snmp_v3_auth_password = Column(String(255))  # Encrypted
    snmp_v3_priv_protocol = Column(String(10))  # DES, AES
    snmp_v3_priv_password = Column(String(255))  # Encrypted
    snmp_port = Column(Integer, default=161)
    
    # SSH configuration
    ssh_enabled = Column(Boolean, default=False)
    ssh_username = Column(String(100))
    ssh_password = Column(String(255))  # Encrypted
    ssh_private_key = Column(String)  # Encrypted
    ssh_port = Column(Integer, default=22)
    ssh_enable_password = Column(String(255))  # Encrypted (for Cisco enable mode)
    
    # REST API configuration
    api_enabled = Column(Boolean, default=False)
    api_endpoint = Column(String(255))
    api_username = Column(String(100))
    api_password = Column(String(255))  # Encrypted
    api_token = Column(String(500))  # Encrypted
    
    # Discovery information
    discovery_protocol = Column(String(50))  # CDP, LLDP, ARP, MANUAL
    discovered_at = Column(DateTime(timezone=True))
    discovery_source = Column(String(100))
    parent_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    
    # Monitoring configuration
    monitoring_enabled = Column(Boolean, default=True)
    polling_interval = Column(Integer, default=300)  # seconds
    availability_check_enabled = Column(Boolean, default=True)
    performance_monitoring_enabled = Column(Boolean, default=True)
    interface_monitoring_enabled = Column(Boolean, default=True)
    custom_oids = Column(JSON)  # List of custom OIDs to monitor
    
    # Device capabilities
    capabilities = Column(JSON)  # List of device capabilities
    interfaces_count = Column(Integer, default=0)
    processors_count = Column(Integer, default=0)
    memory_total_mb = Column(Float)
    storage_total_gb = Column(Float)
    
    # Status and health
    status = Column(Enum(DeviceStatus), default=DeviceStatus.UNKNOWN, index=True)
    last_seen = Column(DateTime(timezone=True))
    uptime_seconds = Column(Integer)
    response_time_ms = Column(Float)
    packet_loss_percent = Column(Float)
    
    # Performance metrics (cached)
    cpu_usage_percent = Column(Float)
    memory_usage_percent = Column(Float)
    temperature_celsius = Column(Float)
    power_consumption_watts = Column(Float)
    
    # Administrative
    is_active = Column(Boolean, default=True, index=True)
    is_critical = Column(Boolean, default=False, index=True)
    maintenance_mode = Column(Boolean, default=False)
    notes = Column(String)
    tags = Column(JSON)  # List of tags for categorization
    custom_attributes = Column(JSON)  # Key-value pairs for custom data
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    site = relationship("Site", back_populates="devices")
    parent_device = relationship("Device", remote_side=[id])
    interfaces = relationship("Interface", back_populates="device", cascade="all, delete-orphan")
    metrics = relationship("DeviceMetric", back_populates="device", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="device", cascade="all, delete-orphan")
    alert_rules = relationship("AlertRule", back_populates="device", cascade="all, delete-orphan")
    maintenance_windows = relationship("MaintenanceWindow", back_populates="device")
    sla_targets = relationship("SLATarget", back_populates="device")
    
    # Indexes for performance
    __table_args__ = (
        Index("idx_device_status_active", "status", "is_active"),
        Index("idx_device_type_vendor", "device_type", "vendor"),
        Index("idx_device_critical", "is_critical", "status"),
        Index("idx_device_monitoring", "monitoring_enabled", "is_active"),
    )
    
    def __repr__(self):
        return f"<Device {self.hostname} ({self.ip_address})>"


class Interface(Base):
    """Network interface model"""
    __tablename__ = "interfaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    
    # Interface identification
    name = Column(String(100), nullable=False)
    description = Column(String(255))
    index = Column(Integer)
    type = Column(String(50))  # Ethernet, Serial, Loopback, etc.
    
    # Configuration
    admin_status = Column(String(20))  # up, down, testing
    operational_status = Column(String(20))  # up, down, testing
    speed_mbps = Column(Integer)
    duplex = Column(String(20))  # full, half, auto
    mtu = Column(Integer)
    
    # Network configuration
    ip_address = Column(INET)
    subnet_mask = Column(String(15))
    mac_address = Column(String(17))
    vlan_id = Column(Integer)
    
    # Statistics (cached)
    in_octets = Column(BigInteger)
    out_octets = Column(BigInteger)
    in_packets = Column(BigInteger)
    out_packets = Column(BigInteger)
    in_errors = Column(BigInteger)
    out_errors = Column(BigInteger)
    in_discards = Column(BigInteger)
    out_discards = Column(BigInteger)
    
    # Utilization (calculated)
    in_utilization_percent = Column(Float)
    out_utilization_percent = Column(Float)
    error_rate_percent = Column(Float)
    
    # Timestamps
    last_change = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="interfaces")
    
    # Indexes
    __table_args__ = (
        Index("idx_interface_device", "device_id", "name"),
        Index("idx_interface_status", "operational_status", "admin_status"),
    )


class Site(Base):
    """Site/Location model"""
    __tablename__ = "sites"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True)
    address = Column(String(255))
    city = Column(String(100))
    state = Column(String(100))
    country = Column(String(100))
    postal_code = Column(String(20))
    latitude = Column(Float)
    longitude = Column(Float)
    time_zone = Column(String(50))
    contact_name = Column(String(100))
    contact_email = Column(String(255))
    contact_phone = Column(String(50))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    devices = relationship("Device", back_populates="site")


from sqlalchemy import BigInteger