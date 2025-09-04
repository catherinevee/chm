"""
Database models for the health monitoring system
Enhanced with comprehensive inventory and asset management
"""

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, ForeignKey, Enum, JSON, BigInteger
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
import uuid
from datetime import datetime
import enum

Base = declarative_base()

class DeviceType(enum.Enum):
    """Device types for categorization"""
    ROUTER = "router"
    SWITCH = "switch"
    FIREWALL = "firewall"
    SERVER = "server"
    WORKSTATION = "workstation"
    PRINTER = "printer"
    CAMERA = "camera"
    SENSOR = "sensor"
    OTHER = "other"

class DeviceStatus(enum.Enum):
    """Device operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    DECOMMISSIONED = "decommissioned"
    QUARANTINE = "quarantine"

class AlertSeverity(enum.Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

class DeviceGroup(enum.Enum):
    """Device group categories"""
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TESTING = "testing"
    DMZ = "dmz"
    INTERNAL = "internal"
    EXTERNAL = "external"

class NotificationType(enum.Enum):
    """Notification types"""
    ALERT = "alert"
    SYSTEM = "system"
    DEVICE_STATUS = "device_status"
    DISCOVERY = "discovery"
    SLA_BREACH = "sla_breach"
    MAINTENANCE = "maintenance"

class NotificationStatus(enum.Enum):
    """Notification status"""
    UNREAD = "unread"
    READ = "read"
    ARCHIVED = "archived"

class AssetStatus(enum.Enum):
    """Asset lifecycle status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETIRED = "retired"
    LOST = "lost"
    STOLEN = "stolen"

class DiscoveryProtocol(enum.Enum):
    """Network discovery protocols"""
    SNMP = "snmp"
    CDP = "cdp"
    LLDP = "lldp"
    ARP = "arp"
    PING = "ping"
    NMAP = "nmap"

class RelationshipType(enum.Enum):
    """Device relationship types"""
    CONNECTED_TO = "connected_to"
    PARENT_CHILD = "parent_child"
    REDUNDANT = "redundant"
    BACKUP = "backup"
    DEPENDS_ON = "depends_on"

class MetricType(enum.Enum):
    """Performance metric types"""
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    TEMPERATURE = "temperature"
    UPTIME = "uptime"
    INTERFACE = "interface"
    BANDWIDTH = "bandwidth"
    LATENCY = "latency"
    PACKET_LOSS = "packet_loss"

class Device(Base):
    """Enhanced device model with comprehensive inventory and asset management"""
    __tablename__ = "devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, unique=True)
    ip_address = Column(String(45), nullable=False, unique=True)
    device_type = Column(Enum(DeviceType), nullable=False)
    current_state = Column(Enum(DeviceStatus), default=DeviceStatus.OFFLINE)
    is_active = Column(Boolean, default=True)
    last_poll_time = Column(DateTime)
    consecutive_failures = Column(Integer, default=0)
    circuit_breaker_trips = Column(Integer, default=0)
    
    # Enhanced inventory fields
    serial_number = Column(String(255), unique=True)
    model = Column(String(255))
    manufacturer = Column(String(255))
    firmware_version = Column(String(255))
    os_version = Column(String(255))
    purchase_date = Column(DateTime)
    warranty_expiry = Column(DateTime)
    location = Column(String(500))
    rack_position = Column(String(100))
    data_center = Column(String(255))
    department = Column(String(255))
    owner = Column(String(255))
    cost = Column(Float)
    asset_tag = Column(String(255), unique=True)
    asset_status = Column(Enum(AssetStatus), default=AssetStatus.ACTIVE)
    notes = Column(Text)
    
    # Device grouping
    device_group = Column(Enum(DeviceGroup), default=DeviceGroup.INTERNAL)
    custom_group = Column(String(255))
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_maintenance = Column(DateTime)
    next_maintenance = Column(DateTime)
    
    # Discovery and topology fields
    discovery_protocol = Column(Enum(DiscoveryProtocol))
    last_discovery = Column(DateTime)
    discovery_status = Column(String(50))
    
    # Relationships
    parent_relationships = relationship("DeviceRelationship", foreign_keys="DeviceRelationship.child_device_id", back_populates="child_device")
    child_relationships = relationship("DeviceRelationship", foreign_keys="DeviceRelationship.parent_device_id", back_populates="parent_device")
    interfaces = relationship("NetworkInterface", back_populates="device")
    sla_metrics = relationship("SLAMetrics", back_populates="device")
    performance_metrics = relationship("PerformanceMetrics", back_populates="device")
    notifications = relationship("Notification", back_populates="device")

class NetworkInterface(Base):
    """Network interface model for detailed interface monitoring"""
    __tablename__ = "network_interfaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    interface_name = Column(String(100), nullable=False)
    interface_type = Column(String(50))  # ethernet, fiber, wireless, etc.
    mac_address = Column(String(17))
    ip_address = Column(String(45))
    subnet_mask = Column(String(45))
    speed = Column(Integer)  # in Mbps
    duplex = Column(String(20))  # full, half
    status = Column(String(20))  # up, down, admin_down
    description = Column(String(500))
    
    # Performance metrics
    in_octets = Column(BigInteger, default=0)
    out_octets = Column(BigInteger, default=0)
    in_errors = Column(Integer, default=0)
    out_errors = Column(Integer, default=0)
    in_discards = Column(Integer, default=0)
    out_discards = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_poll_time = Column(DateTime)
    
    # Relationships
    device = relationship("Device", back_populates="interfaces")

class DeviceRelationship(Base):
    """Device relationship model for network topology"""
    __tablename__ = "device_relationships"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    parent_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    child_device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    relationship_type = Column(Enum(RelationshipType), nullable=False)
    parent_interface = Column(String(100))
    child_interface = Column(String(100))
    bandwidth = Column(Integer)  # in Mbps
    latency = Column(Float)  # in milliseconds
    discovery_protocol = Column(Enum(DiscoveryProtocol))
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_verified = Column(DateTime)
    
    # Relationships
    parent_device = relationship("Device", foreign_keys=[parent_device_id], back_populates="child_relationships")
    child_device = relationship("Device", foreign_keys=[child_device_id], back_populates="parent_relationships")

class SLAMetrics(Base):
    """SLA monitoring metrics"""
    __tablename__ = "sla_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    sla_name = Column(String(255), nullable=False)
    sla_type = Column(String(50))  # uptime, response_time, availability
    target_value = Column(Float, nullable=False)  # target percentage or time
    current_value = Column(Float)
    measurement_period = Column(Integer)  # in minutes
    uptime_percentage = Column(Float)
    downtime_minutes = Column(Integer)
    last_outage_start = Column(DateTime)
    last_outage_end = Column(DateTime)
    total_outages = Column(Integer, default=0)
    sla_status = Column(String(20))  # met, breached, warning
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_measurement = Column(DateTime)
    
    # Relationships
    device = relationship("Device", back_populates="sla_metrics")

class PerformanceMetrics(Base):
    """Performance metrics for graphing and monitoring"""
    __tablename__ = "performance_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    metric_type = Column(Enum(MetricType), nullable=False)
    metric_name = Column(String(255), nullable=False)
    metric_value = Column(Float, nullable=False)
    metric_unit = Column(String(20))  # %, MB, Mbps, °C, etc.
    interface_name = Column(String(100))  # for interface-specific metrics
    threshold_warning = Column(Float)
    threshold_critical = Column(Float)
    metric_metadata = Column(JSON)  # Additional context data
    
    # Timestamps
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    device = relationship("Device", back_populates="performance_metrics")

class NetworkDiscovery(Base):
    """Network discovery sessions and results"""
    __tablename__ = "network_discoveries"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    discovery_name = Column(String(255), nullable=False)
    network_cidr = Column(String(45), nullable=False)
    discovery_protocol = Column(Enum(DiscoveryProtocol), nullable=False)
    status = Column(String(20))  # running, completed, failed
    devices_found = Column(Integer, default=0)
    devices_added = Column(Integer, default=0)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime)
    error_message = Column(Text)
    
    # Configuration
    scan_options = Column(JSON)  # Store scan configuration as JSON
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Alert(Base):
    """Enhanced alert model"""
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False)
    metric_name = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    acknowledged = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    acknowledged_at = Column(DateTime)
    resolved_at = Column(DateTime)
    
    # Relationships
    notifications = relationship("Notification", back_populates="alert")



class DataArchive(Base):
    """Data archiving and retention management"""
    __tablename__ = "data_archives"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    archive_type = Column(String(255), nullable=False)  # metrics, alerts, logs
    source_table = Column(String(255), nullable=False)
    archive_date = Column(DateTime, default=datetime.utcnow)
    data_range_start = Column(DateTime, nullable=False)
    data_range_end = Column(DateTime, nullable=False)
    record_count = Column(Integer)
    archive_size = Column(Integer)  # in bytes
    storage_location = Column(String(500))
    compression_ratio = Column(Float)
    retention_policy = Column(String(255))
    expires_at = Column(DateTime)
    status = Column(String(255), default="archived")  # archived, restored, deleted
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(255))

class BackupLog(Base):
    """Backup operation logging"""
    __tablename__ = "backup_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    backup_type = Column(String(255), nullable=False)  # full, incremental, differential
    backup_date = Column(DateTime, default=datetime.utcnow)
    backup_size = Column(Integer)  # in bytes
    duration = Column(Integer)     # in seconds
    status = Column(String(255))   # success, failed, partial
    storage_location = Column(String(500))
    checksum = Column(String(255))
    error_message = Column(Text)
    
    # Metadata
    created_by = Column(String(255))
    retention_days = Column(Integer, default=30)

class SystemNotification(Base):
    """System notifications and user alerts"""
    __tablename__ = "system_notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    notification_type = Column(String(255), nullable=False)  # alert, maintenance, system
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.INFO)
    target_user = Column(String(255))  # specific user or "all"
    read = Column(Boolean, default=False)
    read_at = Column(DateTime)
    expires_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(255))

class CapacityPlanning(Base):
    """Capacity planning and utilization tracking"""
    __tablename__ = "capacity_planning"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    metric_type = Column(String(255), nullable=False)  # cpu, memory, storage, network
    current_utilization = Column(Float, nullable=False)
    peak_utilization = Column(Float)
    average_utilization = Column(Float)
    threshold_warning = Column(Float, default=80.0)
    threshold_critical = Column(Float, default=95.0)
    capacity_total = Column(Float)
    capacity_available = Column(Float)
    growth_rate = Column(Float)  # percentage per month
    projected_exhaustion = Column(DateTime)
    recommendations = Column(Text)
    
    # Timestamps
    measured_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Notification(Base):
    """System notifications and alerts"""
    __tablename__ = "notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(Enum(NotificationType), nullable=False, default=NotificationType.SYSTEM)
    status = Column(Enum(NotificationStatus), nullable=False, default=NotificationStatus.UNREAD)
    severity = Column(Enum(AlertSeverity), nullable=False, default=AlertSeverity.INFO)
    
    # Related entities
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=True)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=True)
    user_id = Column(String(255))  # User who should receive notification
    
    # Metadata
    notification_metadata = Column(JSON)  # Additional context data
    action_url = Column(String(500))  # URL for notification action
    expires_at = Column(DateTime)  # When notification expires
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    read_at = Column(DateTime)
    archived_at = Column(DateTime)
    
    # Relationships
    device = relationship("Device", back_populates="notifications")
    alert = relationship("Alert", back_populates="notifications")
