"""
SQLAlchemy models for CHM database
Defines the structure for devices, alerts, notifications, and other entities
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, JSON, ForeignKey, Index
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from backend.database.base import Base

class Device(Base):
    """Device inventory and configuration"""
    __tablename__ = "devices"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(45), nullable=False, index=True)
    device_type = Column(String(50), nullable=False, index=True)
    current_state = Column(String(20), nullable=False, default="unknown")
    manufacturer = Column(String(100))
    model = Column(String(100))
    serial_number = Column(String(100), unique=True)
    firmware_version = Column(String(50))
    os_version = Column(String(50))
    location = Column(String(255), index=True)
    rack_position = Column(String(50))
    data_center = Column(String(100))
    department = Column(String(100), index=True)
    owner = Column(String(100))
    cost = Column(Float)
    asset_tag = Column(String(50), unique=True)
    asset_status = Column(String(20), default="active")
    notes = Column(Text)
    device_group = Column(String(100), index=True)
    custom_group = Column(String(100))
    discovery_protocol = Column(String(20), default="snmp")
    is_active = Column(Boolean, default=True)
    last_poll_time = Column(DateTime(timezone=True))
    configuration = Column(JSON)  # Device configuration and thresholds
    
    # Encrypted credentials
    snmp_community_encrypted = Column(Text)  # Encrypted SNMP community string
    snmp_v3_auth_encrypted = Column(Text)  # Encrypted SNMPv3 auth credentials
    snmp_v3_priv_encrypted = Column(Text)  # Encrypted SNMPv3 privacy credentials
    ssh_username = Column(String(100))  # SSH username (not sensitive)
    ssh_password_encrypted = Column(Text)  # Encrypted SSH password
    ssh_key_encrypted = Column(Text)  # Encrypted SSH private key
    api_key_encrypted = Column(Text)  # Encrypted API key
    api_secret_encrypted = Column(Text)  # Encrypted API secret
    last_discovery = Column(DateTime(timezone=True))
    discovery_status = Column(String(20), default="unknown")
    consecutive_failures = Column(Integer, default=0)
    circuit_breaker_trips = Column(Integer, default=0)
    purchase_date = Column(DateTime(timezone=True))
    warranty_expiry = Column(DateTime(timezone=True))
    last_maintenance = Column(DateTime(timezone=True))
    next_maintenance = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    alerts = relationship("Alert", back_populates="device")
    metrics = relationship("DeviceMetric", back_populates="device")
    interfaces = relationship("NetworkInterface", back_populates="device")
    
    __table_args__ = (
        Index('idx_device_hostname_ip', 'hostname', 'ip_address'),
        Index('idx_device_type_status', 'device_type', 'current_state'),
        Index('idx_device_location_group', 'location', 'device_group'),
    )

class NetworkInterface(Base):
    """Network interfaces for devices"""
    __tablename__ = "network_interfaces"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    name = Column(String(100), nullable=False)
    interface_type = Column(String(50))
    status = Column(String(20), default="down")
    speed = Column(String(20))
    duplex = Column(String(20))
    mtu = Column(Integer)
    ip_address = Column(String(45))
    mac_address = Column(String(17))
    description = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="interfaces")

class Alert(Base):
    """System alerts and notifications"""
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    status = Column(String(20), default="active", index=True)
    message = Column(Text, nullable=False)
    details = Column(JSON)
    description = Column(Text)
    alert_metadata = Column(JSON)
    created_by = Column(UUID(as_uuid=True))  # User who created the alert
    acknowledged_by = Column(UUID(as_uuid=True))  # User who acknowledged
    resolved_by = Column(UUID(as_uuid=True))  # User who resolved
    acknowledged_at = Column(DateTime(timezone=True))
    resolved_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="alerts")
    
    __table_args__ = (
        Index('idx_alert_device_severity', 'device_id', 'severity'),
        Index('idx_alert_status_created', 'status', 'created_at'),
    )

class Notification(Base):
    """System notifications"""
    __tablename__ = "notifications"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    notification_type = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default="info")
    read = Column(Boolean, default=False, index=True)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    user_id = Column(UUID(as_uuid=True))
    notification_metadata = Column(JSON)  # Additional metadata for the notification
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    read_at = Column(DateTime(timezone=True))

class DeviceMetric(Base):
    """Device performance metrics"""
    __tablename__ = "device_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    metric_type = Column(String(50), nullable=False)
    value = Column(Float, nullable=False)
    unit = Column(String(20))
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="metrics")
    
    __table_args__ = (
        Index('idx_metric_device_type_timestamp', 'device_id', 'metric_type', 'timestamp'),
    )


class TopologyNode(Base):
    """Network topology nodes"""
    __tablename__ = "topology_nodes"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    label = Column(String(255))  # Node display label
    node_type = Column(String(50), nullable=False)
    x_position = Column(Float, default=0)
    y_position = Column(Float, default=0)
    properties = Column(JSON)
    node_metadata = Column(JSON)  # Additional metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class TopologyEdge(Base):
    """Network topology connections"""
    __tablename__ = "topology_edges"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_node_id = Column(UUID(as_uuid=True), ForeignKey("topology_nodes.id"), nullable=False)
    target_node_id = Column(UUID(as_uuid=True), ForeignKey("topology_nodes.id"), nullable=False)
    edge_type = Column(String(50), default="connection")
    source_interface = Column(String(100))
    target_interface = Column(String(100))
    properties = Column(JSON)
    edge_metadata = Column(JSON)  # Additional metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (
        Index('idx_edge_source_target', 'source_node_id', 'target_node_id'),
    )

class SLAMetric(Base):
    """SLA metrics and compliance tracking"""
    __tablename__ = "sla_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    metric_name = Column(String(100), nullable=False)
    target_value = Column(Float, nullable=False)
    current_value = Column(Float)
    compliance_percentage = Column(Float)
    measurement_period = Column(String(50), default="daily")
    threshold_type = Column(String(20), default="min")  # min, max, exact
    is_compliant = Column(Boolean, default=True)
    sla_metadata = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationship
    device = relationship("Device", backref="sla_metrics")

class CircuitBreakerState(Base):
    """Persistent circuit breaker state tracking"""
    __tablename__ = "circuit_breaker_states"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    identifier = Column(String(255), nullable=False, unique=True, index=True)  # Function/service identifier
    state = Column(String(20), nullable=False, default="closed")  # closed, open, half_open
    failure_count = Column(Integer, default=0)
    success_count = Column(Integer, default=0)
    last_failure_time = Column(DateTime(timezone=True))
    last_success_time = Column(DateTime(timezone=True))
    opened_at = Column(DateTime(timezone=True))  # When circuit opened
    next_attempt_time = Column(DateTime(timezone=True))  # When to try again
    failure_threshold = Column(Integer, default=5)
    recovery_timeout = Column(Integer, default=60)  # seconds
    success_threshold = Column(Integer, default=3)  # for half-open state
    total_calls = Column(Integer, default=0)
    total_failures = Column(Integer, default=0)
    error_details = Column(JSON)  # Recent error information
    metadata = Column(JSON)  # Additional configuration
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    __table_args__ = (
        Index('idx_circuit_breaker_state_identifier', 'identifier'),
        Index('idx_circuit_breaker_state_next_attempt', 'next_attempt_time'),
    )

class SystemHealthMetric(Base):
    """System-wide health and performance metrics"""
    __tablename__ = "system_health_metrics"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    metric_category = Column(String(50), nullable=False, index=True)  # circuit_breaker, resource_usage, etc.
    metric_name = Column(String(100), nullable=False)
    metric_value = Column(Float)
    metric_text = Column(Text)  # For non-numeric values
    service_name = Column(String(100))  # Which service/component
    instance_id = Column(String(100))  # Service instance identifier
    tags = Column(JSON)  # Additional tags/labels
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    __table_args__ = (
        Index('idx_health_metric_category_timestamp', 'metric_category', 'timestamp'),
        Index('idx_health_metric_service_timestamp', 'service_name', 'timestamp'),
    )

class DiscoveryJob(Base):
    """Network discovery job tracking"""
    __tablename__ = "discovery_jobs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    ip_range = Column(String(100), nullable=False)
    protocol = Column(String(50), default="snmp")
    credentials = Column(JSON)  # Encrypted credentials
    options = Column(JSON)
    status = Column(String(50), default="pending")
    devices_found = Column(Integer, default=0)
    devices_added = Column(Integer, default=0)
    errors = Column(JSON)
    results = Column(JSON)
    created_by = Column(UUID(as_uuid=True))
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
