"""
Network Topology Models for CHM

This module defines models for network topology mapping, device relationships,
interface management, and path analysis.
"""

import enum
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, JSON, Float, Index, ARRAY
from sqlalchemy.dialects.postgresql import UUID, INET, ARRAY as PG_ARRAY
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

from .base import Base


class TopologyType(str, enum.Enum):
    """Topology type enumeration"""
    LAYER2 = "layer2"          # Data link layer (switches, bridges)
    LAYER3 = "layer3"          # Network layer (routers, firewalls)
    PHYSICAL = "physical"       # Physical connections
    LOGICAL = "logical"         # Logical/virtual connections
    WIRELESS = "wireless"       # Wireless connections
    VIRTUAL = "virtual"         # Virtual/containerized connections


class InterfaceType(str, enum.Enum):
    """Interface type enumeration"""
    ETHERNET = "ethernet"       # Ethernet interface
    FIBER = "fiber"             # Fiber optic interface
    WIRELESS = "wireless"       # Wireless interface
    SERIAL = "serial"           # Serial interface
    LOOPBACK = "loopback"       # Loopback interface
    TUNNEL = "tunnel"           # Tunnel interface
    VLAN = "vlan"               # VLAN interface
    AGGREGATE = "aggregate"     # Link aggregation
    VIRTUAL = "virtual"         # Virtual interface


class InterfaceStatus(str, enum.Enum):
    """Interface status enumeration"""
    UP = "up"                   # Interface is up and operational
    DOWN = "down"               # Interface is down
    ADMIN_DOWN = "admin_down"   # Interface is administratively down
    TESTING = "testing"         # Interface is in testing mode
    UNKNOWN = "unknown"         # Interface status is unknown
    ERROR = "error"             # Interface has errors


class PathStatus(str, enum.Enum):
    """Path status enumeration"""
    ACTIVE = "active"           # Path is active and usable
    INACTIVE = "inactive"       # Path is inactive
    FAILED = "failed"           # Path has failed
    DEGRADED = "degraded"       # Path is degraded
    TESTING = "testing"         # Path is being tested
    UNKNOWN = "unknown"         # Path status is unknown


class NetworkTopology(Base):
    """Network topology model for mapping device relationships"""
    __tablename__ = "network_topologies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    topology_type = Column(String(50), nullable=False, index=True)
    
    # Topology configuration
    discovery_enabled = Column(Boolean, default=True, nullable=False)
    auto_update = Column(Boolean, default=True, nullable=False)
    update_interval = Column(Integer, default=3600, nullable=False)  # seconds
    
    # Discovery settings
    discovery_protocols = Column(PG_ARRAY(String), nullable=True)  # SNMP, CDP, LLDP, etc.
    discovery_depth = Column(Integer, default=3, nullable=False)   # hop limit
    discovery_timeout = Column(Integer, default=30, nullable=False)  # seconds
    
    # Topology data
    topology_data = Column(JSON, nullable=True)  # Raw topology information
    device_relationships = Column(JSON, nullable=True)  # Device connection matrix
    interface_mappings = Column(JSON, nullable=True)  # Interface connection details
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    last_discovery = Column(DateTime, nullable=True)
    discovery_status = Column(String(50), default="pending", nullable=False)
    
    # Relationships
    devices = relationship("Device", back_populates="topologies")
    interfaces = relationship("NetworkInterface", back_populates="topology")
    paths = relationship("NetworkPath", back_populates="topology")
    
    # Indexes
    __table_args__ = (
        Index('idx_topology_type_status', 'topology_type', 'discovery_status'),
        Index('idx_topology_discovery', 'discovery_enabled', 'last_discovery'),
    )


class NetworkInterface(Base):
    """Network interface model for device connectivity"""
    __tablename__ = "network_interfaces"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    topology_id = Column(Integer, ForeignKey("network_topologies.id"), nullable=True, index=True)
    
    # Interface identification
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    interface_type = Column(String(50), nullable=False, index=True)
    physical_address = Column(String(50), nullable=True, index=True)  # MAC address
    
    # Network configuration
    ip_address = Column(INET, nullable=True, index=True)
    subnet_mask = Column(INET, nullable=True)
    gateway = Column(INET, nullable=True)
    vlan_id = Column(Integer, nullable=True, index=True)
    
    # Status and metrics
    status = Column(String(50), default="unknown", nullable=False, index=True)
    admin_status = Column(String(50), default="unknown", nullable=False)
    operational_status = Column(String(50), default="unknown", nullable=False)
    
    # Performance metrics
    bandwidth_mbps = Column(Float, nullable=True)
    current_utilization = Column(Float, nullable=True)
    error_count = Column(Integer, default=0, nullable=False)
    packet_loss = Column(Float, nullable=True)
    
    # Configuration
    mtu = Column(Integer, nullable=True)
    duplex = Column(String(20), nullable=True)  # full, half, auto
    speed = Column(String(20), nullable=True)  # 10, 100, 1000, auto
    
    # Discovery information
    discovered_protocol = Column(String(50), nullable=True)  # SNMP, CDP, LLDP
    neighbor_device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    neighbor_interface = Column(String(100), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    last_polled = Column(DateTime, nullable=True)
    
    # Relationships
    device = relationship("Device", back_populates="interfaces")
    topology = relationship("NetworkTopology", back_populates="interfaces")
    neighbor_device = relationship("Device", foreign_keys=[neighbor_device_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_interface_device_status', 'device_id', 'status'),
        Index('idx_interface_type_status', 'interface_type', 'status'),
        Index('idx_interface_neighbor', 'neighbor_device_id', 'neighbor_interface'),
    )


class NetworkPath(Base):
    """Network path model for routing and connectivity analysis"""
    __tablename__ = "network_paths"
    
    id = Column(Integer, primary_key=True, index=True)
    topology_id = Column(Integer, ForeignKey("network_topologies.id"), nullable=False, index=True)
    
    # Path identification
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    source_device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    destination_device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    
    # Path characteristics
    path_type = Column(String(50), nullable=False, index=True)  # primary, backup, load_balance
    protocol = Column(String(50), nullable=True)  # OSPF, BGP, static, etc.
    metric = Column(Integer, nullable=True)
    cost = Column(Float, nullable=True)
    
    # Path status
    status = Column(String(50), default="unknown", nullable=False, index=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_primary = Column(Boolean, default=False, nullable=False)
    
    # Path details
    hop_count = Column(Integer, nullable=True)
    total_latency = Column(Float, nullable=True)  # milliseconds
    total_bandwidth = Column(Float, nullable=True)  # Mbps
    path_quality = Column(Float, nullable=True)  # 0-100 score
    
    # Path segments
    path_segments = Column(JSON, nullable=True)  # List of hops and interfaces
    routing_table = Column(JSON, nullable=True)  # Routing information
    
    # Performance metrics
    current_latency = Column(Float, nullable=True)
    current_bandwidth = Column(Float, nullable=True)
    packet_loss = Column(Float, nullable=True)
    jitter = Column(Float, nullable=True)
    
    # Monitoring
    monitoring_enabled = Column(Boolean, default=True, nullable=False)
    alert_thresholds = Column(JSON, nullable=True)
    last_monitored = Column(DateTime, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    
    # Relationships
    topology = relationship("NetworkTopology", back_populates="paths")
    source_device = relationship("Device", foreign_keys=[source_device_id])
    destination_device = relationship("Device", foreign_keys=[destination_device_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_path_source_dest', 'source_device_id', 'destination_device_id'),
        Index('idx_path_status_type', 'status', 'path_type'),
        Index('idx_path_monitoring', 'monitoring_enabled', 'last_monitored'),
    )


class DeviceRelationship(Base):
    """Device relationship model for mapping connections"""
    __tablename__ = "device_relationships"
    
    id = Column(Integer, primary_key=True, index=True)
    topology_id = Column(Integer, ForeignKey("network_topologies.id"), nullable=False, index=True)
    
    # Relationship identification
    source_device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    target_device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    
    # Relationship details
    relationship_type = Column(String(50), nullable=False, index=True)  # connected, routed, wireless, etc.
    connection_protocol = Column(String(50), nullable=True)  # SNMP, CDP, LLDP, manual
    connection_quality = Column(Float, nullable=True)  # 0-100 score
    
    # Interface connections
    source_interface_id = Column(Integer, ForeignKey("network_interfaces.id"), nullable=True)
    target_interface_id = Column(Integer, ForeignKey("network_interfaces.id"), nullable=True)
    
    # Connection metrics
    latency = Column(Float, nullable=True)  # milliseconds
    bandwidth = Column(Float, nullable=True)  # Mbps
    reliability = Column(Float, nullable=True)  # 0-100 percentage
    
    # Discovery information
    discovered_at = Column(DateTime, nullable=True)
    discovery_method = Column(String(50), nullable=True)
    last_verified = Column(DateTime, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now, nullable=False)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, nullable=False)
    
    # Relationships
    topology = relationship("NetworkTopology")
    source_device = relationship("Device", foreign_keys=[source_device_id])
    target_device = relationship("Device", foreign_keys=[target_device_id])
    source_interface = relationship("NetworkInterface", foreign_keys=[source_interface_id])
    target_interface = relationship("NetworkInterface", foreign_keys=[target_interface_id])
    
    # Indexes
    __table_args__ = (
        Index('idx_relationship_source_target', 'source_device_id', 'target_device_id'),
        Index('idx_relationship_type_status', 'relationship_type', 'is_active'),
        Index('idx_relationship_discovery', 'discovery_method', 'discovered_at'),
    )
