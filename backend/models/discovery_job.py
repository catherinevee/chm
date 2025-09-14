"""
CHM Discovery Job Model
Network discovery and scanning job model
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Enum, JSON, Index
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import enum

from core.database import Base

class DiscoveryStatus(str, enum.Enum):
    """Discovery job status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class DiscoveryType(str, enum.Enum):
    """Discovery type enumeration"""
    NETWORK_SCAN = "network_scan"
    DEVICE_DISCOVERY = "device_discovery"
    SERVICE_DISCOVERY = "service_discovery"
    TOPOLOGY_DISCOVERY = "topology_discovery"
    VULNERABILITY_SCAN = "vulnerability_scan"
    CONFIGURATION_AUDIT = "configuration_audit"

class DiscoveryMethod(str, enum.Enum):
    """Discovery method enumeration"""
    ICMP = "icmp"
    SNMP = "snmp"
    ARP = "arp"
    CDP = "cdp"
    LLDP = "lldp"
    SSH = "ssh"
    NMAP = "nmap"
    WMI = "wmi"
    API = "api"

class DiscoveryJob(Base):
    """Discovery job model for network discovery and scanning"""
    
    __tablename__ = "discovery_jobs"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Job identification
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    job_type = Column(Enum(DiscoveryType), nullable=False)
    status = Column(Enum(DiscoveryStatus), default=DiscoveryStatus.PENDING, nullable=False)
    
    # Configuration
    target_networks = Column(JSON, nullable=True)  # List of network ranges
    target_hosts = Column(JSON, nullable=True)     # List of specific hosts
    scan_ports = Column(JSON, nullable=True)       # Port ranges to scan
    scan_options = Column(JSON, nullable=True)     # Additional scan options
    
    # Execution
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    timeout_seconds = Column(Integer, default=3600, nullable=False)  # 1 hour default
    max_concurrent_scans = Column(Integer, default=10, nullable=False)
    
    # Progress tracking
    total_targets = Column(Integer, default=0, nullable=False)
    completed_targets = Column(Integer, default=0, nullable=False)
    failed_targets = Column(Integer, default=0, nullable=False)
    progress_percentage = Column(Integer, default=0, nullable=False)
    
    # Results
    discovered_devices = Column(JSON, nullable=True)  # List of discovered devices
    discovered_services = Column(JSON, nullable=True)  # List of discovered services
    scan_results = Column(JSON, nullable=True)        # Raw scan results
    summary = Column(JSON, nullable=True)             # Scan summary
    
    # Error handling
    error_message = Column(Text, nullable=True)
    error_details = Column(JSON, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    
    # User and permissions
    created_by = Column(Integer, nullable=True)
    assigned_to = Column(Integer, nullable=True)
    priority = Column(Integer, default=5, nullable=False)  # 1-10, higher is more important
    
    # Scheduling
    scheduled_at = Column(DateTime, nullable=True)
    is_recurring = Column(Boolean, default=False, nullable=False)
    recurrence_pattern = Column(String(100), nullable=True)  # Cron-like pattern
    next_run = Column(DateTime, nullable=True)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Soft delete
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, nullable=True)
    
    # Composite indexes for efficient querying
    __table_args__ = (
        Index('idx_discovery_jobs_status_created', 'status', 'created_at'),
        Index('idx_discovery_jobs_type_status', 'job_type', 'status'),
        Index('idx_discovery_jobs_created_by', 'created_by', 'status'),
    )
    
    def __repr__(self):
        return f"<DiscoveryJob(id={self.id}, name='{self.name}', type='{self.job_type}', status='{self.status}')>"
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Get job duration in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        elif self.started_at:
            return (datetime.utcnow() - self.started_at).total_seconds()
        return 0.0
    
    @property
    def duration_formatted(self) -> Optional[str]:
        """Get formatted duration string"""
        if self.duration_seconds is None:
            return ""
        
        duration = self.duration_seconds
        if duration < 60:
            return f"{duration:.1f} seconds"
        elif duration < 3600:
            minutes = duration / 60
            return f"{minutes:.1f} minutes"
        else:
            hours = duration / 3600
            return f"{hours:.1f} hours"
    
    @property
    def is_running(self) -> bool:
        """Check if job is currently running"""
        return self.status == DiscoveryStatus.RUNNING
    
    @property
    def is_completed(self) -> bool:
        """Check if job is completed (success or failure)"""
        return self.status in [DiscoveryStatus.COMPLETED, DiscoveryStatus.FAILED, DiscoveryStatus.CANCELLED]
    
    @property
    def is_failed(self) -> bool:
        """Check if job failed"""
        return self.status == DiscoveryStatus.FAILED
    
    @property
    def can_retry(self) -> bool:
        """Check if job can be retried"""
        return self.is_failed and self.retry_count < self.max_retries
    
    @property
    def is_timed_out(self) -> bool:
        """Check if job has timed out"""
        if not self.started_at or self.is_completed:
            return False
        
        return (datetime.utcnow() - self.started_at).total_seconds() > self.timeout_seconds
    
    @property
    def estimated_completion(self) -> Optional[datetime]:
        """Estimate completion time based on progress"""
        if not self.is_running or self.progress_percentage == 0:
            raise NotImplementedError(f"{func_name} not yet implemented")
        
        if self.started_at:
            elapsed = datetime.utcnow() - self.started_at
            estimated_total = elapsed * (100 / self.progress_percentage)
            return self.started_at + timedelta(seconds=estimated_total.total_seconds())
        
        raise NotImplementedError(f"{func_name} not yet implemented")
    
    def start(self):
        """Start the discovery job"""
        self.status = DiscoveryStatus.RUNNING
        self.started_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def complete(self, results: Dict[str, Any] = None):
        """Mark job as completed"""
        self.status = DiscoveryStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress_percentage = 100
        self.completed_targets = self.total_targets
        self.updated_at = datetime.utcnow()
        
        if results:
            self.discovered_devices = results.get('devices', [])
            self.discovered_services = results.get('services', [])
            self.scan_results = results.get('raw_results', {})
            self.summary = results.get('summary', {})
    
    def fail(self, error_message: str, error_details: Dict[str, Any] = None):
        """Mark job as failed"""
        self.status = DiscoveryStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = error_message
        self.error_details = error_details
        self.updated_at = datetime.utcnow()
    
    def cancel(self):
        """Cancel the discovery job"""
        self.status = DiscoveryStatus.CANCELLED
        self.completed_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()
    
    def update_progress(self, completed: int, failed: int = 0):
        """Update job progress"""
        self.completed_targets = completed
        self.failed_targets = failed
        
        if self.total_targets > 0:
            self.progress_percentage = int((completed / self.total_targets) * 100)
        
        self.updated_at = datetime.utcnow()
    
    def retry(self):
        """Retry the failed job"""
        if not self.can_retry:
            raise ValueError("Job cannot be retried")
        
        self.retry_count += 1
        self.status = DiscoveryStatus.PENDING
        self.started_at = None
        self.completed_at = None
        self.error_message = None
        self.error_details = None
        self.progress_percentage = 0
        self.completed_targets = 0
        self.failed_targets = 0
        self.updated_at = datetime.utcnow()
    
    def to_dict(self) -> dict:
        """Convert discovery job to dictionary"""
        return {
            "id": self.id,
            "uuid": str(self.uuid),
            "name": self.name,
            "description": self.description,
            "job_type": self.job_type.value,
            "status": self.status.value,
            "target_networks": self.target_networks,
            "target_hosts": self.target_hosts,
            "scan_ports": self.scan_ports,
            "scan_options": self.scan_options,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "timeout_seconds": self.timeout_seconds,
            "max_concurrent_scans": self.max_concurrent_scans,
            "total_targets": self.total_targets,
            "completed_targets": self.completed_targets,
            "failed_targets": self.failed_targets,
            "progress_percentage": self.progress_percentage,
            "discovered_devices": self.discovered_devices,
            "discovered_services": self.discovered_services,
            "scan_results": self.scan_results,
            "summary": self.summary,
            "error_message": self.error_message,
            "error_details": self.error_details,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "created_by": self.created_by,
            "assigned_to": self.assigned_to,
            "priority": self.priority,
            "scheduled_at": self.scheduled_at.isoformat() if self.scheduled_at else None,
            "is_recurring": self.is_recurring,
            "recurrence_pattern": self.recurrence_pattern,
            "next_run": self.next_run.isoformat() if self.next_run else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "duration_formatted": self.duration_formatted,
            "is_running": self.is_running,
            "is_completed": self.is_completed,
            "is_failed": self.is_failed,
            "can_retry": self.can_retry,
            "is_timed_out": self.is_timed_out,
            "estimated_completion": self.estimated_completion.isoformat() if self.estimated_completion else None
        }
    
    @classmethod
    def create_network_scan(
        cls,
        name: str,
        target_networks: List[str],
        created_by: int,
        description: str = None
    ) -> 'DiscoveryJob':
        """Create a network scan job"""
        return cls(
            name=name,
            description=description,
            job_type=DiscoveryType.NETWORK_SCAN,
            target_networks=target_networks,
            created_by=created_by
        )
    
    @classmethod
    def create_device_discovery(
        cls,
        name: str,
        target_hosts: List[str],
        created_by: int,
        description: str = None
    ) -> 'DiscoveryJob':
        """Create a device discovery job"""
        return cls(
            name=name,
            description=description,
            job_type=DiscoveryType.DEVICE_DISCOVERY,
            target_hosts=target_hosts,
            created_by=created_by
        )
