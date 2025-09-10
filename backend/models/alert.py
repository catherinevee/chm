"""
CHM Alert Model
Enhanced alerting system with correlation, escalation, and multiple severity levels
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON, Text, Enum, Index, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import enum

from core.database import Base

class AlertSeverity(str, enum.Enum):
    """Alert severity levels"""
    CRITICAL = "critical"      # Immediate attention required
    HIGH = "high"              # High priority
    MEDIUM = "medium"          # Medium priority
    LOW = "low"                # Low priority
    INFO = "info"              # Informational

class AlertStatus(str, enum.Enum):
    """Alert status enumeration"""
    ACTIVE = "active"          # Alert is active and needs attention
    ACKNOWLEDGED = "acknowledged"  # Alert has been acknowledged
    RESOLVED = "resolved"      # Alert has been resolved
    SUPPRESSED = "suppressed"  # Alert is suppressed
    EXPIRED = "expired"        # Alert has expired
    ESCALATED = "escalated"    # Alert has been escalated

class AlertCategory(str, enum.Enum):
    """Alert category enumeration"""
    SYSTEM = "system"          # System-level alerts
    NETWORK = "network"        # Network-related alerts
    PERFORMANCE = "performance"  # Performance degradation
    SECURITY = "security"      # Security incidents
    AVAILABILITY = "availability"  # Service availability
    CAPACITY = "capacity"      # Resource capacity issues
    COMPLIANCE = "compliance"  # Compliance violations
    CUSTOM = "custom"          # Custom alerts

class AlertSource(str, enum.Enum):
    """Alert source enumeration"""
    METRIC_THRESHOLD = "metric_threshold"  # Metric threshold exceeded
    ANOMALY_DETECTION = "anomaly_detection"  # Anomaly detected
    DEVICE_STATUS = "device_status"      # Device status change
    MANUAL = "manual"                     # Manually created
    SCRIPT = "script"                     # Script execution
    EXTERNAL = "external"                 # External system
    CORRELATION = "correlation"           # Correlated from other alerts

class Alert(Base):
    """Enhanced alert model for comprehensive alerting system"""
    
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Basic alert information
    title = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    message = Column(Text, nullable=False)
    severity = Column(Enum(AlertSeverity), nullable=False, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.ACTIVE, nullable=False, index=True)
    category = Column(Enum(AlertCategory), nullable=False, index=True)
    source = Column(Enum(AlertSource), nullable=False, index=True)
    
    # Device and metric association
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)
    device = relationship("Device", back_populates="alerts")
    
    metric_id = Column(Integer, ForeignKey("metrics.id"), nullable=True, index=True)
    metric = relationship("Metric", back_populates="alerts")
    
    # Notifications relationship
    notifications = relationship("Notification", back_populates="alert")
    
    # Alert correlation and grouping
    correlation_id = Column(String(100), nullable=True, index=True)
    parent_alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True)
    child_alerts = relationship("Alert", backref="parent_alert", remote_side=[id])
    
    # Escalation and assignment
    escalation_level = Column(Integer, default=0, nullable=False)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    escalation_policy_id = Column(String(100), nullable=True)
    
    # User assignment
    assigned_user = relationship("User", foreign_keys=[assigned_to], back_populates="alerts")
    
    # Timing and lifecycle
    first_occurrence = Column(DateTime, nullable=False, index=True)
    last_occurrence = Column(DateTime, nullable=False, index=True)
    occurrence_count = Column(Integer, default=1, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    
    # Alert context and metadata
    context = Column(JSON, nullable=True)  # Additional context data
    tags = Column(JSON, nullable=True, index=True)
    external_id = Column(String(100), nullable=True, index=True)
    external_url = Column(String(500), nullable=True)
    
    # Threshold and trigger information
    threshold_value = Column(Float, nullable=True)
    current_value = Column(Float, nullable=True)
    threshold_operator = Column(String(10), nullable=True)  # >, <, >=, <=, ==, !=
    
    # Quality and confidence
    confidence_score = Column(Float, nullable=True)
    false_positive_probability = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)
    
    # Notification and response
    notification_sent = Column(Boolean, default=False, nullable=False)
    notification_channels = Column(JSON, nullable=True)
    response_time_seconds = Column(Float, nullable=True)
    resolution_time_seconds = Column(Float, nullable=True)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    __table_args__ = (
        Index('idx_alerts_device_status', 'device_id', 'status'),
        Index('idx_alerts_severity_status', 'severity', 'status'),
        Index('idx_alerts_category_status', 'category', 'status'),
        Index('idx_alerts_correlation', 'correlation_id', 'status'),
        Index('idx_alerts_escalation', 'escalation_level', 'status'),
        Index('idx_alerts_timing', 'first_occurrence', 'last_occurrence'),
        Index('idx_alerts_expires', 'expires_at', 'status'),
    )
    
    def __repr__(self):
        return f"<Alert(id={self.id}, title='{self.title}', severity='{self.severity}', status='{self.status}')>"
    
    @property
    def age_seconds(self) -> float:
        """Get age of alert in seconds"""
        return (datetime.now() - self.first_occurrence).total_seconds()
    
    @property
    def age_minutes(self) -> float:
        """Get age of alert in minutes"""
        return self.age_seconds / 60.0
    
    @property
    def age_hours(self) -> float:
        """Get age of alert in hours"""
        return self.age_seconds / 3600.0
    
    @property
    def is_active(self) -> bool:
        """Check if alert is currently active"""
        return self.status == AlertStatus.ACTIVE
    
    @property
    def is_acknowledged(self) -> bool:
        """Check if alert has been acknowledged"""
        return self.status == AlertStatus.ACKNOWLEDGED
    
    @property
    def is_resolved(self) -> bool:
        """Check if alert has been resolved"""
        return self.status == AlertStatus.RESOLVED
    
    @property
    def is_expired(self) -> bool:
        """Check if alert has expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    @property
    def needs_escalation(self) -> bool:
        """Check if alert needs escalation"""
        if self.status in [AlertStatus.RESOLVED, AlertStatus.SUPPRESSED, AlertStatus.EXPIRED]:
            return False
        
        # Escalate based on age and severity
        if self.severity == AlertSeverity.CRITICAL and self.age_hours > 1:
            return True
        elif self.severity == AlertSeverity.HIGH and self.age_hours > 4:
            return True
        elif self.severity == AlertSeverity.MEDIUM and self.age_hours > 24:
            return True
        
        return False
    
    @property
    def urgency_score(self) -> float:
        """Calculate urgency score based on severity, age, and occurrence count"""
        base_score = {
            AlertSeverity.CRITICAL: 1.0,
            AlertSeverity.HIGH: 0.8,
            AlertSeverity.MEDIUM: 0.6,
            AlertSeverity.LOW: 0.4,
            AlertSeverity.INFO: 0.2
        }.get(self.severity, 0.5)
        
        # Increase score with age
        age_factor = min(self.age_hours / 24.0, 2.0)  # Cap at 2x
        
        # Increase score with occurrence count
        occurrence_factor = min(self.occurrence_count / 10.0, 1.5)  # Cap at 1.5x
        
        return min(base_score * age_factor * occurrence_factor, 1.0)
    
    def acknowledge(self, user_id: int):
        """Acknowledge the alert"""
        self.status = AlertStatus.ACKNOWLEDGED
        self.acknowledged_at = datetime.now()
        self.updated_by = user_id
        self.updated_at = datetime.now()
    
    def resolve(self, user_id: int, resolution_notes: Optional[str] = None):
        """Resolve the alert"""
        self.status = AlertStatus.RESOLVED
        self.resolved_at = datetime.now()
        self.updated_by = user_id
        self.updated_at = datetime.now()
        
        if resolution_notes:
            if not self.context:
                self.context = {}
            self.context['resolution_notes'] = resolution_notes
        
        # Calculate resolution time
        if self.acknowledged_at:
            self.resolution_time_seconds = (self.resolved_at - self.acknowledged_at).total_seconds()
    
    def escalate(self, escalation_level: int, escalation_policy_id: Optional[str] = None):
        """Escalate the alert"""
        self.escalation_level = escalation_level
        self.status = AlertStatus.ESCALATED
        self.updated_at = datetime.now()
        
        if escalation_policy_id:
            self.escalation_policy_id = escalation_policy_id
        
        # Add escalation tag
        if not self.tags:
            self.tags = []
        self.tags.append(f"escalated_level_{escalation_level}")
    
    def suppress(self, user_id: int, reason: str, duration_hours: Optional[int] = None):
        """Suppress the alert"""
        self.status = AlertStatus.SUPPRESSED
        self.updated_by = user_id
        self.updated_at = datetime.now()
        
        if duration_hours:
            self.expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        # Add suppression context
        if not self.context:
            self.context = {}
        self.context['suppression'] = {
            'reason': reason,
            'suppressed_by': user_id,
            'suppressed_at': datetime.now().isoformat(),
            'duration_hours': duration_hours
        }
    
    def add_occurrence(self, timestamp: Optional[datetime] = None):
        """Add another occurrence of this alert"""
        if timestamp is None:
            timestamp = datetime.now()
        
        self.last_occurrence = timestamp
        self.occurrence_count += 1
        self.updated_at = datetime.now()
    
    def add_tag(self, tag: str):
        """Add a tag to the alert"""
        if not self.tags:
            self.tags = []
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str):
        """Remove a tag from the alert"""
        if self.tags and tag in self.tags:
            self.tags.remove(tag)
    
    def update_context(self, key: str, value: Any):
        """Update alert context"""
        if not self.context:
            self.context = {}
        self.context[key] = value
        self.updated_at = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert alert to dictionary"""
        return {
            "id": self.id,
            "uuid": str(self.uuid),
            "title": self.title,
            "description": self.description,
            "message": self.message,
            "severity": self.severity.value,
            "status": self.status.value,
            "category": self.category.value,
            "source": self.source.value,
            "device_id": self.device_id,
            "metric_id": self.metric_id,
            "correlation_id": self.correlation_id,
            "parent_alert_id": self.parent_alert_id,
            "escalation_level": self.escalation_level,
            "assigned_to": self.assigned_to,
            "first_occurrence": self.first_occurrence.isoformat(),
            "last_occurrence": self.last_occurrence.isoformat(),
            "occurrence_count": self.occurrence_count,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "context": self.context,
            "tags": self.tags,
            "threshold_value": self.threshold_value,
            "current_value": self.current_value,
            "threshold_operator": self.threshold_operator,
            "confidence_score": self.confidence_score,
            "impact_score": self.impact_score,
            "urgency_score": self.urgency_score,
            "age_seconds": self.age_seconds,
            "age_minutes": self.age_minutes,
            "age_hours": self.age_hours,
            "is_active": self.is_active,
            "needs_escalation": self.needs_escalation,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def create_metric_threshold_alert(
        cls,
        device_id: int,
        metric_id: int,
        metric_name: str,
        current_value: float,
        threshold_value: float,
        threshold_operator: str,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        message: Optional[str] = None
    ) -> 'Alert':
        """Create a metric threshold alert"""
        if message is None:
            message = f"Metric {metric_name} {threshold_operator} {threshold_value} (current: {current_value})"
        
        return cls(
            device_id=device_id,
            metric_id=metric_id,
            title=f"Metric Threshold Exceeded: {metric_name}",
            message=message,
            severity=severity,
            category=AlertCategory.PERFORMANCE,
            source=AlertSource.METRIC_THRESHOLD,
            first_occurrence=datetime.now(),
            last_occurrence=datetime.now(),
            threshold_value=threshold_value,
            current_value=current_value,
            threshold_operator=threshold_operator,
            context={
                "metric_name": metric_name,
                "threshold_type": "static"
            }
        )
    
    @classmethod
    def create_device_status_alert(
        cls,
        device_id: int,
        status: str,
        previous_status: str,
        severity: AlertSeverity = AlertSeverity.HIGH,
        message: Optional[str] = None
    ) -> 'Alert':
        """Create a device status change alert"""
        if message is None:
            message = f"Device status changed from {previous_status} to {status}"
        
        return cls(
            device_id=device_id,
            title=f"Device Status Change: {status}",
            message=message,
            severity=severity,
            category=AlertCategory.AVAILABILITY,
            source=AlertSource.DEVICE_STATUS,
            first_occurrence=datetime.now(),
            last_occurrence=datetime.now(),
            context={
                "previous_status": previous_status,
                "current_status": status,
                "status_change": True
            }
        )
    
    @classmethod
    def create_anomaly_alert(
        cls,
        device_id: int,
        metric_name: str,
        detected_value: float,
        expected_range: tuple,
        confidence: float,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        message: Optional[str] = None
    ) -> 'Alert':
        """Create an anomaly detection alert"""
        if message is None:
            message = f"Anomaly detected in {metric_name}: {detected_value} (expected: {expected_range[0]}-{expected_range[1]})"
        
        return cls(
            device_id=device_id,
            title=f"Anomaly Detected: {metric_name}",
            message=message,
            severity=severity,
            category=AlertCategory.PERFORMANCE,
            source=AlertSource.ANOMALY_DETECTION,
            first_occurrence=datetime.now(),
            last_occurrence=datetime.now(),
            current_value=detected_value,
            confidence_score=confidence,
            context={
                "metric_name": metric_name,
                "expected_range": expected_range,
                "anomaly_type": "statistical"
            }
        )
