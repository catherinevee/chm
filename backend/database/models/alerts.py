"""
Alert models for CHM
"""
from sqlalchemy import Column, String, Float, DateTime, Integer, Boolean, JSON, Enum, ForeignKey, Index, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from database.base import Base


class AlertSeverity(enum.Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    DEBUG = "debug"


class AlertStatus(enum.Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class AlertCategory(enum.Enum):
    """Alert categories"""
    AVAILABILITY = "availability"
    PERFORMANCE = "performance"
    CAPACITY = "capacity"
    SECURITY = "security"
    CONFIGURATION = "configuration"
    HARDWARE = "hardware"
    ENVIRONMENTAL = "environmental"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class AlertRule(Base):
    """Alert rule definitions"""
    __tablename__ = "alert_rules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, unique=True)
    description = Column(Text)
    
    # Scope
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    device_group_id = Column(UUID(as_uuid=True), ForeignKey("device_groups.id"))
    applies_to_all = Column(Boolean, default=False)
    
    # Conditions
    metric_type = Column(String(100), nullable=False)
    metric_name = Column(String(255), nullable=False)
    operator = Column(String(10), nullable=False)  # >, <, >=, <=, ==, !=, contains, regex
    threshold = Column(Float)
    threshold_unit = Column(String(50))
    
    # Advanced conditions
    conditions = Column(JSON)  # Complex condition tree
    expression = Column(Text)  # Custom expression for evaluation
    
    # Time-based conditions
    duration_seconds = Column(Integer, default=0)  # How long condition must persist
    occurrences = Column(Integer, default=1)  # Number of occurrences required
    time_window_seconds = Column(Integer)  # Time window for occurrences
    
    # Alert properties
    severity = Column(Enum(AlertSeverity), nullable=False)
    category = Column(Enum(AlertCategory), default=AlertCategory.CUSTOM)
    priority = Column(Integer, default=5)  # 1-10
    
    # Hysteresis and flap detection
    hysteresis = Column(Float, default=0)
    clear_threshold = Column(Float)  # Different threshold for clearing
    flap_detection_enabled = Column(Boolean, default=True)
    flap_count_threshold = Column(Integer, default=5)
    flap_time_window = Column(Integer, default=300)  # seconds
    
    # Notification settings
    notification_enabled = Column(Boolean, default=True)
    notification_channels = Column(JSON)  # List of notification channel IDs
    notification_delay_seconds = Column(Integer, default=0)
    notification_repeat_interval = Column(Integer)  # Repeat notifications every N seconds
    max_notifications = Column(Integer)  # Maximum number of notifications
    
    # Escalation
    escalation_enabled = Column(Boolean, default=False)
    escalation_rules = Column(JSON)  # Escalation chain definition
    
    # Suppression
    suppression_enabled = Column(Boolean, default=False)
    suppression_rules = Column(JSON)  # Time-based or condition-based suppression
    
    # Correlation
    correlation_enabled = Column(Boolean, default=False)
    correlation_window = Column(Integer, default=300)  # seconds
    correlation_rules = Column(JSON)  # Rules for correlating with other alerts
    parent_rule_id = Column(UUID(as_uuid=True), ForeignKey("alert_rules.id"))
    
    # Auto-remediation
    remediation_enabled = Column(Boolean, default=False)
    remediation_script = Column(Text)
    remediation_timeout = Column(Integer, default=300)
    remediation_max_attempts = Column(Integer, default=3)
    
    # Documentation
    runbook_url = Column(String(500))
    wiki_url = Column(String(500))
    tags = Column(JSON)
    
    # Status
    enabled = Column(Boolean, default=True, index=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    updated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Relationships
    device = relationship("Device", back_populates="alert_rules")
    device_group = relationship("DeviceGroup")
    alerts = relationship("Alert", back_populates="rule")
    parent_rule = relationship("AlertRule", remote_side=[id])
    
    # Indexes
    __table_args__ = (
        Index("idx_alert_rule_enabled", "enabled", "severity"),
        Index("idx_alert_rule_device", "device_id", "enabled"),
    )


class Alert(Base):
    """Active and historical alerts"""
    __tablename__ = "alerts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("alert_rules.id"))
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    
    # Alert details
    title = Column(String(500), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(JSON)  # Additional structured details
    
    # Metric information
    metric_type = Column(String(100), nullable=False)
    metric_name = Column(String(255), nullable=False)
    current_value = Column(Float, nullable=False)
    threshold = Column(Float)
    unit = Column(String(50))
    
    # Classification
    severity = Column(Enum(AlertSeverity), nullable=False, index=True)
    category = Column(Enum(AlertCategory), default=AlertCategory.CUSTOM)
    priority = Column(Integer, default=5)
    
    # Status tracking
    status = Column(Enum(AlertStatus), default=AlertStatus.NEW, index=True)
    previous_status = Column(Enum(AlertStatus))
    
    # Correlation
    correlation_id = Column(UUID(as_uuid=True))  # Groups correlated alerts
    parent_alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"))
    is_correlated = Column(Boolean, default=False)
    correlation_count = Column(Integer, default=0)
    
    # Flapping detection
    is_flapping = Column(Boolean, default=False)
    flap_count = Column(Integer, default=0)
    flap_start_time = Column(DateTime(timezone=True))
    
    # Acknowledgment
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    acknowledged_at = Column(DateTime(timezone=True))
    acknowledgment_comment = Column(Text)
    
    # Assignment
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    assigned_at = Column(DateTime(timezone=True))
    assigned_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # Resolution
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    resolved_at = Column(DateTime(timezone=True))
    resolution_comment = Column(Text)
    resolution_code = Column(String(50))  # auto, manual, timeout, etc.
    
    # Suppression
    is_suppressed = Column(Boolean, default=False)
    suppressed_until = Column(DateTime(timezone=True))
    suppression_reason = Column(String(255))
    
    # Notification tracking
    notifications_sent = Column(Integer, default=0)
    last_notification_at = Column(DateTime(timezone=True))
    next_notification_at = Column(DateTime(timezone=True))
    
    # Escalation tracking
    escalation_level = Column(Integer, default=0)
    escalated_at = Column(DateTime(timezone=True))
    escalated_to = Column(JSON)  # List of user/group IDs
    
    # Remediation tracking
    remediation_attempted = Column(Boolean, default=False)
    remediation_attempts = Column(Integer, default=0)
    remediation_status = Column(String(50))
    remediation_output = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    first_seen_at = Column(DateTime(timezone=True))
    last_seen_at = Column(DateTime(timezone=True))
    cleared_at = Column(DateTime(timezone=True))
    
    # Duration tracking
    duration_seconds = Column(Integer)
    time_to_acknowledge = Column(Integer)  # seconds
    time_to_resolve = Column(Integer)  # seconds
    
    # Tags and metadata
    tags = Column(JSON)
    custom_fields = Column(JSON)
    
    # Relationships
    rule = relationship("AlertRule", back_populates="alerts")
    device = relationship("Device", back_populates="alerts")
    parent_alert = relationship("Alert", remote_side=[id])
    comments = relationship("AlertComment", back_populates="alert", cascade="all, delete-orphan")
    history = relationship("AlertHistory", back_populates="alert", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_alert_status_severity", "status", "severity"),
        Index("idx_alert_device_created", "device_id", "created_at"),
        Index("idx_alert_correlation", "correlation_id", "status"),
        Index("idx_alert_active", "status", "is_suppressed", "severity"),
    )


class AlertComment(Base):
    """Comments on alerts"""
    __tablename__ = "alert_comments"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    comment = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False)  # Internal notes vs. public comments
    attachments = Column(JSON)  # List of attachment URLs
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="comments")
    user = relationship("User")


class AlertHistory(Base):
    """Alert state change history"""
    __tablename__ = "alert_history"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    
    # State change
    action = Column(String(50), nullable=False)  # created, acknowledged, assigned, resolved, etc.
    old_status = Column(Enum(AlertStatus))
    new_status = Column(Enum(AlertStatus))
    old_value = Column(JSON)
    new_value = Column(JSON)
    
    # Details
    comment = Column(Text)
    metadata = Column(JSON)
    
    # Timestamp
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    alert = relationship("Alert", back_populates="history")
    user = relationship("User")
    
    # Indexes
    __table_args__ = (
        Index("idx_alert_history_alert", "alert_id", "created_at"),
    )


class DeviceGroup(Base):
    """Device grouping for alert rules"""
    __tablename__ = "device_groups"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True)
    description = Column(Text)
    
    # Group definition
    filter_type = Column(String(20))  # static, dynamic
    filter_criteria = Column(JSON)  # Criteria for dynamic groups
    device_ids = Column(JSON)  # List of device IDs for static groups
    
    # Metadata
    tags = Column(JSON)
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))


class NotificationChannel(Base):
    """Notification channel configuration"""
    __tablename__ = "notification_channels"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), nullable=False, unique=True)
    type = Column(String(50), nullable=False)  # email, slack, teams, webhook, sms, pagerduty
    
    # Configuration
    configuration = Column(JSON)  # Channel-specific configuration
    
    # Filtering
    severity_filter = Column(JSON)  # List of severities to send
    category_filter = Column(JSON)  # List of categories to send
    device_filter = Column(JSON)  # List of device IDs or groups
    time_filter = Column(JSON)  # Time-based filtering rules
    
    # Rate limiting
    rate_limit = Column(Integer)  # Max notifications per hour
    rate_limit_window = Column(Integer, default=3600)  # seconds
    
    # Status
    is_active = Column(Boolean, default=True)
    is_default = Column(Boolean, default=False)
    
    # Testing
    test_mode = Column(Boolean, default=False)
    last_test_at = Column(DateTime(timezone=True))
    last_test_result = Column(JSON)
    
    # Statistics
    notifications_sent = Column(Integer, default=0)
    notifications_failed = Column(Integer, default=0)
    last_notification_at = Column(DateTime(timezone=True))
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))