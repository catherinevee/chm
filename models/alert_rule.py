"""
CHM Alert Rule Model
Configurable alerting rules with conditions, thresholds, and actions
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON, Text, Enum, Index, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import enum

from ..core.database import Base

class RuleStatus(str, enum.Enum):
    """Rule status enumeration"""
    ACTIVE = "active"            # Rule is active and monitoring
    INACTIVE = "inactive"        # Rule is disabled
    DRAFT = "draft"              # Rule is in draft mode
    TESTING = "testing"          # Rule is in testing mode
    ARCHIVED = "archived"        # Rule is archived

class RuleType(str, enum.Enum):
    """Rule type enumeration"""
    METRIC_THRESHOLD = "metric_threshold"  # Metric value threshold
    ANOMALY_DETECTION = "anomaly_detection"  # Statistical anomaly detection
    TREND_ANALYSIS = "trend_analysis"      # Trend-based detection
    PATTERN_MATCHING = "pattern_matching"  # Pattern matching
    COMPOSITE = "composite"                 # Multiple conditions combined
    EXTERNAL = "external"                   # External system trigger
    SCHEDULED = "scheduled"                 # Time-based triggers

class ConditionOperator(str, enum.Enum):
    """Condition operator enumeration"""
    EQUALS = "equals"            # Equal to
    NOT_EQUALS = "not_equals"    # Not equal to
    GREATER_THAN = "gt"          # Greater than
    GREATER_EQUAL = "gte"        # Greater than or equal
    LESS_THAN = "lt"             # Less than
    LESS_EQUAL = "lte"           # Less than or equal
    CONTAINS = "contains"        # Contains (for strings)
    NOT_CONTAINS = "not_contains"  # Does not contain
    IN = "in"                    # In list
    NOT_IN = "not_in"            # Not in list
    REGEX = "regex"              # Regular expression match
    EXISTS = "exists"            # Field exists
    NOT_EXISTS = "not_exists"    # Field does not exist

class ActionType(str, enum.Enum):
    """Action type enumeration"""
    CREATE_ALERT = "create_alert"      # Create a new alert
    UPDATE_ALERT = "update_alert"      # Update existing alert
    SEND_NOTIFICATION = "send_notification"  # Send notification
    EXECUTE_SCRIPT = "execute_script"  # Execute custom script
    WEBHOOK = "webhook"                # Send webhook
    ESCALATE = "escalate"              # Escalate alert
    SUPPRESS = "suppress"              # Suppress other alerts
    CUSTOM = "custom"                  # Custom action

class AlertRule(Base):
    """Configurable alert rule model for flexible alerting"""
    
    __tablename__ = "alert_rules"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), unique=True, index=True, default=uuid.uuid4)
    
    # Basic rule information
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    rule_type = Column(Enum(RuleType), nullable=False, index=True)
    status = Column(Enum(RuleStatus), default=RuleStatus.DRAFT, nullable=False, index=True)
    
    # Rule configuration
    conditions = Column(JSON, nullable=False)  # Rule conditions
    actions = Column(JSON, nullable=False)     # Rule actions
    threshold_config = Column(JSON, nullable=True)  # Threshold-specific config
    anomaly_config = Column(JSON, nullable=True)    # Anomaly detection config
    
    # Scope and targeting
    device_ids = Column(ARRAY(Integer), nullable=True, index=True)  # Target devices
    metric_names = Column(ARRAY(String), nullable=True, index=True)  # Target metrics
    device_groups = Column(ARRAY(String), nullable=True)  # Device group tags
    user_groups = Column(ARRAY(String), nullable=True)   # User group tags
    
    # Timing and scheduling
    evaluation_interval = Column(Integer, default=300, nullable=False)  # Seconds
    evaluation_window = Column(Integer, default=3600, nullable=False)   # Seconds
    cooldown_period = Column(Integer, default=0, nullable=False)       # Seconds
    active_hours = Column(JSON, nullable=True)  # Active time windows
    
    # Severity and priority
    default_severity = Column(String(20), default="medium", nullable=False)
    severity_escalation = Column(JSON, nullable=True)  # Severity escalation rules
    priority_override = Column(Boolean, default=False, nullable=False)
    
    # Performance and limits
    max_alerts_per_hour = Column(Integer, default=100, nullable=False)
    max_alerts_per_day = Column(Integer, default=1000, nullable=False)
    alert_grouping = Column(Boolean, default=True, nullable=False)
    deduplication_window = Column(Integer, default=300, nullable=False)  # Seconds
    
    # Advanced features
    correlation_rules = Column(JSON, nullable=True)  # Alert correlation rules
    suppression_rules = Column(JSON, nullable=True)  # Alert suppression rules
    escalation_policy = Column(String(100), nullable=True)  # Escalation policy ID
    notification_channels = Column(ARRAY(String), nullable=True)  # Default channels
    
    # Testing and validation
    test_mode = Column(Boolean, default=False, nullable=False)
    test_results = Column(JSON, nullable=True)  # Test execution results
    validation_errors = Column(ARRAY(String), nullable=True)  # Validation issues
    
    # Metadata and context
    tags = Column(ARRAY(String), nullable=True, index=True)
    category = Column(String(100), nullable=True, index=True)
    version = Column(String(20), default="1.0", nullable=False)
    external_id = Column(String(100), nullable=True, index=True)
    
    # Statistics and monitoring
    execution_count = Column(Integer, default=0, nullable=False)
    alert_count = Column(Integer, default=0, nullable=False)
    last_execution = Column(DateTime, nullable=True, index=True)
    last_alert_created = Column(DateTime, nullable=True, index=True)
    success_rate = Column(Float, default=0.0, nullable=False)
    average_execution_time = Column(Float, nullable=True)  # Milliseconds
    
    # User associations
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    __table_args__ = (
        Index('idx_alert_rules_type_status', 'rule_type', 'status'),
        Index('idx_alert_rules_category_status', 'category', 'status'),
        Index('idx_alert_rules_devices', 'device_ids', 'status'),
        Index('idx_alert_rules_metrics', 'metric_names', 'status'),
        Index('idx_alert_rules_execution', 'last_execution', 'status'),
        Index('idx_alert_rules_created', 'created_at', 'status'),
        Index('idx_alert_rules_version', 'version', 'status'),
    )
    
    def __repr__(self):
        return f"<AlertRule(id={self.id}, name='{self.name}', type='{self.rule_type}', status='{self.status}')>"
    
    @property
    def is_active(self) -> bool:
        """Check if rule is currently active"""
        return self.status == RuleStatus.ACTIVE
    
    @property
    def is_testing(self) -> bool:
        """Check if rule is in testing mode"""
        return self.status == RuleStatus.TESTING
    
    @property
    def can_execute(self) -> bool:
        """Check if rule can be executed"""
        if not self.is_active:
            return False
        
        # Check cooldown period
        if self.cooldown_period > 0 and self.last_execution:
            cooldown_until = self.last_execution + timedelta(seconds=self.cooldown_period)
            if datetime.now() < cooldown_until:
                return False
        
        # Check rate limits
        if self.alert_count >= self.max_alerts_per_day:
            return False
        
        return True
    
    @property
    def is_in_active_hours(self) -> bool:
        """Check if rule is within active hours"""
        if not self.active_hours:
            return True
        
        now = datetime.now()
        current_time = now.time()
        current_weekday = now.strftime("%A").lower()
        
        # Check if current time is within active hours
        if current_weekday in self.active_hours:
            hours = self.active_hours[current_weekday]
            for time_range in hours:
                start_time = datetime.strptime(time_range["start"], "%H:%M").time()
                end_time = datetime.strptime(time_range["end"], "%H:%M").time()
                
                if start_time <= current_time <= end_time:
                    return True
        
        return False
    
    @property
    def needs_validation(self) -> bool:
        """Check if rule needs validation"""
        return (self.status == RuleStatus.DRAFT or 
                self.validation_errors is not None or
                len(self.validation_errors or []) > 0)
    
    def activate(self, user_id: int):
        """Activate the rule"""
        self.status = RuleStatus.ACTIVE
        self.updated_by = user_id
        self.updated_at = datetime.now()
        
        # Clear validation errors when activating
        if self.validation_errors:
            self.validation_errors = []
    
    def deactivate(self, user_id: int, reason: str = None):
        """Deactivate the rule"""
        self.status = RuleStatus.INACTIVE
        self.updated_by = user_id
        self.updated_at = datetime.now()
        
        if reason:
            if not self.test_results:
                self.test_results = {}
            self.test_results['deactivation_reason'] = reason
    
    def enable_testing(self, user_id: int):
        """Enable testing mode for the rule"""
        self.status = RuleStatus.TESTING
        self.test_mode = True
        self.updated_by = user_id
        self.updated_at = datetime.now()
    
    def record_execution(self, execution_time_ms: float, alerts_created: int = 0, success: bool = True):
        """Record rule execution statistics"""
        self.execution_count += 1
        self.last_execution = datetime.now()
        self.alert_count += alerts_created
        
        if self.last_alert_created is None or alerts_created > 0:
            self.last_alert_created = datetime.now()
        
        # Update success rate
        if success:
            current_success = (self.success_rate * (self.execution_count - 1) + 1.0) / self.execution_count
        else:
            current_success = (self.success_rate * (self.execution_count - 1)) / self.execution_count
        
        self.success_rate = current_success
        
        # Update average execution time
        if self.average_execution_time is None:
            self.average_execution_time = execution_time_ms
        else:
            self.average_execution_time = (
                (self.average_execution_time * (self.execution_count - 1) + execution_time_ms) / 
                self.execution_count
            )
    
    def add_validation_error(self, error: str):
        """Add a validation error"""
        if not self.validation_errors:
            self.validation_errors = []
        if error not in self.validation_errors:
            self.validation_errors.append(error)
    
    def clear_validation_errors(self):
        """Clear all validation errors"""
        self.validation_errors = []
    
    def add_test_result(self, test_name: str, result: Dict[str, Any]):
        """Add a test result"""
        if not self.test_results:
            self.test_results = {}
        self.test_results[test_name] = {
            **result,
            "timestamp": datetime.now().isoformat()
        }
    
    def add_tag(self, tag: str):
        """Add a tag to the rule"""
        if not self.tags:
            self.tags = []
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str):
        """Remove a tag from the rule"""
        if self.tags and tag in self.tags:
            self.tags.remove(tag)
    
    def update_condition(self, condition_id: str, new_condition: Dict[str, Any]):
        """Update a specific condition"""
        if not self.conditions:
            self.conditions = {}
        
        if "conditions" not in self.conditions:
            self.conditions["conditions"] = []
        
        # Find and update the condition
        for i, condition in enumerate(self.conditions["conditions"]):
            if condition.get("id") == condition_id:
                self.conditions["conditions"][i] = new_condition
                break
        
        self.updated_at = datetime.now()
    
    def add_action(self, action: Dict[str, Any]):
        """Add an action to the rule"""
        if not self.actions:
            self.actions = {}
        
        if "actions" not in self.actions:
            self.actions["actions"] = []
        
        # Generate action ID if not provided
        if "id" not in action:
            action["id"] = str(uuid.uuid4())
        
        self.actions["actions"].append(action)
        self.updated_at = datetime.now()
    
    def remove_action(self, action_id: str):
        """Remove an action from the rule"""
        if not self.actions or "actions" not in self.actions:
            return
        
        self.actions["actions"] = [
            action for action in self.actions["actions"] 
            if action.get("id") != action_id
        ]
        self.updated_at = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert rule to dictionary"""
        return {
            "id": self.id,
            "uuid": str(self.uuid),
            "name": self.name,
            "description": self.description,
            "rule_type": self.rule_type.value,
            "status": self.status.value,
            "conditions": self.conditions,
            "actions": self.actions,
            "threshold_config": self.threshold_config,
            "anomaly_config": self.anomaly_config,
            "device_ids": self.device_ids,
            "metric_names": self.metric_names,
            "device_groups": self.device_groups,
            "user_groups": self.user_groups,
            "evaluation_interval": self.evaluation_interval,
            "evaluation_window": self.evaluation_window,
            "cooldown_period": self.cooldown_period,
            "active_hours": self.active_hours,
            "default_severity": self.default_severity,
            "severity_escalation": self.severity_escalation,
            "priority_override": self.priority_override,
            "max_alerts_per_hour": self.max_alerts_per_hour,
            "max_alerts_per_day": self.max_alerts_per_day,
            "alert_grouping": self.alert_grouping,
            "deduplication_window": self.deduplication_window,
            "correlation_rules": self.correlation_rules,
            "suppression_rules": self.suppression_rules,
            "escalation_policy": self.escalation_policy,
            "notification_channels": self.notification_channels,
            "test_mode": self.test_mode,
            "test_results": self.test_results,
            "validation_errors": self.validation_errors,
            "tags": self.tags,
            "category": self.category,
            "version": self.version,
            "external_id": self.external_id,
            "execution_count": self.execution_count,
            "alert_count": self.alert_count,
            "last_execution": self.last_execution.isoformat() if self.last_execution else None,
            "last_alert_created": self.last_alert_created.isoformat() if self.last_alert_created else None,
            "success_rate": self.success_rate,
            "average_execution_time": self.average_execution_time,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "assigned_to": self.assigned_to,
            "is_active": self.is_active,
            "is_testing": self.is_testing,
            "can_execute": self.can_execute,
            "is_in_active_hours": self.is_in_active_hours,
            "needs_validation": self.needs_validation,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def create_metric_threshold_rule(
        cls,
        name: str,
        metric_name: str,
        threshold_value: float,
        operator: str,
        severity: str = "medium",
        device_ids: Optional[List[int]] = None,
        description: Optional[str] = None
    ) -> 'AlertRule':
        """Create a metric threshold rule"""
        if description is None:
            description = f"Alert when {metric_name} {operator} {threshold_value}"
        
        conditions = {
            "operator": "AND",
            "conditions": [
                {
                    "id": str(uuid.uuid4()),
                    "type": "metric_threshold",
                    "metric_name": metric_name,
                    "operator": operator,
                    "value": threshold_value,
                    "enabled": True
                }
            ]
        }
        
        actions = {
            "actions": [
                {
                    "id": str(uuid.uuid4()),
                    "type": "create_alert",
                    "enabled": True,
                    "config": {
                        "severity": severity,
                        "category": "performance",
                        "source": "metric_threshold"
                    }
                }
            ]
        }
        
        return cls(
            name=name,
            description=description,
            rule_type=RuleType.METRIC_THRESHOLD,
            status=RuleStatus.DRAFT,
            conditions=conditions,
            actions=actions,
            threshold_config={
                "metric_name": metric_name,
                "threshold_value": threshold_value,
                "operator": operator,
                "evaluation_window": 300  # 5 minutes
            },
            device_ids=device_ids,
            metric_names=[metric_name],
            default_severity=severity,
            evaluation_interval=60,  # Check every minute
            evaluation_window=300    # 5-minute window
        )
    
    @classmethod
    def create_anomaly_detection_rule(
        cls,
        name: str,
        metric_name: str,
        sensitivity: float = 0.95,
        severity: str = "medium",
        device_ids: Optional[List[int]] = None,
        description: Optional[str] = None
    ) -> 'AlertRule':
        """Create an anomaly detection rule"""
        if description is None:
            description = f"Alert when {metric_name} shows anomalous behavior"
        
        conditions = {
            "operator": "AND",
            "conditions": [
                {
                    "id": str(uuid.uuid4()),
                    "type": "anomaly_detection",
                    "metric_name": metric_name,
                    "sensitivity": sensitivity,
                    "enabled": True
                }
            ]
        }
        
        actions = {
            "actions": [
                {
                    "id": str(uuid.uuid4()),
                    "type": "create_alert",
                    "enabled": True,
                    "config": {
                        "severity": severity,
                        "category": "performance",
                        "source": "anomaly_detection"
                    }
                }
            ]
        }
        
        return cls(
            name=name,
            description=description,
            rule_type=RuleType.ANOMALY_DETECTION,
            status=RuleStatus.DRAFT,
            conditions=conditions,
            actions=actions,
            anomaly_config={
                "metric_name": metric_name,
                "sensitivity": sensitivity,
                "detection_method": "statistical",
                "baseline_window": 86400,  # 24 hours
                "evaluation_window": 3600   # 1 hour
            },
            device_ids=device_ids,
            metric_names=[metric_name],
            default_severity=severity,
            evaluation_interval=300,  # Check every 5 minutes
            evaluation_window=3600    # 1-hour window
        )
    
    @classmethod
    def create_composite_rule(
        cls,
        name: str,
        conditions: List[Dict[str, Any]],
        actions: List[Dict[str, Any]],
        operator: str = "AND",
        severity: str = "medium",
        description: Optional[str] = None
    ) -> 'AlertRule':
        """Create a composite rule with multiple conditions"""
        if description is None:
            description = f"Composite rule: {operator} combination of {len(conditions)} conditions"
        
        rule_conditions = {
            "operator": operator,
            "conditions": conditions
        }
        
        rule_actions = {
            "actions": actions
        }
        
        return cls(
            name=name,
            description=description,
            rule_type=RuleType.COMPOSITE,
            status=RuleStatus.DRAFT,
            conditions=rule_conditions,
            actions=rule_actions,
            default_severity=severity,
            evaluation_interval=300,  # Check every 5 minutes
            evaluation_window=1800    # 30-minute window
        )
