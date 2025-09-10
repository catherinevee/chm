"""
CHM Notification Model
Comprehensive notification system supporting multiple channels and delivery methods
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON, Text, Enum, Index, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
import enum

from core.database import Base

class NotificationChannel(str, enum.Enum):
    """Notification delivery channels"""
    EMAIL = "email"              # Email notifications
    SMS = "sms"                  # SMS/text messages
    WEBHOOK = "webhook"          # HTTP webhook calls
    SLACK = "slack"              # Slack messages
    TEAMS = "teams"              # Microsoft Teams
    PAGERDUTY = "pagerduty"     # PagerDuty integration
    IN_APP = "in_app"            # In-application notifications
    PUSH = "push"                # Push notifications
    VOICE = "voice"              # Voice calls
    CUSTOM = "custom"            # Custom integration

class NotificationStatus(str, enum.Enum):
    """Notification status enumeration"""
    PENDING = "pending"          # Notification is queued for delivery
    SENDING = "sending"          # Notification is being sent
    SENT = "sent"                # Notification was sent but not yet delivered
    DELIVERED = "delivered"      # Notification was successfully delivered
    FAILED = "failed"            # Notification delivery failed
    RETRYING = "retrying"        # Notification is being retried
    CANCELLED = "cancelled"      # Notification was cancelled
    EXPIRED = "expired"          # Notification expired before delivery

class NotificationPriority(str, enum.Enum):
    """Notification priority levels"""
    URGENT = "urgent"            # Immediate delivery required
    HIGH = "high"                # High priority
    NORMAL = "normal"            # Normal priority
    LOW = "low"                  # Low priority
    BULK = "bulk"                # Bulk notifications

class NotificationType(str, enum.Enum):
    """Notification type enumeration"""
    ALERT = "alert"              # Alert notifications
    STATUS = "status"            # Status updates
    MAINTENANCE = "maintenance"  # Maintenance notifications
    SECURITY = "security"        # Security alerts
    PERFORMANCE = "performance"  # Performance notifications
    SYSTEM = "system"            # System notifications
    USER = "user"                # User-related notifications
    CUSTOM = "custom"            # Custom notifications

class Notification(Base):
    """Comprehensive notification model for multi-channel delivery"""
    
    __tablename__ = "notifications"
    
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(36), unique=True, index=True, default=lambda: str(uuid.uuid4()))
    
    # Basic notification information
    title = Column(String(200), nullable=False, index=True)
    message = Column(Text, nullable=False)
    notification_type = Column(Enum(NotificationType), nullable=False, index=True)
    priority = Column(Enum(NotificationPriority), default=NotificationPriority.NORMAL, nullable=False, index=True)
    status = Column(Enum(NotificationStatus), default=NotificationStatus.PENDING, nullable=False, index=True)
    
    # Channel and delivery configuration
    channel = Column(Enum(NotificationChannel), nullable=False, index=True)
    recipient = Column(String(200), nullable=False, index=True)  # Email, phone, webhook URL, etc.
    recipient_type = Column(String(50), nullable=True)  # user, group, external, etc.
    
    # Alert association
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=True, index=True)
    alert = relationship("Alert", back_populates="notifications")
    
    # Device association
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)
    device = relationship("Device", back_populates="notifications")
    
    # User associations
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)  # Target user
    user = relationship("User", foreign_keys=[user_id], back_populates="notifications")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)  # User who created notification
    
    # Delivery configuration
    delivery_config = Column(JSON, nullable=True)  # Channel-specific configuration
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    retry_delay_seconds = Column(Integer, default=300, nullable=False)  # 5 minutes
    
    # Timing and scheduling
    scheduled_for = Column(DateTime, nullable=True, index=True)
    sent_at = Column(DateTime, nullable=True, index=True)
    delivered_at = Column(DateTime, nullable=True, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    
    # Content and formatting
    subject = Column(String(200), nullable=True)  # For email notifications
    body_html = Column(Text, nullable=True)      # HTML formatted body
    body_text = Column(Text, nullable=True)      # Plain text body
    attachments = Column(JSON, nullable=True)    # File attachments
    
    # Delivery tracking
    delivery_attempts = Column(JSON, nullable=True)  # History of delivery attempts
    error_message = Column(Text, nullable=True)      # Last error message
    external_id = Column(String(100), nullable=True, index=True)  # ID from external system
    
    # Metadata and context
    context = Column(JSON, nullable=True)  # Additional context data
    tags = Column(JSON, nullable=True, index=True)
    notification_metadata = Column(JSON, nullable=True)  # Channel-specific metadata
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    __table_args__ = (
        Index('idx_notifications_channel_status', 'channel', 'status'),
        Index('idx_notifications_type_status', 'notification_type', 'status'),
        Index('idx_notifications_priority_status', 'priority', 'status'),
        Index('idx_notifications_alert', 'alert_id', 'status'),
        Index('idx_notifications_device', 'device_id', 'status'),
        Index('idx_notifications_user', 'user_id', 'status'),
        Index('idx_notifications_scheduled', 'scheduled_for', 'status'),
        Index('idx_notifications_expires', 'expires_at', 'status'),
        Index('idx_notifications_recipient', 'recipient', 'channel'),
    )
    
    def __repr__(self):
        return f"<Notification(id={self.id}, title='{self.title}', channel='{self.channel}', status='{self.status}')>"
    
    @property
    def age_seconds(self) -> float:
        """Get age of notification in seconds"""
        return (datetime.now() - self.created_at).total_seconds()
    
    @property
    def age_minutes(self) -> float:
        """Get age of notification in minutes"""
        return self.age_seconds / 60.0
    
    @property
    def age_hours(self) -> float:
        """Get age of notification in hours"""
        return self.age_seconds / 3600.0
    
    @property
    def is_pending(self) -> bool:
        """Check if notification is pending delivery"""
        return self.status == NotificationStatus.PENDING
    
    @property
    def is_sent(self) -> bool:
        """Check if notification has been sent"""
        return self.status in [NotificationStatus.DELIVERED, NotificationStatus.SENT]
    
    @property
    def is_failed(self) -> bool:
        """Check if notification delivery failed"""
        return self.status == NotificationStatus.FAILED
    
    @property
    def can_retry(self) -> bool:
        """Check if notification can be retried"""
        return (self.status == NotificationStatus.FAILED and 
                self.retry_count < self.max_retries)
    
    @property
    def is_expired(self) -> bool:
        """Check if notification has expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    @property
    def is_scheduled(self) -> bool:
        """Check if notification is scheduled for future delivery"""
        return (self.scheduled_for is not None and 
                self.scheduled_for > datetime.now())
    
    @property
    def delivery_time_seconds(self) -> Optional[float]:
        """Get time taken to deliver notification"""
        if self.sent_at and self.delivered_at:
            return (self.delivered_at - self.sent_at).total_seconds()
        return None
    
    def mark_sending(self):
        """Mark notification as being sent"""
        self.status = NotificationStatus.SENDING
        self.updated_at = datetime.now()
    
    def mark_sent(self):
        """Mark notification as sent"""
        self.status = NotificationStatus.SENT
        self.sent_at = datetime.now()
        self.updated_at = datetime.now()
    
    def mark_delivered(self):
        """Mark notification as delivered"""
        self.status = NotificationStatus.DELIVERED
        self.delivered_at = datetime.now()
        self.updated_at = datetime.now()
    
    def mark_failed(self, error_message: str):
        """Mark notification as failed"""
        self.status = NotificationStatus.FAILED
        self.error_message = error_message
        self.updated_at = datetime.now()
        
        # Record delivery attempt
        if not self.delivery_attempts:
            self.delivery_attempts = []
        
        self.delivery_attempts.append({
            "timestamp": datetime.now().isoformat(),
            "status": "failed",
            "error": error_message,
            "retry_count": self.retry_count
        })
    
    def mark_retrying(self):
        """Mark notification as retrying"""
        self.status = NotificationStatus.RETRYING
        self.retry_count += 1
        self.updated_at = datetime.now()
        
        # Record retry attempt
        if not self.delivery_attempts:
            self.delivery_attempts = []
        
        self.delivery_attempts.append({
            "timestamp": datetime.now().isoformat(),
            "status": "retrying",
            "retry_count": self.retry_count
        })
    
    def cancel(self, user_id: int, reason: str = None):
        """Cancel the notification"""
        self.status = NotificationStatus.CANCELLED
        self.updated_at = datetime.now()
        self.deleted_by = user_id
        
        if reason:
            if not self.context:
                self.context = {}
            self.context['cancellation_reason'] = reason
    
    def schedule(self, scheduled_time: datetime):
        """Schedule notification for future delivery"""
        self.scheduled_for = scheduled_time
        self.status = NotificationStatus.PENDING
        self.updated_at = datetime.now()
    
    def add_attachment(self, filename: str, content_type: str, size: int, url: str = None):
        """Add an attachment to the notification"""
        if not self.attachments:
            self.attachments = []
        
        attachment = {
            "filename": filename,
            "content_type": content_type,
            "size": size,
            "url": url,
            "added_at": datetime.now().isoformat()
        }
        
        self.attachments.append(attachment)
    
    def add_tag(self, tag: str):
        """Add a tag to the notification"""
        if not self.tags:
            self.tags = []
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str):
        """Remove a tag from the notification"""
        if self.tags and tag in self.tags:
            self.tags.remove(tag)
    
    def update_context(self, key: str, value: Any):
        """Update notification context"""
        if not self.context:
            self.context = {}
        self.context[key] = value
        self.updated_at = datetime.now()
    
    def to_dict(self) -> dict:
        """Convert notification to dictionary"""
        return {
            "id": self.id,
            "uuid": str(self.uuid),
            "title": self.title,
            "message": self.message,
            "notification_type": self.notification_type.value,
            "priority": self.priority.value,
            "status": self.status.value,
            "channel": self.channel.value,
            "recipient": self.recipient,
            "recipient_type": self.recipient_type,
            "alert_id": self.alert_id,
            "device_id": self.device_id,
            "user_id": self.user_id,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "scheduled_for": self.scheduled_for.isoformat() if self.scheduled_for else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
            "delivered_at": self.delivered_at.isoformat() if self.delivered_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "subject": self.subject,
            "body_html": self.body_html,
            "body_text": self.body_text,
            "attachments": self.attachments,
            "error_message": self.error_message,
            "external_id": self.external_id,
            "context": self.context,
            "tags": self.tags,
            "metadata": self.notification_metadata,
            "age_seconds": self.age_seconds,
            "age_minutes": self.age_minutes,
            "age_hours": self.age_hours,
            "is_pending": self.is_pending,
            "is_sent": self.is_sent,
            "is_failed": self.is_failed,
            "can_retry": self.can_retry,
            "is_expired": self.is_expired,
            "is_scheduled": self.is_scheduled,
            "delivery_time_seconds": self.delivery_time_seconds,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }
    
    @classmethod
    def create_email_notification(
        cls,
        recipient: str,
        subject: str,
        message: str,
        notification_type: NotificationType = NotificationType.ALERT,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        alert_id: Optional[int] = None,
        device_id: Optional[int] = None,
        user_id: Optional[int] = None,
        html_body: Optional[str] = None
    ) -> 'Notification':
        """Create an email notification"""
        return cls(
            title=subject,
            message=message,
            notification_type=notification_type,
            priority=priority,
            channel=NotificationChannel.EMAIL,
            recipient=recipient,
            recipient_type="email",
            alert_id=alert_id,
            device_id=device_id,
            user_id=user_id,
            subject=subject,
            body_text=message,
            body_html=html_body,
            delivery_config={
                "smtp_server": "default",
                "from_address": "noreply@chm.local",
                "reply_to": "support@chm.local"
            }
        )
    
    @classmethod
    def create_sms_notification(
        cls,
        phone_number: str,
        message: str,
        notification_type: NotificationType = NotificationType.ALERT,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        alert_id: Optional[int] = None,
        device_id: Optional[int] = None,
        user_id: Optional[int] = None
    ) -> 'Notification':
        """Create an SMS notification"""
        return cls(
            title="SMS Alert",
            message=message,
            notification_type=notification_type,
            priority=priority,
            channel=NotificationChannel.SMS,
            recipient=phone_number,
            recipient_type="phone",
            alert_id=alert_id,
            device_id=device_id,
            user_id=user_id,
            delivery_config={
                "provider": "default",
                "sender_id": "CHM",
                "priority": priority.value
            }
        )
    
    @classmethod
    def create_webhook_notification(
        cls,
        webhook_url: str,
        message: str,
        payload: Dict[str, Any],
        notification_type: NotificationType = NotificationType.ALERT,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        alert_id: Optional[int] = None,
        device_id: Optional[int] = None,
        user_id: Optional[int] = None
    ) -> 'Notification':
        """Create a webhook notification"""
        return cls(
            title="Webhook Alert",
            message=message,
            notification_type=notification_type,
            priority=priority,
            channel=NotificationChannel.WEBHOOK,
            recipient=webhook_url,
            recipient_type="webhook",
            alert_id=alert_id,
            device_id=device_id,
            user_id=user_id,
            delivery_config={
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "timeout": 30,
                "retry_on_failure": True
            },
            context={"webhook_payload": payload}
        )
    
    @classmethod
    def create_in_app_notification(
        cls,
        user_id: int,
        title: str,
        message: str,
        notification_type: NotificationType = NotificationType.ALERT,
        priority: NotificationPriority = NotificationPriority.NORMAL,
        alert_id: Optional[int] = None,
        device_id: Optional[int] = None
    ) -> 'Notification':
        """Create an in-app notification"""
        return cls(
            title=title,
            message=message,
            notification_type=notification_type,
            priority=priority,
            channel=NotificationChannel.IN_APP,
            recipient=str(user_id),
            recipient_type="user",
            alert_id=alert_id,
            device_id=device_id,
            user_id=user_id,
            delivery_config={
                "display_duration": 5000,  # 5 seconds
                "position": "top-right",
                "auto_dismiss": True
            }
        )
