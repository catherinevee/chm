"""
CHM Notification Service
Multi-channel notification delivery service with retry logic and delivery tracking
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, update
from sqlalchemy.orm import selectinload

from ..models import Notification, Alert, User, Device
from ..models.notification import NotificationChannel, NotificationStatus, NotificationPriority
from ..models.result_objects import OperationStatus
from ..core.database import Base

logger = logging.getLogger(__name__)

@dataclass
class NotificationConfig:
    """Configuration for notification service"""
    smtp_server: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_from_address: str = "noreply@chm.local"
    smtp_reply_to: str = "support@chm.local"
    
    # SMS configuration
    sms_provider: str = "default"
    sms_api_key: str = ""
    sms_api_secret: str = ""
    sms_sender_id: str = "CHM"
    
    # Webhook configuration
    webhook_timeout: int = 30
    webhook_max_retries: int = 3
    webhook_retry_delay: int = 5
    
    # General settings
    max_concurrent_deliveries: int = 10
    delivery_timeout: int = 60
    retry_delay_base: int = 300  # 5 minutes
    max_retry_attempts: int = 3

@dataclass
class DeliveryResult:
    """Result of notification delivery attempt"""
    success: bool
    notification_id: int
    channel: str
    recipient: str
    delivery_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    external_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class NotificationService:
    """Service for delivering notifications through multiple channels"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.config = NotificationConfig()
        self._delivery_semaphore = asyncio.Semaphore(self.config.max_concurrent_deliveries)
        
    async def send_notification(
        self, 
        notification: Notification,
        priority_override: Optional[NotificationPriority] = None
    ) -> DeliveryResult:
        """Send a notification through its configured channel"""
        start_time = datetime.now()
        
        try:
            # Mark notification as sending
            notification.mark_sending()
            await self.db_session.commit()
            
            # Determine delivery method based on channel
            if notification.channel == NotificationChannel.EMAIL:
                result = await self._send_email_notification(notification)
            elif notification.channel == NotificationChannel.SMS:
                result = await self._send_sms_notification(notification)
            elif notification.channel == NotificationChannel.WEBHOOK:
                result = await self._send_webhook_notification(notification)
            elif notification.channel == NotificationChannel.SLACK:
                result = await self._send_slack_notification(notification)
            elif notification.channel == NotificationChannel.TEAMS:
                result = await self._send_teams_notification(notification)
            elif notification.channel == NotificationChannel.IN_APP:
                result = await self._send_in_app_notification(notification)
            else:
                result = DeliveryResult(
                    success=False,
                    notification_id=notification.id,
                    channel=notification.channel.value,
                    recipient=notification.recipient,
                    error_message=f"Unsupported channel: {notification.channel.value}"
                )
            
            # Update notification status based on result
            if result.success:
                notification.mark_delivered()
                if result.external_id:
                    notification.external_id = result.external_id
                if result.metadata:
                    notification.metadata = result.metadata
            else:
                notification.mark_failed(result.error_message or "Delivery failed")
            
            # Calculate delivery time
            delivery_time = (datetime.now() - start_time).total_seconds() * 1000
            result.delivery_time_ms = delivery_time
            
            await self.db_session.commit()
            return result
            
        except Exception as e:
            logger.error(f"Failed to send notification {notification.id}: {str(e)}")
            notification.mark_failed(str(e))
            await self.db_session.commit()
            
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def send_batch_notifications(
        self, 
        notifications: List[Notification]
    ) -> List[DeliveryResult]:
        """Send multiple notifications concurrently"""
        async with self._delivery_semaphore:
            tasks = []
            for notification in notifications:
                task = self.send_notification(notification)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to failure results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append(DeliveryResult(
                        success=False,
                        notification_id=notifications[i].id,
                        channel=notifications[i].channel.value,
                        recipient=notifications[i].recipient,
                        error_message=str(result)
                    ))
                else:
                    processed_results.append(result)
            
            return processed_results
    
    async def _send_email_notification(self, notification: Notification) -> DeliveryResult:
        """Send email notification"""
        try:
            # Prepare email message
            msg = MIMEMultipart()
            msg['From'] = self.config.smtp_from_address
            msg['To'] = notification.recipient
            msg['Subject'] = notification.subject or notification.title
            
            # Add reply-to header
            if self.config.smtp_reply_to:
                msg['Reply-To'] = self.config.smtp_reply_to
            
            # Add body
            if notification.body_html:
                html_part = MIMEText(notification.body_html, 'html')
                msg.attach(html_part)
            
            if notification.body_text:
                text_part = MIMEText(notification.body_text, 'plain')
                msg.attach(text_part)
            
            # Add attachments
            if notification.attachments:
                for attachment in notification.attachments:
                    try:
                        with open(attachment['filename'], 'rb') as f:
                            part = MIMEBase('application', 'octet-stream')
                            part.set_payload(f.read())
                        encoders.encode_base64(part)
                        part.add_header(
                            'Content-Disposition',
                            f'attachment; filename= {attachment["filename"]}'
                        )
                        msg.attach(part)
                    except Exception as e:
                        logger.warning(f"Failed to attach file {attachment['filename']}: {str(e)}")
            
            # Send email
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.smtp_use_tls:
                    server.starttls()
                
                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                
                server.send_message(msg)
            
            return DeliveryResult(
                success=True,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                metadata={"smtp_server": self.config.smtp_server}
            )
            
        except Exception as e:
            logger.error(f"Email delivery failed for notification {notification.id}: {str(e)}")
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def _send_sms_notification(self, notification: Notification) -> DeliveryResult:
        """Send SMS notification"""
        try:
            # This is a placeholder for SMS delivery
            # In production, integrate with actual SMS provider (Twilio, AWS SNS, etc.)
            logger.info(f"SMS notification to {notification.recipient}: {notification.message}")
            
            # Simulate successful delivery
            return DeliveryResult(
                success=True,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                external_id=f"sms_{notification.id}_{datetime.now().timestamp()}",
                metadata={"provider": self.config.sms_provider}
            )
            
        except Exception as e:
            logger.error(f"SMS delivery failed for notification {notification.id}: {str(e)}")
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def _send_webhook_notification(self, notification: Notification) -> DeliveryResult:
        """Send webhook notification"""
        try:
            # Get webhook payload from context
            payload = notification.context.get("webhook_payload", {}) if notification.context else {}
            
            # Add notification data to payload
            webhook_data = {
                "notification_id": notification.id,
                "title": notification.title,
                "message": notification.message,
                "type": notification.notification_type.value,
                "priority": notification.priority.value,
                "timestamp": datetime.now().isoformat(),
                **payload
            }
            
            # Get delivery configuration
            delivery_config = notification.delivery_config or {}
            method = delivery_config.get("method", "POST")
            headers = delivery_config.get("headers", {"Content-Type": "application/json"})
            timeout = delivery_config.get("timeout", self.config.webhook_timeout)
            
            # Send webhook
            response = requests.request(
                method=method,
                url=notification.recipient,
                json=webhook_data,
                headers=headers,
                timeout=timeout
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                return DeliveryResult(
                    success=True,
                    notification_id=notification.id,
                    channel=notification.channel.value,
                    recipient=notification.recipient,
                    external_id=f"webhook_{notification.id}_{response.status_code}",
                    metadata={
                        "status_code": response.status_code,
                        "response_time": response.elapsed.total_seconds(),
                        "response_headers": dict(response.headers)
                    }
                )
            else:
                return DeliveryResult(
                    success=False,
                    notification_id=notification.id,
                    channel=notification.channel.value,
                    recipient=notification.recipient,
                    error_message=f"HTTP {response.status_code}: {response.text}"
                )
                
        except Exception as e:
            logger.error(f"Webhook delivery failed for notification {notification.id}: {str(e)}")
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def _send_slack_notification(self, notification: Notification) -> DeliveryResult:
        """Send Slack notification"""
        try:
            # This is a placeholder for Slack integration
            # In production, use Slack Web API or incoming webhooks
            logger.info(f"Slack notification to {notification.recipient}: {notification.message}")
            
            # Simulate successful delivery
            return DeliveryResult(
                success=True,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                external_id=f"slack_{notification.id}_{datetime.now().timestamp()}",
                metadata={"platform": "slack"}
            )
            
        except Exception as e:
            logger.error(f"Slack delivery failed for notification {notification.id}: {str(e)}")
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def _send_teams_notification(self, notification: Notification) -> DeliveryResult:
        """Send Microsoft Teams notification"""
        try:
            # This is a placeholder for Teams integration
            # In production, use Teams webhook or Microsoft Graph API
            logger.info(f"Teams notification to {notification.recipient}: {notification.message}")
            
            # Simulate successful delivery
            return DeliveryResult(
                success=True,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                external_id=f"teams_{notification.id}_{datetime.now().timestamp()}",
                metadata={"platform": "teams"}
            )
            
        except Exception as e:
            logger.error(f"Teams delivery failed for notification {notification.id}: {str(e)}")
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def _send_in_app_notification(self, notification: Notification) -> DeliveryResult:
        """Send in-app notification"""
        try:
            # In-app notifications are typically stored in the database
            # and retrieved by the frontend application
            # For now, we'll just mark it as delivered
            
            return DeliveryResult(
                success=True,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                external_id=f"inapp_{notification.id}_{datetime.now().timestamp()}",
                metadata={"delivery_method": "database", "platform": "web"}
            )
            
        except Exception as e:
            logger.error(f"In-app notification failed for notification {notification.id}: {str(e)}")
            return DeliveryResult(
                success=False,
                notification_id=notification.id,
                channel=notification.channel.value,
                recipient=notification.recipient,
                error_message=str(e)
            )
    
    async def retry_failed_notifications(self, max_retries: Optional[int] = None) -> List[DeliveryResult]:
        """Retry failed notifications"""
        if max_retries is None:
            max_retries = self.config.max_retry_attempts
        
        try:
            # Find failed notifications that can be retried
            result = await self.db_session.execute(
                select(Notification).where(
                    and_(
                        Notification.status == NotificationStatus.FAILED,
                        Notification.retry_count < max_retries,
                        Notification.is_deleted == False
                    )
                )
            )
            
            failed_notifications = result.scalars().all()
            
            if not failed_notifications:
                return []
            
            # Retry failed notifications
            retry_results = []
            for notification in failed_notifications:
                notification.mark_retrying()
                result = await self.send_notification(notification)
                retry_results.append(result)
            
            await self.db_session.commit()
            return retry_results
            
        except Exception as e:
            logger.error(f"Failed to retry notifications: {str(e)}")
            await self.db_session.rollback()
            return []
    
    async def schedule_notification(
        self, 
        notification: Notification, 
        scheduled_time: datetime
    ) -> bool:
        """Schedule a notification for future delivery"""
        try:
            notification.schedule(scheduled_time)
            await self.db_session.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to schedule notification: {str(e)}")
            await self.db_session.rollback()
            return False
    
    async def cancel_notification(self, notification_id: int, user_id: int, reason: str = None) -> bool:
        """Cancel a scheduled notification"""
        try:
            result = await self.db_session.execute(
                select(Notification).where(Notification.id == notification_id)
            )
            notification = result.scalar_one_or_none()
            
            if not notification:
                return False
            
            notification.cancel(user_id, reason)
            await self.db_session.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel notification: {str(e)}")
            await self.db_session.rollback()
            return False
    
    async def get_notification_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get notification delivery statistics"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            # Get notifications in time range
            result = await self.db_session.execute(
                select(Notification).where(
                    and_(
                        Notification.created_at >= since,
                        Notification.is_deleted == False
                    )
                )
            )
            
            notifications = result.scalars().all()
            
            if not notifications:
                return {
                    "total_notifications": 0,
                    "delivery_rate": 0.0,
                    "channel_breakdown": {},
                    "status_breakdown": {},
                    "average_delivery_time": 0.0
                }
            
            # Calculate statistics
            total_notifications = len(notifications)
            delivered_notifications = sum(1 for n in notifications if n.is_sent)
            delivery_rate = (delivered_notifications / total_notifications) * 100 if total_notifications > 0 else 0
            
            # Channel breakdown
            channel_breakdown = {}
            for notification in notifications:
                channel = notification.channel.value
                channel_breakdown[channel] = channel_breakdown.get(channel, 0) + 1
            
            # Status breakdown
            status_breakdown = {}
            for notification in notifications:
                status = notification.status.value
                status_breakdown[status] = status_breakdown.get(status, 0) + 1
            
            # Average delivery time
            delivery_times = [n.delivery_time_seconds for n in notifications if n.delivery_time_seconds]
            average_delivery_time = sum(delivery_times) / len(delivery_times) if delivery_times else 0
            
            return {
                "total_notifications": total_notifications,
                "delivery_rate": round(delivery_rate, 2),
                "channel_breakdown": channel_breakdown,
                "status_breakdown": status_breakdown,
                "average_delivery_time": round(average_delivery_time, 3),
                "time_range_hours": hours
            }
            
        except Exception as e:
            logger.error(f"Failed to get notification stats: {str(e)}")
            return {
                "total_notifications": 0,
                "delivery_rate": 0.0,
                "channel_breakdown": {},
                "status_breakdown": {},
                "average_delivery_time": 0.0
            }
    
    def update_config(self, config: NotificationConfig):
        """Update notification configuration"""
        self.config = config
        logger.info(f"Updated notification config: {config}")
    
    async def test_channel_connectivity(self, channel: NotificationChannel) -> Dict[str, Any]:
        """Test connectivity for a specific notification channel"""
        try:
            if channel == NotificationChannel.EMAIL:
                return await self._test_email_connectivity()
            elif channel == NotificationChannel.WEBHOOK:
                return await self._test_webhook_connectivity()
            else:
                return {
                    "success": False,
                    "error": f"Channel {channel.value} connectivity testing not implemented"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _test_email_connectivity(self) -> Dict[str, Any]:
        """Test SMTP connectivity"""
        try:
            with smtplib.SMTP(self.config.smtp_server, self.config.smtp_port) as server:
                if self.config.smtp_use_tls:
                    server.starttls()
                
                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)
                
                return {
                    "success": True,
                    "server": self.config.smtp_server,
                    "port": self.config.smtp_port,
                    "tls_enabled": self.config.smtp_use_tls
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "server": self.config.smtp_server,
                "port": self.config.smtp_port
            }
    
    async def _test_webhook_connectivity(self) -> Dict[str, Any]:
        """Test webhook connectivity"""
        try:
            # Test with a simple ping request
            test_url = "https://httpbin.org/get"
            response = requests.get(test_url, timeout=self.config.webhook_timeout)
            
            return {
                "success": response.status_code == 200,
                "test_url": test_url,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "test_url": "https://httpbin.org/get"
            }
