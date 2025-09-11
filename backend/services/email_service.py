"""
Email Service for CHM Application
Handles all email communications including verification, password reset, and notifications
"""

import asyncio
import logging
import smtplib
import ssl
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, List, Optional, Any
from pathlib import Path
import aiosmtplib
from jinja2 import Template, Environment, FileSystemLoader, select_autoescape
from pydantic import EmailStr

from backend.config import settings
from backend.common.exceptions import (
    EmailException,
    ConfigurationException,
    ValidationException
)
from backend.database.base import AsyncSession
from backend.models.user import User
from backend.models.notification import Notification, NotificationType, NotificationStatus

logger = logging.getLogger(__name__)


class EmailService:
    """Service for handling all email operations"""
    
    def __init__(self):
        """Initialize email service with configuration"""
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_username = settings.smtp_username
        self.smtp_password = settings.smtp_password
        self.from_email = settings.smtp_from_email or "noreply@chm.local"
        self.from_name = getattr(settings, 'from_name', None) or "CHM System"
        self.use_tls = settings.smtp_use_tls
        self.use_ssl = getattr(settings, 'smtp_use_ssl', False)
        
        # Template configuration
        self.template_dir = Path(__file__).parent.parent / "templates" / "email"
        self.template_env = None
        self._initialize_templates()
        
        # Email queue for batch sending
        self.email_queue: List[Dict[str, Any]] = []
        self.max_queue_size = 100
        
        # Rate limiting
        self.rate_limit = getattr(settings, 'email_rate_limit', 10)  # emails per second
        self.last_sent = datetime.utcnow()
        
        logger.info("EmailService initialized")
    
    def _initialize_templates(self):
        """Initialize Jinja2 template environment"""
        try:
            if self.template_dir.exists():
                self.template_env = Environment(
                    loader=FileSystemLoader(str(self.template_dir)),
                    autoescape=select_autoescape(['html', 'xml'])
                )
                logger.info(f"Email templates loaded from {self.template_dir}")
            else:
                logger.warning(f"Template directory not found: {self.template_dir}")
                # Create default templates in memory
                self._create_default_templates()
        except Exception as e:
            logger.error(f"Failed to initialize templates: {e}")
            self._create_default_templates()
    
    def _create_default_templates(self):
        """Create default email templates in memory"""
        self.template_env = Environment(loader=None)
        
        # Default templates as strings
        self.default_templates = {
            'verification': """
                <!DOCTYPE html>
                <html>
                <head><title>Email Verification</title></head>
                <body>
                    <h2>Welcome to CHM, {{ user_name }}!</h2>
                    <p>Please verify your email address by clicking the link below:</p>
                    <p><a href="{{ verification_url }}">Verify Email</a></p>
                    <p>Or copy this link: {{ verification_url }}</p>
                    <p>This link will expire in {{ expiry_hours }} hours.</p>
                    <p>If you didn't create this account, please ignore this email.</p>
                </body>
                </html>
            """,
            'password_reset': """
                <!DOCTYPE html>
                <html>
                <head><title>Password Reset</title></head>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>Hi {{ user_name }},</p>
                    <p>We received a request to reset your password. Click the link below:</p>
                    <p><a href="{{ reset_url }}">Reset Password</a></p>
                    <p>Or copy this link: {{ reset_url }}</p>
                    <p>This link will expire in {{ expiry_hours }} hours.</p>
                    <p>If you didn't request this, please ignore this email.</p>
                </body>
                </html>
            """,
            'alert_notification': """
                <!DOCTYPE html>
                <html>
                <head><title>CHM Alert</title></head>
                <body>
                    <h2>Alert: {{ alert_title }}</h2>
                    <p><strong>Severity:</strong> {{ severity }}</p>
                    <p><strong>Device:</strong> {{ device_name }}</p>
                    <p><strong>Time:</strong> {{ alert_time }}</p>
                    <p><strong>Description:</strong></p>
                    <p>{{ alert_description }}</p>
                    <p><a href="{{ dashboard_url }}">View in Dashboard</a></p>
                </body>
                </html>
            """,
            'welcome': """
                <!DOCTYPE html>
                <html>
                <head><title>Welcome to CHM</title></head>
                <body>
                    <h2>Welcome to CHM, {{ user_name }}!</h2>
                    <p>Your account has been successfully created.</p>
                    <p><strong>Username:</strong> {{ username }}</p>
                    <p><strong>Role:</strong> {{ role }}</p>
                    <p>You can now log in at: <a href="{{ login_url }}">{{ login_url }}</a></p>
                    <p>If you have any questions, please contact your administrator.</p>
                </body>
                </html>
            """,
            'account_locked': """
                <!DOCTYPE html>
                <html>
                <head><title>Account Locked</title></head>
                <body>
                    <h2>Account Security Alert</h2>
                    <p>Hi {{ user_name }},</p>
                    <p>Your account has been locked due to multiple failed login attempts.</p>
                    <p>Time: {{ lock_time }}</p>
                    <p>If this was you, please wait {{ lockout_duration }} minutes before trying again.</p>
                    <p>If this wasn't you, please contact your administrator immediately.</p>
                </body>
                </html>
            """,
            'mfa_code': """
                <!DOCTYPE html>
                <html>
                <head><title>MFA Verification Code</title></head>
                <body>
                    <h2>Your Verification Code</h2>
                    <p>Hi {{ user_name }},</p>
                    <p>Your verification code is:</p>
                    <h1 style="font-family: monospace;">{{ mfa_code }}</h1>
                    <p>This code will expire in {{ expiry_minutes }} minutes.</p>
                    <p>If you didn't request this code, please secure your account immediately.</p>
                </body>
                </html>
            """
        }
    
    async def send_verification_email(
        self,
        user: User,
        verification_token: str,
        db: AsyncSession
    ) -> bool:
        """
        Send email verification to new user
        
        Args:
            user: User object
            verification_token: Token for email verification
            db: Database session
            
        Returns:
            True if email sent successfully
        """
        try:
            frontend_url = getattr(settings, 'frontend_url', 'http://localhost:3000')
            verification_url = f"{frontend_url}/verify-email?token={verification_token}"
            
            template_data = {
                'user_name': user.full_name or user.username,
                'verification_url': verification_url,
                'expiry_hours': 24
            }
            
            subject = "Verify your CHM account"
            html_content = self._render_template('verification', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            # Log notification
            if success:
                await self._log_notification(
                    db=db,
                    user_id=user.id,
                    type=NotificationType.EMAIL,
                    subject=subject,
                    status=NotificationStatus.SENT
                )
                logger.info(f"Verification email sent to {user.email}")
            else:
                await self._log_notification(
                    db=db,
                    user_id=user.id,
                    type=NotificationType.EMAIL,
                    subject=subject,
                    status=NotificationStatus.FAILED
                )
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to send verification email: {e}")
            return False
    
    async def send_password_reset_email(
        self,
        user: User,
        reset_token: str,
        db: AsyncSession
    ) -> bool:
        """
        Send password reset email
        
        Args:
            user: User object
            reset_token: Token for password reset
            db: Database session
            
        Returns:
            True if email sent successfully
        """
        try:
            frontend_url = getattr(settings, 'frontend_url', 'http://localhost:3000')
            reset_url = f"{frontend_url}/reset-password?token={reset_token}"
            
            template_data = {
                'user_name': user.full_name or user.username,
                'reset_url': reset_url,
                'expiry_hours': 1
            }
            
            subject = "Password Reset Request"
            html_content = self._render_template('password_reset', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            # Log notification
            if success:
                await self._log_notification(
                    db=db,
                    user_id=user.id,
                    type=NotificationType.EMAIL,
                    subject=subject,
                    status=NotificationStatus.SENT
                )
                logger.info(f"Password reset email sent to {user.email}")
            else:
                await self._log_notification(
                    db=db,
                    user_id=user.id,
                    type=NotificationType.EMAIL,
                    subject=subject,
                    status=NotificationStatus.FAILED
                )
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to send password reset email: {e}")
            return False
    
    async def send_welcome_email(
        self,
        user: User,
        db: AsyncSession
    ) -> bool:
        """
        Send welcome email to new user
        
        Args:
            user: User object
            db: Database session
            
        Returns:
            True if email sent successfully
        """
        try:
            template_data = {
                'user_name': user.full_name or user.username,
                'username': user.username,
                'role': user.role,
                'login_url': f"{getattr(settings, 'frontend_url', 'http://localhost:3000')}/login"
            }
            
            subject = "Welcome to CHM"
            html_content = self._render_template('welcome', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                logger.info(f"Welcome email sent to {user.email}")
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to send welcome email: {e}")
            return False
    
    async def send_alert_notification(
        self,
        user: User,
        alert_data: Dict[str, Any],
        db: AsyncSession
    ) -> bool:
        """
        Send alert notification email
        
        Args:
            user: User object
            alert_data: Alert information
            db: Database session
            
        Returns:
            True if email sent successfully
        """
        try:
            template_data = {
                'alert_title': alert_data.get('title', 'System Alert'),
                'severity': alert_data.get('severity', 'Unknown'),
                'device_name': alert_data.get('device_name', 'N/A'),
                'alert_time': alert_data.get('timestamp', datetime.utcnow()).isoformat(),
                'alert_description': alert_data.get('description', 'No description'),
                'dashboard_url': f"{getattr(settings, 'frontend_url', 'http://localhost:3000')}/alerts/{alert_data.get('id', '')}"
            }
            
            subject = f"CHM Alert: {template_data['alert_title']}"
            html_content = self._render_template('alert_notification', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            # Log notification
            if success:
                await self._log_notification(
                    db=db,
                    user_id=user.id,
                    type=NotificationType.ALERT,
                    subject=subject,
                    status=NotificationStatus.SENT,
                    metadata={'alert_id': alert_data.get('id')}
                )
                logger.info(f"Alert notification sent to {user.email}")
            else:
                await self._log_notification(
                    db=db,
                    user_id=user.id,
                    type=NotificationType.ALERT,
                    subject=subject,
                    status=NotificationStatus.FAILED,
                    metadata={'alert_id': alert_data.get('id')}
                )
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to send alert notification: {e}")
            return False
    
    async def send_account_locked_email(
        self,
        user: User,
        lockout_duration: int,
        db: AsyncSession
    ) -> bool:
        """
        Send account locked notification
        
        Args:
            user: User object
            lockout_duration: Duration in minutes
            db: Database session
            
        Returns:
            True if email sent successfully
        """
        try:
            template_data = {
                'user_name': user.full_name or user.username,
                'lock_time': datetime.utcnow().isoformat(),
                'lockout_duration': lockout_duration
            }
            
            subject = "Account Security Alert"
            html_content = self._render_template('account_locked', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                logger.info(f"Account locked email sent to {user.email}")
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to send account locked email: {e}")
            return False
    
    async def send_mfa_code(
        self,
        user: User,
        mfa_code: str,
        expiry_minutes: int = 5,
        db: Optional[AsyncSession] = None
    ) -> bool:
        """
        Send MFA verification code
        
        Args:
            user: User object
            mfa_code: MFA code
            expiry_minutes: Code expiry time
            db: Database session
            
        Returns:
            True if email sent successfully
        """
        try:
            template_data = {
                'user_name': user.full_name or user.username,
                'mfa_code': mfa_code,
                'expiry_minutes': expiry_minutes
            }
            
            subject = "Your CHM Verification Code"
            html_content = self._render_template('mfa_code', template_data)
            
            success = await self._send_email(
                to_email=user.email,
                subject=subject,
                html_content=html_content
            )
            
            if success:
                logger.info(f"MFA code sent to {user.email}")
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to send MFA code: {e}")
            return False
    
    async def send_bulk_email(
        self,
        recipients: List[str],
        subject: str,
        html_content: str,
        text_content: Optional[str] = None
    ) -> Dict[str, bool]:
        """
        Send bulk email to multiple recipients
        
        Args:
            recipients: List of email addresses
            subject: Email subject
            html_content: HTML content
            text_content: Plain text content
            
        Returns:
            Dictionary of email -> success status
        """
        results = {}
        
        for recipient in recipients:
            # Apply rate limiting
            await self._apply_rate_limit()
            
            success = await self._send_email(
                to_email=recipient,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )
            results[recipient] = success
            
        return results
    
    async def queue_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        priority: int = 5
    ) -> bool:
        """
        Queue email for batch sending
        
        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML content
            text_content: Plain text content
            priority: Priority (1-10, 1 is highest)
            
        Returns:
            True if queued successfully
        """
        try:
            if len(self.email_queue) >= self.max_queue_size:
                logger.warning("Email queue is full")
                return False
            
            self.email_queue.append({
                'to_email': to_email,
                'subject': subject,
                'html_content': html_content,
                'text_content': text_content,
                'priority': priority,
                'queued_at': datetime.utcnow()
            })
            
            # Sort by priority
            self.email_queue.sort(key=lambda x: x['priority'])
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to queue email: {e}")
            return False
    
    async def process_email_queue(self) -> Dict[str, int]:
        """
        Process queued emails
        
        Returns:
            Statistics of processed emails
        """
        stats = {'sent': 0, 'failed': 0}
        
        while self.email_queue:
            email_data = self.email_queue.pop(0)
            
            # Apply rate limiting
            await self._apply_rate_limit()
            
            success = await self._send_email(
                to_email=email_data['to_email'],
                subject=email_data['subject'],
                html_content=email_data['html_content'],
                text_content=email_data.get('text_content')
            )
            
            if success:
                stats['sent'] += 1
            else:
                stats['failed'] += 1
        
        logger.info(f"Email queue processed: {stats}")
        return stats
    
    def _render_template(self, template_name: str, data: Dict[str, Any]) -> str:
        """
        Render email template
        
        Args:
            template_name: Template name
            data: Template data
            
        Returns:
            Rendered HTML content
        """
        try:
            if self.template_env and self.template_env.loader:
                template = self.template_env.get_template(f"{template_name}.html")
                return template.render(**data)
            else:
                # Use default templates
                template_str = self.default_templates.get(template_name, "")
                template = Template(template_str)
                return template.render(**data)
                
        except Exception as e:
            logger.error(f"Failed to render template {template_name}: {e}")
            # Return basic HTML
            return f"<html><body><h2>{data.get('subject', 'CHM Notification')}</h2><p>Template rendering failed.</p></body></html>"
    
    async def _send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: Optional[str] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """
        Send email via SMTP
        
        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML content
            text_content: Plain text content
            attachments: List of attachments
            
        Returns:
            True if sent successfully
        """
        try:
            # Validate configuration
            if not all([self.smtp_host, self.smtp_port, self.from_email]):
                logger.error("Email configuration incomplete")
                return False
            
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = f"{self.from_name} <{self.from_email}>"
            message['To'] = to_email
            
            # Add text and HTML parts
            if text_content:
                text_part = MIMEText(text_content, 'plain')
                message.attach(text_part)
            
            html_part = MIMEText(html_content, 'html')
            message.attach(html_part)
            
            # Send email
            if settings.environment == "testing":
                # In testing, just log the email
                logger.info(f"TEST MODE: Email to {to_email} - Subject: {subject}")
                return True
            
            # Use aiosmtplib for async sending
            await aiosmtplib.send(
                message,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_username if self.smtp_username else None,
                password=self.smtp_password if self.smtp_password else None,
                use_tls=self.use_tls,
                start_tls=self.use_ssl
            )
            
            logger.info(f"Email sent to {to_email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {e}")
            return False
    
    async def _apply_rate_limit(self):
        """Apply rate limiting for email sending"""
        if self.rate_limit > 0:
            min_interval = 1.0 / self.rate_limit
            elapsed = (datetime.utcnow() - self.last_sent).total_seconds()
            
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            
            self.last_sent = datetime.utcnow()
    
    async def _log_notification(
        self,
        db: AsyncSession,
        user_id: int,
        type: NotificationType,
        subject: str,
        status: NotificationStatus,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Log notification to database
        
        Args:
            db: Database session
            user_id: User ID
            type: Notification type
            subject: Subject
            status: Status
            metadata: Additional metadata
        """
        try:
            notification = Notification(
                user_id=user_id,
                type=type,
                title=subject,
                message=subject,
                status=status,
                metadata=metadata or {}
            )
            db.add(notification)
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to log notification: {e}")
            await db.rollback()
    
    async def test_connection(self) -> bool:
        """
        Test SMTP connection
        
        Returns:
            True if connection successful
        """
        try:
            if not all([self.smtp_host, self.smtp_port]):
                logger.error("SMTP configuration incomplete")
                return False
            
            # Test connection
            await aiosmtplib.send(
                MIMEText("Test", 'plain'),
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_username if self.smtp_username else None,
                password=self.smtp_password if self.smtp_password else None,
                use_tls=self.use_tls,
                start_tls=self.use_ssl,
                sender=self.from_email,
                recipients=["test@example.com"]
            )
            
            logger.info("SMTP connection test successful")
            return True
            
        except Exception as e:
            logger.error(f"SMTP connection test failed: {e}")
            return False


# Global email service instance
email_service = EmailService()