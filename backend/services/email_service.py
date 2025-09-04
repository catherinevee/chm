"""
Email Service for sending notifications
"""

# Try to import aiosmtplib
try:
    import aiosmtplib
    AIOSMTPLIB_AVAILABLE = True
except ImportError:
    aiosmtplib = None
    AIOSMTPLIB_AVAILABLE = False

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional, Dict, Any
import logging

# Try to import jinja2
try:
    from jinja2 import Template
    JINJA2_AVAILABLE = True
except ImportError:
    Template = None
    JINJA2_AVAILABLE = False

from backend.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    """Service for sending email notifications"""
    
    # Email templates
    TEMPLATES = {
        'alert': """
        <html>
        <body>
            <h2>Alert Notification</h2>
            <p><strong>Device:</strong> {{ device_name }}</p>
            <p><strong>Severity:</strong> {{ severity }}</p>
            <p><strong>Message:</strong> {{ message }}</p>
            <p><strong>Time:</strong> {{ timestamp }}</p>
            {% if details %}
            <h3>Details:</h3>
            <ul>
            {% for key, value in details.items() %}
                <li><strong>{{ key }}:</strong> {{ value }}</li>
            {% endfor %}
            </ul>
            {% endif %}
        </body>
        </html>
        """,
        
        'sla_breach': """
        <html>
        <body>
            <h2>SLA Breach Notification</h2>
            <p><strong>Device:</strong> {{ device_name }}</p>
            <p><strong>SLA Metric:</strong> {{ sla_metric }}</p>
            <p><strong>Target Value:</strong> {{ target_value }}%</p>
            <p><strong>Current Value:</strong> {{ current_value }}%</p>
            <p><strong>Compliance:</strong> {{ compliance }}%</p>
            <p><strong>Time:</strong> {{ timestamp }}</p>
        </body>
        </html>
        """,
        
        'discovery_complete': """
        <html>
        <body>
            <h2>Network Discovery Complete</h2>
            <p><strong>Job Name:</strong> {{ job_name }}</p>
            <p><strong>Network Range:</strong> {{ network_range }}</p>
            <p><strong>Devices Found:</strong> {{ devices_found }}</p>
            <p><strong>Devices Added:</strong> {{ devices_added }}</p>
            <p><strong>Duration:</strong> {{ duration }}</p>
            {% if errors %}
            <h3>Errors:</h3>
            <ul>
            {% for error in errors %}
                <li>{{ error }}</li>
            {% endfor %}
            </ul>
            {% endif %}
        </body>
        </html>
        """,
        
        'password_reset': """
        <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>Hello {{ username }},</p>
            <p>You have requested to reset your password for CHM.</p>
            <p>Please click the link below to reset your password:</p>
            <p><a href="{{ reset_link }}">Reset Password</a></p>
            <p>This link will expire in {{ expire_hours }} hours.</p>
            <p>If you did not request this reset, please ignore this email.</p>
        </body>
        </html>
        """,
        
        'welcome': """
        <html>
        <body>
            <h2>Welcome to CHM</h2>
            <p>Hello {{ username }},</p>
            <p>Your account has been created successfully.</p>
            <p><strong>Username:</strong> {{ username }}</p>
            <p><strong>Email:</strong> {{ email }}</p>
            <p>Please click the link below to verify your email address:</p>
            <p><a href="{{ verification_link }}">Verify Email</a></p>
        </body>
        </html>
        """
    }
    
    def __init__(self):
        self.smtp_host = settings.smtp_host
        self.smtp_port = settings.smtp_port
        self.smtp_username = settings.smtp_username
        self.smtp_password = settings.smtp_password
        self.smtp_from = settings.smtp_from_email or settings.smtp_username
        self.smtp_use_tls = settings.smtp_use_tls
        self.enabled = bool(self.smtp_host and self.smtp_username) and AIOSMTPLIB_AVAILABLE
        
        if not AIOSMTPLIB_AVAILABLE:
            logger.warning("Email service is disabled - aiosmtplib not installed")
        elif not (self.smtp_host and self.smtp_username):
            logger.warning("Email service is disabled - SMTP settings not configured")
    
    async def send_email(
        self,
        to_emails: List[str],
        subject: str,
        body: str,
        html: bool = True,
        cc_emails: Optional[List[str]] = None,
        bcc_emails: Optional[List[str]] = None,
        attachments: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """Send an email"""
        if not self.enabled:
            logger.warning(f"Email not sent (service disabled): {subject} to {to_emails}")
            return False
        
        try:
            # Create message
            message = MIMEMultipart('alternative')
            message['Subject'] = subject
            message['From'] = self.smtp_from
            message['To'] = ', '.join(to_emails)
            
            if cc_emails:
                message['Cc'] = ', '.join(cc_emails)
            if bcc_emails:
                message['Bcc'] = ', '.join(bcc_emails)
            
            # Add body
            if html:
                part = MIMEText(body, 'html')
            else:
                part = MIMEText(body, 'plain')
            message.attach(part)
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    # Would implement attachment handling here
                    pass
            
            # Send email
            async with aiosmtplib.SMTP(
                hostname=self.smtp_host,
                port=self.smtp_port,
                use_tls=self.smtp_use_tls
            ) as smtp:
                if self.smtp_username and self.smtp_password:
                    await smtp.login(self.smtp_username, self.smtp_password)
                
                await smtp.send_message(message)
            
            logger.info(f"Email sent successfully: {subject} to {to_emails}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    async def send_alert_email(
        self,
        to_emails: List[str],
        device_name: str,
        severity: str,
        message: str,
        timestamp: str,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send alert notification email"""
        template = Template(self.TEMPLATES['alert'])
        html_body = template.render(
            device_name=device_name,
            severity=severity,
            message=message,
            timestamp=timestamp,
            details=details
        )
        
        subject = f"[CHM Alert] {severity.upper()}: {device_name}"
        
        return await self.send_email(
            to_emails=to_emails,
            subject=subject,
            body=html_body,
            html=True
        )
    
    async def send_sla_breach_email(
        self,
        to_emails: List[str],
        device_name: str,
        sla_metric: str,
        target_value: float,
        current_value: float,
        compliance: float,
        timestamp: str
    ) -> bool:
        """Send SLA breach notification email"""
        template = Template(self.TEMPLATES['sla_breach'])
        html_body = template.render(
            device_name=device_name,
            sla_metric=sla_metric,
            target_value=target_value,
            current_value=current_value,
            compliance=compliance,
            timestamp=timestamp
        )
        
        subject = f"[CHM SLA Breach] {device_name}: {sla_metric}"
        
        return await self.send_email(
            to_emails=to_emails,
            subject=subject,
            body=html_body,
            html=True
        )
    
    async def send_discovery_complete_email(
        self,
        to_emails: List[str],
        job_name: str,
        network_range: str,
        devices_found: int,
        devices_added: int,
        duration: str,
        errors: Optional[List[str]] = None
    ) -> bool:
        """Send discovery completion email"""
        template = Template(self.TEMPLATES['discovery_complete'])
        html_body = template.render(
            job_name=job_name,
            network_range=network_range,
            devices_found=devices_found,
            devices_added=devices_added,
            duration=duration,
            errors=errors
        )
        
        subject = f"[CHM Discovery] {job_name} Complete"
        
        return await self.send_email(
            to_emails=to_emails,
            subject=subject,
            body=html_body,
            html=True
        )
    
    async def send_password_reset_email(
        self,
        to_email: str,
        username: str,
        reset_link: str,
        expire_hours: int = 24
    ) -> bool:
        """Send password reset email"""
        template = Template(self.TEMPLATES['password_reset'])
        html_body = template.render(
            username=username,
            reset_link=reset_link,
            expire_hours=expire_hours
        )
        
        subject = "[CHM] Password Reset Request"
        
        return await self.send_email(
            to_emails=[to_email],
            subject=subject,
            body=html_body,
            html=True
        )
    
    async def send_welcome_email(
        self,
        to_email: str,
        username: str,
        verification_link: str
    ) -> bool:
        """Send welcome email to new user"""
        template = Template(self.TEMPLATES['welcome'])
        html_body = template.render(
            username=username,
            email=to_email,
            verification_link=verification_link
        )
        
        subject = "[CHM] Welcome to Catalyst Health Monitor"
        
        return await self.send_email(
            to_emails=[to_email],
            subject=subject,
            body=html_body,
            html=True
        )
    
    async def test_email_configuration(self) -> bool:
        """Test email configuration"""
        if not self.enabled:
            return False
        
        try:
            async with aiosmtplib.SMTP(
                hostname=self.smtp_host,
                port=self.smtp_port,
                use_tls=self.smtp_use_tls
            ) as smtp:
                if self.smtp_username and self.smtp_password:
                    await smtp.login(self.smtp_username, self.smtp_password)
                
                # Just test connection
                await smtp.noop()
            
            logger.info("Email configuration test successful")
            return True
            
        except Exception as e:
            logger.error(f"Email configuration test failed: {e}")
            return False

# Global email service instance
email_service = EmailService()