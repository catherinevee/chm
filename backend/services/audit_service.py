"""
Audit Service for CHM Application
Handles comprehensive audit logging, compliance tracking, and security event monitoring
"""

import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import hashlib
from dataclasses import dataclass, asdict

from backend.config import settings
from backend.database.base import AsyncSession
# AuditLog model not yet implemented
class AuditLog:
    pass
class AuditAction:
    pass
class AuditSeverity:
    pass
from models.user import User
from sqlalchemy import select, and_, or_, desc, func
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)


class AuditCategory(str, Enum):
    """Audit log categories"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_CONFIG = "system_config"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    NETWORK = "network"
    DEVICE = "device"
    ALERT = "alert"


@dataclass
class AuditEvent:
    """Audit event data model"""
    action: AuditAction
    category: AuditCategory
    severity: AuditSeverity
    user_id: Optional[int]
    username: Optional[str]
    resource_type: str
    resource_id: Optional[str]
    resource_name: Optional[str]
    description: str
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    session_id: Optional[str]
    correlation_id: Optional[str]
    timestamp: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data


class AuditService:
    """Service for comprehensive audit logging and compliance"""
    
    def __init__(self):
        """Initialize audit service"""
        # Configuration
        self.enabled = settings.audit_enabled or True
        self.retention_days = settings.audit_retention_days or 365
        self.log_to_file = settings.audit_log_to_file or True
        self.log_file_path = settings.audit_log_path or "/var/log/chm/audit.log"
        self.compliance_mode = settings.compliance_mode or False
        
        # Security settings
        self.encrypt_sensitive_data = settings.encrypt_audit_data or False
        self.hash_pii = settings.hash_pii_in_audit or True
        
        # Alert thresholds
        self.failed_login_threshold = 5
        self.privilege_escalation_alert = True
        self.data_export_alert = True
        
        # Cache for performance
        self.event_cache = []
        self.cache_size = 100
        self.flush_interval = 60  # seconds
        
        logger.info("AuditService initialized")
    
    async def log_event(
        self,
        db: AsyncSession,
        event: AuditEvent
    ) -> bool:
        """
        Log audit event
        
        Args:
            db: Database session
            event: Audit event
            
        Returns:
            True if logged successfully
        """
        if not self.enabled:
            return True
        
        try:
            # Sanitize sensitive data
            sanitized_details = self._sanitize_details(event.details)
            
            # Create audit log entry
            audit_log = AuditLog(
                action=event.action,
                category=event.category,
                severity=event.severity,
                user_id=event.user_id,
                username=event.username,
                resource_type=event.resource_type,
                resource_id=event.resource_id,
                resource_name=event.resource_name,
                description=event.description,
                details=sanitized_details,
                ip_address=event.ip_address,
                user_agent=event.user_agent,
                session_id=event.session_id,
                correlation_id=event.correlation_id,
                timestamp=event.timestamp
            )
            
            db.add(audit_log)
            await db.commit()
            
            # Log to file if enabled
            if self.log_to_file:
                self._log_to_file(event)
            
            # Check for security alerts
            await self._check_security_alerts(db, event)
            
            # Add to cache for batch processing
            self.event_cache.append(event)
            if len(self.event_cache) >= self.cache_size:
                await self._flush_cache(db)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            return False
    
    async def log_authentication(
        self,
        db: AsyncSession,
        user_id: Optional[int],
        username: str,
        action: AuditAction,
        success: bool,
        ip_address: str,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log authentication event"""
        event = AuditEvent(
            action=action,
            category=AuditCategory.AUTHENTICATION,
            severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
            user_id=user_id,
            username=username,
            resource_type="authentication",
            resource_id=str(user_id) if user_id else None,
            resource_name=username,
            description=f"Authentication {action.value}: {'Success' if success else 'Failed'}",
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=details.get('session_id') if details else None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def log_authorization(
        self,
        db: AsyncSession,
        user_id: int,
        username: str,
        resource: str,
        permission: str,
        granted: bool,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log authorization event"""
        event = AuditEvent(
            action=AuditAction.PERMISSION_CHECK,
            category=AuditCategory.AUTHORIZATION,
            severity=AuditSeverity.INFO if granted else AuditSeverity.WARNING,
            user_id=user_id,
            username=username,
            resource_type="authorization",
            resource_id=resource,
            resource_name=resource,
            description=f"Permission '{permission}' on '{resource}': {'Granted' if granted else 'Denied'}",
            details=details or {'permission': permission, 'granted': granted},
            ip_address=ip_address,
            user_agent=None,
            session_id=None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def log_data_access(
        self,
        db: AsyncSession,
        user_id: int,
        username: str,
        resource_type: str,
        resource_id: str,
        action: str,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log data access event"""
        event = AuditEvent(
            action=AuditAction.DATA_ACCESS,
            category=AuditCategory.DATA_ACCESS,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=f"{resource_type}:{resource_id}",
            description=f"Data access: {action} on {resource_type}",
            details=details or {'action': action},
            ip_address=ip_address,
            user_agent=None,
            session_id=None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def log_data_modification(
        self,
        db: AsyncSession,
        user_id: int,
        username: str,
        resource_type: str,
        resource_id: str,
        action: str,
        old_value: Optional[Any] = None,
        new_value: Optional[Any] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log data modification event"""
        mod_details = details or {}
        if old_value is not None:
            mod_details['old_value'] = self._sanitize_value(old_value)
        if new_value is not None:
            mod_details['new_value'] = self._sanitize_value(new_value)
        mod_details['action'] = action
        
        event = AuditEvent(
            action=AuditAction.DATA_MODIFICATION,
            category=AuditCategory.DATA_MODIFICATION,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=f"{resource_type}:{resource_id}",
            description=f"Data modification: {action} on {resource_type}",
            details=mod_details,
            ip_address=ip_address,
            user_agent=None,
            session_id=None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def log_security_event(
        self,
        db: AsyncSession,
        event_type: str,
        severity: AuditSeverity,
        description: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log security event"""
        event = AuditEvent(
            action=AuditAction.SECURITY_EVENT,
            category=AuditCategory.SECURITY,
            severity=severity,
            user_id=user_id,
            username=username,
            resource_type="security",
            resource_id=event_type,
            resource_name=event_type,
            description=description,
            details=details or {'event_type': event_type},
            ip_address=ip_address,
            user_agent=None,
            session_id=None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def log_device_event(
        self,
        db: AsyncSession,
        device_id: str,
        device_name: str,
        event_type: str,
        description: str,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log device-related event"""
        event = AuditEvent(
            action=AuditAction.DEVICE_EVENT,
            category=AuditCategory.DEVICE,
            severity=AuditSeverity.INFO,
            user_id=user_id,
            username=username,
            resource_type="device",
            resource_id=device_id,
            resource_name=device_name,
            description=description,
            details=details or {'event_type': event_type},
            ip_address=None,
            user_agent=None,
            session_id=None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def log_alert_event(
        self,
        db: AsyncSession,
        alert_id: str,
        alert_type: str,
        severity: AuditSeverity,
        description: str,
        device_id: Optional[str] = None,
        user_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Log alert-related event"""
        event = AuditEvent(
            action=AuditAction.ALERT_TRIGGERED,
            category=AuditCategory.ALERT,
            severity=severity,
            user_id=user_id,
            username=None,
            resource_type="alert",
            resource_id=alert_id,
            resource_name=alert_type,
            description=description,
            details=details or {'alert_type': alert_type, 'device_id': device_id},
            ip_address=None,
            user_agent=None,
            session_id=None,
            correlation_id=None,
            timestamp=datetime.utcnow()
        )
        
        await self.log_event(db, event)
    
    async def search_logs(
        self,
        db: AsyncSession,
        user_id: Optional[int] = None,
        action: Optional[AuditAction] = None,
        category: Optional[AuditCategory] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        severity: Optional[AuditSeverity] = None,
        ip_address: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[AuditLog]:
        """
        Search audit logs
        
        Args:
            Various search criteria
            
        Returns:
            List of matching audit logs
        """
        try:
            query = select(AuditLog)
            
            conditions = []
            if user_id:
                conditions.append(AuditLog.user_id == user_id)
            if action:
                conditions.append(AuditLog.action == action)
            if category:
                conditions.append(AuditLog.category == category)
            if resource_type:
                conditions.append(AuditLog.resource_type == resource_type)
            if resource_id:
                conditions.append(AuditLog.resource_id == resource_id)
            if severity:
                conditions.append(AuditLog.severity == severity)
            if ip_address:
                conditions.append(AuditLog.ip_address == ip_address)
            if start_date:
                conditions.append(AuditLog.timestamp >= start_date)
            if end_date:
                conditions.append(AuditLog.timestamp <= end_date)
            
            if conditions:
                query = query.where(and_(*conditions))
            
            query = query.order_by(desc(AuditLog.timestamp))
            query = query.limit(limit).offset(offset)
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to search audit logs: {e}")
            return []
    
    async def get_user_activity(
        self,
        db: AsyncSession,
        user_id: int,
        days: int = 7,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get recent user activity"""
        start_date = datetime.utcnow() - timedelta(days=days)
        
        return await self.search_logs(
            db=db,
            user_id=user_id,
            start_date=start_date,
            limit=limit
        )
    
    async def get_failed_logins(
        self,
        db: AsyncSession,
        hours: int = 24,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get recent failed login attempts"""
        start_date = datetime.utcnow() - timedelta(hours=hours)
        
        return await self.search_logs(
            db=db,
            action=AuditAction.LOGIN_FAILED,
            start_date=start_date,
            limit=limit
        )
    
    async def get_security_events(
        self,
        db: AsyncSession,
        severity: Optional[AuditSeverity] = None,
        hours: int = 24,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get recent security events"""
        start_date = datetime.utcnow() - timedelta(hours=hours)
        
        return await self.search_logs(
            db=db,
            category=AuditCategory.SECURITY,
            severity=severity or AuditSeverity.WARNING,
            start_date=start_date,
            limit=limit
        )
    
    async def get_compliance_report(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        categories: Optional[List[AuditCategory]] = None
    ) -> Dict[str, Any]:
        """
        Generate compliance report
        
        Args:
            db: Database session
            start_date: Report start date
            end_date: Report end date
            categories: Categories to include
            
        Returns:
            Compliance report data
        """
        try:
            # Get all logs in date range
            query = select(AuditLog).where(
                and_(
                    AuditLog.timestamp >= start_date,
                    AuditLog.timestamp <= end_date
                )
            )
            
            if categories:
                query = query.where(AuditLog.category.in_(categories))
            
            result = await db.execute(query)
            logs = result.scalars().all()
            
            # Generate statistics
            report = {
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'total_events': len(logs),
                'events_by_category': {},
                'events_by_severity': {},
                'events_by_action': {},
                'top_users': {},
                'failed_authentications': 0,
                'data_modifications': 0,
                'security_events': 0,
                'compliance_violations': 0
            }
            
            # Process logs
            for log in logs:
                # Count by category
                cat = log.category or 'unknown'
                report['events_by_category'][cat] = report['events_by_category'].get(cat, 0) + 1
                
                # Count by severity
                sev = log.severity or 'unknown'
                report['events_by_severity'][sev] = report['events_by_severity'].get(sev, 0) + 1
                
                # Count by action
                act = log.action or 'unknown'
                report['events_by_action'][act] = report['events_by_action'].get(act, 0) + 1
                
                # Track top users
                if log.username:
                    report['top_users'][log.username] = report['top_users'].get(log.username, 0) + 1
                
                # Count specific event types
                if log.action == AuditAction.LOGIN_FAILED:
                    report['failed_authentications'] += 1
                if log.category == AuditCategory.DATA_MODIFICATION:
                    report['data_modifications'] += 1
                if log.category == AuditCategory.SECURITY:
                    report['security_events'] += 1
                if log.severity == AuditSeverity.CRITICAL:
                    report['compliance_violations'] += 1
            
            # Sort top users
            report['top_users'] = dict(
                sorted(report['top_users'].items(), key=lambda x: x[1], reverse=True)[:10]
            )
            
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate compliance report: {e}")
            return {}
    
    async def cleanup_old_logs(
        self,
        db: AsyncSession,
        retention_days: Optional[int] = None
    ) -> int:
        """
        Clean up old audit logs
        
        Args:
            db: Database session
            retention_days: Days to retain (uses config if not specified)
            
        Returns:
            Number of logs deleted
        """
        try:
            days = retention_days or self.retention_days
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Archive old logs before deletion if needed
            if self.compliance_mode:
                await self._archive_logs(db, cutoff_date)
            
            # Delete old logs
            query = select(AuditLog).where(AuditLog.timestamp < cutoff_date)
            result = await db.execute(query)
            old_logs = result.scalars().all()
            
            for log in old_logs:
                db.delete(log)
            
            await db.commit()
            
            deleted_count = len(old_logs)
            logger.info(f"Cleaned up {deleted_count} old audit logs")
            
            return deleted_count
            
        except Exception as e:
            logger.error(f"Failed to cleanup old logs: {e}")
            return 0
    
    def _sanitize_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive data in details"""
        if not details:
            return {}
        
        sanitized = {}
        sensitive_keys = ['password', 'token', 'secret', 'api_key', 'private_key']
        
        for key, value in details.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif self.hash_pii and key.lower() in ['email', 'phone', 'ssn']:
                sanitized[key] = self._hash_value(str(value))
            else:
                sanitized[key] = self._sanitize_value(value)
        
        return sanitized
    
    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize individual value"""
        if isinstance(value, dict):
            return self._sanitize_details(value)
        elif isinstance(value, list):
            return [self._sanitize_value(v) for v in value]
        elif isinstance(value, str) and len(value) > 1000:
            return value[:1000] + "...[truncated]"
        return value
    
    def _hash_value(self, value: str) -> str:
        """Hash sensitive value"""
        return hashlib.sha256(value.encode()).hexdigest()[:16]
    
    def _log_to_file(self, event: AuditEvent):
        """Log event to file"""
        try:
            log_entry = {
                'timestamp': event.timestamp.isoformat(),
                'action': event.action,
                'category': event.category,
                'severity': event.severity,
                'user': event.username,
                'resource': f"{event.resource_type}:{event.resource_id}",
                'description': event.description,
                'ip_address': event.ip_address
            }
            
            # Write to file (would use proper file logging in production)
            logger.info(f"AUDIT: {json.dumps(log_entry)}")
            
        except Exception as e:
            logger.error(f"Failed to log to file: {e}")
    
    async def _check_security_alerts(self, db: AsyncSession, event: AuditEvent):
        """Check if event should trigger security alert"""
        try:
            # Check for multiple failed logins
            if event.action == AuditAction.LOGIN_FAILED and event.user_id:
                recent_failures = await self.search_logs(
                    db=db,
                    user_id=event.user_id,
                    action=AuditAction.LOGIN_FAILED,
                    start_date=datetime.utcnow() - timedelta(minutes=10),
                    limit=10
                )
                
                if len(recent_failures) >= self.failed_login_threshold:
                    await self.log_security_event(
                        db=db,
                        event_type="BRUTE_FORCE_ATTEMPT",
                        severity=AuditSeverity.WARNING,
                        description=f"Multiple failed login attempts for user {event.username}",
                        user_id=event.user_id,
                        username=event.username,
                        ip_address=event.ip_address,
                        details={'failure_count': len(recent_failures)}
                    )
            
            # Check for privilege escalation
            if self.privilege_escalation_alert and event.action in [
                AuditAction.ROLE_CHANGE,
                AuditAction.PERMISSION_GRANT
            ]:
                await self.log_security_event(
                    db=db,
                    event_type="PRIVILEGE_ESCALATION",
                    severity=AuditSeverity.WARNING,
                    description=f"Privilege escalation for user {event.username}",
                    user_id=event.user_id,
                    username=event.username,
                    details=event.details
                )
            
            # Check for data export
            if self.data_export_alert and event.action == AuditAction.DATA_EXPORT:
                await self.log_security_event(
                    db=db,
                    event_type="DATA_EXPORT",
                    severity=AuditSeverity.INFO,
                    description=f"Data export by user {event.username}",
                    user_id=event.user_id,
                    username=event.username,
                    details=event.details
                )
                
        except Exception as e:
            logger.error(f"Failed to check security alerts: {e}")
    
    async def _flush_cache(self, db: AsyncSession):
        """Flush event cache"""
        # Process cached events for analytics
        self.event_cache.clear()
    
    async def _archive_logs(self, db: AsyncSession, cutoff_date: datetime):
        """Archive old logs for compliance"""
        # Implementation would export to long-term storage
        pass


# Global audit service instance
audit_service = AuditService()

# Alias for compatibility
EventCategory = AuditCategory
