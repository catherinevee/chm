"""
Audit Logging Service for CHM Security & Compliance System

This service provides comprehensive audit logging capabilities including:
- Security event logging and correlation
- Compliance audit trail management
- Log analysis and reporting
- Real-time monitoring and alerting
- Data retention and archival
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import uuid
from collections import defaultdict, Counter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text, between
from sqlalchemy.orm import selectinload

from ..models.security import SecurityAuditLog, SecurityIncident, ComplianceFramework
from ..models.result_objects import CollectionResult, OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    """Audit event data structure"""
    event_type: str
    event_category: str
    event_action: str
    user_id: Optional[int] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    success: bool = True
    failure_reason: Optional[str] = None
    risk_score: Optional[float] = None
    event_data: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    compliance_framework: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class AuditQuery:
    """Audit log query parameters"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    user_ids: Optional[List[int]] = None
    event_types: Optional[List[str]] = None
    event_categories: Optional[List[str]] = None
    resource_types: Optional[List[str]] = None
    success_only: Optional[bool] = None
    min_risk_score: Optional[float] = None
    compliance_framework: Optional[str] = None
    correlation_id: Optional[str] = None
    tags: Optional[List[str]] = None
    limit: int = 1000
    offset: int = 0


@dataclass
class AuditStats:
    """Audit statistics"""
    total_events: int
    successful_events: int
    failed_events: int
    unique_users: int
    unique_resources: int
    risk_distribution: Dict[str, int]
    event_type_distribution: Dict[str, int]
    time_range: Tuple[datetime, datetime]


class AuditLoggingService:
    """Service for comprehensive audit logging and analysis"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._event_buffer = []
        self._buffer_size = 100
        self._flush_interval = 30  # seconds
    
    async def log_event(self, event: AuditEvent) -> CollectionResult:
        """Log an audit event"""
        try:
            # Add to buffer for batch processing
            self._event_buffer.append(event)
            
            # Flush buffer if it's full
            if len(self._event_buffer) >= self._buffer_size:
                await self._flush_buffer()
            
            return CollectionResult(
                success=True,
                message="Event logged successfully"
            )
            
        except Exception as e:
            logger.error(f"Error logging audit event: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to log event: {str(e)}"
            )
    
    async def log_security_event(self, event_type: str, user_id: Optional[int] = None,
                                resource_type: Optional[str] = None, resource_id: Optional[str] = None,
                                action: str = "access", success: bool = True,
                                failure_reason: Optional[str] = None, **kwargs) -> CollectionResult:
        """Log a security-related audit event"""
        event = AuditEvent(
            event_type=event_type,
            event_category="security",
            event_action=action,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            failure_reason=failure_reason,
            **kwargs
        )
        
        return await self.log_event(event)
    
    async def log_access_event(self, user_id: int, resource_type: str, resource_id: str,
                              action: str, success: bool = True, **kwargs) -> CollectionResult:
        """Log an access control event"""
        return await self.log_security_event(
            event_type="access_control",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            success=success,
            **kwargs
        )
    
    async def log_authentication_event(self, user_id: Optional[int], username: Optional[str],
                                      success: bool, failure_reason: Optional[str] = None,
                                      **kwargs) -> CollectionResult:
        """Log an authentication event"""
        return await self.log_security_event(
            event_type="authentication",
            user_id=user_id,
            username=username,
            action="login" if success else "login_failed",
            success=success,
            failure_reason=failure_reason,
            **kwargs
        )
    
    async def log_data_access_event(self, user_id: int, resource_type: str, resource_id: str,
                                   action: str, data_classification: Optional[str] = None,
                                   **kwargs) -> CollectionResult:
        """Log a data access event"""
        event_data = kwargs.get('event_data', {})
        if data_classification:
            event_data['data_classification'] = data_classification
        
        return await self.log_security_event(
            event_type="data_access",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            event_data=event_data,
            **kwargs
        )
    
    async def query_audit_logs(self, query: AuditQuery) -> CollectionResult:
        """Query audit logs with filters"""
        try:
            # Build the base query
            sql_query = select(SecurityAuditLog)
            
            # Apply filters
            conditions = []
            
            if query.start_time:
                conditions.append(SecurityAuditLog.timestamp >= query.start_time)
            
            if query.end_time:
                conditions.append(SecurityAuditLog.timestamp <= query.end_time)
            
            if query.user_ids:
                conditions.append(SecurityAuditLog.user_id.in_(query.user_ids))
            
            if query.event_types:
                conditions.append(SecurityAuditLog.event_type.in_(query.event_types))
            
            if query.event_categories:
                conditions.append(SecurityAuditLog.event_category.in_(query.event_categories))
            
            if query.resource_types:
                conditions.append(SecurityAuditLog.resource_type.in_(query.resource_types))
            
            if query.success_only is not None:
                conditions.append(SecurityAuditLog.success == query.success_only)
            
            if query.min_risk_score is not None:
                conditions.append(SecurityAuditLog.risk_score >= query.min_risk_score)
            
            if query.compliance_framework:
                conditions.append(SecurityAuditLog.compliance_framework == query.compliance_framework)
            
            if query.correlation_id:
                conditions.append(SecurityAuditLog.correlation_id == query.correlation_id)
            
            if query.tags:
                for tag in query.tags:
                    conditions.append(SecurityAuditLog.tags.contains([tag]))
            
            # Apply conditions
            if conditions:
                sql_query = sql_query.where(and_(*conditions))
            
            # Apply ordering, limit, and offset
            sql_query = sql_query.order_by(desc(SecurityAuditLog.timestamp))
            sql_query = sql_query.offset(query.offset).limit(query.limit)
            
            # Execute query
            result = await self.db_session.execute(sql_query)
            audit_logs = result.scalars().all()
            
            return CollectionResult(
                success=True,
                data=audit_logs,
                message=f"Retrieved {len(audit_logs)} audit logs"
            )
            
        except Exception as e:
            logger.error(f"Error querying audit logs: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to query audit logs: {str(e)}"
            )
    
    async def get_audit_statistics(self, start_time: datetime, end_time: datetime) -> AuditStats:
        """Get audit statistics for a time period"""
        try:
            # Base query for the time period
            base_conditions = [
                SecurityAuditLog.timestamp >= start_time,
                SecurityAuditLog.timestamp <= end_time
            ]
            
            # Total events
            total_result = await self.db_session.execute(
                select(func.count(SecurityAuditLog.id)).where(and_(*base_conditions))
            )
            total_events = total_result.scalar() or 0
            
            # Successful events
            success_result = await self.db_session.execute(
                select(func.count(SecurityAuditLog.id)).where(
                    and_(*base_conditions, SecurityAuditLog.success == True)
                )
            )
            successful_events = success_result.scalar() or 0
            
            # Failed events
            failed_events = total_events - successful_events
            
            # Unique users
            users_result = await self.db_session.execute(
                select(func.count(func.distinct(SecurityAuditLog.user_id))).where(
                    and_(*base_conditions, SecurityAuditLog.user_id.isnot(None))
                )
            )
            unique_users = users_result.scalar() or 0
            
            # Unique resources
            resources_result = await self.db_session.execute(
                select(func.count(func.distinct(SecurityAuditLog.resource_id))).where(
                    and_(*base_conditions, SecurityAuditLog.resource_id.isnot(None))
                )
            )
            unique_resources = resources_result.scalar() or 0
            
            # Risk score distribution
            risk_result = await self.db_session.execute(
                select(
                    func.case(
                        (SecurityAuditLog.risk_score < 3.0, 'low'),
                        (SecurityAuditLog.risk_score < 7.0, 'medium'),
                        else_='high'
                    ).label('risk_level'),
                    func.count(SecurityAuditLog.id)
                ).where(
                    and_(*base_conditions, SecurityAuditLog.risk_score.isnot(None))
                ).group_by('risk_level')
            )
            
            risk_distribution = {row[0]: row[1] for row in risk_result.fetchall()}
            
            # Event type distribution
            event_type_result = await self.db_session.execute(
                select(
                    SecurityAuditLog.event_type,
                    func.count(SecurityAuditLog.id)
                ).where(and_(*base_conditions)).group_by(SecurityAuditLog.event_type)
            )
            
            event_type_distribution = {row[0]: row[1] for row in event_type_result.fetchall()}
            
            return AuditStats(
                total_events=total_events,
                successful_events=successful_events,
                failed_events=failed_events,
                unique_users=unique_users,
                unique_resources=unique_resources,
                risk_distribution=risk_distribution,
                event_type_distribution=event_type_distribution,
                time_range=(start_time, end_time)
            )
            
        except Exception as e:
            logger.error(f"Error getting audit statistics: {str(e)}")
            return AuditStats(
                total_events=0,
                successful_events=0,
                failed_events=0,
                unique_users=0,
                unique_resources=0,
                risk_distribution={},
                event_type_distribution={},
                time_range=(start_time, end_time)
            )
    
    async def detect_anomalies(self, time_window_hours: int = 24) -> CollectionResult:
        """Detect anomalous patterns in audit logs"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=time_window_hours)
            
            # Get recent events
            recent_events = await self.db_session.execute(
                select(SecurityAuditLog).where(
                    and_(
                        SecurityAuditLog.timestamp >= start_time,
                        SecurityAuditLog.timestamp <= end_time
                    )
                )
            )
            events = recent_events.scalars().all()
            
            anomalies = []
            
            # Detect failed login attempts
            failed_logins = [e for e in events if e.event_type == "authentication" and not e.success]
            if len(failed_logins) > 10:  # Threshold for failed login attempts
                anomalies.append({
                    "type": "excessive_failed_logins",
                    "count": len(failed_logins),
                    "description": f"Excessive failed login attempts: {len(failed_logins)} in {time_window_hours} hours",
                    "severity": "high" if len(failed_logins) > 50 else "medium"
                })
            
            # Detect unusual access patterns
            user_access_counts = defaultdict(int)
            for event in events:
                if event.user_id and event.success:
                    user_access_counts[event.user_id] += 1
            
            # Find users with unusually high access counts
            if user_access_counts:
                avg_access = sum(user_access_counts.values()) / len(user_access_counts)
                threshold = avg_access * 3  # 3x average
                
                for user_id, count in user_access_counts.items():
                    if count > threshold:
                        anomalies.append({
                            "type": "unusual_access_pattern",
                            "user_id": user_id,
                            "count": count,
                            "description": f"User {user_id} has {count} access events (threshold: {threshold:.1f})",
                            "severity": "medium"
                        })
            
            # Detect high-risk events
            high_risk_events = [e for e in events if e.risk_score and e.risk_score > 7.0]
            if high_risk_events:
                anomalies.append({
                    "type": "high_risk_events",
                    "count": len(high_risk_events),
                    "description": f"High-risk security events detected: {len(high_risk_events)}",
                    "severity": "high"
                })
            
            return CollectionResult(
                success=True,
                data=anomalies,
                message=f"Detected {len(anomalies)} anomalies"
            )
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to detect anomalies: {str(e)}"
            )
    
    async def generate_compliance_report(self, framework_name: str, 
                                       start_time: datetime, end_time: datetime) -> CollectionResult:
        """Generate compliance report for a specific framework"""
        try:
            # Get framework
            framework_result = await self.db_session.execute(
                select(ComplianceFramework).where(ComplianceFramework.name == framework_name)
            )
            framework = framework_result.scalar_one_or_none()
            
            if not framework:
                return CollectionResult(
                    success=False,
                    error=f"Compliance framework '{framework_name}' not found"
                )
            
            # Get relevant audit events
            events_result = await self.db_session.execute(
                select(SecurityAuditLog).where(
                    and_(
                        SecurityAuditLog.timestamp >= start_time,
                        SecurityAuditLog.timestamp <= end_time,
                        SecurityAuditLog.compliance_framework == framework_name
                    )
                )
            )
            events = events_result.scalars().all()
            
            # Generate report data
            report_data = {
                "framework": {
                    "name": framework.name,
                    "type": framework.framework_type,
                    "version": framework.version
                },
                "time_period": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                },
                "summary": {
                    "total_events": len(events),
                    "compliant_events": len([e for e in events if e.success]),
                    "non_compliant_events": len([e for e in events if not e.success]),
                    "compliance_percentage": framework.compliance_percentage
                },
                "events": [
                    {
                        "timestamp": event.timestamp.isoformat(),
                        "event_type": event.event_type,
                        "action": event.event_action,
                        "user_id": event.user_id,
                        "resource_type": event.resource_type,
                        "success": event.success,
                        "risk_score": event.risk_score
                    }
                    for event in events
                ]
            }
            
            return CollectionResult(
                success=True,
                data=report_data,
                message=f"Generated compliance report for {framework_name}"
            )
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to generate compliance report: {str(e)}"
            )
    
    async def archive_old_logs(self, retention_days: int = 365) -> CollectionResult:
        """Archive old audit logs based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # Count logs to be archived
            count_result = await self.db_session.execute(
                select(func.count(SecurityAuditLog.id)).where(
                    SecurityAuditLog.timestamp < cutoff_date
                )
            )
            log_count = count_result.scalar() or 0
            
            if log_count == 0:
                return CollectionResult(
                    success=True,
                    message="No logs to archive"
                )
            
            # In a production system, you would:
            # 1. Export logs to archival storage (S3, etc.)
            # 2. Compress and encrypt the data
            # 3. Delete from primary database
            # For now, we'll just mark them as archived
            
            # Update logs to mark as archived
            await self.db_session.execute(
                text("""
                    UPDATE security_audit_logs 
                    SET event_data = COALESCE(event_data, '{}'::jsonb) || '{"archived": true}'::jsonb
                    WHERE timestamp < :cutoff_date
                """),
                {"cutoff_date": cutoff_date}
            )
            
            await self.db_session.commit()
            
            return CollectionResult(
                success=True,
                message=f"Archived {log_count} audit logs older than {retention_days} days"
            )
            
        except Exception as e:
            logger.error(f"Error archiving old logs: {str(e)}")
            await self.db_session.rollback()
            return CollectionResult(
                success=False,
                error=f"Failed to archive logs: {str(e)}"
            )
    
    async def _flush_buffer(self):
        """Flush the event buffer to database"""
        if not self._event_buffer:
            return
        
        try:
            # Convert events to audit log entries
            audit_logs = []
            for event in self._event_buffer:
                audit_log = SecurityAuditLog(
                    event_type=event.event_type,
                    event_category=event.event_category,
                    event_action=event.event_action,
                    user_id=event.user_id,
                    username=event.username,
                    session_id=event.session_id,
                    ip_address=event.ip_address,
                    user_agent=event.user_agent,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    resource_name=event.resource_name,
                    success=event.success,
                    failure_reason=event.failure_reason,
                    risk_score=event.risk_score,
                    event_data=event.event_data,
                    tags=event.tags,
                    compliance_framework=event.compliance_framework,
                    correlation_id=event.correlation_id or str(uuid.uuid4())
                )
                audit_logs.append(audit_log)
            
            # Bulk insert
            self.db_session.add_all(audit_logs)
            await self.db_session.commit()
            
            # Clear buffer
            self._event_buffer.clear()
            
            logger.info(f"Flushed {len(audit_logs)} audit events to database")
            
        except Exception as e:
            logger.error(f"Error flushing audit buffer: {str(e)}")
            await self.db_session.rollback()
            # Keep events in buffer for retry
            raise
    
    async def start_background_tasks(self):
        """Start background tasks for audit logging"""
        # Start periodic buffer flush
        asyncio.create_task(self._periodic_flush())
    
    async def _periodic_flush(self):
        """Periodically flush the event buffer"""
        while True:
            try:
                await asyncio.sleep(self._flush_interval)
                if self._event_buffer:
                    await self._flush_buffer()
            except Exception as e:
                logger.error(f"Error in periodic flush: {str(e)}")
    
    async def stop_background_tasks(self):
        """Stop background tasks and flush remaining events"""
        if self._event_buffer:
            await self._flush_buffer()
