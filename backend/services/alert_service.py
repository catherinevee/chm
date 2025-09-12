"""
Alert Service - Business logic for alert management
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update
from sqlalchemy.orm import selectinload

from backend.database.models import Alert, Device, Notification
from backend.database.user_models import User
from backend.services.notification_service import NotificationService
from backend.common.exceptions import AppException
import logging

logger = logging.getLogger(__name__)

class AlertService:
    """Service for managing system alerts"""
    
    @staticmethod
    async def create_alert(
        db: AsyncSession,
        alert_data: Dict[str, Any],
        user_id: Optional[UUID] = None
    ) -> Alert:
        """Create a new alert"""
        try:
            # Validate device if provided
            device_id = alert_data.get('device_id')
            if device_id:
                device = await db.get(Device, device_id)
                if not device:
                    raise AppException(
                        status_code=404,
                        detail=f"Device {device_id} not found"
                    )
            
            # Create alert
            alert = Alert(
                device_id=device_id,
                alert_type=alert_data.get('alert_type', 'manual'),
                severity=alert_data.get('severity', 'info'),
                message=alert_data['message'],
                description=alert_data.get('description'),
                status='active',
                metadata=alert_data.get('metadata', {}),
                created_by=user_id
            )
            
            db.add(alert)
            await db.commit()
            await db.refresh(alert)
            
            # Send notifications based on severity
            await AlertService._send_alert_notifications(db, alert)
            
            # Broadcast alert via WebSocket
            from backend.api.websocket_manager import ws_manager
            await ws_manager.broadcast_alert({
                "alert_id": str(alert.id),
                "device_id": str(alert.device_id),
                "device_name": device.hostname,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "status": alert.status,
                "message": alert.message,
                "created_at": alert.created_at.isoformat()
            })
            
            return alert
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating alert: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to create alert: {str(e)}"
            )
    
    @staticmethod
    async def get_alerts(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        device_id: Optional[UUID] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        alert_type: Optional[str] = None
    ) -> List[Alert]:
        """Get alerts with filtering"""
        try:
            query = select(Alert).options(
                selectinload(Alert.device)
            )
            
            # Apply filters
            filters = []
            if device_id:
                filters.append(Alert.device_id == device_id)
            if severity:
                filters.append(Alert.severity == severity)
            if status:
                filters.append(Alert.status == status)
            if alert_type:
                filters.append(Alert.alert_type == alert_type)
            
            if filters:
                query = query.where(and_(*filters))
            
            # Order by created_at descending (newest first)
            query = query.order_by(Alert.created_at.desc())
            
            # Apply pagination
            query = query.offset(skip).limit(limit)
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Error getting alerts: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get alerts: {str(e)}"
            )
    
    @staticmethod
    async def get_alert_statistics(
        db: AsyncSession,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get alert statistics"""
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            
            # Total alerts
            total_query = select(func.count(Alert.id)).where(
                Alert.created_at >= since
            )
            total_result = await db.execute(total_query)
            total_count = total_result.scalar() or 0
            
            # Alerts by severity
            severity_query = select(
                Alert.severity,
                func.count(Alert.id).label('count')
            ).where(
                Alert.created_at >= since
            ).group_by(Alert.severity)
            
            severity_result = await db.execute(severity_query)
            severity_counts = {row.severity: row.count for row in severity_result}
            
            # Alerts by status
            status_query = select(
                Alert.status,
                func.count(Alert.id).label('count')
            ).where(
                Alert.created_at >= since
            ).group_by(Alert.status)
            
            status_result = await db.execute(status_query)
            status_counts = {row.status: row.count for row in status_result}
            
            # Active alerts count
            active_query = select(func.count(Alert.id)).where(
                Alert.status == 'active'
            )
            active_result = await db.execute(active_query)
            active_count = active_result.scalar() or 0
            
            # Average resolution time
            resolved_query = select(
                func.avg(
                    func.extract('epoch', Alert.resolved_at - Alert.created_at)
                )
            ).where(
                and_(
                    Alert.resolved_at.is_not(None),
                    Alert.created_at >= since
                )
            )
            resolved_result = await db.execute(resolved_query)
            avg_resolution_seconds = resolved_result.scalar()
            
            return {
                'period_hours': hours,
                'total_alerts': total_count,
                'active_alerts': active_count,
                'by_severity': severity_counts,
                'by_status': status_counts,
                'avg_resolution_time_minutes': (
                    round(avg_resolution_seconds / 60, 2) 
                    if avg_resolution_seconds else None
                )
            }
            
        except Exception as e:
            logger.error(f"Error getting alert statistics: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get alert statistics: {str(e)}"
            )
    
    @staticmethod
    async def acknowledge_alert(
        db: AsyncSession,
        alert_id: UUID,
        user_id: UUID,
        notes: Optional[str] = None
    ) -> Alert:
        """Acknowledge an alert"""
        try:
            alert = await db.get(Alert, alert_id)
            if not alert:
                raise AppException(
                    status_code=404,
                    detail=f"Alert {alert_id} not found"
                )
            
            if alert.status != 'active':
                raise AppException(
                    status_code=400,
                    detail=f"Alert is not active (current status: {alert.status})"
                )
            
            # Update alert
            alert.status = 'acknowledged'
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = user_id
            
            # Add notes to metadata
            if notes:
                if not alert.metadata:
                    alert.metadata = {}
                alert.metadata['acknowledgment_notes'] = notes
            
            await db.commit()
            await db.refresh(alert)
            
            # Create notification
            notification_service = NotificationService()
            await notification_service.create_notification(
                db,
                user_id=alert.created_by,
                title="Alert Acknowledged",
                message=f"Alert '{alert.message}' has been acknowledged",
                notification_type='alert_update',
                metadata={'alert_id': str(alert_id)}
            )
            
            return alert
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error acknowledging alert: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to acknowledge alert: {str(e)}"
            )
    
    @staticmethod
    async def resolve_alert(
        db: AsyncSession,
        alert_id: UUID,
        user_id: UUID,
        resolution: Optional[str] = None
    ) -> Alert:
        """Resolve an alert"""
        try:
            alert = await db.get(Alert, alert_id)
            if not alert:
                raise AppException(
                    status_code=404,
                    detail=f"Alert {alert_id} not found"
                )
            
            if alert.status == 'resolved':
                raise AppException(
                    status_code=400,
                    detail="Alert is already resolved"
                )
            
            # Update alert
            alert.status = 'resolved'
            alert.resolved_at = datetime.utcnow()
            alert.resolved_by = user_id
            
            # Add resolution to metadata
            if resolution:
                if not alert.metadata:
                    alert.metadata = {}
                alert.metadata['resolution'] = resolution
            
            await db.commit()
            await db.refresh(alert)
            
            # Create notification
            notification_service = NotificationService()
            await notification_service.create_notification(
                db,
                user_id=alert.created_by,
                title="Alert Resolved",
                message=f"Alert '{alert.message}' has been resolved",
                notification_type='alert_update',
                metadata={'alert_id': str(alert_id)}
            )
            
            return alert
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error resolving alert: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to resolve alert: {str(e)}"
            )
    
    @staticmethod
    async def escalate_alert(
        db: AsyncSession,
        alert_id: UUID,
        user_id: UUID,
        escalation_level: int = 1
    ) -> Alert:
        """Escalate an alert to higher severity"""
        try:
            alert = await db.get(Alert, alert_id)
            if not alert:
                raise AppException(
                    status_code=404,
                    detail=f"Alert {alert_id} not found"
                )
            
            if alert.status == 'resolved':
                raise AppException(
                    status_code=400,
                    detail="Cannot escalate resolved alert"
                )
            
            # Escalate severity
            severity_levels = ['info', 'warning', 'error', 'critical']
            current_index = severity_levels.index(alert.severity)
            new_index = min(current_index + escalation_level, len(severity_levels) - 1)
            
            if new_index == current_index:
                raise AppException(
                    status_code=400,
                    detail="Alert is already at maximum severity"
                )
            
            alert.severity = severity_levels[new_index]
            
            # Update metadata
            if not alert.metadata:
                alert.metadata = {}
            alert.metadata['escalated'] = True
            alert.metadata['escalated_by'] = str(user_id)
            alert.metadata['escalated_at'] = datetime.utcnow().isoformat()
            
            await db.commit()
            await db.refresh(alert)
            
            # Send escalation notifications
            await AlertService._send_escalation_notifications(db, alert, user_id)
            
            return alert
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error escalating alert: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to escalate alert: {str(e)}"
            )
    
    @staticmethod
    async def bulk_update_status(
        db: AsyncSession,
        alert_ids: List[UUID],
        status: str,
        user_id: UUID
    ) -> int:
        """Bulk update alert status"""
        try:
            if status not in ['acknowledged', 'resolved']:
                raise AppException(
                    status_code=400,
                    detail="Invalid status for bulk update"
                )
            
            # Update alerts
            stmt = update(Alert).where(
                and_(
                    Alert.id.in_(alert_ids),
                    Alert.status == 'active'
                )
            ).values(
                status=status,
                acknowledged_at=datetime.utcnow() if status == 'acknowledged' else None,
                acknowledged_by=user_id if status == 'acknowledged' else None,
                resolved_at=datetime.utcnow() if status == 'resolved' else None,
                resolved_by=user_id if status == 'resolved' else None
            )
            
            result = await db.execute(stmt)
            await db.commit()
            
            return result.rowcount
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error bulk updating alerts: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to bulk update alerts: {str(e)}"
            )
    
    @staticmethod
    async def _send_alert_notifications(
        db: AsyncSession,
        alert: Alert
    ) -> None:
        """Send notifications for new alert based on severity"""
        try:
            notification_service = NotificationService()
            
            # Determine recipients based on severity
            if alert.severity in ['critical', 'error']:
                # Send to all admins
                admin_query = select(User).where(User.is_superuser == True)
                admin_result = await db.execute(admin_query)
                admins = admin_result.scalars().all()
                
                for admin in admins:
                    await notification_service.create_notification(
                        db,
                        user_id=admin.id,
                        title=f"Critical Alert: {alert.message}",
                        message=alert.description or alert.message,
                        notification_type='critical_alert',
                        priority='high',
                        metadata={'alert_id': str(alert.id)}
                    )
            
        except Exception as e:
            logger.error(f"Error sending alert notifications: {str(e)}")
    
    @staticmethod
    async def _send_escalation_notifications(
        db: AsyncSession,
        alert: Alert,
        escalated_by: UUID
    ) -> None:
        """Send notifications for alert escalation"""
        try:
            notification_service = NotificationService()
            
            # Send to all admins
            admin_query = select(User).where(User.is_superuser == True)
            admin_result = await db.execute(admin_query)
            admins = admin_result.scalars().all()
            
            for admin in admins:
                await notification_service.create_notification(
                    db,
                    user_id=admin.id,
                    title=f"Alert Escalated: {alert.message}",
                    message=f"Alert has been escalated to {alert.severity} severity",
                    notification_type='alert_escalation',
                    priority='high',
                    metadata={
                        'alert_id': str(alert.id),
                        'escalated_by': str(escalated_by)
                    }
                )
            
        except Exception as e:
            logger.error(f"Error sending escalation notifications: {str(e)}")
    async def get_active_alert_count(self):
        """Get count of active alerts"""
        try:
            # In production, query database for active alerts
            # For now, return sample data
            return 5
        except Exception as e:
            logger.error(f"Failed to get active alert count: {e}")
            return 0
