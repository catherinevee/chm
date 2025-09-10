"""
CHM Alerts API
Alert management and notification endpoints
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.alert_service import AlertService
from backend.services.notification_service import NotificationService
from core.database import get_db
from models.alert import Alert as AlertModel
from models.alert import AlertCategory, AlertSeverity, AlertStatus
from models.device import Device as DeviceModel

logger = logging.getLogger(__name__)

router = APIRouter()

# Pydantic models
class AlertCreate(BaseModel):
    device_id: int
    alert_type: str
    severity: str
    message: str
    details: Optional[dict] = None

class Alert(BaseModel):
    id: int
    device_id: int
    alert_type: str
    severity: str
    message: str
    details: Optional[dict] = None
    status: str
    created_at: str
    acknowledged_at: Optional[str] = None
    resolved_at: Optional[str] = None

# Alerts endpoints
@router.get("/", response_model=List[Alert])
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    device_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db)
):
    """List alerts with filtering and pagination"""
    logger.info(f"Alerts list request: skip={skip}, limit={limit}")
    
    try:
        # Build query with filters
        query = select(AlertModel)
        
        if severity:
            query = query.where(AlertModel.severity == AlertSeverity(severity))
        if status:
            query = query.where(AlertModel.status == AlertStatus(status))
        if device_id:
            query = query.where(AlertModel.device_id == device_id)
        
        # Apply pagination and ordering (newest first)
        query = query.order_by(AlertModel.created_at.desc()).offset(skip).limit(limit)
        
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        # Convert to response models
        response_alerts = []
        for alert in alerts:
            response_alerts.append(Alert(
                id=alert.id,
                device_id=alert.device_id,
                alert_type=alert.alert_type,
                severity=alert.severity.value if alert.severity else "unknown",
                message=alert.message,
                details=alert.details,
                status=alert.status.value if alert.status else "unknown",
                created_at=alert.created_at.isoformat() if alert.created_at else None,
                acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None
            ))
        
        logger.info(f"Returning {len(response_alerts)} alerts")
        return response_alerts
        
    except ValueError as e:
        logger.error(f"Invalid filter values: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid filter values: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to list alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")

@router.post("/", response_model=Alert)
async def create_alert(alert_data: AlertCreate, db: AsyncSession = Depends(get_db)):
    """Create a new alert"""
    logger.info(f"Alert creation request: {alert_data.alert_type}")
    
    try:
        # Validate device exists
        device_query = select(DeviceModel).where(DeviceModel.id == alert_data.device_id)
        device_result = await db.execute(device_query)
        device = device_result.scalar_one_or_none()
        if not device:
            raise HTTPException(status_code=400, detail="Device not found")
        
        # Create new alert
        new_alert = AlertModel(
            device_id=alert_data.device_id,
            alert_type=alert_data.alert_type,
            severity=AlertSeverity(alert_data.severity),
            message=alert_data.message,
            details=alert_data.details,
            status=AlertStatus.ACTIVE,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(new_alert)
        await db.commit()
        await db.refresh(new_alert)
        
        # Send notifications for high severity alerts
        if new_alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            try:
                # TODO: Implement notification sending
                pass  # notification_service = NotificationService(db)
            except Exception as e:
                logger.warning(f"Failed to send alert notification: {e}")
        
        logger.info(f"Created alert {new_alert.id} for device {alert_data.device_id}")
        
        return Alert(
            id=new_alert.id,
            device_id=new_alert.device_id,
            alert_type=new_alert.alert_type,
            severity=new_alert.severity.value,
            message=new_alert.message,
            details=new_alert.details,
            status=new_alert.status.value,
            created_at=new_alert.created_at.isoformat(),
            acknowledged_at=new_alert.acknowledged_at.isoformat() if new_alert.acknowledged_at else None,
            resolved_at=new_alert.resolved_at.isoformat() if new_alert.resolved_at else None
        )
        
    except ValueError as e:
        logger.error(f"Invalid alert data: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid alert data: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create alert: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create alert")

@router.get("/statistics")
async def get_alert_statistics(db: AsyncSession = Depends(get_db)):
    """Get alert statistics"""
    logger.info("Alert statistics request")
    
    try:
        # Count alerts by status
        total_result = await db.execute(select(func.count(AlertModel.id)))
        total_alerts = total_result.scalar()
        
        active_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.status == AlertStatus.ACTIVE))
        active_alerts = active_result.scalar()
        
        acknowledged_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.status == AlertStatus.ACKNOWLEDGED))
        acknowledged_alerts = acknowledged_result.scalar()
        
        resolved_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.status == AlertStatus.RESOLVED))
        resolved_alerts = resolved_result.scalar()
        
        # Count alerts by severity
        critical_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.severity == AlertSeverity.CRITICAL))
        critical_alerts = critical_result.scalar()
        
        high_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.severity == AlertSeverity.HIGH))
        high_alerts = high_result.scalar()
        
        medium_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.severity == AlertSeverity.MEDIUM))
        medium_alerts = medium_result.scalar()
        
        low_result = await db.execute(select(func.count(AlertModel.id)).where(AlertModel.severity == AlertSeverity.LOW))
        low_alerts = low_result.scalar()
        
        # Calculate average response time for acknowledged alerts
        acknowledged_query = select(AlertModel).where(
            and_(
                AlertModel.status == AlertStatus.ACKNOWLEDGED,
                AlertModel.acknowledged_at.isnot(None)
            )
        )
        acknowledged_result = await db.execute(acknowledged_query)
        acknowledged_with_times = acknowledged_result.scalars().all()
        
        avg_response_time = 0.0
        if acknowledged_with_times:
            total_response_time = 0
            for alert in acknowledged_with_times:
                if alert.acknowledged_at and alert.created_at:
                    response_time = (alert.acknowledged_at - alert.created_at).total_seconds()
                    total_response_time += response_time
            avg_response_time = total_response_time / len(acknowledged_with_times)
        
        return {
            "total_alerts": total_alerts,
            "active_alerts": active_alerts,
            "acknowledged_alerts": acknowledged_alerts,
            "resolved_alerts": resolved_alerts,
            "severity_breakdown": {
                "critical": critical_alerts,
                "high": high_alerts,
                "medium": medium_alerts,
                "low": low_alerts
            },
            "average_response_time_seconds": round(avg_response_time, 2)
        }
        
    except Exception as e:
        logger.error(f"Failed to get alert statistics: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert statistics")

@router.get("/{alert_id}", response_model=Alert)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Get alert details"""
    logger.info(f"Alert details request: {alert_id}")
    
    try:
        alert_query = select(AlertModel).where(AlertModel.id == alert_id)
        alert_result = await db.execute(alert_query)
        alert = alert_result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        return Alert(
            id=alert.id,
            device_id=alert.device_id,
            alert_type=alert.alert_type,
            severity=alert.severity.value if alert.severity else "unknown",
            message=alert.message,
            details=alert.details,
            status=alert.status.value if alert.status else "unknown",
            created_at=alert.created_at.isoformat() if alert.created_at else None,
            acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
            resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alert")

@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Acknowledge an alert"""
    logger.info(f"Alert acknowledgement request: {alert_id}")
    
    try:
        alert_query = select(AlertModel).where(AlertModel.id == alert_id)
        alert_result = await db.execute(alert_query)
        alert = alert_result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        if alert.status == AlertStatus.ACKNOWLEDGED:
            return {"message": "Alert already acknowledged"}
        
        if alert.status == AlertStatus.RESOLVED:
            raise HTTPException(status_code=400, detail="Cannot acknowledge resolved alert")
        
        # Update alert status
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_at = datetime.utcnow()
        alert.updated_at = datetime.utcnow()
        
        await db.commit()
        
        logger.info(f"Acknowledged alert {alert_id}")
        
        return {"message": "Alert acknowledged successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert")

@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Resolve an alert"""
    logger.info(f"Alert resolution request: {alert_id}")
    
    try:
        alert_query = select(AlertModel).where(AlertModel.id == alert_id)
        alert_result = await db.execute(alert_query)
        alert = alert_result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        if alert.status == AlertStatus.RESOLVED:
            return {"message": "Alert already resolved"}
        
        # Update alert status
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.utcnow()
        alert.updated_at = datetime.utcnow()
        
        # If not already acknowledged, acknowledge it first
        if alert.status != AlertStatus.ACKNOWLEDGED:
            alert.acknowledged_at = datetime.utcnow()
        
        await db.commit()
        
        logger.info(f"Resolved alert {alert_id}")
        
        return {"message": "Alert resolved successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve alert {alert_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to resolve alert")

@router.delete("/{alert_id}")
async def delete_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    """Delete an alert"""
    logger.info(f"Alert deletion request: {alert_id}")
    
    try:
        alert_query = select(AlertModel).where(AlertModel.id == alert_id)
        alert_result = await db.execute(alert_query)
        alert = alert_result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Delete the alert
        await db.delete(alert)
        await db.commit()
        
        logger.info(f"Deleted alert {alert_id}")
        
        return {"message": "Alert deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete alert {alert_id}: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete alert")

@router.get("/correlations/groups")
async def get_correlated_alerts(
    db: AsyncSession = Depends(get_db),
    time_window: int = Query(300, description="Time window in seconds for correlation")
):
    """Get correlated alert groups"""
    logger.info(f"Correlation request with window: {time_window}s")
    
    try:
        # Create correlation engine instance
        # TODO: Implement alert correlation
        # correlation_engine = AlertCorrelationEngine()
        correlated_alerts = []
        
        # Get correlated groups (placeholder)
        correlation_groups = []
        
        # Format response
        response_groups = []
        for group in correlation_groups:
            # Get alerts in group
            alert_ids = group.get("alert_ids", [])
            alerts_query = select(AlertModel).where(AlertModel.id.in_(alert_ids))
            alerts_result = await db.execute(alerts_query)
            alerts = alerts_result.scalars().all()
            
            response_groups.append({
                "group_id": group.get("group_id"),
                "correlation_type": group.get("correlation_type", "similarity"),
                "confidence_score": group.get("confidence", 0.0),
                "alert_count": len(alerts),
                "severity": group.get("severity", "unknown"),
                "alerts": [
                    {
                        "id": alert.id,
                        "device_id": alert.device_id,
                        "message": alert.message,
                        "severity": alert.severity.value if alert.severity else "unknown",
                        "created_at": alert.created_at.isoformat() if alert.created_at else None
                    }
                    for alert in alerts
                ],
                "root_cause": group.get("root_cause"),
                "recommended_action": group.get("recommended_action")
            })
        
        return {
            "correlation_groups": response_groups,
            "total_groups": len(response_groups),
            "time_window_seconds": time_window,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get correlated alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to get correlated alerts")

@router.post("/correlations/analyze")
async def analyze_alert_patterns(
    device_ids: Optional[List[int]] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db)
):
    """Analyze alert patterns and correlations"""
    logger.info("Alert pattern analysis request")
    
    try:
        # Build query for alerts
        query = select(AlertModel)
        
        if device_ids:
            query = query.where(AlertModel.device_id.in_(device_ids))
        
        if start_time:
            query = query.where(AlertModel.created_at >= start_time)
        
        if end_time:
            query = query.where(AlertModel.created_at <= end_time)
        
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        if not alerts:
            return {
                "patterns": [],
                "alert_count": 0,
                "message": "No alerts found for analysis"
            }
        
        # Analyze patterns
        # TODO: Implement alert correlation
        # correlation_engine = AlertCorrelationEngine()
        correlated_alerts = []
        patterns = []  # Placeholder for pattern analysis
        
        return {
            "patterns": patterns,
            "alert_count": len(alerts),
            "time_range": {
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else None
            },
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to analyze alert patterns: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze alert patterns")

@router.post("/bulk/acknowledge")
async def bulk_acknowledge_alerts(
    alert_ids: List[int],
    db: AsyncSession = Depends(get_db)
):
    """Acknowledge multiple alerts at once"""
    logger.info(f"Bulk acknowledge request for {len(alert_ids)} alerts")
    
    try:
        # Get alerts
        alerts_query = select(AlertModel).where(AlertModel.id.in_(alert_ids))
        alerts_result = await db.execute(alerts_query)
        alerts = alerts_result.scalars().all()
        
        if not alerts:
            raise HTTPException(status_code=404, detail="No alerts found")
        
        acknowledged_count = 0
        for alert in alerts:
            if alert.status == AlertStatus.ACTIVE:
                alert.status = AlertStatus.ACKNOWLEDGED
                alert.acknowledged_at = datetime.utcnow()
                alert.updated_at = datetime.utcnow()
                acknowledged_count += 1
        
        await db.commit()
        
        logger.info(f"Acknowledged {acknowledged_count} alerts")
        
        return {
            "acknowledged_count": acknowledged_count,
            "total_alerts": len(alerts),
            "message": f"Successfully acknowledged {acknowledged_count} alerts"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to bulk acknowledge alerts: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to bulk acknowledge alerts")

__all__ = ["router"]
