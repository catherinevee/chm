"""
CHM Alerts API
Alert management and notification endpoints
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from typing import List, Optional
import logging
from datetime import datetime

from core.database import get_db
from models.alert import Alert as AlertModel, AlertStatus, AlertSeverity, AlertCategory
from services.notification_service import notification_service

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
    db = Depends(get_db)
):
    """List alerts with filtering and pagination"""
    logger.info(f"Alerts list request: skip={skip}, limit={limit}")
    
    try:
        # Build query with filters
        query = db.query(AlertModel)
        
        if severity:
            query = query.filter(AlertModel.severity == AlertSeverity(severity))
        if status:
            query = query.filter(AlertModel.status == AlertStatus(status))
        if device_id:
            query = query.filter(AlertModel.device_id == device_id)
        
        # Apply pagination and ordering (newest first)
        alerts = query.order_by(AlertModel.created_at.desc()).offset(skip).limit(limit).all()
        
        # Convert to response models
        result = []
        for alert in alerts:
            result.append(Alert(
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
        
        logger.info(f"Returning {len(result)} alerts")
        return result
        
    except ValueError as e:
        logger.error(f"Invalid filter values: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid filter values: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to list alerts: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")

@router.post("/", response_model=Alert)
async def create_alert(alert_data: AlertCreate, db = Depends(get_db)):
    """Create a new alert"""
    logger.info(f"Alert creation request: {alert_data.alert_type}")
    
    try:
        # Validate device exists
        from models.device import Device
        device = db.query(Device).filter(Device.id == alert_data.device_id).first()
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
        db.commit()
        db.refresh(new_alert)
        
        # Send notifications for high severity alerts
        if new_alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.HIGH]:
            try:
                await notification_service.send_alert_notification(new_alert)
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
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create alert")

@router.get("/statistics")
async def get_alert_statistics(db = Depends(get_db)):
    """Get alert statistics"""
    logger.info("Alert statistics request")
    
    try:
        # Count alerts by status
        total_alerts = db.query(AlertModel).count()
        active_alerts = db.query(AlertModel).filter(AlertModel.status == AlertStatus.ACTIVE).count()
        acknowledged_alerts = db.query(AlertModel).filter(AlertModel.status == AlertStatus.ACKNOWLEDGED).count()
        resolved_alerts = db.query(AlertModel).filter(AlertModel.status == AlertStatus.RESOLVED).count()
        
        # Count alerts by severity
        critical_alerts = db.query(AlertModel).filter(AlertModel.severity == AlertSeverity.CRITICAL).count()
        high_alerts = db.query(AlertModel).filter(AlertModel.severity == AlertSeverity.HIGH).count()
        medium_alerts = db.query(AlertModel).filter(AlertModel.severity == AlertSeverity.MEDIUM).count()
        low_alerts = db.query(AlertModel).filter(AlertModel.severity == AlertSeverity.LOW).count()
        
        # Calculate average response time for acknowledged alerts
        acknowledged_with_times = db.query(AlertModel).filter(
            AlertModel.status == AlertStatus.ACKNOWLEDGED,
            AlertModel.acknowledged_at.isnot(None)
        ).all()
        
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
async def get_alert(alert_id: int, db = Depends(get_db)):
    """Get alert details"""
    logger.info(f"Alert details request: {alert_id}")
    
    try:
        alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
        
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
async def acknowledge_alert(alert_id: int, db = Depends(get_db)):
    """Acknowledge an alert"""
    logger.info(f"Alert acknowledgement request: {alert_id}")
    
    try:
        alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
        
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
        
        db.commit()
        
        logger.info(f"Acknowledged alert {alert_id}")
        
        return {"message": "Alert acknowledged successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to acknowledge alert")

@router.post("/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db = Depends(get_db)):
    """Resolve an alert"""
    logger.info(f"Alert resolution request: {alert_id}")
    
    try:
        alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
        
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
        
        db.commit()
        
        logger.info(f"Resolved alert {alert_id}")
        
        return {"message": "Alert resolved successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resolve alert {alert_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to resolve alert")

@router.delete("/{alert_id}")
async def delete_alert(alert_id: int, db = Depends(get_db)):
    """Delete an alert"""
    logger.info(f"Alert deletion request: {alert_id}")
    
    try:
        alert = db.query(AlertModel).filter(AlertModel.id == alert_id).first()
        
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        # Delete the alert
        db.delete(alert)
        db.commit()
        
        logger.info(f"Deleted alert {alert_id}")
        
        return {"message": "Alert deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete alert {alert_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete alert")

__all__ = ["router"]
