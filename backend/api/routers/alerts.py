"""
Alert management API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, update
from pydantic import BaseModel, Field
import logging
import uuid

from backend.database.models import Alert, Device
from backend.database.base import get_db
from backend.services.validation_service import ValidationService
from backend.api.dependencies.auth import (
    get_current_user,
    require_alerts_read,
    require_alerts_write,
    require_alerts_delete,
    standard_rate_limit
)
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

class AlertCreate(BaseModel):
    device_id: str
    alert_type: str
    severity: str = Field(..., pattern="^(info|warning|critical|error)$")
    message: str
    details: Optional[Dict[str, Any]] = None

class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, pattern="^(active|acknowledged|resolved)$")
    acknowledged_by: Optional[str] = None
    message: Optional[str] = None

class AlertResponse(BaseModel):
    id: str
    device_id: str
    device_hostname: Optional[str] = None
    alert_type: str
    severity: str
    status: str
    message: str
    details: Optional[Dict[str, Any]]
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    resolved_at: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total: int
    page: int
    per_page: int
    unacknowledged_count: int
    critical_count: int

class AlertStatistics(BaseModel):
    total_alerts: int
    active_alerts: int
    acknowledged_alerts: int
    resolved_alerts: int
    alerts_by_severity: Dict[str, int]
    alerts_by_type: Dict[str, int]
    recent_critical_alerts: List[AlertResponse]

@router.post("", response_model=AlertResponse, dependencies=[Depends(standard_rate_limit)])
async def create_alert(
    alert_data: AlertCreate,
    current_user: User = Depends(require_alerts_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new alert
    """
    try:
        # Validate device exists
        device = await db.get(Device, alert_data.device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Create alert
        alert = Alert(
            device_id=alert_data.device_id,
            alert_type=alert_data.alert_type,
            severity=alert_data.severity,
            status="active",
            message=ValidationService.sanitize_string(alert_data.message),
            details=alert_data.details
        )
        
        db.add(alert)
        await db.commit()
        await db.refresh(alert)
        
        return AlertResponse(
            id=str(alert.id),
            device_id=str(alert.device_id),
            device_hostname=device.hostname,
            alert_type=alert.alert_type,
            severity=alert.severity,
            status=alert.status,
            message=alert.message,
            details=alert.details,
            acknowledged_by=alert.acknowledged_by,
            acknowledged_at=alert.acknowledged_at,
            resolved_at=alert.resolved_at,
            created_at=alert.created_at,
            updated_at=alert.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create alert"
        )

@router.get("", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    device_id: Optional[str] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    alert_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(require_alerts_read),
    db: AsyncSession = Depends(get_db)
):
    """
    List alerts with filtering and pagination
    """
    try:
        # Build query
        query = select(Alert).options(selectinload(Alert.device))
        
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
        if start_date:
            filters.append(Alert.created_at >= start_date)
        if end_date:
            filters.append(Alert.created_at <= end_date)
        
        if filters:
            query = query.where(and_(*filters))
        
        # Order by creation date (newest first)
        query = query.order_by(desc(Alert.created_at))
        
        # Get total count
        count_query = select(func.count()).select_from(Alert)
        if filters:
            count_query = count_query.where(and_(*filters))
        total = await db.scalar(count_query)
        
        # Get unacknowledged count
        unacknowledged_count = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.status == "active",
                Alert.acknowledged_by.is_(None)
            ))
        )
        
        # Get critical count
        critical_count = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.severity == "critical",
                Alert.status == "active"
            ))
        )
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        alerts = result.scalars().all()
        
        # Build response
        alert_responses = []
        for alert in alerts:
            alert_responses.append(AlertResponse(
                id=str(alert.id),
                device_id=str(alert.device_id),
                device_hostname=alert.device.hostname if alert.device else None,
                alert_type=alert.alert_type,
                severity=alert.severity,
                status=alert.status,
                message=alert.message,
                details=alert.details,
                acknowledged_by=alert.acknowledged_by,
                acknowledged_at=alert.acknowledged_at,
                resolved_at=alert.resolved_at,
                created_at=alert.created_at,
                updated_at=alert.updated_at
            ))
        
        return AlertListResponse(
            alerts=alert_responses,
            total=total,
            page=page,
            per_page=per_page,
            unacknowledged_count=unacknowledged_count,
            critical_count=critical_count
        )
        
    except Exception as e:
        logger.error(f"Error listing alerts: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list alerts"
        )

@router.get("/statistics", response_model=AlertStatistics)
async def get_alert_statistics(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    current_user: User = Depends(require_alerts_read),
    db: AsyncSession = Depends(get_db)
):
    """
    Get alert statistics and summary
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get counts by status
        total_alerts = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(Alert.created_at >= cutoff_time)
        )
        
        active_alerts = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.status == "active",
                Alert.created_at >= cutoff_time
            ))
        )
        
        acknowledged_alerts = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.status == "acknowledged",
                Alert.created_at >= cutoff_time
            ))
        )
        
        resolved_alerts = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.status == "resolved",
                Alert.created_at >= cutoff_time
            ))
        )
        
        # Get counts by severity
        severity_counts_result = await db.execute(
            select(
                Alert.severity,
                func.count().label("count")
            )
            .where(Alert.created_at >= cutoff_time)
            .group_by(Alert.severity)
        )
        alerts_by_severity = {
            row.severity: row.count
            for row in severity_counts_result
        }
        
        # Get counts by type
        type_counts_result = await db.execute(
            select(
                Alert.alert_type,
                func.count().label("count")
            )
            .where(Alert.created_at >= cutoff_time)
            .group_by(Alert.alert_type)
        )
        alerts_by_type = {
            row.alert_type: row.count
            for row in type_counts_result
        }
        
        # Get recent critical alerts
        recent_critical_result = await db.execute(
            select(Alert)
            .options(selectinload(Alert.device))
            .where(and_(
                Alert.severity == "critical",
                Alert.created_at >= cutoff_time
            ))
            .order_by(desc(Alert.created_at))
            .limit(10)
        )
        recent_critical = recent_critical_result.scalars().all()
        
        recent_critical_alerts = [
            AlertResponse(
                id=str(alert.id),
                device_id=str(alert.device_id),
                device_hostname=alert.device.hostname if alert.device else None,
                alert_type=alert.alert_type,
                severity=alert.severity,
                status=alert.status,
                message=alert.message,
                details=alert.details,
                acknowledged_by=alert.acknowledged_by,
                acknowledged_at=alert.acknowledged_at,
                resolved_at=alert.resolved_at,
                created_at=alert.created_at,
                updated_at=alert.updated_at
            )
            for alert in recent_critical
        ]
        
        return AlertStatistics(
            total_alerts=total_alerts,
            active_alerts=active_alerts,
            acknowledged_alerts=acknowledged_alerts,
            resolved_alerts=resolved_alerts,
            alerts_by_severity=alerts_by_severity,
            alerts_by_type=alerts_by_type,
            recent_critical_alerts=recent_critical_alerts
        )
        
    except Exception as e:
        logger.error(f"Error getting alert statistics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get alert statistics"
        )

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    current_user: User = Depends(require_alerts_read),
    db: AsyncSession = Depends(get_db)
):
    """
    Get alert details by ID
    """
    try:
        # Validate UUID
        try:
            uuid.UUID(alert_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid alert ID format"
            )
        
        # Get alert with device info
        result = await db.execute(
            select(Alert)
            .options(selectinload(Alert.device))
            .where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        return AlertResponse(
            id=str(alert.id),
            device_id=str(alert.device_id),
            device_hostname=alert.device.hostname if alert.device else None,
            alert_type=alert.alert_type,
            severity=alert.severity,
            status=alert.status,
            message=alert.message,
            details=alert.details,
            acknowledged_by=alert.acknowledged_by,
            acknowledged_at=alert.acknowledged_at,
            resolved_at=alert.resolved_at,
            created_at=alert.created_at,
            updated_at=alert.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get alert"
        )

@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: str,
    current_user: User = Depends(require_alerts_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Acknowledge an alert
    """
    try:
        # Get alert
        alert = await db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        # Update alert
        alert.status = "acknowledged"
        alert.acknowledged_by = current_user.username
        alert.acknowledged_at = datetime.utcnow()
        alert.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(alert)
        
        # Load device info
        await db.refresh(alert, ["device"])
        
        return AlertResponse(
            id=str(alert.id),
            device_id=str(alert.device_id),
            device_hostname=alert.device.hostname if alert.device else None,
            alert_type=alert.alert_type,
            severity=alert.severity,
            status=alert.status,
            message=alert.message,
            details=alert.details,
            acknowledged_by=alert.acknowledged_by,
            acknowledged_at=alert.acknowledged_at,
            resolved_at=alert.resolved_at,
            created_at=alert.created_at,
            updated_at=alert.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error acknowledging alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to acknowledge alert"
        )

@router.post("/{alert_id}/resolve", response_model=AlertResponse)
async def resolve_alert(
    alert_id: str,
    resolution_note: Optional[str] = None,
    current_user: User = Depends(require_alerts_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Resolve an alert
    """
    try:
        # Get alert
        alert = await db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        # Update alert
        alert.status = "resolved"
        alert.resolved_at = datetime.utcnow()
        alert.updated_at = datetime.utcnow()
        
        # Add resolution note to details if provided
        if resolution_note:
            if not alert.details:
                alert.details = {}
            alert.details["resolution_note"] = resolution_note
            alert.details["resolved_by"] = current_user.username
        
        await db.commit()
        await db.refresh(alert)
        
        # Load device info
        await db.refresh(alert, ["device"])
        
        return AlertResponse(
            id=str(alert.id),
            device_id=str(alert.device_id),
            device_hostname=alert.device.hostname if alert.device else None,
            alert_type=alert.alert_type,
            severity=alert.severity,
            status=alert.status,
            message=alert.message,
            details=alert.details,
            acknowledged_by=alert.acknowledged_by,
            acknowledged_at=alert.acknowledged_at,
            resolved_at=alert.resolved_at,
            created_at=alert.created_at,
            updated_at=alert.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resolving alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to resolve alert"
        )

@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: str,
    current_user: User = Depends(require_alerts_delete),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete an alert (admin only)
    """
    try:
        # Get alert
        alert = await db.get(Alert, alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found"
            )
        
        # Delete alert
        await db.delete(alert)
        await db.commit()
        
        return {"message": "Alert deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting alert: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete alert"
        )

from sqlalchemy.orm import selectinload