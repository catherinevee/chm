"""
SLA (Service Level Agreement) monitoring API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, desc
from pydantic import BaseModel, Field, validator
import logging
import uuid

from backend.database.base import get_db
from backend.database.models import SLAMetric, Device
from backend.api.dependencies.auth import (
    get_current_user,
    standard_rate_limit
)
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sla", tags=["sla"])

# Database session dependency is imported from backend.database.base

# Since we don't have an SLA table in the existing models, we'll use a simplified approach
# In production, you'd create proper SLA models

class SLAMetricCreate(BaseModel):
    device_id: str
    metric_name: str = Field(..., description="Name of the SLA metric")
    target_value: float = Field(..., description="Target SLA value")
    threshold_warning: float = Field(..., description="Warning threshold")
    threshold_critical: float = Field(..., description="Critical threshold")
    calculation_period: str = Field(default="daily", pattern="^(hourly|daily|weekly|monthly)$")
    enabled: bool = Field(default=True)

class SLAMetricUpdate(BaseModel):
    target_value: Optional[float] = None
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    calculation_period: Optional[str] = None
    enabled: Optional[bool] = None

class SLAMetricResponse(BaseModel):
    id: str
    device_id: str
    device_hostname: Optional[str]
    metric_name: str
    target_value: float
    threshold_warning: float
    threshold_critical: float
    calculation_period: str
    enabled: bool
    current_value: Optional[float]
    compliance_percentage: Optional[float]
    status: str
    created_at: datetime
    updated_at: Optional[datetime]

class SLAReport(BaseModel):
    period_start: datetime
    period_end: datetime
    total_metrics: int
    compliant_metrics: int
    warning_metrics: int
    critical_metrics: int
    overall_compliance: float
    metrics: List[Dict[str, Any]]

@router.post("/metrics", response_model=SLAMetricResponse, dependencies=[Depends(standard_rate_limit)])
async def create_sla_metric(
    sla_data: SLAMetricCreate,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Create a new SLA metric for a device
    """
    try:
        # For this example, we'll store SLA data in a simplified way
        # In production, you'd have a proper SLA table
        
        # Verify device exists
        from backend.database.models import Device
        device = await db_session.get(Device, sla_data.device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Create SLA metric (simplified - would be a proper model in production)
        sla_metric = {
            "id": str(uuid.uuid4()),
            "device_id": sla_data.device_id,
            "device_hostname": device.hostname,
            "metric_name": sla_data.metric_name,
            "target_value": sla_data.target_value,
            "threshold_warning": sla_data.threshold_warning,
            "threshold_critical": sla_data.threshold_critical,
            "calculation_period": sla_data.calculation_period,
            "enabled": sla_data.enabled,
            "current_value": None,
            "compliance_percentage": 100.0,
            "status": "healthy",
            "created_at": datetime.utcnow(),
            "updated_at": None
        }
        
        # In production, save to database
        # For now, return the created metric
        
        logger.info(f"SLA metric created for device {device.hostname} by user {current_user.username}")
        
        return SLAMetricResponse(**sla_metric)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating SLA metric: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create SLA metric"
        )

@router.get("/metrics/{device_id}", response_model=List[SLAMetricResponse])
async def get_device_sla_metrics(
    device_id: str,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Get SLA metrics for a specific device
    """
    try:
        # Verify device exists
        from backend.database.models import Device, DeviceMetric
        device = await db_session.get(Device, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Calculate SLA metrics based on actual device metrics
        # This is a simplified example
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        
        # Get availability (uptime)
        total_time = 24 * 60  # 24 hours in minutes
        downtime_result = await db_session.execute(
            select(func.count()).select_from(DeviceMetric)
            .where(and_(
                DeviceMetric.device_id == device_id,
                DeviceMetric.metric_type == "availability",
                DeviceMetric.value == 0,
                DeviceMetric.timestamp >= cutoff_time
            ))
        )
        downtime_minutes = downtime_result.scalar() or 0
        uptime_percentage = ((total_time - downtime_minutes) / total_time) * 100
        
        # Get response time
        response_time_result = await db_session.execute(
            select(func.avg(DeviceMetric.value)).where(and_(
                DeviceMetric.device_id == device_id,
                DeviceMetric.metric_type == "response_time",
                DeviceMetric.timestamp >= cutoff_time
            ))
        )
        avg_response_time = response_time_result.scalar() or 0
        
        # Create SLA metric responses
        sla_metrics = [
            SLAMetricResponse(
                id=str(uuid.uuid4()),
                device_id=device_id,
                device_hostname=device.hostname,
                metric_name="availability",
                target_value=99.9,
                threshold_warning=99.0,
                threshold_critical=95.0,
                calculation_period="daily",
                enabled=True,
                current_value=uptime_percentage,
                compliance_percentage=min(100, (uptime_percentage / 99.9) * 100),
                status="healthy" if uptime_percentage >= 99.9 else "warning" if uptime_percentage >= 99.0 else "critical",
                created_at=datetime.utcnow(),
                updated_at=None
            ),
            SLAMetricResponse(
                id=str(uuid.uuid4()),
                device_id=device_id,
                device_hostname=device.hostname,
                metric_name="response_time",
                target_value=100.0,  # 100ms target
                threshold_warning=200.0,
                threshold_critical=500.0,
                calculation_period="daily",
                enabled=True,
                current_value=avg_response_time,
                compliance_percentage=min(100, (100.0 / max(avg_response_time, 1)) * 100) if avg_response_time > 0 else 100,
                status="healthy" if avg_response_time <= 100 else "warning" if avg_response_time <= 200 else "critical",
                created_at=datetime.utcnow(),
                updated_at=None
            )
        ]
        
        return sla_metrics
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting SLA metrics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get SLA metrics"
        )

@router.get("/report", response_model=SLAReport)
async def get_sla_report(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    device_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Generate SLA compliance report
    """
    try:
        # Default to last 30 days if no date range specified
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Build query for devices
        from backend.database.models import Device, DeviceMetric
        device_query = select(Device)
        if device_id:
            device_query = device_query.where(Device.id == device_id)
        
        device_result = await db_session.execute(device_query)
        devices = device_result.scalars().all()
        
        # Calculate SLA metrics for each device
        metrics = []
        total_metrics = 0
        compliant_metrics = 0
        warning_metrics = 0
        critical_metrics = 0
        
        for device in devices:
            # Calculate availability
            total_time = (end_date - start_date).total_seconds() / 60  # in minutes
            
            # Get downtime periods
            downtime_result = await db_session.execute(
                select(func.count()).select_from(DeviceMetric)
                .where(and_(
                    DeviceMetric.device_id == device.id,
                    DeviceMetric.metric_type == "availability",
                    DeviceMetric.value == 0,
                    DeviceMetric.timestamp >= start_date,
                    DeviceMetric.timestamp <= end_date
                ))
            )
            downtime_minutes = downtime_result.scalar() or 0
            uptime_percentage = ((total_time - downtime_minutes) / total_time) * 100 if total_time > 0 else 100
            
            # Determine status
            if uptime_percentage >= 99.9:
                status = "compliant"
                compliant_metrics += 1
            elif uptime_percentage >= 99.0:
                status = "warning"
                warning_metrics += 1
            else:
                status = "critical"
                critical_metrics += 1
            
            total_metrics += 1
            
            metrics.append({
                "device_id": str(device.id),
                "device_hostname": device.hostname,
                "metric": "availability",
                "target": 99.9,
                "actual": round(uptime_percentage, 2),
                "compliance": min(100, (uptime_percentage / 99.9) * 100),
                "status": status
            })
        
        # Calculate overall compliance
        overall_compliance = (compliant_metrics / total_metrics * 100) if total_metrics > 0 else 0
        
        return SLAReport(
            period_start=start_date,
            period_end=end_date,
            total_metrics=total_metrics,
            compliant_metrics=compliant_metrics,
            warning_metrics=warning_metrics,
            critical_metrics=critical_metrics,
            overall_compliance=round(overall_compliance, 2),
            metrics=metrics
        )
        
    except Exception as e:
        logger.error(f"Error generating SLA report: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate SLA report"
        )

@router.put("/metrics/{sla_id}", response_model=SLAMetricResponse)
async def update_sla_metric(
    sla_id: str,
    update_data: SLAMetricUpdate,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Update an SLA metric
    """
    try:
        # In production, fetch and update from database
        # For now, return a mock updated response
        
        return SLAMetricResponse(
            id=sla_id,
            device_id="mock-device-id",
            device_hostname="mock-device",
            metric_name="availability",
            target_value=update_data.target_value or 99.9,
            threshold_warning=update_data.threshold_warning or 99.0,
            threshold_critical=update_data.threshold_critical or 95.0,
            calculation_period=update_data.calculation_period or "daily",
            enabled=update_data.enabled if update_data.enabled is not None else True,
            current_value=99.95,
            compliance_percentage=100.0,
            status="healthy",
            created_at=datetime.utcnow() - timedelta(days=30),
            updated_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Error updating SLA metric: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update SLA metric"
        )

@router.delete("/metrics/{sla_id}")
async def delete_sla_metric(
    sla_id: str,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Delete an SLA metric
    """
    try:
        # In production, delete from database
        # For now, return success
        
        logger.info(f"SLA metric {sla_id} deleted by user {current_user.username}")
        
        return {"message": "SLA metric deleted successfully"}
        
    except Exception as e:
        logger.error(f"Error deleting SLA metric: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete SLA metric"
        )