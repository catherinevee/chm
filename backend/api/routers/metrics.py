"""
Metrics and performance monitoring API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, desc
from pydantic import BaseModel, Field
import logging

from backend.database.models import Device, DeviceMetric
from backend.database.base import get_db
from backend.services.validation_service import ValidationService, ValidationError
from backend.api.dependencies.auth import (
    get_current_user,
    require_metrics_read,
    require_metrics_write,
    standard_rate_limit
)
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/metrics", tags=["metrics"])

class MetricData(BaseModel):
    metric_type: str
    value: float
    unit: Optional[str] = None
    timestamp: datetime

class MetricCreate(BaseModel):
    device_id: str
    metrics: List[MetricData]

class MetricResponse(BaseModel):
    id: str
    device_id: str
    metric_type: str
    value: float
    unit: Optional[str]
    timestamp: datetime
    created_at: datetime

class MetricSummary(BaseModel):
    metric_type: str
    current_value: float
    min_value: float
    max_value: float
    avg_value: float
    unit: Optional[str]
    last_updated: datetime

class DeviceMetricsSummary(BaseModel):
    device_id: str
    hostname: str
    metrics: List[MetricSummary]

class PerformanceSummary(BaseModel):
    total_devices: int
    active_devices: int
    devices_with_issues: int
    average_cpu: float
    average_memory: float
    average_response_time: float
    top_cpu_devices: List[Dict[str, Any]]
    top_memory_devices: List[Dict[str, Any]]

@router.post("/", response_model=List[MetricResponse], dependencies=[Depends(standard_rate_limit)])
async def create_metrics(
    metric_data: MetricCreate,
    current_user: User = Depends(require_metrics_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Create new metrics for a device
    """
    try:
        # Validate device exists
        device = await db.get(Device, metric_data.device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Create metrics
        created_metrics = []
        for metric in metric_data.metrics:
            # Validate metric name
            metric_type = ValidationService.validate_metric_name(metric.metric_type)
            
            new_metric = DeviceMetric(
                device_id=metric_data.device_id,
                metric_type=metric_type,
                value=metric.value,
                unit=metric.unit,
                timestamp=metric.timestamp
            )
            db.add(new_metric)
            created_metrics.append(new_metric)
        
        await db.commit()
        
        # Create response
        response = []
        for metric in created_metrics:
            await db.refresh(metric)
            response.append(MetricResponse(
                id=str(metric.id),
                device_id=str(metric.device_id),
                metric_type=metric.metric_type,
                value=metric.value,
                unit=metric.unit,
                timestamp=metric.timestamp,
                created_at=metric.created_at
            ))
        
        return response
        
    except HTTPException:
        raise
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error creating metrics: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create metrics"
        )

@router.get("/performance/summary", response_model=PerformanceSummary)
async def get_performance_summary(
    hours: int = Query(24, ge=1, le=168, description="Hours to look back"),
    current_user: User = Depends(require_metrics_read),
    db: AsyncSession = Depends(get_db)
):
    """
    Get overall performance summary across all devices
    """
    try:
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get device counts
        total_devices = await db.scalar(select(func.count()).select_from(Device))
        active_devices = await db.scalar(
            select(func.count()).select_from(Device)
            .where(Device.is_active == True)
        )
        
        # Get devices with issues (high CPU, memory, or down)
        devices_with_issues = await db.scalar(
            select(func.count()).select_from(Device)
            .where(
                or_(
                    Device.current_state == "down",
                    Device.current_state == "critical"
                )
            )
        )
        
        # Get average metrics
        cpu_avg = await db.scalar(
            select(func.avg(DeviceMetric.value))
            .where(and_(
                DeviceMetric.metric_type == "cpu_usage",
                DeviceMetric.timestamp >= cutoff_time
            ))
        ) or 0
        
        memory_avg = await db.scalar(
            select(func.avg(DeviceMetric.value))
            .where(and_(
                DeviceMetric.metric_type == "memory_usage",
                DeviceMetric.timestamp >= cutoff_time
            ))
        ) or 0
        
        response_avg = await db.scalar(
            select(func.avg(DeviceMetric.value))
            .where(and_(
                DeviceMetric.metric_type == "response_time",
                DeviceMetric.timestamp >= cutoff_time
            ))
        ) or 0
        
        # Get top CPU devices
        top_cpu_query = (
            select(
                Device.id,
                Device.hostname,
                func.avg(DeviceMetric.value).label("avg_cpu")
            )
            .join(DeviceMetric, Device.id == DeviceMetric.device_id)
            .where(and_(
                DeviceMetric.metric_type == "cpu_usage",
                DeviceMetric.timestamp >= cutoff_time
            ))
            .group_by(Device.id, Device.hostname)
            .order_by(desc("avg_cpu"))
            .limit(5)
        )
        top_cpu_result = await db.execute(top_cpu_query)
        top_cpu_devices = [
            {
                "device_id": str(row.id),
                "hostname": row.hostname,
                "avg_cpu": round(row.avg_cpu, 2)
            }
            for row in top_cpu_result
        ]
        
        # Get top memory devices
        top_memory_query = (
            select(
                Device.id,
                Device.hostname,
                func.avg(DeviceMetric.value).label("avg_memory")
            )
            .join(DeviceMetric, Device.id == DeviceMetric.device_id)
            .where(and_(
                DeviceMetric.metric_type == "memory_usage",
                DeviceMetric.timestamp >= cutoff_time
            ))
            .group_by(Device.id, Device.hostname)
            .order_by(desc("avg_memory"))
            .limit(5)
        )
        top_memory_result = await db.execute(top_memory_query)
        top_memory_devices = [
            {
                "device_id": str(row.id),
                "hostname": row.hostname,
                "avg_memory": round(row.avg_memory, 2)
            }
            for row in top_memory_result
        ]
        
        return PerformanceSummary(
            total_devices=total_devices,
            active_devices=active_devices,
            devices_with_issues=devices_with_issues,
            average_cpu=round(cpu_avg, 2),
            average_memory=round(memory_avg, 2),
            average_response_time=round(response_avg, 2),
            top_cpu_devices=top_cpu_devices,
            top_memory_devices=top_memory_devices
        )
        
    except Exception as e:
        logger.error(f"Error getting performance summary: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get performance summary"
        )

@router.get("/performance/{device_id}", response_model=DeviceMetricsSummary)
async def get_device_performance(
    device_id: str,
    hours: int = Query(24, ge=1, le=168),
    current_user: User = Depends(require_metrics_read),
    db: AsyncSession = Depends(get_db)
):
    """
    Get performance metrics for a specific device
    """
    try:
        # Get device
        device = await db.get(Device, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get metric summaries
        metric_types = ["cpu_usage", "memory_usage", "disk_usage", "network_in", "network_out", "response_time"]
        summaries = []
        
        for metric_type in metric_types:
            # Get statistics for each metric type
            stats = await db.execute(
                select(
                    func.max(DeviceMetric.value).label("max_val"),
                    func.min(DeviceMetric.value).label("min_val"),
                    func.avg(DeviceMetric.value).label("avg_val"),
                    func.max(DeviceMetric.timestamp).label("last_updated")
                )
                .where(and_(
                    DeviceMetric.device_id == device_id,
                    DeviceMetric.metric_type == metric_type,
                    DeviceMetric.timestamp >= cutoff_time
                ))
            )
            stat_row = stats.one()
            
            if stat_row.max_val is not None:
                # Get current value
                current_result = await db.execute(
                    select(DeviceMetric)
                    .where(and_(
                        DeviceMetric.device_id == device_id,
                        DeviceMetric.metric_type == metric_type
                    ))
                    .order_by(desc(DeviceMetric.timestamp))
                    .limit(1)
                )
                current_metric = current_result.scalar_one_or_none()
                
                if current_metric:
                    summaries.append(MetricSummary(
                        metric_type=metric_type,
                        current_value=current_metric.value,
                        min_value=stat_row.min_val,
                        max_value=stat_row.max_val,
                        avg_value=round(stat_row.avg_val, 2),
                        unit=current_metric.unit,
                        last_updated=stat_row.last_updated
                    ))
        
        return DeviceMetricsSummary(
            device_id=str(device.id),
            hostname=device.hostname,
            metrics=summaries
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device performance: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get device performance"
        )

@router.get("/performance/{device_id}/graph")
async def get_device_metrics_graph(
    device_id: str,
    metric_type: str = Query(..., description="Metric type to graph"),
    hours: int = Query(24, ge=1, le=168),
    interval: int = Query(60, ge=1, le=3600, description="Aggregation interval in minutes"),
    current_user: User = Depends(require_metrics_read),
    db: AsyncSession = Depends(get_db)
):
    """
    Get time-series data for graphing device metrics
    """
    try:
        # Validate device
        device = await db.get(Device, device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Validate metric type
        metric_type = ValidationService.validate_metric_name(metric_type)
        
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get metrics with time-based aggregation
        query = (
            select(
                DeviceMetric.timestamp,
                DeviceMetric.value,
                DeviceMetric.unit
            )
            .where(and_(
                DeviceMetric.device_id == device_id,
                DeviceMetric.metric_type == metric_type,
                DeviceMetric.timestamp >= cutoff_time
            ))
            .order_by(DeviceMetric.timestamp)
        )
        
        result = await db.execute(query)
        metrics = result.all()
        
        # Aggregate data based on interval
        aggregated_data = []
        if metrics:
            current_bucket = None
            bucket_values = []
            
            for metric in metrics:
                # Calculate bucket based on interval
                bucket_time = metric.timestamp.replace(
                    minute=(metric.timestamp.minute // interval) * interval,
                    second=0,
                    microsecond=0
                )
                
                if current_bucket != bucket_time:
                    if bucket_values:
                        # Add aggregated point
                        aggregated_data.append({
                            "timestamp": current_bucket.isoformat(),
                            "value": sum(bucket_values) / len(bucket_values),
                            "min": min(bucket_values),
                            "max": max(bucket_values),
                            "count": len(bucket_values)
                        })
                    
                    current_bucket = bucket_time
                    bucket_values = [metric.value]
                else:
                    bucket_values.append(metric.value)
            
            # Add last bucket
            if bucket_values:
                aggregated_data.append({
                    "timestamp": current_bucket.isoformat(),
                    "value": sum(bucket_values) / len(bucket_values),
                    "min": min(bucket_values),
                    "max": max(bucket_values),
                    "count": len(bucket_values)
                })
        
        return {
            "device_id": str(device.id),
            "hostname": device.hostname,
            "metric_type": metric_type,
            "unit": metrics[0].unit if metrics else None,
            "data_points": aggregated_data,
            "start_time": cutoff_time.isoformat(),
            "end_time": datetime.utcnow().isoformat(),
            "interval_minutes": interval
        }
        
    except HTTPException:
        raise
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error getting metrics graph: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get metrics graph data"
        )

from sqlalchemy import or_