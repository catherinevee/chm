"""
CHM Metrics API
Metrics and monitoring data endpoints
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.metrics_service import MetricsService
from core.database import get_db
from backend.models.device import Device as DeviceModel
from backend.models.metric import CollectionMethod
from backend.models.metric import Metric as MetricModel
from backend.models.metric import MetricCategory, MetricQuality, MetricType

logger = logging.getLogger(__name__)

router = APIRouter()

# Pydantic models
class MetricData(BaseModel):
    device_id: int
    name: str
    value: float
    unit: Optional[str] = None
    metric_type: str = "gauge"
    category: str = "system"
    labels: Optional[dict] = None
    timestamp: Optional[str] = None

class MetricResponse(BaseModel):
    id: int
    name: str
    value: float
    unit: Optional[str]
    metric_type: str
    category: str
    device_id: int
    timestamp: str
    quality_score: Optional[float]

class PerformanceSummary(BaseModel):
    device_id: int
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_throughput: float
    timestamp: str

# Metrics endpoints
@router.post("/", response_model=List[MetricResponse])
async def create_metrics(metrics: List[MetricData], db: AsyncSession = Depends(get_db)):
    """Create metrics data"""
    logger.info(f"Metrics creation request: {len(metrics)} metrics")
    
    try:
        created_metrics = []
        
        for metric_data in metrics:
            # Validate device exists
            device_query = select(DeviceModel).where(DeviceModel.id == metric_data.device_id)
            device_result = await db.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Device with ID {metric_data.device_id} not found"
                )
            
            # Parse timestamp
            timestamp = datetime.now()
            if metric_data.timestamp:
                try:
                    timestamp = datetime.fromisoformat(metric_data.timestamp.replace('Z', '+00:00'))
                except ValueError:
                    logger.warning(f"Invalid timestamp format: {metric_data.timestamp}, using current time")
            
            # Create metric
            metric = MetricModel(
                device_id=metric_data.device_id,
                name=metric_data.name,
                value=metric_data.value,
                unit=metric_data.unit,
                metric_type=MetricType(metric_data.metric_type),
                category=MetricCategory(metric_data.category),
                labels=metric_data.labels,
                timestamp=timestamp,
                collection_method=CollectionMethod.SNMP,  # Default for now
                quality_score=1.0,  # Default quality
                quality_level=MetricQuality.EXCELLENT
            )
            
            db.add(metric)
            created_metrics.append(metric)
        
        await db.commit()
        
        # Refresh to get IDs
        for metric in created_metrics:
            await db.refresh(metric)
        
        logger.info(f"Successfully stored {len(created_metrics)} metrics")
        
        # Convert to response format
        response_metrics = []
        for metric in created_metrics:
            response_metrics.append(MetricResponse(
                id=metric.id,
                name=metric.name,
                value=metric.value,
                unit=metric.unit,
                metric_type=metric.metric_type.value,
                category=metric.category.value,
                device_id=metric.device_id,
                timestamp=metric.timestamp.isoformat(),
                quality_score=metric.quality_score
            ))
        
        return response_metrics
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create metrics: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create metrics")

@router.get("/performance/summary")
async def get_performance_summary(db: AsyncSession = Depends(get_db)):
    """Get overall performance summary"""
    logger.info("Performance summary request")
    
    try:
        # Get total device count
        device_count_query = select(func.count(DeviceModel.id))
        device_count_result = await db.execute(device_count_query)
        total_devices = device_count_result.scalar()
        
        # Get recent metrics count (last 24 hours)
        recent_time = datetime.now() - timedelta(hours=24)
        recent_metrics_query = select(func.count(MetricModel.id)).where(
            MetricModel.timestamp >= recent_time
        )
        recent_metrics_result = await db.execute(recent_metrics_query)
        recent_metrics_count = recent_metrics_result.scalar()
        
        # Get average quality score from recent metrics
        avg_quality_query = select(func.avg(MetricModel.quality_score)).where(
            MetricModel.timestamp >= recent_time,
            MetricModel.quality_score.isnot(None)
        )
        avg_quality_result = await db.execute(avg_quality_query)
        avg_quality = avg_quality_result.scalar() or 0.0
        
        # Calculate overall health score
        overall_health = min(1.0, avg_quality)
        
        # Get metrics by category
        category_stats_query = select(
            MetricModel.category,
            func.count(MetricModel.id).label('count'),
            func.avg(MetricModel.quality_score).label('avg_quality')
        ).where(
            MetricModel.timestamp >= recent_time
        ).group_by(MetricModel.category)
        
        category_stats_result = await db.execute(category_stats_query)
        category_stats = category_stats_result.fetchall()
        
        return {
            "overall_health": round(overall_health, 2),
            "devices_monitored": total_devices,
            "recent_metrics_count": recent_metrics_count,
            "average_quality_score": round(avg_quality, 2),
            "category_stats": [
                {
                    "category": stat.category.value,
                    "count": stat.count,
                    "avg_quality": round(stat.avg_quality or 0.0, 2)
                }
                for stat in category_stats
            ],
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to get performance summary: {e}")
        raise HTTPException(status_code=500, detail="Failed to get performance summary")

@router.get("/performance/{device_id}")
async def get_device_performance(device_id: int, db: AsyncSession = Depends(get_db)):
    """Get device performance metrics"""
    logger.info(f"Device performance request: {device_id}")
    
    try:
        # Validate device exists
        device_query = select(DeviceModel).where(DeviceModel.id == device_id)
        device_result = await db.execute(device_query)
        device = device_result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get recent metrics for this device (last 24 hours)
        recent_time = datetime.now() - timedelta(hours=24)
        metrics_query = select(MetricModel).where(
            and_(
                MetricModel.device_id == device_id,
                MetricModel.timestamp >= recent_time
            )
        ).order_by(desc(MetricModel.timestamp))
        
        metrics_result = await db.execute(metrics_query)
        metrics = metrics_result.scalars().all()
        
        if not metrics:
            return {
                "device_id": device_id,
                "device_name": device.name,
                "performance_score": 0.0,
                "metrics_count": 0,
                "last_updated": None,
                "status": "no_data"
            }
        
        # Calculate performance metrics
        total_metrics = len(metrics)
        avg_quality = sum(m.quality_score or 0.0 for m in metrics) / total_metrics
        performance_score = min(1.0, avg_quality)
        
        # Get latest metrics by category
        latest_metrics = {}
        for metric in metrics:
            if metric.category.value not in latest_metrics:
                latest_metrics[metric.category.value] = metric
        
        # Calculate specific performance indicators
        cpu_usage = 0.0
        memory_usage = 0.0
        disk_usage = 0.0
        network_throughput = 0.0
        
        for category, metric in latest_metrics.items():
            if "cpu" in metric.name.lower():
                cpu_usage = metric.value
            elif "memory" in metric.name.lower() or "ram" in metric.name.lower():
                memory_usage = metric.value
            elif "disk" in metric.name.lower() or "storage" in metric.name.lower():
                disk_usage = metric.value
            elif "network" in metric.name.lower() or "throughput" in metric.name.lower():
                network_throughput = metric.value
        
        # Determine status
        if performance_score >= 0.8:
            status = "excellent"
        elif performance_score >= 0.6:
            status = "good"
        elif performance_score >= 0.4:
            status = "fair"
        else:
            status = "poor"
        
        return {
            "device_id": device_id,
            "device_name": device.name,
            "performance_score": round(performance_score, 2),
            "metrics_count": total_metrics,
            "average_quality": round(avg_quality, 2),
            "last_updated": metrics[0].timestamp.isoformat(),
            "status": status,
            "cpu_usage": cpu_usage,
            "memory_usage": memory_usage,
            "disk_usage": disk_usage,
            "network_throughput": network_throughput,
            "categories_monitored": list(latest_metrics.keys())
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device performance for {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get device performance")

@router.get("/performance/{device_id}/graph")
async def get_device_performance_graph(
    device_id: int,
    metric_type: str = "cpu",
    time_range: str = "24h",
    db: AsyncSession = Depends(get_db)
):
    """Get time-series graph data for device"""
    logger.info(f"Device graph request: {device_id}, {metric_type}")
    
    try:
        # Validate device exists
        device_query = select(DeviceModel).where(DeviceModel.id == device_id)
        device_result = await db.execute(device_query)
        device = device_result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Parse time range
        if time_range == "1h":
            time_delta = timedelta(hours=1)
        elif time_range == "6h":
            time_delta = timedelta(hours=6)
        elif time_range == "24h":
            time_delta = timedelta(hours=24)
        elif time_range == "7d":
            time_delta = timedelta(days=7)
        elif time_range == "30d":
            time_delta = timedelta(days=30)
        else:
            time_delta = timedelta(hours=24)  # Default
        
        start_time = datetime.now() - time_delta
        
        # Query metrics for the specified time range and metric type
        metrics_query = select(MetricModel).where(
            and_(
                MetricModel.device_id == device_id,
                MetricModel.timestamp >= start_time,
                MetricModel.name.ilike(f"%{metric_type}%")
            )
        ).order_by(MetricModel.timestamp)
        
        metrics_result = await db.execute(metrics_query)
        metrics = metrics_result.scalars().all()
        
        # Format data for graphing
        graph_data = []
        for metric in metrics:
            graph_data.append({
                "timestamp": metric.timestamp.isoformat(),
                "value": metric.value,
                "unit": metric.unit,
                "quality_score": metric.quality_score,
                "name": metric.name
            })
        
        # Calculate statistics
        if graph_data:
            values = [point["value"] for point in graph_data]
            min_value = min(values)
            max_value = max(values)
            avg_value = sum(values) / len(values)
        else:
            min_value = max_value = avg_value = 0.0
        
        return {
            "device_id": device_id,
            "device_name": device.name,
            "metric_type": metric_type,
            "time_range": time_range,
            "data_points": len(graph_data),
            "data": graph_data,
            "statistics": {
                "min_value": round(min_value, 2),
                "max_value": round(max_value, 2),
                "avg_value": round(avg_value, 2)
            },
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device graph data for {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get device graph data")

@router.get("/realtime/{device_id}")
async def get_realtime_metrics(
    device_id: int,
    metric_name: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Get real-time metrics from buffer"""
    logger.info(f"Real-time metrics request: device={device_id}, metric={metric_name}")
    
    try:
        # Validate device exists
        device_query = select(DeviceModel).where(DeviceModel.id == device_id)
        device_result = await db.execute(device_query)
        device = device_result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get metrics from service
        metrics_service = MetricsService(db)
        device_metrics = await metrics_service.get_device_metrics(device_id, limit=100)
        
        if not device_metrics:
            return {
                "device_id": device_id,
                "device_name": device.name,
                "metrics": [],
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Filter by metric name if specified
        if metric_name:
            filtered_metrics = {}
            for key, series in device_metrics.items():
                if metric_name.lower() in series.name.lower():
                    filtered_metrics[key] = series
            device_metrics = filtered_metrics
        
        # Convert to response format
        metrics_data = []
        for series_key, series in device_metrics.items():
            # Get latest value
            if series.points:
                latest_point = series.points[-1]
                metrics_data.append({
                    "name": series.name,
                    "value": latest_point[1],
                    "timestamp": latest_point[0].isoformat(),
                    "type": series.metric_type.value if series.metric_type else "gauge",
                    "points_count": len(series.points),
                    "buffer_duration": (series.points[-1][0] - series.points[0][0]).total_seconds() if len(series.points) > 1 else 0
                })
        
        return {
            "device_id": device_id,
            "device_name": device.name,
            "metrics": metrics_data,
            "total_metrics": len(metrics_data),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get real-time metrics for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get real-time metrics")

@router.post("/aggregate/{device_id}")
async def aggregate_device_metrics(
    device_id: int,
    aggregation_type: str = "avg",
    window_minutes: int = 5,
    db: AsyncSession = Depends(get_db)
):
    """Aggregate metrics for a device"""
    logger.info(f"Aggregate metrics request: device={device_id}, type={aggregation_type}, window={window_minutes}")
    
    try:
        # Validate device
        device_query = select(DeviceModel).where(DeviceModel.id == device_id)
        device_result = await db.execute(device_query)
        device = device_result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Validate aggregation type
        valid_types = ['avg', 'min', 'max', 'sum', 'count']
        if aggregation_type.lower() not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid aggregation type: {aggregation_type}. Valid types: {', '.join(valid_types)}"
            )
        
        # Get metrics from service
        metrics_service = MetricsService(db)
        device_metrics = await metrics_service.get_device_metrics(device_id, limit=100)
        
        if not device_metrics:
            return {
                "device_id": device_id,
                "aggregation_type": aggregation_type,
                "window_minutes": window_minutes,
                "aggregated_metrics": [],
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Aggregate each metric series
        aggregated_data = []
        window = timedelta(minutes=window_minutes)
        
        for series_key, series in device_metrics.items():
            aggregated = series.aggregate(agg_type, window)
            
            if aggregated:
                aggregated_data.append({
                    "metric_name": series.name,
                    "aggregation_type": aggregation_type,
                    "window_minutes": window_minutes,
                    "data_points": [
                        {
                            "timestamp": point[0].isoformat(),
                            "value": point[1]
                        }
                        for point in aggregated
                    ]
                })
        
        return {
            "device_id": device_id,
            "device_name": device.name,
            "aggregation_type": aggregation_type,
            "window_minutes": window_minutes,
            "aggregated_metrics": aggregated_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to aggregate metrics for device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to aggregate metrics")

__all__ = ["router"]
