"""
CHM Monitoring API
Health checks and Prometheus metrics endpoints
"""

import logging
from datetime import datetime
from typing import Any, Dict

import psutil
from fastapi import APIRouter, Depends, Response
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.prometheus_metrics import prometheus_metrics
from backend.services.websocket_service import websocket_manager
from core.database import get_db
from backend.models.alert import Alert as AlertModel
from backend.models.alert import AlertSeverity, AlertStatus
from backend.models.device import Device as DeviceModel
from backend.models.device import DeviceStatus
from backend.models.metric import Metric as MetricModel

# Redis service not yet implemented
redis_cache = None
# Metrics collector not yet implemented
metrics_collector = None

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/health")
async def health_check():
    """Basic health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "service": "CHM API"
    }


@router.get("/health/detailed")
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Detailed health check with component status"""
    health_status = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "components": {}
    }
    
    # Check database
    try:
        result = await db.execute(select(func.count(DeviceModel.id)))
        device_count = result.scalar()
        health_status["components"]["database"] = {
            "status": "healthy",
            "devices": device_count
        }
    except Exception as e:
        health_status["components"]["database"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"
    
    # Check Redis
    try:
        redis_status = await redis_cache.check_connection()
        health_status["components"]["redis"] = {
            "status": "healthy" if redis_status else "unhealthy",
            "connected": redis_status
        }
    except Exception as e:
        health_status["components"]["redis"] = {
            "status": "unhealthy",
            "error": str(e)
        }
        health_status["status"] = "degraded"
    
    # Check WebSocket
    ws_stats = websocket_manager.get_connection_stats()
    health_status["components"]["websocket"] = {
        "status": "healthy",
        "connections": ws_stats.get("total_connections", 0)
    }
    
    # Check metrics collector
    collector_stats = metrics_collector.get_statistics()
    health_status["components"]["metrics_collector"] = {
        "status": "healthy",
        "buffer_size": collector_stats.get("buffer_size", 0),
        "metrics_collected": collector_stats.get("metrics_collected", 0)
    }
    
    # System resources
    health_status["components"]["system"] = {
        "status": "healthy",
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage('/').percent
    }
    
    return health_status


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics_endpoint(db: AsyncSession = Depends(get_db)):
    """Prometheus metrics endpoint"""
    try:
        # Update device counts
        device_status_query = select(
            DeviceModel.status,
            func.count(DeviceModel.id)
        ).group_by(DeviceModel.status)
        
        device_result = await db.execute(device_status_query)
        device_counts = device_result.fetchall()
        
        total_devices = 0
        online_devices = 0
        offline_devices = 0
        status_counts = {}
        
        for status, count in device_counts:
            total_devices += count
            status_counts[status.value if status else "unknown"] = count
            
            if status == DeviceStatus.ACTIVE:
                online_devices = count
            elif status == DeviceStatus.INACTIVE:
                offline_devices = count
        
        prometheus_metrics.update_device_counts(
            total=total_devices,
            online=online_devices,
            offline=offline_devices,
            by_status=status_counts
        )
        
        # Update alert counts
        alert_severity_query = select(
            AlertModel.severity,
            func.count(AlertModel.id)
        ).where(
            AlertModel.status == AlertStatus.ACTIVE
        ).group_by(AlertModel.severity)
        
        alert_result = await db.execute(alert_severity_query)
        alert_counts = alert_result.fetchall()
        
        severity_counts = {}
        for severity, count in alert_counts:
            severity_counts[severity.value if severity else "unknown"] = count
        
        prometheus_metrics.update_alert_counts(severity_counts)
        
        # Update system metrics
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        
        prometheus_metrics.update_system_metrics(
            cpu_percent=cpu_percent,
            memory_bytes=memory.used
        )
        
        # Update buffer size
        collector_stats = metrics_collector.get_statistics()
        prometheus_metrics.update_buffer_size(
            collector_stats.get("buffer_size", 0)
        )
        
        # Update WebSocket connections
        ws_stats = websocket_manager.get_connection_stats()
        prometheus_metrics.websocket_connections.set(
            ws_stats.get("total_connections", 0)
        )
        
        # Generate Prometheus metrics
        metrics_output = prometheus_metrics.get_metrics()
        
        return Response(
            content=metrics_output,
            media_type=CONTENT_TYPE_LATEST
        )
        
    except Exception as e:
        logger.error(f"Failed to generate Prometheus metrics: {e}")
        return Response(
            content=f"# Error generating metrics: {str(e)}\n",
            media_type="text/plain",
            status_code=500
        )


@router.get("/metrics/json")
async def metrics_json_endpoint(db: AsyncSession = Depends(get_db)):
    """Get metrics in JSON format"""
    try:
        metrics = {}
        
        # Device metrics
        device_result = await db.execute(
            select(func.count(DeviceModel.id))
        )
        metrics["devices_total"] = device_result.scalar()
        
        active_result = await db.execute(
            select(func.count(DeviceModel.id)).where(
                DeviceModel.status == DeviceStatus.ACTIVE
            )
        )
        metrics["devices_active"] = active_result.scalar()
        
        # Alert metrics
        alert_result = await db.execute(
            select(func.count(AlertModel.id)).where(
                AlertModel.status == AlertStatus.ACTIVE
            )
        )
        metrics["alerts_active"] = alert_result.scalar()
        
        # Metric data points
        metric_result = await db.execute(
            select(func.count(MetricModel.id))
        )
        metrics["metrics_total"] = metric_result.scalar()
        
        # System metrics
        metrics["system"] = {
            "cpu_percent": psutil.cpu_percent(interval=0.1),
            "memory_percent": psutil.virtual_memory().percent,
            "disk_percent": psutil.disk_usage('/').percent,
            "network_connections": len(psutil.net_connections())
        }
        
        # WebSocket metrics
        ws_stats = websocket_manager.get_connection_stats()
        metrics["websocket"] = ws_stats
        
        # Collector metrics
        collector_stats = metrics_collector.get_statistics()
        metrics["collector"] = collector_stats
        
        return JSONResponse(content=metrics)
        
    except Exception as e:
        logger.error(f"Failed to generate JSON metrics: {e}")
        return JSONResponse(
            content={"error": str(e)},
            status_code=500
        )


@router.get("/status")
async def system_status(db: AsyncSession = Depends(get_db)):
    """Get overall system status"""
    try:
        # Gather status information
        status = {
            "operational": True,
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "components": {},
            "statistics": {}
        }
        
        # Device statistics
        device_stats = await db.execute(
            select(
                func.count(DeviceModel.id).label("total"),
                func.sum(func.cast(DeviceModel.status == DeviceStatus.ACTIVE, int)).label("active")
            )
        )
        device_data = device_stats.one()
        
        status["statistics"]["devices"] = {
            "total": device_data.total or 0,
            "active": device_data.active or 0,
            "inactive": (device_data.total or 0) - (device_data.active or 0)
        }
        
        # Alert statistics
        alert_stats = await db.execute(
            select(
                func.count(AlertModel.id).label("total"),
                func.sum(func.cast(AlertModel.status == AlertStatus.ACTIVE, int)).label("active"),
                func.sum(func.cast(AlertModel.severity == AlertSeverity.CRITICAL, int)).label("critical")
            )
        )
        alert_data = alert_stats.one()
        
        status["statistics"]["alerts"] = {
            "total": alert_data.total or 0,
            "active": alert_data.active or 0,
            "critical": alert_data.critical or 0
        }
        
        # Component status
        status["components"] = {
            "api": "operational",
            "database": "operational",
            "polling": "operational",
            "metrics": "operational",
            "alerts": "operational",
            "websocket": "operational"
        }
        
        # Check for critical issues
        if alert_data.critical and alert_data.critical > 0:
            status["operational"] = False
            status["components"]["alerts"] = "degraded"
        
        return status
        
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return {
            "operational": False,
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e)
        }


@router.get("/readiness")
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Kubernetes readiness probe endpoint"""
    try:
        # Check database connectivity
        await db.execute(select(1))
        
        # Check critical services
        if not websocket_manager._running:
            return JSONResponse(
                content={"ready": False, "reason": "WebSocket manager not running"},
                status_code=503
            )
        
        return {"ready": True}
        
    except Exception as e:
        logger.error(f"Readiness check failed: {e}")
        return JSONResponse(
            content={"ready": False, "reason": str(e)},
            status_code=503
        )


@router.get("/liveness")
async def liveness_check():
    """Kubernetes liveness probe endpoint"""
    return {"alive": True}


__all__ = ["router"]