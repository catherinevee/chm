"""
Health check and system monitoring API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status
from typing import Dict, Any, List
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, text
from pydantic import BaseModel
import platform
import logging
import os

# Try to import psutil
try:
    import psutil
except ImportError:
    psutil = None

from backend.database.models import Device, Alert, DeviceMetric, DiscoveryJob
from backend.database.base import get_db as get_database_session
from backend.api.dependencies.auth import get_optional_current_user
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["health"])

# Use the imported get_db function
get_db = get_database_session

class HealthStatus(BaseModel):
    status: str
    timestamp: datetime
    uptime_seconds: float
    version: str

class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    process_count: int
    thread_count: int

class DatabaseHealth(BaseModel):
    connected: bool
    pool_size: int
    active_connections: int
    response_time_ms: float

class ServiceHealth(BaseModel):
    service: str
    status: str
    healthy: bool
    details: Dict[str, Any]

class ComponentHealth(BaseModel):
    database: DatabaseHealth
    background_tasks: ServiceHealth
    websocket: ServiceHealth
    discovery: ServiceHealth
    system_metrics: SystemMetrics

class ApplicationHealth(BaseModel):
    status: str
    healthy: bool
    timestamp: datetime
    uptime_seconds: float
    version: str
    environment: str
    components: ComponentHealth
    statistics: Dict[str, Any]

# Track application start time
APP_START_TIME = datetime.utcnow()

@router.get("/health", response_model=HealthStatus)
async def health_check():
    """
    Basic health check endpoint
    """
    try:
        uptime = (datetime.utcnow() - APP_START_TIME).total_seconds()
        
        return HealthStatus(
            status="healthy",
            timestamp=datetime.utcnow(),
            uptime_seconds=uptime,
            version=os.getenv("APP_VERSION", "2.0.0")
        )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service unhealthy"
        )

@router.get("/health/detailed", response_model=ApplicationHealth)
async def detailed_health_check(
    current_user: User = Depends(get_optional_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Detailed health check with component status
    """
    try:
        uptime = (datetime.utcnow() - APP_START_TIME).total_seconds()
        
        # Check database health
        db_health = await check_database_health(db_session)
        
        # Check background tasks
        bg_health = await check_background_tasks_health()
        
        # Check WebSocket service
        ws_health = await check_websocket_health()
        
        # Check discovery service
        discovery_health = await check_discovery_health(db_session)
        
        # Get system metrics
        system_metrics = get_system_metrics()
        
        # Get application statistics
        statistics = await get_application_statistics(db_session)
        
        # Determine overall health
        all_healthy = (
            db_health.connected and
            bg_health.healthy and
            ws_health.healthy and
            discovery_health.healthy
        )
        
        return ApplicationHealth(
            status="healthy" if all_healthy else "degraded",
            healthy=all_healthy,
            timestamp=datetime.utcnow(),
            uptime_seconds=uptime,
            version=os.getenv("APP_VERSION", "2.0.0"),
            environment=os.getenv("ENVIRONMENT", "development"),
            components=ComponentHealth(
                database=db_health,
                background_tasks=bg_health,
                websocket=ws_health,
                discovery=discovery_health,
                system_metrics=system_metrics
            ),
            statistics=statistics
        )
        
    except Exception as e:
        logger.error(f"Detailed health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Failed to perform health check"
        )

async def check_database_health(db_session: AsyncSession) -> DatabaseHealth:
    """Check database connection and performance"""
    try:
        # Measure query response time
        start_time = datetime.utcnow()
        result = await db_session.execute(text("SELECT 1"))
        response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        # Get connection pool stats
        pool_stats = await db.get_connection_stats()
        
        return DatabaseHealth(
            connected=True,
            pool_size=pool_stats.get("pool_size", 0),
            active_connections=pool_stats.get("checked_out", 0),
            response_time_ms=response_time
        )
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        return DatabaseHealth(
            connected=False,
            pool_size=0,
            active_connections=0,
            response_time_ms=-1
        )

async def check_background_tasks_health() -> ServiceHealth:
    """Check background tasks service health"""
    try:
        from backend.services.background_tasks import background_service
        
        # Check if service is running
        is_running = background_service.is_running if hasattr(background_service, 'is_running') else False
        active_tasks = background_service.active_tasks_count() if hasattr(background_service, 'active_tasks_count') else 0
        
        return ServiceHealth(
            service="background_tasks",
            status="running" if is_running else "stopped",
            healthy=is_running,
            details={
                "active_tasks": active_tasks,
                "max_workers": os.getenv("BACKGROUND_WORKERS", 10)
            }
        )
    except Exception as e:
        logger.error(f"Background tasks health check failed: {str(e)}")
        return ServiceHealth(
            service="background_tasks",
            status="error",
            healthy=False,
            details={"error": str(e)}
        )

async def check_websocket_health() -> ServiceHealth:
    """Check WebSocket service health"""
    try:
        from backend.api.websocket_manager import ws_manager
        
        stats = ws_manager.get_statistics()
        
        return ServiceHealth(
            service="websocket",
            status="running",
            healthy=True,
            details={
                "active_connections": stats.get("active_connections", 0),
                "authenticated_users": stats.get("authenticated_users", 0),
                "event_subscriptions": stats.get("event_subscriptions", {})
            }
        )
    except Exception as e:
        logger.error(f"WebSocket health check failed: {str(e)}")
        return ServiceHealth(
            service="websocket",
            status="error",
            healthy=False,
            details={"error": str(e)}
        )

async def check_discovery_health(db_session: AsyncSession) -> ServiceHealth:
    """Check discovery service health"""
    try:
        # Check for recent discovery jobs
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        recent_jobs = await db_session.scalar(
            select(func.count()).select_from(DiscoveryJob)
            .where(DiscoveryJob.created_at >= cutoff_time)
        )
        
        # Check for running jobs
        running_jobs = await db_session.scalar(
            select(func.count()).select_from(DiscoveryJob)
            .where(DiscoveryJob.status == "running")
        )
        
        return ServiceHealth(
            service="discovery",
            status="running",
            healthy=True,
            details={
                "recent_jobs": recent_jobs,
                "running_jobs": running_jobs
            }
        )
    except Exception as e:
        logger.error(f"Discovery health check failed: {str(e)}")
        return ServiceHealth(
            service="discovery",
            status="error",
            healthy=False,
            details={"error": str(e)}
        )

def get_system_metrics() -> SystemMetrics:
    """Get system resource metrics"""
    try:
        if not psutil:
            # Return dummy metrics if psutil is not available
            return SystemMetrics(
                cpu_percent=0,
                memory_percent=0,
                memory_used_mb=0,
                memory_available_mb=0,
                disk_usage_percent=0,
                process_count=0,
                thread_count=0
            )
        
        # Get CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Get memory usage
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        memory_used_mb = memory.used / (1024 * 1024)
        memory_available_mb = memory.available / (1024 * 1024)
        
        # Get disk usage
        disk = psutil.disk_usage('/')
        disk_usage_percent = disk.percent
        
        # Get process info
        process = psutil.Process()
        thread_count = process.num_threads()
        
        # Get total process count
        process_count = len(psutil.pids())
        
        return SystemMetrics(
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            memory_used_mb=round(memory_used_mb, 2),
            memory_available_mb=round(memory_available_mb, 2),
            disk_usage_percent=disk_usage_percent,
            process_count=process_count,
            thread_count=thread_count
        )
    except Exception as e:
        logger.error(f"Failed to get system metrics: {str(e)}")
        return SystemMetrics(
            cpu_percent=0,
            memory_percent=0,
            memory_used_mb=0,
            memory_available_mb=0,
            disk_usage_percent=0,
            process_count=0,
            thread_count=0
        )

async def get_application_statistics(db_session: AsyncSession) -> Dict[str, Any]:
    """Get application usage statistics"""
    try:
        # Get device statistics
        total_devices = await db_session.scalar(
            select(func.count()).select_from(Device)
        )
        active_devices = await db_session.scalar(
            select(func.count()).select_from(Device)
            .where(Device.is_active == True)
        )
        
        # Get alert statistics
        active_alerts = await db_session.scalar(
            select(func.count()).select_from(Alert)
            .where(Alert.status == "active")
        )
        critical_alerts = await db_session.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.status == "active",
                Alert.severity == "critical"
            ))
        )
        
        # Get metrics statistics (last hour)
        cutoff_time = datetime.utcnow() - timedelta(hours=1)
        recent_metrics = await db_session.scalar(
            select(func.count()).select_from(DeviceMetric)
            .where(DeviceMetric.timestamp >= cutoff_time)
        )
        
        return {
            "devices": {
                "total": total_devices,
                "active": active_devices,
                "inactive": total_devices - active_devices
            },
            "alerts": {
                "active": active_alerts,
                "critical": critical_alerts
            },
            "metrics": {
                "recent_count": recent_metrics,
                "collection_rate": round(recent_metrics / 3600, 2) if recent_metrics else 0
            }
        }
    except Exception as e:
        logger.error(f"Failed to get application statistics: {str(e)}")
        return {}

@router.get("/health/ready")
async def readiness_check(db_session: AsyncSession = Depends(get_db)):
    """
    Kubernetes readiness probe endpoint
    """
    try:
        # Check if database is accessible
        await db_session.execute(text("SELECT 1"))
        
        return {"status": "ready", "timestamp": datetime.utcnow().isoformat()}
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not ready"
        )

@router.get("/health/live")
async def liveness_check():
    """
    Kubernetes liveness probe endpoint
    """
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}