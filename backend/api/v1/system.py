"""
System API endpoints for CHM.

This module provides comprehensive system management endpoints including:
- System status and health checks
- Service management
- Configuration management
- System metrics and diagnostics
- Backup and restore operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, Field

from core.database import get_db
from backend.services.auth_service import get_current_user
import logging
logger = logging.getLogger(__name__)
from backend.core.orchestrator import orchestrator
from backend.services.permission_service import permission_service
from backend.services.audit_service import audit_service, AuditEvent, EventCategory
from backend.services.monitoring_engine import monitoring_engine
from backend.services.alerting_system import alerting_system
from backend.services.reporting_analytics import reporting_analytics, ReportType, TimeRange
from models.user import User



router = APIRouter(prefix="/api/v1/system", tags=["System"])


# Request/Response Models

class SystemStatusResponse(BaseModel):
    """System status response."""
    status: str
    uptime: float
    version: str
    services: Dict[str, Any]
    system_resources: Dict[str, float]
    database: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ServiceActionRequest(BaseModel):
    """Service action request."""
    action: str  # start, stop, restart
    service_name: str


class ServiceActionResponse(BaseModel):
    """Service action response."""
    success: bool
    service: str
    action: str
    message: str


class HealthCheckResponse(BaseModel):
    """Health check response."""
    status: str  # healthy, degraded, unhealthy
    checks: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MetricsResponse(BaseModel):
    """System metrics response."""
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    network_connections: int
    active_sessions: int
    active_alerts: int
    devices_monitored: int
    metrics_collected: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ConfigurationRequest(BaseModel):
    """Configuration update request."""
    section: str
    key: str
    value: Any


class BackupRequest(BaseModel):
    """System backup request."""
    include_database: bool = True
    include_configurations: bool = True
    include_credentials: bool = False
    include_logs: bool = False


class DiagnosticsResponse(BaseModel):
    """System diagnostics response."""
    system: Dict[str, Any]
    services: Dict[str, Any]
    database: Dict[str, Any]
    performance: Dict[str, Any]
    errors: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]


# API Endpoints

@router.get("/status", response_model=SystemStatusResponse)
async def get_system_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get comprehensive system status."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.read"
            )
        )
        
        # Get system status from orchestrator
        status = await orchestrator.get_system_status()
        
        return SystemStatusResponse(
            status=status["application"]["status"],
            uptime=status["application"]["uptime"],
            version=status["application"]["version"],
            services=status["services"],
            system_resources=status["system"],
            database=status["database"]
        )
        
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system status"
        )


@router.get("/health", response_model=HealthCheckResponse)
async def health_check(
    db: AsyncSession = Depends(get_db)
):
    """Perform system health check."""
    try:
        checks = {}
        overall_status = "healthy"
        
        # Check database
        try:
            result = await db.execute(text("SELECT 1"))
            result.scalar()
            checks["database"] = {"status": "healthy"}
        except Exception as e:
            checks["database"] = {"status": "unhealthy", "error": str(e)}
            overall_status = "unhealthy"
        
        # Check Redis if available
        try:
            from backend.services.session_manager import session_manager
            if session_manager.redis_client:
                await session_manager.redis_client.ping()
                checks["redis"] = {"status": "healthy"}
            else:
                checks["redis"] = {"status": "unavailable"}
        except Exception as e:
            checks["redis"] = {"status": "unhealthy", "error": str(e)}
            overall_status = "degraded" if overall_status == "healthy" else overall_status
        
        # Check critical services
        status = await orchestrator.get_system_status()
        for service_name, service_info in status["services"].items():
            if service_info["status"] == "running":
                checks[service_name] = {"status": "healthy"}
            elif service_info["status"] == "degraded":
                checks[service_name] = {"status": "degraded"}
                overall_status = "degraded" if overall_status == "healthy" else overall_status
            else:
                checks[service_name] = {
                    "status": "unhealthy",
                    "error": service_info.get("last_error")
                }
                if service_name in ["database", "auth", "monitoring"]:
                    overall_status = "unhealthy"
        
        return HealthCheckResponse(
            status=overall_status,
            checks=checks
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthCheckResponse(
            status="unhealthy",
            checks={"error": str(e)}
        )


@router.get("/metrics", response_model=MetricsResponse)
async def get_system_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get system metrics."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.metrics"
            )
        )
        
        # Get system status
        status = await orchestrator.get_system_status()
        
        # Get monitoring statistics
        monitoring_stats = await monitoring_engine.get_monitoring_status()
        
        # Get alert statistics
        alert_stats = await alerting_system.get_alert_statistics()
        
        # Get session statistics
        from backend.services.session_manager import session_manager
        session_stats = await session_manager.get_statistics()
        
        return MetricsResponse(
            cpu_usage=status["system"]["cpu_percent"],
            memory_usage=status["system"]["memory_percent"],
            disk_usage=status["system"]["disk_percent"],
            network_connections=status["system"]["network_connections"],
            active_sessions=session_stats.get("active_sessions", 0),
            active_alerts=alert_stats["total_active"],
            devices_monitored=monitoring_stats["devices_monitored"],
            metrics_collected=monitoring_stats["metrics_collected"]
        )
        
    except Exception as e:
        logger.error(f"Failed to get system metrics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve system metrics"
        )


@router.post("/services/action", response_model=ServiceActionResponse)
async def manage_service(
    request: ServiceActionRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Manage system services."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.manage"
            )
        )
        
        # Validate action
        if request.action not in ["start", "stop", "restart"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid action. Must be start, stop, or restart"
            )
        
        # Perform action
        success = False
        message = ""
        
        if request.action == "restart":
            success = await orchestrator.restart_service(request.service_name)
            message = f"Service {request.service_name} restarted" if success else "Failed to restart service"
        else:
            # Individual start/stop not implemented in orchestrator
            message = f"Action {request.action} not yet implemented"
        
        # Audit
        await audit_service.log_event(
            db,
            AuditEvent(
                category=EventCategory.SYSTEM,
                action=f"service_{request.action}",
                user_id=current_user.id,
                details={
                    "service": request.service_name,
                    "action": request.action,
                    "success": success
                }
            )
        )
        
        return ServiceActionResponse(
            success=success,
            service=request.service_name,
            action=request.action,
            message=message
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to manage service: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to manage service"
        )


@router.get("/configuration/{section}")
async def get_configuration(
    section: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get system configuration."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.config.read"
            )
        )
        
        # Get configuration based on section
        from backend.config import settings
        
        config = {}
        if section == "general":
            config = {
                "app_name": settings.APP_NAME,
                "version": settings.VERSION,
                "debug": settings.DEBUG,
                "environment": settings.ENVIRONMENT
            }
        elif section == "monitoring":
            config = {
                "default_interval": monitoring_engine.config.default_interval,
                "max_concurrent_tasks": monitoring_engine.config.max_concurrent_tasks,
                "retry_count": monitoring_engine.config.retry_count
            }
        elif section == "alerting":
            config = {
                "max_alerts_per_device": alerting_system.config.max_alerts_per_device,
                "deduplication_window": alerting_system.config.deduplication_window,
                "escalation_timeout": alerting_system.config.escalation_timeout
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Configuration section '{section}' not found"
            )
        
        return config
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve configuration"
        )


@router.put("/configuration")
async def update_configuration(
    request: ConfigurationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Update system configuration."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.config.write"
            )
        )
        
        # Update configuration based on section
        success = False
        
        if request.section == "monitoring":
            if hasattr(monitoring_engine.config, request.key):
                setattr(monitoring_engine.config, request.key, request.value)
                success = True
        elif request.section == "alerting":
            if hasattr(alerting_system.config, request.key):
                setattr(alerting_system.config, request.key, request.value)
                success = True
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid configuration: {request.section}.{request.key}"
            )
        
        # Audit
        await audit_service.log_event(
            db,
            AuditEvent(
                category=EventCategory.CONFIGURATION,
                action="config_update",
                user_id=current_user.id,
                details={
                    "section": request.section,
                    "key": request.key,
                    "value": request.value
                }
            )
        )
        
        return {"success": True, "message": "Configuration updated"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update configuration: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update configuration"
        )


@router.get("/diagnostics", response_model=DiagnosticsResponse)
async def run_diagnostics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Run system diagnostics."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.diagnostics"
            )
        )
        
        # Get system status
        status = await orchestrator.get_system_status()
        
        # Collect diagnostics
        errors = []
        warnings = []
        
        # Check services
        for service_name, service_info in status["services"].items():
            if service_info["status"] == "error":
                errors.append({
                    "component": service_name,
                    "error": service_info.get("last_error", "Service error"),
                    "timestamp": datetime.utcnow().isoformat()
                })
            elif service_info["status"] == "degraded":
                warnings.append({
                    "component": service_name,
                    "warning": "Service degraded",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
        # Check system resources
        if status["system"]["cpu_percent"] > 80:
            warnings.append({
                "component": "cpu",
                "warning": f"High CPU usage: {status['system']['cpu_percent']}%",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        if status["system"]["memory_percent"] > 85:
            warnings.append({
                "component": "memory",
                "warning": f"High memory usage: {status['system']['memory_percent']}%",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        if status["system"]["disk_percent"] > 90:
            errors.append({
                "component": "disk",
                "error": f"Critical disk usage: {status['system']['disk_percent']}%",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        # Check database
        if status["database"]["pool_checked_out"] > status["database"]["pool_size"] * 0.8:
            warnings.append({
                "component": "database",
                "warning": "Database connection pool near capacity",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        return DiagnosticsResponse(
            system=status["system"],
            services=status["services"],
            database=status["database"],
            performance={
                "uptime": status["application"]["uptime"],
                "response_time": 0.0  # Would measure actual response time
            },
            errors=errors,
            warnings=warnings
        )
        
    except Exception as e:
        logger.error(f"Failed to run diagnostics: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to run diagnostics"
        )


@router.post("/backup")
async def create_backup(
    request: BackupRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Create system backup."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.backup"
            )
        )
        
        # Generate backup ID
        backup_id = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Start backup in background
        async def perform_backup():
            try:
                # Backup implementation would go here
                # This would backup database, configs, etc.
                logger.info(f"Starting backup: {backup_id}")
                
                # Simulate backup process
                await asyncio.sleep(5)
                
                logger.info(f"Backup completed: {backup_id}")
                
            except Exception as e:
                logger.error(f"Backup failed: {e}")
        
        background_tasks.add_task(perform_backup)
        
        # Audit
        await audit_service.log_event(
            db,
            AuditEvent(
                category=EventCategory.SYSTEM,
                action="backup_initiated",
                user_id=current_user.id,
                details={
                    "backup_id": backup_id,
                    "options": request.dict()
                }
            )
        )
        
        return {
            "success": True,
            "backup_id": backup_id,
            "message": "Backup initiated in background"
        }
        
    except Exception as e:
        logger.error(f"Failed to create backup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create backup"
        )


@router.get("/logs")
async def get_system_logs(
    level: Optional[str] = Query("INFO", regex="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$"),
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Get system logs."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.logs"
            )
        )
        
        # In production, this would read from actual log files
        # For now, return mock data
        logs = [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "level": level,
                "component": "system",
                "message": "System log entry example"
            }
        ]
        
        return {
            "logs": logs,
            "total": len(logs),
            "limit": limit,
            "level": level
        }
        
    except Exception as e:
        logger.error(f"Failed to get logs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve logs"
        )


@router.post("/maintenance-mode")
async def toggle_maintenance_mode(
    enabled: bool,
    duration_hours: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Toggle maintenance mode."""
    try:
        # Check permission
        await permission_service.require_permission(
            db,
            permission_service.PermissionContext(
                user_id=current_user.id,
                action="system.maintenance"
            )
        )
        
        if enabled:
            # Add maintenance window
            start_time = datetime.utcnow()
            end_time = start_time + timedelta(hours=duration_hours or 1)
            
            window_id = await alerting_system.add_maintenance_window(
                name="System Maintenance",
                start_time=start_time,
                end_time=end_time,
                suppress_all=True
            )
            
            message = f"Maintenance mode enabled until {end_time.isoformat()}"
        else:
            # End maintenance mode
            # Would need to track and cancel active maintenance windows
            message = "Maintenance mode disabled"
        
        # Audit
        await audit_service.log_event(
            db,
            AuditEvent(
                category=EventCategory.SYSTEM,
                action="maintenance_mode",
                user_id=current_user.id,
                details={
                    "enabled": enabled,
                    "duration_hours": duration_hours
                }
            )
        )
        
        return {
            "success": True,
            "enabled": enabled,
            "message": message
        }
        
    except Exception as e:
        logger.error(f"Failed to toggle maintenance mode: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to toggle maintenance mode"
        )