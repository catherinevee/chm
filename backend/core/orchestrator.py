"""
Main Application Orchestrator for CHM.

This module coordinates all services and provides:
- Service lifecycle management
- Dependency injection
- Health monitoring
- Graceful shutdown
- Service discovery
- Configuration management
- Error recovery
"""

import asyncio
import signal
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import psutil
import traceback

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from core.database import DatabaseManager
from backend.services.auth_service import auth_service
from backend.services.user_service import user_service
from backend.services.email_service import email_service
from backend.services.session_manager import session_manager
from backend.services.mfa_service import mfa_service
from backend.services.audit_service import audit_service
from backend.services.rbac_service import rbac_service
from backend.services.permission_service import permission_service
from backend.services.device_service import device_service
from backend.services.snmp_service import snmp_service
from backend.services.ssh_service import ssh_service
from backend.services.monitoring_engine import monitoring_engine
from backend.services.alerting_system import alerting_system
from backend.services.websocket_service import websocket_service
from backend.services.notification_dispatcher import notification_dispatcher
from backend.services.reporting_analytics import reporting_analytics




class ServiceStatus(str, Enum):
    """Service status states."""
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    DEGRADED = "degraded"


class ServicePriority(int, Enum):
    """Service startup priority (lower = higher priority)."""
    CRITICAL = 1  # Database, Cache
    CORE = 2      # Auth, Session
    ESSENTIAL = 3 # Device, Monitoring
    STANDARD = 4  # Alerting, Notification
    OPTIONAL = 5  # Reporting, Analytics


class ServiceInfo:
    """Service information and metadata."""
    
    def __init__(
        self,
        name: str,
        service: Any,
        priority: ServicePriority,
        dependencies: List[str] = None,
        health_check: Optional[Callable] = None,
        startup_method: Optional[str] = "start",
        shutdown_method: Optional[str] = "stop"
    ):
        self.name = name
        self.service = service
        self.priority = priority
        self.dependencies = dependencies or []
        self.health_check = health_check
        self.startup_method = startup_method
        self.shutdown_method = shutdown_method
        self.status = ServiceStatus.STOPPED
        self.start_time: Optional[datetime] = None
        self.error_count = 0
        self.last_error: Optional[str] = None
        self.health_status: Dict[str, Any] = {}


class ApplicationOrchestrator:
    """Main application orchestrator for CHM."""
    
    def __init__(self):
        """Initialize orchestrator."""
        self.services: Dict[str, ServiceInfo] = {}
        self.db_engine = None
        self.db_session_factory = None
        self.running = False
        self.shutdown_event = asyncio.Event()
        self._health_monitor_task: Optional[asyncio.Task] = None
        self._initialize_services()
    
    def _initialize_services(self):
        """Initialize service registry."""
        # Register all services with their metadata
        self.services = {
            # Critical Services
            "database": ServiceInfo(
                name="Database",
                service=None,  # Will be initialized separately
                priority=ServicePriority.CRITICAL,
                health_check=self._check_database_health
            ),
            
            # Core Services
            "auth": ServiceInfo(
                name="Authentication",
                service=auth_service,
                priority=ServicePriority.CORE,
                dependencies=["database"],
                health_check=lambda: {"status": "healthy"}
            ),
            "session": ServiceInfo(
                name="Session Manager",
                service=session_manager,
                priority=ServicePriority.CORE,
                dependencies=["database"],
                startup_method="initialize",
                health_check=self._check_session_health
            ),
            "user": ServiceInfo(
                name="User Service",
                service=user_service,
                priority=ServicePriority.CORE,
                dependencies=["database", "auth"]
            ),
            "rbac": ServiceInfo(
                name="RBAC Service",
                service=rbac_service,
                priority=ServicePriority.CORE,
                dependencies=["database", "auth"]
            ),
            "permission": ServiceInfo(
                name="Permission Service",
                service=permission_service,
                priority=ServicePriority.CORE,
                dependencies=["database", "rbac"]
            ),
            
            # Essential Services
            "device": ServiceInfo(
                name="Device Service",
                service=device_service,
                priority=ServicePriority.ESSENTIAL,
                dependencies=["database", "auth"]
            ),
            "snmp": ServiceInfo(
                name="SNMP Service",
                service=snmp_service,
                priority=ServicePriority.ESSENTIAL,
                dependencies=["device"],
                health_check=lambda: {"status": "healthy", "oid_cache_size": len(snmp_service.oid_cache)}
            ),
            "ssh": ServiceInfo(
                name="SSH Service",
                service=ssh_service,
                priority=ServicePriority.ESSENTIAL,
                dependencies=["device"],
                health_check=lambda: {"status": "healthy", "connections": len(ssh_service.connection_pool)}
            ),
            "monitoring": ServiceInfo(
                name="Monitoring Engine",
                service=monitoring_engine,
                priority=ServicePriority.ESSENTIAL,
                dependencies=["device", "snmp", "ssh"],
                health_check=self._check_monitoring_health
            ),
            
            # Standard Services
            "alerting": ServiceInfo(
                name="Alerting System",
                service=alerting_system,
                priority=ServicePriority.STANDARD,
                dependencies=["monitoring"],
                health_check=lambda: alerting_system.get_alert_statistics()
            ),
            "websocket": ServiceInfo(
                name="WebSocket Service",
                service=websocket_service,
                priority=ServicePriority.STANDARD,
                dependencies=["auth"],
                health_check=lambda: websocket_service.get_statistics()
            ),
            "notification": ServiceInfo(
                name="Notification Dispatcher",
                service=notification_dispatcher,
                priority=ServicePriority.STANDARD,
                dependencies=["alerting"],
                health_check=lambda: notification_dispatcher.get_statistics()
            ),
            
            # Optional Services
            "email": ServiceInfo(
                name="Email Service",
                service=email_service,
                priority=ServicePriority.OPTIONAL,
                dependencies=["notification"]
            ),
            "mfa": ServiceInfo(
                name="MFA Service",
                service=mfa_service,
                priority=ServicePriority.OPTIONAL,
                dependencies=["auth", "user"]
            ),
            "audit": ServiceInfo(
                name="Audit Service",
                service=audit_service,
                priority=ServicePriority.OPTIONAL,
                dependencies=["database"]
            ),
            "reporting": ServiceInfo(
                name="Reporting Analytics",
                service=reporting_analytics,
                priority=ServicePriority.OPTIONAL,
                dependencies=["monitoring", "database"],
                health_check=lambda: {"status": "healthy", "reports_cached": len(reporting_analytics.report_cache)}
            )
        }
    
    async def initialize(self):
        """Initialize the application."""
        logger.info("=" * 60)
        logger.info("CHM - Catalyst Health Monitor")
        logger.info("Initializing Application...")
        logger.info("=" * 60)
        
        try:
            # Initialize database
            await self._initialize_database()
            
            # Initialize services in priority order
            await self._initialize_services_by_priority()
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            # Start health monitoring
            self._health_monitor_task = asyncio.create_task(self._health_monitor_loop())
            
            self.running = True
            
            logger.info("=" * 60)
            logger.info("Application initialized successfully")
            logger.info(f"Total services: {len(self.services)}")
            logger.info(f"Services running: {self._count_running_services()}")
            logger.info("=" * 60)
            
        except Exception as e:
            logger.error(f"Failed to initialize application: {e}")
            logger.error(traceback.format_exc())
            await self.shutdown()
            raise
    
    async def start(self):
        """Start the application and all services."""
        if not self.running:
            await self.initialize()
        
        logger.info("Application started. Press Ctrl+C to shutdown.")
        
        try:
            # Wait for shutdown signal
            await self.shutdown_event.wait()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            await self.shutdown()
    
    async def shutdown(self):
        """Gracefully shutdown the application."""
        if not self.running:
            return
        
        logger.info("=" * 60)
        logger.info("Shutting down application...")
        logger.info("=" * 60)
        
        self.running = False
        
        # Cancel health monitor
        if self._health_monitor_task:
            self._health_monitor_task.cancel()
            try:
                await self._health_monitor_task
            except asyncio.CancelledError:
                pass
        
        # Shutdown services in reverse priority order
        await self._shutdown_services()
        
        # Close database connections
        if self.db_engine:
            await self.db_engine.dispose()
        
        logger.info("=" * 60)
        logger.info("Application shutdown complete")
        logger.info("=" * 60)
    
    async def restart_service(self, service_name: str) -> bool:
        """Restart a specific service."""
        if service_name not in self.services:
            logger.error(f"Service not found: {service_name}")
            return False
        
        service_info = self.services[service_name]
        
        # Stop service
        await self._stop_service(service_info)
        
        # Start service
        return await self._start_service(service_info)
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status."""
        return {
            "application": {
                "status": "running" if self.running else "stopped",
                "uptime": self._get_uptime(),
                "version": settings.VERSION
            },
            "services": {
                name: {
                    "status": info.status.value,
                    "uptime": (datetime.utcnow() - info.start_time).total_seconds() if info.start_time else 0,
                    "error_count": info.error_count,
                    "last_error": info.last_error,
                    "health": info.health_status
                }
                for name, info in self.services.items()
            },
            "system": {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "network_connections": len(psutil.net_connections()),
                "process_count": len(psutil.pids())
            },
            "database": {
                "connected": self.db_engine is not None,
                "pool_size": self.db_engine.pool.size() if self.db_engine else 0,
                "pool_checked_out": self.db_engine.pool.checked_out() if self.db_engine else 0
            }
        }
    
    # Private methods
    
    async def _initialize_database(self):
        """Initialize database connection."""
        logger.info("Initializing database...")
        
        try:
            # Create async engine
            self.db_engine = create_async_engine(
                settings.DATABASE_URL,
                echo=settings.DEBUG,
                pool_size=20,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            # Create session factory
            self.db_session_factory = sessionmaker(
                self.db_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Test connection
            async with self.db_session_factory() as session:
                result = await session.execute(text("SELECT 1"))
                result.scalar()
            
            self.services["database"].status = ServiceStatus.RUNNING
            self.services["database"].start_time = datetime.utcnow()
            
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            self.services["database"].status = ServiceStatus.ERROR
            self.services["database"].last_error = str(e)
            raise
    
    async def _initialize_services_by_priority(self):
        """Initialize services in priority order."""
        # Group services by priority
        priority_groups = {}
        for name, info in self.services.items():
            if name == "database":  # Skip database, already initialized
                continue
            
            priority = info.priority.value
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append((name, info))
        
        # Start services by priority
        for priority in sorted(priority_groups.keys()):
            services = priority_groups[priority]
            logger.info(f"Starting priority {priority} services...")
            
            # Start services in parallel within same priority
            tasks = []
            for name, info in services:
                if self._check_dependencies(info):
                    tasks.append(self._start_service(info))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, result in enumerate(results):
                    if isinstance(result, Exception):
                        service_name = services[i][0]
                        logger.error(f"Failed to start {service_name}: {result}")
    
    async def _start_service(self, service_info: ServiceInfo) -> bool:
        """Start a single service."""
        try:
            logger.info(f"Starting {service_info.name}...")
            service_info.status = ServiceStatus.STARTING
            
            # Check if service has start method
            if hasattr(service_info.service, service_info.startup_method):
                start_method = getattr(service_info.service, service_info.startup_method)
                
                # Check if method needs database session
                if service_info.name in ["monitoring", "alerting", "reporting"]:
                    async with self.db_session_factory() as session:
                        await start_method(session)
                else:
                    await start_method()
            
            service_info.status = ServiceStatus.RUNNING
            service_info.start_time = datetime.utcnow()
            service_info.error_count = 0
            
            logger.info(f"{service_info.name} started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start {service_info.name}: {e}")
            service_info.status = ServiceStatus.ERROR
            service_info.last_error = str(e)
            service_info.error_count += 1
            return False
    
    async def _stop_service(self, service_info: ServiceInfo):
        """Stop a single service."""
        try:
            if service_info.status != ServiceStatus.RUNNING:
                return
            
            logger.info(f"Stopping {service_info.name}...")
            service_info.status = ServiceStatus.STOPPING
            
            # Check if service has stop method
            if hasattr(service_info.service, service_info.shutdown_method):
                stop_method = getattr(service_info.service, service_info.shutdown_method)
                await stop_method()
            
            service_info.status = ServiceStatus.STOPPED
            service_info.start_time = None
            
            logger.info(f"{service_info.name} stopped")
            
        except Exception as e:
            logger.error(f"Error stopping {service_info.name}: {e}")
            service_info.last_error = str(e)
    
    async def _shutdown_services(self):
        """Shutdown all services in reverse priority order."""
        # Group services by priority
        priority_groups = {}
        for name, info in self.services.items():
            if name == "database":  # Database handled separately
                continue
            
            priority = info.priority.value
            if priority not in priority_groups:
                priority_groups[priority] = []
            priority_groups[priority].append(info)
        
        # Stop services in reverse priority order
        for priority in sorted(priority_groups.keys(), reverse=True):
            services = priority_groups[priority]
            logger.info(f"Stopping priority {priority} services...")
            
            # Stop services in parallel within same priority
            tasks = []
            for info in services:
                if info.status == ServiceStatus.RUNNING:
                    tasks.append(self._stop_service(info))
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
    
    def _check_dependencies(self, service_info: ServiceInfo) -> bool:
        """Check if service dependencies are met."""
        for dep in service_info.dependencies:
            if dep in self.services:
                dep_info = self.services[dep]
                if dep_info.status != ServiceStatus.RUNNING:
                    logger.warning(
                        f"Cannot start {service_info.name}: "
                        f"dependency {dep} is not running"
                    )
                    return False
        return True
    
    def _count_running_services(self) -> int:
        """Count running services."""
        return sum(
            1 for info in self.services.values()
            if info.status == ServiceStatus.RUNNING
        )
    
    def _get_uptime(self) -> float:
        """Get application uptime in seconds."""
        # Find earliest service start time
        start_times = [
            info.start_time for info in self.services.values()
            if info.start_time
        ]
        
        if start_times:
            earliest = min(start_times)
            return (datetime.utcnow() - earliest).total_seconds()
        
        return 0
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown."""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            self.shutdown_event.set()
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    async def _health_monitor_loop(self):
        """Monitor service health periodically."""
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                for name, info in self.services.items():
                    if info.status == ServiceStatus.RUNNING and info.health_check:
                        try:
                            info.health_status = await self._run_health_check(info)
                            
                            # Check if service is degraded
                            if info.health_status.get("status") == "degraded":
                                info.status = ServiceStatus.DEGRADED
                            elif info.health_status.get("status") == "error":
                                info.status = ServiceStatus.ERROR
                                info.error_count += 1
                        except Exception as e:
                            logger.error(f"Health check failed for {name}: {e}")
                            info.health_status = {"status": "error", "error": str(e)}
                
                # Auto-restart failed services if needed
                await self._handle_failed_services()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
    
    async def _run_health_check(self, service_info: ServiceInfo) -> Dict[str, Any]:
        """Run health check for a service."""
        if asyncio.iscoroutinefunction(service_info.health_check):
            return await service_info.health_check()
        else:
            return service_info.health_check()
    
    async def _handle_failed_services(self):
        """Handle failed services with auto-restart logic."""
        for name, info in self.services.items():
            if info.status == ServiceStatus.ERROR and info.error_count < 3:
                logger.warning(f"Attempting to restart {name} (attempt {info.error_count + 1})")
                await self.restart_service(name)
    
    async def _check_database_health(self) -> Dict[str, Any]:
        """Check database health."""
        try:
            async with self.db_session_factory() as session:
                result = await session.execute(text("SELECT 1"))
                result.scalar()
                
                # Get connection pool stats
                pool_size = self.db_engine.pool.size()
                pool_checked_out = self.db_engine.pool.checked_out()
                
                return {
                    "status": "healthy",
                    "pool_size": pool_size,
                    "pool_checked_out": pool_checked_out,
                    "pool_overflow": self.db_engine.pool.overflow()
                }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _check_session_health(self) -> Dict[str, Any]:
        """Check session manager health."""
        try:
            stats = await session_manager.get_statistics()
            return {
                "status": "healthy",
                "active_sessions": stats.get("active_sessions", 0),
                "redis_connected": session_manager.redis_client is not None
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _check_monitoring_health(self) -> Dict[str, Any]:
        """Check monitoring engine health."""
        try:
            status = await monitoring_engine.get_monitoring_status()
            return {
                "status": "healthy" if status["status"] == "running" else "degraded",
                **status
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Create singleton instance
orchestrator = ApplicationOrchestrator()


async def run_application():
    """Main entry point for running the application."""
    try:
        await orchestrator.start()
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Run the application
    asyncio.run(run_application())