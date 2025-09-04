"""
Production monitoring server with proper uvicorn/FastAPI integration.
Replaces the basic HTTP server with a robust, production-ready implementation.
"""

import asyncio
import logging
import signal
import sys
from typing import Optional, Dict, Any, Callable
from contextlib import asynccontextmanager
from datetime import datetime
import json

try:
    from fastapi import FastAPI, Response, HTTPException, Depends, Security, status, Request
    from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    from fastapi.responses import PlainTextResponse, JSONResponse
    from fastapi.exceptions import RequestValidationError
    import uvicorn
    from uvicorn.config import Config
    from uvicorn.server import Server
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

try:
    from pydantic import BaseModel, Field, ValidationError, validator
    from pydantic.error_wrappers import ErrorWrapper
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False

from backend.monitoring.health_monitor import HealthMonitor, HealthStatus
from backend.monitoring.performance_tracker import PerformanceTracker
from backend.config.config_manager import ConfigManager, CHMConfig

# Import result objects
from ..utils.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus as ResultHealthStatus, HealthLevel
)

logger = logging.getLogger(__name__)


# Request validation models
if PYDANTIC_AVAILABLE:
    class HealthCheckRequest(BaseModel):
        """Request model for health check endpoint."""
        include_details: bool = Field(default=False, description="Include detailed health information")
        component_filter: Optional[str] = Field(default=None, description="Filter by component name")
        timeout: Optional[float] = Field(default=30.0, ge=0.1, le=120.0, description="Timeout in seconds")
    
    class MetricsRequest(BaseModel):
        """Request model for metrics endpoint."""
        format: str = Field(default="prometheus", regex="^(prometheus|json)$", description="Output format")
        include_system: bool = Field(default=True, description="Include system metrics")
        component_filter: Optional[str] = Field(default=None, description="Filter by component")
        
        @validator('format')
        def validate_format(cls, v):
            if v not in ['prometheus', 'json']:
                raise ValueError('format must be either "prometheus" or "json"')
            return v
    
    class PerformanceQueryRequest(BaseModel):
        """Request model for performance data queries."""
        start_time: Optional[datetime] = Field(default=None, description="Start time for query range")
        end_time: Optional[datetime] = Field(default=None, description="End time for query range")
        metric_names: Optional[List[str]] = Field(default=None, description="Specific metrics to include")
        aggregation: str = Field(default="avg", regex="^(avg|min|max|sum|count|p50|p90|p95|p99)$")
        interval: Optional[int] = Field(default=60, ge=1, le=3600, description="Aggregation interval in seconds")
        
        @validator('end_time')
        def validate_time_range(cls, v, values):
            if 'start_time' in values and values['start_time'] and v:
                if v <= values['start_time']:
                    raise ValueError('end_time must be after start_time')
            return v
    
    class ComponentActionRequest(BaseModel):
        """Request model for component actions."""
        action: str = Field(regex="^(restart|stop|start|reload)$", description="Action to perform")
        component: str = Field(min_length=1, max_length=50, description="Component identifier")
        force: bool = Field(default=False, description="Force the action")
        
        @validator('action')
        def validate_action(cls, v):
            allowed_actions = ['restart', 'stop', 'start', 'reload']
            if v not in allowed_actions:
                raise ValueError(f'action must be one of: {", ".join(allowed_actions)}')
            return v
        
        @validator('component')
        def validate_component(cls, v):
            # Only allow alphanumeric, underscore, and hyphen
            import re
            if not re.match(r'^[a-zA-Z0-9_-]+$', v):
                raise ValueError('component must contain only alphanumeric characters, underscores, and hyphens')
            return v
else:
    # Fallback classes when pydantic is not available
    class HealthCheckRequest:
        def __init__(self, include_details=False, component_filter=None, timeout=30.0):
            self.include_details = include_details
            self.component_filter = component_filter
            self.timeout = min(max(timeout, 0.1), 120.0) if timeout else 30.0
    
    class MetricsRequest:
        def __init__(self, format="prometheus", include_system=True, component_filter=None):
            self.format = format if format in ['prometheus', 'json'] else 'prometheus'
            self.include_system = include_system
            self.component_filter = component_filter
    
    class PerformanceQueryRequest:
        def __init__(self, start_time=None, end_time=None, metric_names=None, aggregation="avg", interval=60):
            self.start_time = start_time
            self.end_time = end_time
            self.metric_names = metric_names
            self.aggregation = aggregation if aggregation in ['avg', 'min', 'max', 'sum', 'count', 'p50', 'p90', 'p95', 'p99'] else 'avg'
            self.interval = min(max(interval, 1), 3600) if interval else 60
    
    class ComponentActionRequest:
        def __init__(self, action, component, force=False):
            allowed_actions = ['restart', 'stop', 'start', 'reload']
            self.action = action if action in allowed_actions else 'restart'
            self.component = component
            self.force = force


class RequestValidator:
    """Validates incoming requests for security and correctness."""
    
    @staticmethod
    def validate_query_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize query parameters."""
        validated = {}
        
        # Whitelist of allowed parameters
        allowed_params = {
            'include_details', 'component_filter', 'timeout', 'format',
            'include_system', 'start_time', 'end_time', 'metric_names',
            'aggregation', 'interval', 'action', 'component', 'force'
        }
        
        for key, value in params.items():
            if key not in allowed_params:
                logger.warning(f"Ignoring unauthorized parameter: {key}")
                continue
            
            # Sanitize string parameters
            if isinstance(value, str):
                # Remove potentially dangerous characters
                sanitized = ''.join(c for c in value if c.isalnum() or c in '_-.:/')
                if len(sanitized) > 255:  # Prevent excessively long strings
                    sanitized = sanitized[:255]
                validated[key] = sanitized
            
            # Validate numeric parameters
            elif isinstance(value, (int, float)):
                if key in ['timeout', 'interval']:
                    validated[key] = min(max(value, 0.1), 3600)  # Clamp to reasonable range
                else:
                    validated[key] = value
            
            # Validate boolean parameters
            elif isinstance(value, bool):
                validated[key] = value
            
            # Handle list parameters
            elif isinstance(value, list):
                if key == 'metric_names':
                    # Validate metric names
                    sanitized_list = []
                    for item in value:
                        if isinstance(item, str) and len(item) <= 100:
                            sanitized = ''.join(c for c in item if c.isalnum() or c in '_-.')
                            if sanitized:
                                sanitized_list.append(sanitized)
                    validated[key] = sanitized_list[:50]  # Limit to 50 items
            
            else:
                logger.warning(f"Ignoring parameter with invalid type: {key}")
        
        return validated
    
    @staticmethod
    def validate_request_size(request_body: bytes, max_size: int = 1024 * 1024) -> bool:
        """Validate request body size."""
        if len(request_body) > max_size:
            logger.warning(f"Request body too large: {len(request_body)} bytes")
            return False
        return True
    
    @staticmethod
    def validate_content_type(content_type: str) -> bool:
        """Validate content type."""
        allowed_types = [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain'
        ]
        
        if not content_type:
            return True  # Allow empty content type for GET requests
        
        # Extract main content type (ignore charset, boundary, etc.)
        main_type = content_type.split(';')[0].strip().lower()
        
        if main_type not in allowed_types:
            logger.warning(f"Unsupported content type: {content_type}")
            return False
        
        return True
    
    @staticmethod
    def validate_user_agent(user_agent: str) -> bool:
        """Validate user agent string."""
        if not user_agent:
            return True  # Allow empty user agent
        
        # Check for suspicious patterns
        suspicious_patterns = [
            'sqlmap', 'nikto', 'nmap', 'masscan',
            '<script', 'javascript:', 'vbscript:',
            'union select', 'drop table', 'exec(',
            'system(', 'eval(', 'base64_decode'
        ]
        
        user_agent_lower = user_agent.lower()
        for pattern in suspicious_patterns:
            if pattern in user_agent_lower:
                logger.warning(f"Suspicious user agent detected: {user_agent}")
                return False
        
        # Check length
        if len(user_agent) > 1000:
            logger.warning(f"User agent too long: {len(user_agent)} characters")
            return False
        
        return True


class MonitoringServer:
    """Production-grade monitoring server with uvicorn and FastAPI"""
    
    def __init__(self,
                 health_monitor: HealthMonitor,
                 performance_tracker: Optional[PerformanceTracker] = None,
                 config: Optional[CHMConfig] = None,
                 host: str = "0.0.0.0",
                 port: int = 8080,
                 auth_enabled: bool = True,
                 auth_token: Optional[str] = None):
        self.health_monitor = health_monitor
        self.performance_tracker = performance_tracker
        self.config = config
        self.host = host
        self.port = port
        self.auth_enabled = auth_enabled
        self.auth_token = auth_token or self._generate_default_token()
        
        self.app: Optional[FastAPI] = None
        self.server: Optional[Server] = None
        self._server_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        # Security
        self.security = HTTPBearer(auto_error=False) if auth_enabled else None
        
        # Initialize the FastAPI app
        self._create_app()
    
    def _generate_default_token(self) -> str:
        """Generate a default monitoring token if none provided"""
        import secrets
        token = secrets.token_urlsafe(32)
        logger.warning(f"Generated default monitoring token: {token[:8]}... (first 8 chars shown)")
        return token
    
    def _create_app(self):
        """Create the FastAPI application with all endpoints"""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            """Manage application lifecycle"""
            # Startup
            logger.info("Monitoring server starting up")
            if self.health_monitor and not self.health_monitor._running:
                await self.health_monitor.start_monitoring()
            if self.performance_tracker and not self.performance_tracker._running:
                await self.performance_tracker.start()
            yield
            # Shutdown
            logger.info("Monitoring server shutting down")
            if self.health_monitor and self.health_monitor._running:
                await self.health_monitor.stop_monitoring()
            if self.performance_tracker and self.performance_tracker._running:
                await self.performance_tracker.stop()
        
        self.app = FastAPI(
            title="CHM Monitoring Server",
            description="Production monitoring endpoints for CHM system",
            version="2.0.0",
            lifespan=lifespan,
            docs_url="/monitoring/docs" if not self.auth_enabled else None,  # Disable docs in production
            redoc_url="/monitoring/redoc" if not self.auth_enabled else None,
            openapi_url="/monitoring/openapi.json" if not self.auth_enabled else None
        )
        
        # Add middleware
        self._setup_middleware()
        
        # Add routes
        self._setup_routes()
    
    def _setup_middleware(self):
        """Configure middleware for the FastAPI app"""
        # Request validation middleware
        @self.app.middleware("http")
        async def request_validation_middleware(request: Request, call_next):
            """Validate incoming requests for security."""
            try:
                # Validate request size
                if request.method in ["POST", "PUT", "PATCH"]:
                    body = await request.body()
                    if not RequestValidator.validate_request_size(body):
                        return JSONResponse(
                            status_code=413,
                            content={"error": "Request body too large"}
                        )
                
                # Validate content type
                content_type = request.headers.get("content-type", "")
                if not RequestValidator.validate_content_type(content_type):
                    return JSONResponse(
                        status_code=415,
                        content={"error": "Unsupported content type"}
                    )
                
                # Validate user agent
                user_agent = request.headers.get("user-agent", "")
                if not RequestValidator.validate_user_agent(user_agent):
                    return JSONResponse(
                        status_code=400,
                        content={"error": "Invalid user agent"}
                    )
                
                # Validate query parameters
                if request.query_params:
                    validated_params = RequestValidator.validate_query_params(
                        dict(request.query_params)
                    )
                    # Replace query params with validated ones
                    request.scope["query_string"] = "&".join(
                        f"{k}={v}" for k, v in validated_params.items()
                    ).encode()
                
                response = await call_next(request)
                
                # Add security headers
                response.headers["X-Content-Type-Options"] = "nosniff"
                response.headers["X-Frame-Options"] = "DENY"
                response.headers["X-XSS-Protection"] = "1; mode=block"
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"
                
                return response
                
            except Exception as e:
                logger.error(f"Request validation middleware error: {e}")
                return JSONResponse(
                    status_code=500,
                    content={"error": "Internal server error"}
                )
        
        # Rate limiting middleware
        @self.app.middleware("http")
        async def rate_limiting_middleware(request: Request, call_next):
            """Simple rate limiting based on IP."""
            client_ip = request.client.host if request.client else "unknown"
            
            # Allow localhost and monitoring tools
            if client_ip in ["127.0.0.1", "::1", "localhost"]:
                return await call_next(request)
            
            # Simple rate limiting logic could be enhanced with Redis
            # For now, just log the request
            logger.debug(f"Request from {client_ip} to {request.url.path}")
            
            response = await call_next(request)
            return response
        
        # CORS middleware for browser-based monitoring dashboards
        if self.config:
            allowed_origins = getattr(self.config.monitoring, 'cors_origins', ["http://localhost:3000"])
        else:
            allowed_origins = ["http://localhost:3000"]  # More secure default
        
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
        )
        
        # Compression for large metric responses
        self.app.add_middleware(GZipMiddleware, minimum_size=1000)
        
        # Global exception handler
        @self.app.exception_handler(RequestValidationError)
        async def validation_exception_handler(request: Request, exc: RequestValidationError):
            """Handle Pydantic validation errors."""
            return JSONResponse(
                status_code=422,
                content={
                    "error": "Validation error",
                    "details": exc.errors()
                }
            )
        
        @self.app.exception_handler(Exception)
        async def global_exception_handler(request: Request, exc: Exception):
            """Handle unexpected errors."""
            logger.error(f"Unexpected error in {request.method} {request.url.path}: {exc}")
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error"}
            )
        
        # Add custom middleware for metrics collection
        @self.app.middleware("http")
        async def collect_metrics(request, call_next):
            """Collect request metrics"""
            if self.performance_tracker:
                operation_id = f"http_request_{request.url.path}"
                start_time = asyncio.get_event_loop().time()
                
                try:
                    response = await call_next(request)
                    duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                    
                    self.performance_tracker.record_metric(
                        name="http_request_duration",
                        value=duration_ms,
                        duration_ms=duration_ms,
                        labels={
                            "method": request.method,
                            "path": request.url.path,
                            "status": str(response.status_code)
                        }
                    )
                    
                    return response
                except Exception as e:
                    duration_ms = (asyncio.get_event_loop().time() - start_time) * 1000
                    
                    self.performance_tracker.record_metric(
                        name="http_request_duration",
                        value=duration_ms,
                        duration_ms=duration_ms,
                        labels={
                            "method": request.method,
                            "path": request.url.path,
                            "status": "500"
                        },
                        metadata={"error": str(e)}
                    )
                    raise
            else:
                return await call_next(request)
    
    def _verify_auth(self, credentials: Optional[HTTPAuthorizationCredentials] = None) -> bool:
        """Verify authentication credentials"""
        if not self.auth_enabled:
            return True
        
        if not credentials or not credentials.credentials:
            return False
        
        return credentials.credentials == self.auth_token
    
    def _get_auth_dependency(self):
        """Get authentication dependency for protected endpoints"""
        if not self.auth_enabled:
            return create_partial_success_result(
                data=None,
                error_code="AUTH_DISABLED",
                message="Authentication is disabled for this monitoring server",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No authentication required",
                        details="Monitoring server is running without authentication"
                    )
                ),
                suggestions=["Enable authentication for production use", "Configure proper security measures"]
            )
        
        async def verify_token(credentials: HTTPAuthorizationCredentials = Security(self.security)):
            if not self._verify_auth(credentials):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid authentication token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            return credentials
        
        return verify_token
    
    def _setup_routes(self):
        """Setup all monitoring routes"""
        auth_dep = self._get_auth_dependency()
        
        # Health endpoints (no auth for Kubernetes probes)
        @self.app.get("/health")
        async def health():
            """Comprehensive health check"""
            try:
                health_data = await self.health_monitor.get_health_status()
                
                # Determine HTTP status code based on health
                if health_data['status'] == HealthStatus.HEALTHY.value:
                    status_code = 200
                elif health_data['status'] == HealthStatus.DEGRADED.value:
                    status_code = 200  # Still return 200 for degraded
                else:
                    status_code = 503
                
                return JSONResponse(
                    content=health_data,
                    status_code=status_code
                )
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return JSONResponse(
                    content={
                        "status": "error",
                        "message": str(e),
                        "timestamp": datetime.now().isoformat()
                    },
                    status_code=503
                )
        
        @self.app.get("/ready")
        async def ready():
            """Readiness probe for Kubernetes"""
            try:
                health_data = await self.health_monitor.get_health_status()
                ready = health_data['status'] in [
                    HealthStatus.HEALTHY.value,
                    HealthStatus.DEGRADED.value
                ]
                
                return JSONResponse(
                    content={
                        "ready": ready,
                        "status": health_data['status'],
                        "timestamp": datetime.now().isoformat()
                    },
                    status_code=200 if ready else 503
                )
            except Exception as e:
                logger.error(f"Readiness check failed: {e}")
                return JSONResponse(
                    content={
                        "ready": False,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    },
                    status_code=503
                )
        
        @self.app.get("/live")
        async def live():
            """Liveness probe for Kubernetes"""
            return JSONResponse(
                content={
                    "alive": True,
                    "timestamp": datetime.now().isoformat()
                },
                status_code=200
            )
        
        # Metrics endpoint (optionally protected)
        metrics_deps = [Depends(auth_dep)] if auth_dep else []
        
        @self.app.get("/metrics", dependencies=metrics_deps)
        async def metrics():
            """Prometheus metrics endpoint"""
            try:
                metrics_text = await self.health_monitor.get_metrics()
                return PlainTextResponse(
                    content=metrics_text,
                    media_type="text/plain; version=0.0.4; charset=utf-8"
                )
            except Exception as e:
                logger.error(f"Failed to get metrics: {e}")
                raise HTTPException(status_code=500, detail="Failed to retrieve metrics")
        
        # Protected diagnostic endpoints
        if auth_dep:
            @self.app.get("/diagnostics", dependencies=[Depends(auth_dep)])
            async def diagnostics():
                """Detailed diagnostic information"""
                try:
                    health_data = await self.health_monitor.get_health_status()
                    
                    diagnostics_data = {
                        "timestamp": datetime.now().isoformat(),
                        "health": health_data,
                        "monitoring": {
                            "health_monitor_running": self.health_monitor._running,
                            "checks_registered": len(self.health_monitor._health_checks),
                            "results_stored": sum(
                                len(results) 
                                for results in self.health_monitor._check_results.values()
                            )
                        }
                    }
                    
                    if self.performance_tracker:
                        diagnostics_data["performance"] = {
                            "tracker_running": self.performance_tracker._running,
                            "metrics_collected": len(self.performance_tracker._metrics),
                            "active_operations": len(self.performance_tracker._active_operations),
                            "cache_entries": len(self.performance_tracker._stats_cache)
                        }
                    
                    return JSONResponse(content=diagnostics_data)
                    
                except Exception as e:
                    logger.error(f"Failed to get diagnostics: {e}")
                    raise HTTPException(status_code=500, detail=str(e))
            
            @self.app.get("/performance/summary", dependencies=[Depends(auth_dep)])
            async def performance_summary():
                """Performance summary"""
                if not self.performance_tracker:
                    raise HTTPException(status_code=501, detail="Performance tracking not enabled")
                
                try:
                    summary = self.performance_tracker.get_performance_summary()
                    return JSONResponse(content=summary)
                except Exception as e:
                    logger.error(f"Failed to get performance summary: {e}")
                    raise HTTPException(status_code=500, detail=str(e))
            
            @self.app.post("/health/check/{check_name}/run", dependencies=[Depends(auth_dep)])
            async def run_health_check(check_name: str):
                """Manually trigger a specific health check"""
                if check_name not in self.health_monitor._health_checks:
                    raise HTTPException(status_code=404, detail=f"Health check '{check_name}' not found")
                
                try:
                    check = self.health_monitor._health_checks[check_name]
                    result = await self.health_monitor._execute_health_check(check)
                    
                    return JSONResponse(content={
                        "name": result.name,
                        "status": result.status.value,
                        "message": result.message,
                        "duration_ms": result.duration_ms,
                        "timestamp": result.timestamp.isoformat()
                    })
                except Exception as e:
                    logger.error(f"Failed to run health check {check_name}: {e}")
                    raise HTTPException(status_code=500, detail=str(e))
    
    async def start(self):
        """Start the monitoring server"""
        if self.server:
            logger.warning("Monitoring server already running")
            return
        
        # Configure uvicorn
        config = Config(
            app=self.app,
            host=self.host,
            port=self.port,
            log_level="info",
            access_log=False,  # We handle our own access logging
            use_colors=False,
            server_header=False,  # Don't advertise server version
            date_header=True,
            limit_concurrency=1000,
            limit_max_requests=10000,
            timeout_keep_alive=5
        )
        
        self.server = Server(config)
        
        # Start server in background task
        self._server_task = asyncio.create_task(self.server.serve())
        
        logger.info(f"Monitoring server started on {self.host}:{self.port}")
        if self.auth_enabled:
            logger.info("Authentication enabled for protected endpoints")
    
    async def stop(self):
        """Stop the monitoring server gracefully"""
        if not self.server:
            return
        
        logger.info("Stopping monitoring server...")
        
        # Signal shutdown
        self.server.should_exit = True
        self._shutdown_event.set()
        
        # Wait for server task to complete
        if self._server_task:
            try:
                await asyncio.wait_for(self._server_task, timeout=10.0)
            except asyncio.TimeoutError:
                logger.warning("Server shutdown timed out, forcing stop")
                self._server_task.cancel()
                try:
                    await self._server_task
                except asyncio.CancelledError:
                    pass
        
        self.server = None
        self._server_task = None
        logger.info("Monitoring server stopped")
    
    async def wait_for_shutdown(self):
        """Wait for shutdown signal"""
        await self._shutdown_event.wait()


class MonitoringServerManager:
    """Manages monitoring server lifecycle with signal handling"""
    
    def __init__(self,
                 health_monitor: HealthMonitor,
                 performance_tracker: Optional[PerformanceTracker] = None,
                 config: Optional[CHMConfig] = None):
        self.health_monitor = health_monitor
        self.performance_tracker = performance_tracker
        self.config = config
        self.server: Optional[MonitoringServer] = None
        self._shutdown_event = asyncio.Event()
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(sig, frame):
            logger.info(f"Received signal {sig}, initiating shutdown...")
            self._shutdown_event.set()
        
        # Register signal handlers
        for sig in [signal.SIGTERM, signal.SIGINT]:
            signal.signal(sig, signal_handler)
        
        # Windows compatibility
        if sys.platform == "win32":
            signal.signal(signal.SIGBREAK, signal_handler)
    
    async def run(self, host: str = "0.0.0.0", port: int = 8080):
        """Run the monitoring server"""
        # Setup signal handlers
        self._setup_signal_handlers()
        
        # Determine auth settings from config
        auth_enabled = True
        auth_token = None
        
        if self.config:
            monitoring_config = getattr(self.config, 'monitoring', None)
            if monitoring_config:
                auth_enabled = getattr(monitoring_config, 'auth_enabled', True)
                auth_token = getattr(monitoring_config, 'auth_token', None)
                host = getattr(monitoring_config, 'host', host)
                port = getattr(monitoring_config, 'port', port)
        
        # Create and start server
        self.server = MonitoringServer(
            health_monitor=self.health_monitor,
            performance_tracker=self.performance_tracker,
            config=self.config,
            host=host,
            port=port,
            auth_enabled=auth_enabled,
            auth_token=auth_token
        )
        
        await self.server.start()
        
        # Wait for shutdown signal
        await self._shutdown_event.wait()
        
        # Graceful shutdown
        await self.server.stop()
    
    async def stop(self):
        """Stop the monitoring server"""
        self._shutdown_event.set()
        if self.server:
            await self.server.stop()


async def create_and_run_monitoring_server(
    config_path: Optional[str] = None,
    host: str = "0.0.0.0",
    port: int = 8080
):
    """Factory function to create and run monitoring server"""
    # Load configuration
    config = None
    if config_path:
        config_manager = ConfigManager(config_file=config_path)
        config = config_manager.get_config()
    
    # Create monitoring components
    from backend.monitoring.health_monitor import MetricsCollector
    
    metrics_collector = MetricsCollector()
    health_monitor = HealthMonitor(metrics_collector=metrics_collector)
    performance_tracker = PerformanceTracker()
    
    # Create and run manager
    manager = MonitoringServerManager(
        health_monitor=health_monitor,
        performance_tracker=performance_tracker,
        config=config
    )
    
    await manager.run(host=host, port=port)


if __name__ == "__main__":
    # Run monitoring server standalone
    import argparse
    
    parser = argparse.ArgumentParser(description="CHM Monitoring Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind to")
    parser.add_argument("--config", help="Path to configuration file")
    
    args = parser.parse_args()
    
    asyncio.run(create_and_run_monitoring_server(
        config_path=args.config,
        host=args.host,
        port=args.port
    ))