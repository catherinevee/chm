"""
FastAPI application main entry point
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
import logging
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import configuration
from backend.config import settings

# Import database
from backend.database.base import init_db

# Import routers directly to avoid circular dependencies
from backend.api.routers.auth import router as auth_router
from backend.api.routers.devices import router as devices_router
from backend.api.routers.metrics import router as metrics_router
from backend.api.routers.alerts import router as alerts_router
from backend.api.routers.discovery import router as discovery_router
from backend.api.routers.notifications import router as notifications_router
from backend.api.routers.sla import router as sla_router
from backend.api.routers.topology import router as topology_router
from backend.api.routers.import_export import router as import_export_router
from backend.api.routers.health import router as health_router

# Setup logging first
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import middleware
from backend.common.middleware import RateLimitMiddleware
from backend.api.websocket_manager import ws_manager as websocket_manager
from backend.common.error_handler import setup_exception_handlers

# Import optional components that may not be fully implemented
try:
    from backend.tasks.background_tasks import task_scheduler, schedule_default_tasks
except ImportError as e:
    logger.warning(f"Background tasks not available: {e}")
    task_scheduler = None
    schedule_default_tasks = None

try:
    from backend.monitoring.connection_pool import ssh_pool, snmp_pool
except ImportError as e:
    logger.warning(f"Connection pools not available: {e}")
    ssh_pool = None
    snmp_pool = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown"""
    # Startup
    logger.info(f"Starting {settings.app_name}...")
    
    try:
        # Initialize database
        await init_db()
        logger.info("Database initialized successfully")
        
        # Start connection pools if available
        if ssh_pool and snmp_pool:
            await ssh_pool.start()
            await snmp_pool.start()
            logger.info("Connection pools started")
        else:
            logger.warning("Connection pools not available")
        
        # Start background task scheduler if available
        if task_scheduler and schedule_default_tasks:
            await task_scheduler.start()
            schedule_default_tasks()
            logger.info("Background tasks scheduler started")
        else:
            logger.warning("Background tasks not available")
        
        logger.info("Application started successfully")
        
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    
    try:
        # Cleanup WebSocket connections
        await websocket_manager.disconnect_all()
        
        # Stop background task scheduler if available
        if task_scheduler:
            await task_scheduler.stop()
        logger.info("Background tasks scheduler stopped")
        
        # Stop connection pools if available
        if ssh_pool and snmp_pool:
            await ssh_pool.stop()
            await snmp_pool.stop()
            logger.info("Connection pools stopped")
        
        logger.info("Application shutdown complete")
        
    except Exception as e:
        logger.error(f"Error during shutdown: {e}")

# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    description="Enterprise Network Monitoring and Management Platform",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add trusted host middleware for security
if settings.environment == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # Will be restricted in production
    )

# Add rate limiting middleware
app.add_middleware(RateLimitMiddleware)

# Setup exception handlers
setup_exception_handlers(app)

# Include API routers with prefixes
app.include_router(auth_router, prefix="/api/v1/auth", tags=["Authentication"])
app.include_router(devices_router, prefix="/api/v1/devices", tags=["Devices"])
app.include_router(metrics_router, prefix="/api/v1/metrics", tags=["Metrics"])
app.include_router(alerts_router, prefix="/api/v1/alerts", tags=["Alerts"])
app.include_router(discovery_router, prefix="/api/v1/discovery", tags=["Discovery"])
app.include_router(notifications_router, prefix="/api/v1/notifications", tags=["Notifications"])
app.include_router(sla_router, prefix="/api/v1/sla", tags=["SLA"])
app.include_router(topology_router, prefix="/api/v1/topology", tags=["Topology"])
app.include_router(import_export_router, prefix="/api/v1", tags=["Import/Export"])
app.include_router(health_router, prefix="/api/v1", tags=["Health"])

# WebSocket endpoint for real-time updates
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates"""
    await websocket_manager.connect(websocket)
    
    try:
        while True:
            # Wait for messages from client
            data = await websocket.receive_text()
            
            # Process message
            try:
                message = json.loads(data)
                
                if message.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif message.get("type") == "subscribe":
                    # Handle subscription to specific events
                    await websocket_manager.subscribe(
                        websocket,
                        message.get("events", [])
                    )
                else:
                    # Echo back for now
                    await websocket.send_text(data)
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
                
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        websocket_manager.disconnect(websocket)

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "name": settings.app_name,
        "version": "2.0.0",
        "status": "running",
        "environment": settings.environment,
        "api_docs": "/api/docs",
        "api_redoc": "/api/redoc"
    }

# API info endpoint
@app.get("/api")
async def api_info():
    """API information endpoint"""
    return {
        "name": f"{settings.app_name} API",
        "version": "v1",
        "endpoints": {
            "auth": "/api/v1/auth",
            "devices": "/api/v1/devices",
            "metrics": "/api/v1/metrics",
            "alerts": "/api/v1/alerts",
            "discovery": "/api/v1/discovery",
            "notifications": "/api/v1/notifications",
            "sla": "/api/v1/sla",
            "topology": "/api/v1/topology",
            "import": "/api/v1/import",
            "export": "/api/v1/export",
            "health": "/api/v1/health",
            "websocket": "/ws"
        },
        "documentation": {
            "swagger": "/api/docs",
            "redoc": "/api/redoc",
            "openapi": "/api/openapi.json"
        }
    }

# Import json for WebSocket message handling
import json

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "backend.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.debug,
        log_level="debug" if settings.debug else "info"
    )