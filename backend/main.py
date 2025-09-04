"""
CHM - Cloud Health Monitor
Main application entry point
"""
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import asyncio
from typing import AsyncGenerator

from api.routers import auth, devices, metrics, alerts, discovery, monitoring, reports, sla, maintenance
from database.connection import init_db, close_db
from services.background_tasks import start_background_tasks, stop_background_tasks
from services.websocket_manager import websocket_manager
from services.cache_service import cache_service
from services.connection_pool import connection_pool
from security.audit import audit_logger
from config import settings

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator:
    """Application lifespan manager"""
    try:
        # Initialize database
        await init_db()
        
        # Initialize cache
        await cache_service.initialize()
        
        # Initialize connection pool
        await connection_pool.initialize()
        
        # Start background tasks
        await start_background_tasks()
        
        # Initialize audit logger
        await audit_logger.initialize()
        
        print("CHM Application started successfully")
        
        yield
        
    finally:
        # Cleanup on shutdown
        await stop_background_tasks()
        await connection_pool.cleanup()
        await cache_service.cleanup()
        await close_db()
        await audit_logger.cleanup()
        print("CHM Application shutdown complete")

app = FastAPI(
    title="CHM - Cloud Health Monitor",
    description="Enterprise Network Monitoring and Management System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api/auth", tags=["Authentication"])
app.include_router(devices.router, prefix="/api/devices", tags=["Devices"])
app.include_router(metrics.router, prefix="/api/metrics", tags=["Metrics"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(discovery.router, prefix="/api/discovery", tags=["Discovery"])
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["Monitoring"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(sla.router, prefix="/api/sla", tags=["SLA"])
app.include_router(maintenance.router, prefix="/api/maintenance", tags=["Maintenance"])

# WebSocket endpoint
app.mount("/ws", websocket_manager.app)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "database": await check_database_health(),
        "cache": await cache_service.health_check(),
        "monitoring": await connection_pool.health_check()
    }

async def check_database_health():
    """Check database connectivity"""
    try:
        from database.connection import get_db
        async with get_db() as db:
            result = await db.execute("SELECT 1")
            return "healthy" if result else "unhealthy"
    except Exception:
        return "unhealthy"

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL
    )