"""
CHM Main Application
FastAPI application with all routes and middleware
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

from core.config import get_settings
from api.v1.router import api_router
from core.middleware import RequestLoggingMiddleware
from backend.services.prometheus_metrics import MetricsMiddleware
from backend.services.audit_service import audit_service
# AuditMiddleware not yet implemented
class AuditMiddleware:
    def __init__(self, app):
        self.app = app
    async def __call__(self, scope, receive, send):
        await self.app(scope, receive, send)

# Get application settings
settings = get_settings()

def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    
    app = FastAPI(
        title="CHM - Catalyst Health Monitor",
        description="Enterprise-grade network monitoring and management system",
        version="2.0.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        openapi_url="/openapi.json" if settings.debug else None,
    )
    
    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_hosts,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    if settings.trusted_hosts:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=settings.trusted_hosts
        )
    
    # Add custom middleware
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(AuditMiddleware)
    
    # Include API routes
    app.include_router(api_router, prefix="/api/v1")
    
    # Startup and shutdown events
    @app.on_event("startup")
    async def startup_event():
        """Initialize services on startup"""
        # Audit logger startup placeholder
        pass
        logger.info("CHM application started")
    
    @app.on_event("shutdown")
    async def shutdown_event():
        """Cleanup on shutdown"""
        # Audit logger shutdown placeholder
        pass
        logger.info("CHM application stopped")
    
    # Health check endpoints
    @app.get("/")
    async def root() -> Dict[str, Any]:
        """Root endpoint - health check"""
        return {
            "status": "healthy",
            "service": "CHM - Catalyst Health Monitor",
            "version": "2.0.0",
            "message": "Network monitoring system is running"
        }
    
    @app.get("/health")
    async def health_check() -> Dict[str, Any]:
        """Health check endpoint"""
        return {
            "status": "healthy",
            "timestamp": "2025-01-03T09:00:00Z",
            "service": "CHM",
            "version": "2.0.0"
        }
    
    @app.get("/api/status")
    async def api_status() -> Dict[str, Any]:
        """API status endpoint"""
        return {
            "api_version": "v1",
            "status": "operational",
            "endpoints": {
                "auth": "/api/v1/auth",
                "devices": "/api/v1/devices",
                "metrics": "/api/v1/metrics",
                "alerts": "/api/v1/alerts",
                "discovery": "/api/v1/discovery",
                "notifications": "/api/v1/notifications"
            }
        }
    
    # Global exception handler
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request, exc):
        """Global HTTP exception handler"""
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.detail, "status_code": exc.status_code}
        )
    
    # Custom OpenAPI schema
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        
        openapi_schema = get_openapi(
            title="CHM API",
            version="2.0.0",
            description="CHM Catalyst Health Monitor API",
            routes=app.routes,
        )
        
        # Add security schemes
        openapi_schema["components"]["securitySchemes"] = {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
            }
        }
        
        app.openapi_schema = openapi_schema
        return app.openapi_schema
    
    app.openapi = custom_openapi
    
    return app

# Create the application instance
app = create_app()

# Export the app for uvicorn
__all__ = ["app"]
