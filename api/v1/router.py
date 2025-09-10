"""
CHM API v1 Router
Main router that includes all API endpoints
"""

from fastapi import APIRouter

from . import alerts, auth, devices, discovery, metrics, monitoring, notifications

# Create main API router
api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(devices.router, prefix="/devices", tags=["Device Management"])
api_router.include_router(metrics.router, prefix="/metrics", tags=["Metrics & Monitoring"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts & Notifications"])
api_router.include_router(discovery.router, prefix="/discovery", tags=["Network Discovery"])
api_router.include_router(notifications.router, prefix="/notifications", tags=["User Notifications"])
api_router.include_router(monitoring.router, prefix="/monitoring", tags=["Health & Monitoring"])

# Health check endpoint
@api_router.get("/health")
async def health_check():
    """API health check"""
    return {
        "status": "healthy",
        "api_version": "v1",
        "endpoints": [
            "/auth",
            "/devices", 
            "/metrics",
            "/alerts",
            "/discovery",
            "/notifications"
        ]
    }

__all__ = ["api_router"]
