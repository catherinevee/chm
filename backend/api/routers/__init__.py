"""
API routers package
"""

# Import all routers for easy access
from backend.api.routers.auth import router as auth
from backend.api.routers.devices import router as devices
from backend.api.routers.metrics import router as metrics
from backend.api.routers.alerts import router as alerts
from backend.api.routers.discovery import router as discovery
from backend.api.routers.notifications import router as notifications
from backend.api.routers.sla import router as sla
from backend.api.routers.topology import router as topology
from backend.api.routers.import_export import router as import_export
from backend.api.routers.health import router as health

__all__ = [
    'auth',
    'devices',
    'metrics',
    'alerts',
    'discovery',
    'notifications',
    'sla',
    'topology',
    'import_export',
    'health',
]