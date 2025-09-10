"""
API routers package

Router imports have been moved to prevent circular dependencies.
Import routers directly where needed:
    from backend.api.routers.auth import router as auth_router
    from backend.api.routers.devices import router as devices_router
    etc.
"""

# No imports at package level to prevent circular dependencies
__all__ = []