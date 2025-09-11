"""
Module to handle proper import order for tests
This ensures UUID patching happens before any model imports
"""

def patch_and_get_app():
    """Patch UUID and then import app"""
    # First, apply UUID patching
    from tests.setup_test_db import patch_uuid_type
    patch_uuid_type()
    
    # Force reload of modules that might have cached UUID
    import sys
    modules_to_reload = [
        'sqlalchemy.dialects.postgresql',
        'backend.database.models',
        'backend.database.user_models',
        'backend.database.base'
    ]
    
    for module_name in modules_to_reload:
        if module_name in sys.modules:
            del sys.modules[module_name]
    
    # Now import the app
    from main import app
    return app


def get_patched_models():
    """Get models after patching"""
    from tests.setup_test_db import patch_uuid_type
    patch_uuid_type()
    
    # Import models after patching
    from backend.database.models import Device, Alert, DeviceMetric
    from backend.database.user_models import User, Role, Permission
    
    return {
        'Device': Device,
        'Alert': Alert,
        'DeviceMetric': DeviceMetric,
        'User': User,
        'Role': Role,
        'Permission': Permission
    }