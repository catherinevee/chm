"""
Pytest plugin to apply UUID patching before any test imports
This file should be loaded by pytest first
"""

# Apply patching immediately when pytest loads this
import sys
from sqlalchemy import String, TypeDecorator, CHAR
from sqlalchemy.dialects import postgresql
import uuid as uuid_lib


class SQLiteUUID(TypeDecorator):
    """Platform-independent UUID type for SQLite compatibility"""
    impl = CHAR(36)
    cache_ok = True
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif isinstance(value, uuid_lib.UUID):
            return str(value)
        else:
            return str(value)
    
    def process_result_value(self, value, dialect):
        if value is None:
            return value
        else:
            if not isinstance(value, uuid_lib.UUID):
                try:
                    return uuid_lib.UUID(value)
                except:
                    return value
            return value


# Apply patch immediately
postgresql.UUID = SQLiteUUID

# Clear any cached model imports to force reimport with patched UUID
modules_to_clear = [
    'backend.database.models',
    'backend.database.user_models',
    'backend.database.base',
    'main',
    'api.v1.router',
    'api.v1.auth',
    'api.v1.devices',
    'api.v1.alerts',
    'api.v1.metrics'
]

for module in modules_to_clear:
    if module in sys.modules:
        del sys.modules[module]

print("UUID patching applied successfully for SQLite testing")