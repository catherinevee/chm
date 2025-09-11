"""
SQLite compatibility for PostgreSQL UUID types
This module must be imported before any models to patch UUID support
"""

from sqlalchemy import String
from sqlalchemy.types import TypeDecorator, CHAR
import uuid as uuid_lib


class SQLiteUUID(TypeDecorator):
    """Platform-independent UUID type that works with SQLite"""
    impl = CHAR(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid_lib.UUID):
            return str(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid_lib.UUID):
            return value
        return uuid_lib.UUID(value)
    
    def _compiler_dispatch(self, visitor, **kw):
        """Return String type for SQLite compilation"""
        return String(36)._compiler_dispatch(visitor, **kw)


def patch_uuid_for_sqlite():
    """Monkey-patch PostgreSQL UUID to work with SQLite"""
    import sys
    from sqlalchemy.dialects import postgresql
    
    # Replace the UUID class with our SQLite-compatible version
    postgresql.UUID = SQLiteUUID
    
    # Also patch any already-imported modules
    for module_name, module in list(sys.modules.items()):
        if module and hasattr(module, 'UUID'):
            if 'sqlalchemy.dialects.postgresql' in str(type(module.UUID)):
                module.UUID = SQLiteUUID


# Patch immediately when this module is imported
patch_uuid_for_sqlite()