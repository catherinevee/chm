"""
Root conftest that applies UUID patching before any imports
This file is in the root directory to be loaded first by pytest
"""

# Apply UUID patching immediately
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


# Replace PostgreSQL UUID with SQLite-compatible version
postgresql.UUID = SQLiteUUID

print("Root conftest loaded - UUID patching applied")