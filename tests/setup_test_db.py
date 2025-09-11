"""
Setup test database with proper UUID handling for SQLite
This module MUST be imported before any other application modules
"""

import sys
from sqlalchemy import String, TypeDecorator, CHAR
from sqlalchemy.dialects import postgresql
import uuid as uuid_lib


class SQLiteUUID(TypeDecorator):
    """Platform-independent UUID type for SQLite compatibility"""
    impl = CHAR(36)
    cache_ok = True
    
    def load_dialect_impl(self, dialect):
        if dialect.name == 'postgresql':
            # If somehow we're using PostgreSQL, use native UUID
            return dialect.type_descriptor(postgresql.UUID())
        else:
            # For SQLite and others, use string
            return dialect.type_descriptor(CHAR(36))
    
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
        elif isinstance(value, uuid_lib.UUID):
            return value
        else:
            try:
                return uuid_lib.UUID(value)
            except (TypeError, ValueError):
                return value


def patch_uuid_type():
    """Replace PostgreSQL UUID with SQLite-compatible version"""
    # Store original UUID class
    original_uuid = postgresql.UUID
    
    # Create wrapper that returns our SQLiteUUID
    class UUIDWrapper:
        def __init__(self, as_uuid=True):
            self.as_uuid = as_uuid
            
        def __call__(self, *args, **kwargs):
            return SQLiteUUID()
        
        def __new__(cls, *args, **kwargs):
            return SQLiteUUID()
    
    # Replace UUID in postgresql dialect
    postgresql.UUID = UUIDWrapper
    
    # Also patch it in sys.modules to catch any cached imports
    for name, module in list(sys.modules.items()):
        if module and 'sqlalchemy' in name:
            if hasattr(module, 'UUID'):
                module.UUID = UUIDWrapper


# Apply patch immediately on import
patch_uuid_type()


def create_test_engine():
    """Create SQLite engine for testing with proper UUID support"""
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool
    
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    
    engine = create_async_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
    
    return engine


async def create_test_tables(engine):
    """Create all tables in the test database"""
    from backend.database.base import Base
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_test_session(engine):
    """Get a test database session"""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    
    async_session = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        yield session