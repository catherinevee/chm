"""
Database initialization and session management
"""

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from sqlalchemy.pool import NullPool
from contextlib import asynccontextmanager
import logging
from typing import AsyncGenerator

from backend.config import settings

logger = logging.getLogger(__name__)

# Create base class for models
Base = declarative_base()

# Create async engine with appropriate settings for each database type
database_url = settings.get_database_url()
is_postgresql = "postgresql" in database_url
is_sqlite = "sqlite" in database_url

# Build engine arguments based on database type
engine_args = {
    "echo": settings.debug,
    "future": True,
}

if is_postgresql:
    # PostgreSQL-specific settings
    engine_args.update({
        "pool_size": settings.database_pool_size,
        "max_overflow": settings.database_max_overflow,
        "pool_pre_ping": True,
        "pool_recycle": 3600,  # Recycle connections after 1 hour
        "connect_args": {
            "server_settings": {
                "application_name": settings.app_name,
                "jit": "off"
            },
            "command_timeout": 60,
            "timeout": 30
        }
    })
elif is_sqlite:
    # SQLite-specific settings
    # For testing, use aiosqlite URL format
    if "sqlite:///" in database_url and "aiosqlite" not in database_url:
        database_url = database_url.replace("sqlite:///", "sqlite+aiosqlite:///")
    engine_args.update({
        "connect_args": {"check_same_thread": False},
        "poolclass": NullPool  # No connection pooling for SQLite
    })

engine = create_async_engine(database_url, **engine_args)

# Create async session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False
)

class DatabaseManager:
    """Manages database connections and sessions"""
    
    def __init__(self):
        self.engine = engine
        self.async_session_maker = async_session_maker
        self._initialized = False
    
    async def init_db(self):
        """Initialize database (create tables if needed)"""
        try:
            if self._initialized:
                return
            
            logger.info("Initializing database...")
            
            # Import all models to ensure they are registered
            try:
                from backend.database.models import (
                    Device, DeviceMetric, Alert, NetworkInterface,
                    DiscoveryJob, TopologyNode, TopologyEdge,
                    Notification, SLAMetric
                )
            except ImportError as e:
                logger.warning(f"Could not import database models: {e}")
            
            try:
                from backend.database.user_models import (
                    User, Role, Permission, UserSession, AuditLog
                )
            except ImportError as e:
                logger.warning(f"Could not import user models: {e}")
            
            # Create all tables
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            self._initialized = True
            logger.info("Database initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
    
    async def close(self):
        """Close database connections"""
        await self.engine.dispose()
        logger.info("Database connections closed")
    
    @asynccontextmanager
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get an async database session"""
        async with self.async_session_maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    async def health_check(self) -> bool:
        """Check database health"""
        try:
            from sqlalchemy import text
            async with self.get_session() as session:
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False

# Global database manager instance
db_manager = DatabaseManager()

# Convenience functions
async def init_db():
    """Initialize the database"""
    await db_manager.init_db()

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session"""
    async with db_manager.get_session() as session:
        yield session

# For backwards compatibility
get_db = get_session