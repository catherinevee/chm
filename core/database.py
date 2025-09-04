"""
CHM Database Layer
Async SQLAlchemy database configuration and base models
"""

import asyncio
from typing import AsyncGenerator, Optional
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import MetaData, text
from sqlalchemy.orm import DeclarativeBase
import logging

from .config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Database URL
DATABASE_URL = settings.database_url

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.debug,
    pool_pre_ping=True,
    pool_recycle=300,
    pool_size=10,
    max_overflow=20
)

# Create async session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False
)

# Base class for all models
class Base(DeclarativeBase):
    """Base class for all database models"""
    pass

# Metadata for database schema
metadata = MetaData()

# Import all models to register them with metadata
from ..models import User, Device, Metric, Alert, DiscoveryJob, Notification

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session"""
    async with async_session() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()

async def init_db():
    """Initialize database tables"""
    async with engine.begin() as conn:
        # Create all tables
        await conn.run_sync(metadata.create_all)
        logger.info("Database tables created successfully")

async def check_db_connection() -> bool:
    """Check if database connection is working"""
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        return False

async def close_db():
    """Close database connections"""
    await engine.dispose()
    logger.info("Database connections closed")

# Database health check
async def db_health_check() -> dict:
    """Check database health status"""
    try:
        is_connected = await check_db_connection()
        if is_connected:
            # Get basic database info
            async with engine.begin() as conn:
                result = await conn.execute(text("SELECT version()"))
                version = result.scalar()
                
                # Get table count
                result = await conn.execute(text("""
                    SELECT COUNT(*) FROM information_schema.tables 
                    WHERE table_schema = 'public'
                """))
                table_count = result.scalar()
                
                return {
                    "status": "healthy",
                    "connected": True,
                    "version": version,
                    "table_count": table_count,
                    "message": "Database is operational"
                }
        else:
            return {
                "status": "unhealthy",
                "connected": False,
                "version": None,
                "table_count": 0,
                "message": "Database connection failed"
            }
    except Exception as e:
        logger.error(f"Database health check failed: {e}")
        return {
            "status": "error",
            "connected": False,
            "version": None,
            "table_count": 0,
            "message": f"Health check error: {str(e)}"
        }
