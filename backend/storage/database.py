"""
Database connection and session management
Handles async database operations
"""

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import AsyncSession as AsyncSessionType
import os
from contextlib import asynccontextmanager, contextmanager
from typing import AsyncGenerator, Generator
import asyncio
import logging

logger = logging.getLogger(__name__)

class Database:
    def __init__(self):
        self.database_url = os.getenv("DATABASE_URL")
        self.async_engine = None
        self.async_session_maker = None
    
    async def connect(self):
        """Initialize async database connection"""
        if not self.database_url:
            raise ValueError("DATABASE_URL environment variable is not set")
        
        # Create async engine with improved connection handling
        self.async_engine = create_async_engine(
            self.database_url,
            echo=False,
            pool_pre_ping=True,
            pool_recycle=300,
            pool_size=20,          # Increased pool size
            max_overflow=30,       # Allow more overflow connections
            pool_timeout=30,       # Timeout for getting connection from pool
            connect_args={
                "server_settings": {
                    "application_name": "CHM_HealthMonitor",
                }
            }
        )
        
        # Create async session maker
        self.async_session_maker = sessionmaker(
            self.async_engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False
        )
        
        # Create tables if they don't exist
        await self.create_tables()
    
    @asynccontextmanager
    async def get_async_session(self) -> AsyncGenerator[AsyncSessionType, None]:
        """Async context manager for database sessions"""
        if not self.async_session_maker:
            raise RuntimeError("Database not connected. Call connect() first.")
        
        session = self.async_session_maker()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
    
    @contextmanager
    def get_session(self):
        """Synchronous context manager for database sessions (for sync code)"""
        if not self.async_engine:
            raise RuntimeError("Database not connected. Call connect() first.")
        
        # Create a sync engine for sync operations
        sync_url = self.database_url.replace("+asyncpg", "")
        sync_engine = create_engine(sync_url)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)
        
        session = SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    async def disconnect(self):
        """Close database connection"""
        if self.async_engine:
            await self.async_engine.dispose()
    
    async def health_check(self) -> bool:
        """Check database connection health"""
        try:
            async with self.get_async_session() as session:
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            return False
    
    async def get_connection_stats(self) -> dict:
        """Get database connection pool statistics"""
        if not self.async_engine:
            return {"error": "Database not connected"}
        
        pool = self.async_engine.pool
        return {
            "pool_size": pool.size(),
            "checked_in": pool.checkedin(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "total_connections": pool.size() + pool.overflow()
        }
    
    async def create_tables(self):
        """Create all tables"""
        from .models import Base
        
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def drop_tables(self):
        """Drop all tables"""
        from .models import Base
        
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

db = Database()
