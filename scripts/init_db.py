#!/usr/bin/env python3
"""
Database initialization script for CHM
Creates all necessary database tables and initial data
"""

import asyncio
import os
import sys
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.database import engine, metadata, async_session
from core.config import get_settings
from models import *  # Import all models to register them
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def init_database():
    """Initialize the database with all tables"""
    try:
        logger.info("Starting database initialization...")
        
        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(metadata.create_all)
        
        logger.info("✅ Database tables created successfully")
        
        # Wait a moment to ensure transaction is committed
        await asyncio.sleep(1)
        
        # Create initial data if needed
        await create_initial_data()
        
        logger.info("✅ Database initialization completed successfully")
        
    except Exception as e:
        logger.error(f"❌ Database initialization failed: {e}")
        raise
    finally:
        await engine.dispose()

async def create_initial_data():
    """Create initial data for the application"""
    try:
        # First verify the table exists with a separate connection
        table_exists = False
        try:
            async with async_session() as test_session:
                from sqlalchemy import text
                await test_session.execute(text("SELECT COUNT(*) FROM users LIMIT 1"))
                table_exists = True
                logger.info("✅ Users table exists and is accessible")
        except Exception as e:
            logger.error(f"❌ Users table not accessible: {e}")
            # Try to create tables again just in case
            async with engine.begin() as conn:
                await conn.run_sync(metadata.create_all)
            logger.info("Retried table creation")
            
            # Wait for the transaction to complete
            await asyncio.sleep(2)
            
            # Verify table creation worked
            try:
                async with async_session() as verify_session:
                    await verify_session.execute(text("SELECT COUNT(*) FROM users LIMIT 1"))
                    table_exists = True
                    logger.info("✅ Users table created and verified")
            except Exception as verify_e:
                logger.error(f"❌ Table creation verification failed: {verify_e}")
                raise
        
        if table_exists:
            # Now check for existing users in a fresh session
            async with async_session() as session:
                from backend.models.user import User
                from sqlalchemy import select
                
                result = await session.execute(select(User))
                existing_users = result.scalars().first()
                
                if not existing_users:
                    logger.info("Creating initial admin user...")
                    
                    from backend.services.auth_service import auth_service
                    
                    # Create admin user
                    admin_user = User(
                        username="admin",
                        email="admin@chm.local",
                        hashed_password=auth_service.hash_password("admin123"),
                        full_name="System Administrator",
                        role="admin",
                        status="active",
                        is_verified=True
                    )
                    
                    session.add(admin_user)
                    await session.commit()
                    
                    logger.info("✅ Initial admin user created (username: admin, password: admin123)")
                else:
                    logger.info("✅ Users already exist, skipping initial user creation")
                
    except Exception as e:
        logger.error(f"❌ Failed to create initial data: {e}")
        raise

async def main():
    """Main function"""
    settings = get_settings()
    logger.info(f"Initializing database: {settings.database_url}")
    
    await init_database()

if __name__ == "__main__":
    asyncio.run(main())
