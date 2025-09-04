#!/usr/bin/env python3
"""
Database setup script for CHM
Handles initial database creation, table creation, and data seeding
"""

import asyncio
import os
import sys
import logging
from pathlib import Path

# Add the backend directory to the Python path
backend_path = Path(__file__).parent.parent.parent / "backend"
sys.path.insert(0, str(backend_path))

from database.connections import db_manager
from database.models import Base
from database.migrations import seed_initial_data

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def setup_database():
    """Set up the database with tables and initial data"""
    try:
        logger.info("Starting database setup...")
        
        # Initialize database connections
        await db_manager.initialize()
        logger.info("Database connections established")
        
        # Check PostgreSQL availability
        if not db_manager.is_available('postgresql'):
            logger.error("PostgreSQL is not available. Please ensure the database is running.")
            return False
        
        # Create tables
        logger.info("Creating database tables...")
        async with db_manager.postgres_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")
        
        # Seed initial data
        logger.info("Seeding initial data...")
        await seed_initial_data()
        logger.info("Initial data seeded successfully")
        
        logger.info("Database setup completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Database setup failed: {e}")
        return False

async def check_database_status():
    """Check the current status of all database connections"""
    try:
        await db_manager.initialize()
        status = db_manager.get_connection_summary()
        
        print("\n" + "="*50)
        print("DATABASE CONNECTION STATUS")
        print("="*50)
        
        for db_type, connected in status['status'].items():
            status_icon = "✅" if connected else "❌"
            print(f"{status_icon} {db_type.upper()}: {'Connected' if connected else 'Disconnected'}")
        
        print(f"\nOverall Status: {status['available_count']}/{status['total_count']} databases connected")
        
        if status.get('degraded_mode', False):
            print("⚠️  Degraded mode enabled - some functionality may be limited")
        
        print("="*50)
        
        return status['available_count'] > 0
        
    except Exception as e:
        logger.error(f"Failed to check database status: {e}")
        return False

async def main():
    """Main function"""
    if len(sys.argv) > 1:
        command = sys.argv[1].lower()
        
        if command == "setup":
            success = await setup_database()
            sys.exit(0 if success else 1)
            
        elif command == "status":
            success = await check_database_status()
            sys.exit(0 if success else 1)
            
        elif command == "help":
            print("""
CHM Database Setup Script

Usage:
    python setup_database.py [command]

Commands:
    setup     - Create database tables and seed initial data
    status    - Check database connection status
    help      - Show this help message

Examples:
    python setup_database.py setup
    python setup_database.py status
            """)
            sys.exit(0)
            
        else:
            print(f"Unknown command: {command}")
            print("Use 'python setup_database.py help' for usage information")
            sys.exit(1)
    else:
        # Default to setup
        success = await setup_database()
        sys.exit(0 if success else 1)

if __name__ == "__main__":
    asyncio.run(main())



