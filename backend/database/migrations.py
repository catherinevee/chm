"""
Database migration script for CHM
Creates tables and initial data
"""

import asyncio
import logging
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from datetime import datetime, timedelta
import uuid

from .connections import get_db_manager
from .models import Base

logger = logging.getLogger(__name__)

async def create_tables():
    """Create all database tables"""
    try:
        db_manager = await get_db_manager()
        await db_manager.initialize()
        
        # Create tables
        async with db_manager.postgres_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created successfully")
        
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        raise

async def seed_initial_data():
    """Seed initial data for testing"""
    try:
        db_manager = await get_db_manager()
        await db_manager.initialize()
        
        async with db_manager.get_postgres_session() as session:
            # Check if data already exists
            result = await session.execute(text("SELECT COUNT(*) FROM devices"))
            count = result.scalar()
            
            if count > 0:
                logger.info("Database already has data, skipping seed")
                return
            
            # Insert sample devices
            sample_devices = [
                {
                    "id": str(uuid.uuid4()),
                    "hostname": "core-router-01",
                    "ip_address": "192.168.1.1",
                    "device_type": "ROUTER",
                    "current_state": "ONLINE",
                    "manufacturer": "Cisco",
                    "model": "ISR4331",
                    "location": "Data Center A",
                    "serial_number": "FDO12345678",
                    "firmware_version": "16.09.04",
                    "discovery_protocol": "SNMP",
                    "is_active": True,
                    "device_group": "PRODUCTION",
                    "department": "IT Infrastructure",
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                },
                {
                    "id": str(uuid.uuid4()),
                    "hostname": "access-switch-01",
                    "ip_address": "192.168.1.10",
                    "device_type": "SWITCH",
                    "current_state": "ONLINE",
                    "manufacturer": "Cisco",
                    "model": "Catalyst 2960X",
                    "location": "Floor 1 IDF",
                    "serial_number": "FCW12345678",
                    "firmware_version": "15.2(4)E10",
                    "discovery_protocol": "SNMP",
                    "is_active": True,
                    "device_group": "PRODUCTION",
                    "department": "IT Infrastructure",
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                },
                {
                    "id": str(uuid.uuid4()),
                    "hostname": "firewall-01",
                    "ip_address": "192.168.1.254",
                    "device_type": "FIREWALL",
                    "current_state": "ONLINE",
                    "manufacturer": "Fortinet",
                    "model": "FortiGate 100F",
                    "location": "Data Center A",
                    "serial_number": "FG100F12345678",
                    "firmware_version": "7.0.12",
                    "discovery_protocol": "SNMP",
                    "is_active": True,
                    "device_group": "DMZ",
                    "department": "IT Security",
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                },
                {
                    "id": str(uuid.uuid4()),
                    "hostname": "server-web-01",
                    "ip_address": "192.168.1.100",
                    "device_type": "SERVER",
                    "current_state": "ONLINE",
                    "manufacturer": "Dell",
                    "model": "PowerEdge R740",
                    "location": "Data Center B",
                    "serial_number": "DL12345678",
                    "firmware_version": "2.15.0",
                    "discovery_protocol": "PING",
                    "is_active": True,
                    "device_group": "PRODUCTION",
                    "department": "Application Services",
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                },
                {
                    "id": str(uuid.uuid4()),
                    "hostname": "wireless-ap-01",
                    "ip_address": "192.168.1.50",
                    "device_type": "OTHER",
                    "current_state": "OFFLINE",
                    "manufacturer": "Ubiquiti",
                    "model": "UniFi AP AC Pro",
                    "location": "Building A - Floor 2",
                    "serial_number": "UB12345678",
                    "firmware_version": "4.3.28",
                    "discovery_protocol": "SNMP",
                    "is_active": True,
                    "device_group": "INTERNAL",
                    "department": "IT Infrastructure",
                    "created_at": datetime.utcnow(),
                    "updated_at": datetime.utcnow()
                }
            ]
            
            # Insert devices
            for device_data in sample_devices:
                await session.execute(
                    text("""
                        INSERT INTO devices (
                            id, hostname, ip_address, device_type, current_state,
                            manufacturer, model, location, serial_number, firmware_version,
                            discovery_protocol, is_active, device_group, department,
                            created_at, updated_at
                        ) VALUES (
                            :id, :hostname, :ip_address, :device_type, :current_state,
                            :manufacturer, :model, :location, :serial_number, :firmware_version,
                            :discovery_protocol, :is_active, :device_group, :department,
                            :created_at, :updated_at
                        )
                    """),
                    device_data
                )
            
            # Skip alerts and notifications for now - focus on devices first
            logger.info("Skipping alerts and notifications for now")
            
            await session.commit()
            logger.info("Initial data seeded successfully")
            
    except Exception as e:
        logger.error(f"Error seeding initial data: {e}")
        raise

async def run_migrations():
    """Run all database migrations"""
    logger.info("Starting database migrations...")
    
    try:
        # Create tables
        await create_tables()
        
        # Seed initial data
        await seed_initial_data()
        
        logger.info("Database migrations completed successfully")
        
    except Exception as e:
        logger.error(f"Migration failed: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(run_migrations())
