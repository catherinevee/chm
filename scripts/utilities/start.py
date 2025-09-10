#!/usr/bin/env python3
"""
Startup script for Catalyst Health Monitor
Initializes database and starts services
"""

import asyncio
import os
import sys
import logging
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from backend.storage.database import db
from backend.storage.models import Base
from sqlalchemy import text

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def initialize_database():
    """Initialize database tables"""
    try:
        logging.info("Connecting to database...")
        await db.connect()
        
        logging.info("Creating database tables...")
        await db.create_tables()
        
        logging.info("Database tables created successfully!")
        return True
    except Exception as e:
        logging.error(f"Database initialization failed: {e}")
        return False

async def create_sample_data():
    """Create sample devices, credentials, and thresholds"""
    try:
        async with db.get_async_session() as session:
            # Check if we already have devices
            existing = await session.execute(text("SELECT COUNT(*) FROM devices"))
            if existing.scalar() > 0:
                logging.info("Sample data already exists. Skipping creation.")
                return True
            
            from backend.storage.models import Device, DeviceCredential, Threshold, DeviceType, DeviceState, AlertSeverity
            
            # Create sample devices
            devices = [
                Device(
                    hostname="core-switch-1",
                    ip_address="192.168.1.1",
                    device_type=DeviceType.C3560,
                    current_state=DeviceState.HEALTHY,
                    consecutive_failures=0,
                    circuit_breaker_trips=0
                ),
                Device(
                    hostname="access-switch-1",
                    ip_address="192.168.1.2",
                    device_type=DeviceType.C2960,
                    current_state=DeviceState.HEALTHY,
                    consecutive_failures=0,
                    circuit_breaker_trips=0
                ),
                Device(
                    hostname="distribution-switch-1",
                    ip_address="192.168.1.3",
                    device_type=DeviceType.C4500,
                    current_state=DeviceState.HEALTHY,
                    consecutive_failures=0,
                    circuit_breaker_trips=0
                )
            ]
            
            session.add_all(devices)
            await session.flush()  # Get the IDs
            
            # Create sample credentials
            credentials = [
                DeviceCredential(
                    device_id=devices[0].id,
                    protocol="snmp",
                    version="2c",
                    community="public",
                    encrypted=False
                ),
                DeviceCredential(
                    device_id=devices[1].id,
                    protocol="snmp",
                    version="2c",
                    community="public",
                    encrypted=False
                ),
                DeviceCredential(
                    device_id=devices[2].id,
                    protocol="snmp",
                    version="3",
                    username="monitor",
                    auth_protocol="SHA",
                    auth_password="auth_pass",
                    priv_protocol="AES",
                    priv_password="priv_pass",
                    encrypted=True
                )
            ]
            
            session.add_all(credentials)
            
            # Create sample thresholds
            thresholds = [
                Threshold(
                    device_type=DeviceType.C2960,
                    metric_name="cpu",
                    warning_value=60,
                    critical_value=80,
                    comparison="greater"
                ),
                Threshold(
                    device_type=DeviceType.C2960,
                    metric_name="memory_free_kb",
                    warning_value=5000,
                    critical_value=3000,
                    comparison="less"
                ),
                Threshold(
                    device_type=DeviceType.C3560,
                    metric_name="cpu",
                    warning_value=70,
                    critical_value=85,
                    comparison="greater"
                ),
                Threshold(
                    device_type=DeviceType.C3560,
                    metric_name="memory_free_kb",
                    warning_value=10000,
                    critical_value=5000,
                    comparison="less"
                ),
                Threshold(
                    device_type=DeviceType.C4500,
                    metric_name="cpu",
                    warning_value=75,
                    critical_value=90,
                    comparison="greater"
                ),
                Threshold(
                    device_type=DeviceType.C4500,
                    metric_name="memory_free_kb",
                    warning_value=50000,
                    critical_value=20000,
                    comparison="less"
                )
            ]
            
            session.add_all(thresholds)
            
            # Create sample alerts
            from backend.storage.models import Alert
            alerts = [
                Alert(
                    device_id=devices[0].id,
                    severity=AlertSeverity.WARNING,
                    metric_name="cpu",
                    metric_value=65,
                    message="CPU utilization is above warning threshold"
                ),
                Alert(
                    device_id=devices[1].id,
                    severity=AlertSeverity.INFO,
                    metric_name="memory_free_kb",
                    metric_value=4500,
                    message="Memory usage is approaching warning threshold"
                )
            ]
            
            session.add_all(alerts)
            await session.commit()
            
            logging.info("Sample data created successfully!")
            return True
            
    except Exception as e:
        logging.error(f"Failed to create sample data: {e}")
        return False

async def main():
    """Main initialization function"""
    logging.basicConfig(level=logging.INFO)
    logging.info("Starting Catalyst Health Monitor initialization...")
    
    try:
        # Initialize database
        if not await initialize_database():
            return False
        
        # Create sample data
        if not await create_sample_data():
            return False
        
        logging.info("Catalyst Health Monitor initialization completed successfully!")
        logging.info("You can now start the application:")
        logging.info("  Backend: python -m uvicorn backend.api.main:app --reload")
        logging.info("  Frontend: cd frontend && npm start")
        
        return True
        
    except Exception as e:
        logging.error(f"Startup failed: {e}")
        return False
    finally:
        try:
            await db.disconnect()
        except:
            pass

if __name__ == "__main__":
    success = asyncio.run(main())
    if not success:
        sys.exit(1)
