"""
Test to verify database configuration fixes
"""

import pytest
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_database_url_conversion():
    """Test that database URLs are properly converted for async drivers"""
    from core.database import DATABASE_URL
    
    # Test that PostgreSQL URLs are converted to use asyncpg
    if DATABASE_URL.startswith("postgresql://"):
        assert "+asyncpg" in DATABASE_URL, f"PostgreSQL URL should use asyncpg driver: {DATABASE_URL}"
    elif DATABASE_URL.startswith("postgres://"):
        assert "+asyncpg" in DATABASE_URL, f"PostgreSQL URL should use asyncpg driver: {DATABASE_URL}"
    elif DATABASE_URL.startswith("sqlite"):
        # SQLite URLs should remain unchanged
        assert "aiosqlite" in DATABASE_URL, f"SQLite URL should use aiosqlite driver: {DATABASE_URL}"
    
    print(f"✅ Database URL is correctly configured: {DATABASE_URL}")

def test_database_engine_creation():
    """Test that database engine can be created without errors"""
    try:
        from core.database import engine
        assert engine is not None
        print("✅ Database engine created successfully")
    except Exception as e:
        pytest.fail(f"❌ Failed to create database engine: {e}")

def test_database_models_import():
    """Test that all database models can be imported"""
    try:
        from models import (
            User, Device, Metric, Alert, DiscoveryJob, Notification,
            AlertRule, DeviceCredentials, NetworkTopology, SecurityAuditLog
        )
        print("✅ All database models imported successfully")
    except ImportError as e:
        pytest.fail(f"❌ Failed to import database models: {e}")

if __name__ == "__main__":
    # Run basic validation
    print("🧪 Testing database configuration fixes...")
    
    try:
        test_database_url_conversion()
        test_database_engine_creation()
        test_database_models_import()
        print("\n🎉 All database configuration tests passed!")
    except Exception as e:
        print(f"\n❌ Database configuration test failed: {e}")
        sys.exit(1)
