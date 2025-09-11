"""
Isolated test to verify UUID patching works
Run this file directly to test without pytest complications
"""

# Apply UUID patching FIRST before any imports
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
                return uuid_lib.UUID(value)
            return value


# Replace PostgreSQL UUID
postgresql.UUID = SQLiteUUID

# Now we can import the models
from backend.database.models import Device
from backend.database.user_models import User
from backend.database.base import Base

# Test creating tables with SQLite
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.pool import StaticPool
import asyncio


async def test_database_creation():
    """Test that we can create tables with our UUID patch"""
    # Create SQLite engine
    DATABASE_URL = "sqlite+aiosqlite:///:memory:"
    engine = create_async_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=True  # Show SQL for debugging
    )
    
    # Create tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    print("SUCCESS: Tables created successfully!")
    
    # Create a session and add a test user
    async_session = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False
    )
    
    async with async_session() as session:
        # Create a test user
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed",
            is_active=True,
            is_verified=True
        )
        session.add(user)
        await session.commit()
        
        print(f"SUCCESS: User created with ID: {user.id}")
        
        # Create a test device
        device = Device(
            hostname="test-device",
            ip_address="192.168.1.1",
            device_type="router",
            current_state="active"
        )
        session.add(device)
        await session.commit()
        
        print(f"SUCCESS: Device created with ID: {device.id}")
    
    await engine.dispose()
    print("\nALL TESTS PASSED! UUID patching works correctly.")


if __name__ == "__main__":
    # Run the test
    asyncio.run(test_database_creation())