"""
Pytest configuration and fixtures for CHM testing
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import Mock, patch

from backend.storage.database import get_session
from backend.storage.models import Base
from backend.config.config_manager import CHMConfig

# Test database URL
TEST_DATABASE_URL = "postgresql+asyncpg://postgres:postgres@localhost:5432/chm_test"

@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()

@pytest.fixture
async def test_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create test database session."""
    async_session = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session
        await session.rollback()

@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    with patch("backend.config.config_manager.CHMConfig") as mock:
        mock.return_value = Mock(
            database_url=TEST_DATABASE_URL,
            jwt_secret_key="test-secret-key",
            encryption_key="test-encryption-key",
            environment="testing"
        )
        yield mock

@pytest.fixture
def mock_redis():
    """Mock Redis connection for testing."""
    with patch("backend.services.cache_service.redis") as mock:
        mock.return_value = Mock()
        yield mock

@pytest.fixture
def mock_websocket_manager():
    """Mock WebSocket manager for testing."""
    with patch("backend.services.websocket_manager.websocket_manager") as mock:
        mock.return_value = Mock()
        yield mock
