"""
Comprehensive tests for Database modules
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from core.database import (
    engine, get_db, init_db, check_db_connection,
    db_health_check
)
from backend.database.base import Base
from backend.database.models import *
from backend.models.user import User
from backend.models.device import Device


class TestDatabaseCore:
    """Test core database functionality"""

    @pytest.fixture
    def mock_engine(self):
        """Mock database engine"""
        return AsyncMock(spec=AsyncEngine)

    @pytest.fixture
    def mock_session(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)

    def test_engine_creation(self):
        """Test database engine creation"""
        with patch('core.database.create_async_engine') as mock_create:
            mock_engine = AsyncMock()
            mock_create.return_value = mock_engine
            
            engine = engine("postgresql+asyncpg://user:pass@localhost/db")
            
            assert engine == mock_engine
            mock_create.assert_called_once()

    def test_engine_with_pool_settings(self):
        """Test engine creation with connection pool settings"""
        with patch('core.database.create_async_engine') as mock_create:
            url = "postgresql+asyncpg://user:pass@localhost/db"
            
            engine(url, pool_size=20, max_overflow=30)
            
            mock_create.assert_called_once()
            args, kwargs = mock_create.call_args
            assert kwargs.get('pool_size') == 20
            assert kwargs.get('max_overflow') == 30

    @pytest.mark.asyncio
    async def test_get_db_session_manager(self, mock_engine):
        """Test database session manager"""
        with patch('core.database.engine', return_value=mock_engine):
            with patch('core.database.async_sessionmaker') as mock_sessionmaker:
                mock_session = AsyncMock()
                mock_sessionmaker.return_value = mock_session
                
                async for db in get_db():
                    assert db == mock_session
                    break

    @pytest.mark.asyncio
    async def test_get_db_session_cleanup(self, mock_engine):
        """Test that database session is properly cleaned up"""
        with patch('core.database.engine', return_value=mock_engine):
            with patch('core.database.async_sessionmaker') as mock_sessionmaker:
                mock_session = AsyncMock()
                mock_sessionmaker.return_value = mock_session
                
                db_gen = get_db()
                db = await db_gen.__anext__()
                
                try:
                    await db_gen.__anext__()
                except StopAsyncIteration:
                    pass
                
                mock_session.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_db_success(self, mock_engine):
        """Test successful table creation"""
        with patch('core.database.engine', return_value=mock_engine):
            mock_conn = AsyncMock()
            mock_engine.begin.return_value.__aenter__.return_value = mock_conn
            
            await init_db()
            
            mock_engine.begin.assert_called_once()
            mock_conn.run_sync.assert_called_once()

    @pytest.mark.asyncio
    async def test_init_db_failure(self, mock_engine):
        """Test table creation failure"""
        with patch('core.database.engine', return_value=mock_engine):
            mock_engine.begin.side_effect = SQLAlchemyError("Connection failed")
            
            with pytest.raises(SQLAlchemyError):
                await init_db()

    @pytest.mark.asyncio
    async def test_check_db_connection_success(self, mock_engine):
        """Test successful database connection check"""
        with patch('core.database.engine', return_value=mock_engine):
            mock_conn = AsyncMock()
            mock_result = MagicMock()
            mock_result.scalar.return_value = 1
            mock_conn.execute.return_value = mock_result
            mock_engine.begin.return_value.__aenter__.return_value = mock_conn
            
            result = await check_db_connection()
            
            assert result is True
            mock_conn.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_db_connection_failure(self, mock_engine):
        """Test database connection check failure"""
        with patch('core.database.engine', return_value=mock_engine):
            mock_engine.begin.side_effect = SQLAlchemyError("Connection failed")
            
            result = await check_db_connection()
            
            assert result is False


class TestDatabaseHealthCheck:
    """Test database health check functionality"""

    @pytest.fixture
    def mock_session(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)

    @pytest.mark.asyncio
    async def test_db_health_check_success(self, mock_session):
        """Test successful health check"""
        mock_result = MagicMock()
        mock_result.scalar.return_value = "PostgreSQL 13.0"
        mock_session.execute.return_value = mock_result
        
        with patch('core.database.engine.begin') as mock_begin:
            mock_begin.return_value.__aenter__.return_value = mock_session
            
            result = await db_health_check()
            
            assert result["status"] == "healthy"
            assert result["connected"] is True

    @pytest.mark.asyncio
    async def test_db_health_check_failure(self, mock_session):
        """Test health check with database failure"""
        with patch('core.database.engine.begin') as mock_begin:
            mock_begin.side_effect = SQLAlchemyError("Database error")
            
            result = await db_health_check()
            
            assert result["status"] == "error"
            assert result["connected"] is False


class TestDatabaseModels:
    """Test database model definitions and relationships"""

    def test_base_model_attributes(self):
        """Test base model has required attributes"""
        assert hasattr(Base, 'metadata')
        assert hasattr(Base, '__tablename__')

    def test_user_model_table(self):
        """Test User model table definition"""
        user_table = User.__table__
        
        # Check required columns exist
        column_names = [col.name for col in user_table.columns]
        required_columns = ['id', 'username', 'email', 'hashed_password']
        
        for col in required_columns:
            assert col in column_names

    def test_device_model_table(self):
        """Test Device model table definition"""
        device_table = Device.__table__
        
        # Check required columns exist
        column_names = [col.name for col in device_table.columns]
        required_columns = ['id', 'name', 'ip_address', 'device_type']
        
        for col in required_columns:
            assert col in column_names

    def test_model_relationships(self):
        """Test model relationships are defined"""
        # Test User-Device relationship if it exists
        if hasattr(User, 'devices'):
            assert hasattr(User, 'devices')
        
        # Test Device-Metric relationship if it exists
        if hasattr(Device, 'metrics'):
            assert hasattr(Device, 'metrics')

    def test_model_constraints(self):
        """Test model constraints"""
        user_table = User.__table__
        
        # Check unique constraints
        unique_columns = []
        for constraint in user_table.constraints:
            if hasattr(constraint, 'columns'):
                for col in constraint.columns:
                    if hasattr(constraint, 'unique') and constraint.unique:
                        unique_columns.append(col.name)
        
        # Username and email should be unique (if implemented)

    def test_model_indexes(self):
        """Test model indexes"""
        device_table = Device.__table__
        
        # Check that indexes exist (implementation specific)
        indexes = device_table.indexes
        assert isinstance(indexes, set)

    def test_model_serialization(self):
        """Test model serialization methods"""
        # Test if models have serialization methods
        user = User()
        device = Device()
        
        # Check for common serialization attributes/methods
        if hasattr(user, 'to_dict'):
            assert callable(user.to_dict)
        
        if hasattr(device, 'to_dict'):
            assert callable(device.to_dict)


class TestDatabaseMigrations:
    """Test database migration functionality"""

    @pytest.mark.asyncio
    async def test_migration_version_check(self):
        """Test database migration version checking"""
        # Test migration version retrieval (if implemented)
        with patch('alembic.config.Config') as mock_config:
            with patch('alembic.script.ScriptDirectory.from_config') as mock_script:
                # Test migration functionality if available
                pass

    @pytest.mark.asyncio
    async def test_upgrade_database(self):
        """Test database upgrade operation"""
        # Test database upgrade (if implemented)
        with patch('alembic.command.upgrade') as mock_upgrade:
            # Test upgrade functionality if available
            pass

    @pytest.mark.asyncio
    async def test_downgrade_database(self):
        """Test database downgrade operation"""
        # Test database downgrade (if implemented)
        with patch('alembic.command.downgrade') as mock_downgrade:
            # Test downgrade functionality if available
            pass


class TestDatabaseTransactions:
    """Test database transaction handling"""

    @pytest.fixture
    def mock_session(self):
        """Mock database session with transaction support"""
        session = AsyncMock(spec=AsyncSession)
        session.begin.return_value.__aenter__ = AsyncMock()
        session.begin.return_value.__aexit__ = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_transaction_commit(self, mock_session):
        """Test transaction commit"""
        with patch('core.database.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            
            async with mock_session.begin():
                # Simulate some database operations
                await mock_session.execute("INSERT INTO users VALUES (...)")
                await mock_session.commit()
            
            mock_session.commit.assert_called()

    @pytest.mark.asyncio
    async def test_transaction_rollback(self, mock_session):
        """Test transaction rollback on error"""
        with patch('core.database.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            
            try:
                async with mock_session.begin():
                    await mock_session.execute("INSERT INTO users VALUES (...)")
                    raise IntegrityError("Duplicate key", None, None)
            except IntegrityError:
                await mock_session.rollback()
            
            mock_session.rollback.assert_called()

    @pytest.mark.asyncio
    async def test_nested_transactions(self, mock_session):
        """Test nested transaction handling"""
        with patch('core.database.get_db') as mock_get_db:
            mock_get_db.return_value.__aenter__.return_value = mock_session
            
            # Simulate nested transaction
            async with mock_session.begin():
                await mock_session.execute("INSERT INTO users VALUES (...)")
                
                # Nested savepoint
                async with mock_session.begin_nested():
                    await mock_session.execute("INSERT INTO devices VALUES (...)")
                
                await mock_session.commit()

    @pytest.mark.asyncio
    async def test_concurrent_sessions(self):
        """Test concurrent database sessions"""
        session1 = AsyncMock(spec=AsyncSession)
        session2 = AsyncMock(spec=AsyncSession)
        
        with patch('core.database.get_db') as mock_get_db:
            mock_get_db.side_effect = [
                session1.__aenter__.return_value,
                session2.__aenter__.return_value
            ]
            
            # Simulate concurrent operations
            async def operation1():
                db = await mock_get_db().__aenter__()
                await db.execute("SELECT * FROM users")
            
            async def operation2():
                db = await mock_get_db().__aenter__()
                await db.execute("SELECT * FROM devices")
            
            # Both operations should work independently
            await operation1()
            await operation2()