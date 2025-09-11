"""
Comprehensive tests for Database Connection and Session Management
Testing database connections, session handling, connection pooling, and transaction management
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import uuid

from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, create_async_engine
from sqlalchemy.exc import OperationalError, IntegrityError, DBAPIError
from sqlalchemy import text, select, MetaData
from sqlalchemy.pool import QueuePool, NullPool

# Database imports
from backend.database.base import DatabaseManager, get_session, init_db
from backend.database.connection_manager import (
    DatabaseConnectionManager, DatabaseConfig, ConnectionPoolConfig,
    DatabaseType, ConnectionState, DatabaseTransactionManager
)
from backend.database.models import Device


@pytest.fixture
def sample_db_config():
    """Create sample database configuration"""
    return DatabaseConfig(
        database_type=DatabaseType.SQLITE,
        host="localhost",
        port=5432,
        database=":memory:",
        username="test",
        password="test",
        pool_config=ConnectionPoolConfig(
            pool_size=5,
            max_overflow=10,
            pool_timeout=30.0
        )
    )


@pytest.fixture
def mock_engine():
    """Create mock async engine"""
    engine = AsyncMock(spec=AsyncEngine)
    engine.dispose = AsyncMock()
    engine.begin = AsyncMock()
    engine.connect = AsyncMock()
    
    # Mock pool
    mock_pool = MagicMock()
    mock_pool.size.return_value = 5
    mock_pool.checkedin.return_value = 3
    mock_pool.overflow.return_value = 2
    engine.pool = mock_pool
    engine.sync_engine = MagicMock()
    
    return engine


@pytest.fixture
def mock_session():
    """Create mock async session"""
    session = AsyncMock(spec=AsyncSession)
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    session.execute = AsyncMock()
    session.begin = AsyncMock()
    session.begin_nested = AsyncMock()
    return session


class TestDatabaseManager:
    """Test DatabaseManager functionality"""
    
    def test_database_manager_initialization(self):
        """Test DatabaseManager initialization"""
        db_manager = DatabaseManager()
        
        assert db_manager.engine is not None
        assert db_manager.async_session_maker is not None
        assert db_manager._initialized is False
    
    @patch('backend.database.base.engine')
    async def test_init_db_success(self, mock_engine):
        """Test successful database initialization"""
        # Mock engine.begin context manager
        mock_conn = AsyncMock()
        mock_engine.begin = AsyncMock()
        mock_engine.begin.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_engine.begin.return_value.__aexit__ = AsyncMock(return_value=None)
        
        db_manager = DatabaseManager()
        db_manager.engine = mock_engine
        
        await db_manager.init_db()
        
        assert db_manager._initialized is True
        mock_engine.begin.assert_called_once()
        mock_conn.run_sync.assert_called_once()
    
    @patch('backend.database.base.engine')
    async def test_init_db_already_initialized(self, mock_engine):
        """Test init_db when already initialized"""
        db_manager = DatabaseManager()
        db_manager._initialized = True
        db_manager.engine = mock_engine
        
        await db_manager.init_db()
        
        # Should not call engine operations if already initialized
        mock_engine.begin.assert_not_called()
    
    @patch('backend.database.base.engine')
    async def test_init_db_failure(self, mock_engine):
        """Test database initialization failure"""
        mock_engine.begin.side_effect = Exception("Connection failed")
        
        db_manager = DatabaseManager()
        db_manager.engine = mock_engine
        
        with pytest.raises(Exception, match="Connection failed"):
            await db_manager.init_db()
        
        assert db_manager._initialized is False
    
    async def test_close(self, mock_engine):
        """Test database connection closing"""
        db_manager = DatabaseManager()
        db_manager.engine = mock_engine
        
        await db_manager.close()
        
        mock_engine.dispose.assert_called_once()
    
    @patch('backend.database.base.async_session_maker')
    async def test_get_session_success(self, mock_session_maker):
        """Test successful session creation and cleanup"""
        mock_session = AsyncMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=None)
        
        db_manager = DatabaseManager()
        
        async with db_manager.get_session() as session:
            assert session is mock_session
        
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
    
    @patch('backend.database.base.async_session_maker')
    async def test_get_session_with_exception(self, mock_session_maker):
        """Test session handling with exception"""
        mock_session = AsyncMock()
        mock_session_maker.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session_maker.return_value.__aexit__ = AsyncMock(return_value=None)
        
        db_manager = DatabaseManager()
        
        with pytest.raises(Exception, match="Test error"):
            async with db_manager.get_session() as session:
                raise Exception("Test error")
        
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
    
    async def test_health_check_success(self):
        """Test successful health check"""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar.return_value = 1
        mock_session.execute.return_value = mock_result
        
        db_manager = DatabaseManager()
        
        with patch.object(db_manager, 'get_session') as mock_get_session:
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            result = await db_manager.health_check()
        
        assert result is True
        mock_session.execute.assert_called_once()
    
    async def test_health_check_failure(self):
        """Test health check failure"""
        db_manager = DatabaseManager()
        
        with patch.object(db_manager, 'get_session') as mock_get_session:
            mock_get_session.side_effect = Exception("Connection failed")
            
            result = await db_manager.health_check()
        
        assert result is False


class TestDatabaseConnectionManager:
    """Test DatabaseConnectionManager functionality"""
    
    def test_connection_manager_initialization(self, sample_db_config):
        """Test connection manager initialization"""
        manager = DatabaseConnectionManager(sample_db_config)
        
        assert manager.config == sample_db_config
        assert manager.engine is None
        assert manager.state == ConnectionState.DISCONNECTED
        assert manager.stats['connections_created'] == 0
    
    @patch('backend.database.connection_manager.create_async_engine')
    async def test_connect_success(self, mock_create_engine, sample_db_config):
        """Test successful database connection"""
        mock_engine = AsyncMock()
        mock_conn = AsyncMock()
        mock_create_engine.return_value = mock_engine
        
        # Mock engine.connect context manager
        mock_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        manager = DatabaseConnectionManager(sample_db_config)
        
        with patch.object(manager, '_setup_event_listeners'), \
             patch('asyncio.create_task') as mock_create_task:
            
            result = await manager.connect()
        
        assert result is True
        assert manager.state == ConnectionState.CONNECTED
        assert manager.engine is mock_engine
        assert manager.stats['connections_created'] == 1
        mock_create_engine.assert_called_once()
        mock_create_task.assert_called_once()
    
    @patch('backend.database.connection_manager.create_async_engine')
    async def test_connect_already_connected(self, mock_create_engine, sample_db_config):
        """Test connect when already connected"""
        manager = DatabaseConnectionManager(sample_db_config)
        manager.state = ConnectionState.CONNECTED
        
        result = await manager.connect()
        
        assert result is True
        mock_create_engine.assert_not_called()
    
    @patch('backend.database.connection_manager.create_async_engine')
    async def test_connect_failure(self, mock_create_engine, sample_db_config):
        """Test connection failure"""
        mock_create_engine.side_effect = Exception("Connection failed")
        
        manager = DatabaseConnectionManager(sample_db_config)
        result = await manager.connect()
        
        assert result is False
        assert manager.state == ConnectionState.FAILED
        assert manager.last_error is not None
        assert manager.stats['connections_failed'] == 1
    
    @patch('backend.database.connection_manager.create_async_engine')
    async def test_connect_with_read_replicas(self, mock_create_engine, sample_db_config):
        """Test connection with read replicas"""
        sample_db_config.read_replicas = [
            "postgresql+asyncpg://user:pass@replica1:5432/db",
            "postgresql+asyncpg://user:pass@replica2:5432/db"
        ]
        
        mock_main_engine = AsyncMock()
        mock_replica1_engine = AsyncMock()
        mock_replica2_engine = AsyncMock()
        
        mock_create_engine.side_effect = [mock_main_engine, mock_replica1_engine, mock_replica2_engine]
        
        # Mock connect for main engine
        mock_conn = AsyncMock()
        mock_main_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_main_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        manager = DatabaseConnectionManager(sample_db_config)
        
        with patch.object(manager, '_setup_event_listeners'), \
             patch('asyncio.create_task'):
            
            result = await manager.connect()
        
        assert result is True
        assert len(manager.read_engines) == 2
        assert mock_create_engine.call_count == 3
    
    async def test_disconnect(self, sample_db_config):
        """Test database disconnection"""
        mock_engine = AsyncMock()
        mock_replica_engine = AsyncMock()
        mock_health_task = AsyncMock()
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.engine = mock_engine
        manager.read_engines = [mock_replica_engine]
        manager._health_check_task = mock_health_task
        manager.state = ConnectionState.CONNECTED
        
        await manager.disconnect()
        
        assert manager.engine is None
        assert len(manager.read_engines) == 0
        assert manager.state == ConnectionState.DISCONNECTED
        mock_health_task.cancel.assert_called_once()
        mock_engine.dispose.assert_called_once()
        mock_replica_engine.dispose.assert_called_once()
    
    @patch('backend.database.connection_manager.async_sessionmaker')
    async def test_get_session_write(self, mock_sessionmaker, sample_db_config):
        """Test get_session for write operations"""
        mock_engine = AsyncMock()
        mock_session = AsyncMock()
        mock_session_factory = AsyncMock(return_value=mock_session)
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.engine = mock_engine
        manager.session_factory = mock_session_factory
        manager.state = ConnectionState.CONNECTED
        
        async with manager.get_session(read_only=False) as session:
            assert session is mock_session
        
        mock_session.commit.assert_called_once()
        mock_session.close.assert_called_once()
        assert manager.stats['transactions_committed'] == 1
    
    @patch('backend.database.connection_manager.async_sessionmaker')
    async def test_get_session_read_with_replica(self, mock_sessionmaker, sample_db_config):
        """Test get_session for read operations with replica"""
        mock_main_engine = AsyncMock()
        mock_replica_engine = AsyncMock()
        mock_session = AsyncMock()
        mock_sessionmaker.return_value.return_value = mock_session
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.engine = mock_main_engine
        manager.read_engines = [mock_replica_engine]
        manager.state = ConnectionState.CONNECTED
        
        async with manager.get_session(read_only=True) as session:
            assert session is mock_session
        
        mock_sessionmaker.assert_called_with(
            mock_replica_engine,
            class_=AsyncSession,
            expire_on_commit=False
        )
    
    async def test_get_session_not_connected(self, sample_db_config):
        """Test get_session when not connected"""
        manager = DatabaseConnectionManager(sample_db_config)
        manager.state = ConnectionState.DISCONNECTED
        
        with pytest.raises(RuntimeError, match="Database not connected"):
            async with manager.get_session():
                pass
    
    async def test_get_session_with_exception(self, sample_db_config):
        """Test get_session with exception during transaction"""
        mock_session = AsyncMock()
        mock_session_factory = AsyncMock(return_value=mock_session)
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.session_factory = mock_session_factory
        manager.state = ConnectionState.CONNECTED
        
        with pytest.raises(Exception, match="Test error"):
            async with manager.get_session() as session:
                raise Exception("Test error")
        
        mock_session.rollback.assert_called_once()
        mock_session.close.assert_called_once()
        assert manager.stats['transactions_rolled_back'] == 1
        assert manager.stats['queries_failed'] == 1
    
    def test_get_read_engine_round_robin(self, sample_db_config):
        """Test read engine selection with round-robin"""
        mock_engine1 = AsyncMock()
        mock_engine2 = AsyncMock()
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.read_engines = [mock_engine1, mock_engine2]
        
        # First call should return engine1
        engine1 = manager._get_read_engine()
        assert engine1 is mock_engine1
        assert manager.current_read_index == 1
        
        # Second call should return engine2
        engine2 = manager._get_read_engine()
        assert engine2 is mock_engine2
        assert manager.current_read_index == 0  # Wrapped around
    
    def test_get_read_engine_no_replicas(self, sample_db_config):
        """Test read engine when no replicas available"""
        mock_main_engine = AsyncMock()
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.engine = mock_main_engine
        manager.read_engines = []
        
        engine = manager._get_read_engine()
        assert engine is mock_main_engine
    
    async def test_execute_query(self, sample_db_config):
        """Test raw SQL query execution"""
        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_session.execute.return_value = mock_result
        
        manager = DatabaseConnectionManager(sample_db_config)
        
        with patch.object(manager, 'get_session') as mock_get_session:
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            result = await manager.execute("SELECT * FROM devices", {"limit": 10})
        
        assert result is mock_result
        mock_session.execute.assert_called_once()
    
    async def test_execute_many_queries(self, sample_db_config):
        """Test executing multiple queries"""
        mock_session = AsyncMock()
        mock_result1 = MagicMock()
        mock_result2 = MagicMock()
        mock_session.execute.side_effect = [mock_result1, mock_result2]
        
        manager = DatabaseConnectionManager(sample_db_config)
        
        with patch.object(manager, 'get_session') as mock_get_session:
            mock_get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
            mock_get_session.return_value.__aexit__ = AsyncMock(return_value=None)
            
            params_list = [{"id": 1}, {"id": 2}]
            results = await manager.execute_many("SELECT * FROM devices WHERE id = :id", params_list)
        
        assert len(results) == 2
        assert results[0] is mock_result1
        assert results[1] is mock_result2
        assert mock_session.execute.call_count == 2
    
    def test_get_pool_status(self, sample_db_config):
        """Test getting connection pool status"""
        mock_pool = MagicMock()
        mock_pool.size.return_value = 5
        mock_pool.checkedin.return_value = 3
        mock_pool.overflow.return_value = 2
        
        mock_engine = MagicMock()
        mock_engine.pool = mock_pool
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.engine = mock_engine
        
        status = manager.get_pool_status()
        
        assert status['size'] == 5
        assert status['checked_in'] == 3
        assert status['overflow'] == 2
        assert status['total'] == 7
    
    def test_get_statistics(self, sample_db_config):
        """Test getting connection statistics"""
        manager = DatabaseConnectionManager(sample_db_config)
        manager.stats['connections_created'] = 5
        manager._query_times = [0.1, 0.2, 0.3, 0.5, 1.0]
        manager._slow_queries = [
            {'query': 'SELECT * FROM large_table', 'duration': 2.5}
        ]
        manager.connected_at = datetime.now() - timedelta(hours=1)
        
        with patch.object(manager, 'get_pool_status', return_value={'size': 5}):
            stats = manager.get_statistics()
        
        assert stats['connections_created'] == 5
        assert 'avg_query_time' in stats
        assert stats['max_query_time'] == 1.0
        assert stats['min_query_time'] == 0.1
        assert 'pool_status' in stats
        assert len(stats['slow_queries_list']) == 1
        assert stats['connection_uptime'] > 0
    
    @patch('backend.database.connection_manager.create_async_engine')
    async def test_reconnect_success(self, mock_create_engine, sample_db_config):
        """Test successful reconnection"""
        mock_old_engine = AsyncMock()
        mock_new_engine = AsyncMock()
        mock_conn = AsyncMock()
        
        mock_create_engine.return_value = mock_new_engine
        mock_new_engine.connect.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_new_engine.connect.return_value.__aexit__ = AsyncMock(return_value=None)
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.engine = mock_old_engine
        manager.state = ConnectionState.FAILED
        
        result = await manager.reconnect(max_retries=1)
        
        assert result is True
        assert manager.state == ConnectionState.CONNECTED
        assert manager.engine is mock_new_engine
        mock_old_engine.dispose.assert_called_once()
    
    @patch('backend.database.connection_manager.create_async_engine')
    @patch('asyncio.sleep')
    async def test_reconnect_failure_with_retries(self, mock_sleep, mock_create_engine, sample_db_config):
        """Test reconnection failure with retries"""
        mock_create_engine.side_effect = Exception("Connection failed")
        
        manager = DatabaseConnectionManager(sample_db_config)
        manager.state = ConnectionState.FAILED
        
        result = await manager.reconnect(max_retries=2)
        
        assert result is False
        assert manager.state == ConnectionState.FAILED
        assert mock_create_engine.call_count == 2
        mock_sleep.assert_called_once()  # Backoff between retries


class TestDatabaseTransactionManager:
    """Test DatabaseTransactionManager functionality"""
    
    def test_transaction_manager_initialization(self, sample_db_config):
        """Test transaction manager initialization"""
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        assert tx_manager.connection_manager is connection_manager
    
    async def test_transaction_success(self, sample_db_config):
        """Test successful transaction"""
        mock_session = AsyncMock()
        mock_connection_manager = AsyncMock()
        mock_connection_manager.get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_connection_manager.get_session.return_value.__aexit__ = AsyncMock(return_value=None)
        
        # Mock session.begin context manager
        mock_session.begin.return_value.__aenter__ = AsyncMock()
        mock_session.begin.return_value.__aexit__ = AsyncMock(return_value=None)
        
        tx_manager = DatabaseTransactionManager(mock_connection_manager)
        
        async with tx_manager.transaction() as session:
            assert session is mock_session
        
        mock_session.execute.assert_not_called()  # No isolation level set
    
    async def test_transaction_with_isolation_level(self, sample_db_config):
        """Test transaction with specific isolation level"""
        mock_session = AsyncMock()
        mock_connection_manager = AsyncMock()
        mock_connection_manager.get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_connection_manager.get_session.return_value.__aexit__ = AsyncMock(return_value=None)
        
        # Mock session.begin context manager
        mock_session.begin.return_value.__aenter__ = AsyncMock()
        mock_session.begin.return_value.__aexit__ = AsyncMock(return_value=None)
        
        tx_manager = DatabaseTransactionManager(mock_connection_manager)
        
        async with tx_manager.transaction(isolation_level="SERIALIZABLE") as session:
            assert session is mock_session
        
        mock_session.execute.assert_called_once_with(
            text("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        )
    
    async def test_savepoint_success(self, sample_db_config):
        """Test successful savepoint"""
        mock_session = AsyncMock()
        mock_savepoint = AsyncMock()
        mock_session.begin_nested.return_value = mock_savepoint
        
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        async with tx_manager.savepoint(mock_session, "sp1") as sp:
            assert sp is mock_savepoint
        
        mock_savepoint.commit.assert_called_once()
    
    async def test_savepoint_rollback_on_exception(self, sample_db_config):
        """Test savepoint rollback on exception"""
        mock_session = AsyncMock()
        mock_savepoint = AsyncMock()
        mock_session.begin_nested.return_value = mock_savepoint
        
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        with pytest.raises(Exception, match="Test error"):
            async with tx_manager.savepoint(mock_session, "sp1"):
                raise Exception("Test error")
        
        mock_savepoint.rollback.assert_called_once()
    
    async def test_with_retry_success(self, sample_db_config):
        """Test with_retry successful execution"""
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        async def test_func():
            return "success"
        
        result = await tx_manager.with_retry(test_func, max_retries=3)
        assert result == "success"
    
    @patch('asyncio.sleep')
    async def test_with_retry_with_retries(self, mock_sleep, sample_db_config):
        """Test with_retry with retries on operational error"""
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        call_count = 0
        async def test_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise OperationalError("Connection lost", None, None)
            return "success"
        
        result = await tx_manager.with_retry(test_func, max_retries=3)
        assert result == "success"
        assert call_count == 3
        assert mock_sleep.call_count == 2  # 2 retry delays
    
    async def test_with_retry_non_retryable_error(self, sample_db_config):
        """Test with_retry with non-retryable error"""
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        async def test_func():
            raise ValueError("Invalid value")  # Not in retry_on list
        
        with pytest.raises(ValueError, match="Invalid value"):
            await tx_manager.with_retry(test_func, max_retries=3)
    
    @patch('asyncio.sleep')
    async def test_with_retry_max_retries_exceeded(self, mock_sleep, sample_db_config):
        """Test with_retry when max retries exceeded"""
        connection_manager = DatabaseConnectionManager(sample_db_config)
        tx_manager = DatabaseTransactionManager(connection_manager)
        
        async def test_func():
            raise OperationalError("Persistent error", None, None)
        
        with pytest.raises(OperationalError, match="Persistent error"):
            await tx_manager.with_retry(test_func, max_retries=2)
        
        assert mock_sleep.call_count == 1  # Only one retry delay before final failure


class TestDatabaseConfig:
    """Test DatabaseConfig functionality"""
    
    def test_database_config_initialization(self):
        """Test database config initialization"""
        config = DatabaseConfig(
            database_type=DatabaseType.POSTGRESQL,
            host="localhost",
            port=5432,
            database="test_db",
            username="test_user",
            password="test_pass"
        )
        
        assert config.database_type == DatabaseType.POSTGRESQL
        assert config.host == "localhost"
        assert config.port == 5432
        assert config.database == "test_db"
        assert config.pool_config.pool_size == 20  # Default value
    
    def test_get_url_postgresql_async(self):
        """Test PostgreSQL URL generation (async)"""
        config = DatabaseConfig(
            database_type=DatabaseType.POSTGRESQL,
            host="localhost",
            port=5432,
            database="test_db",
            username="user",
            password="pass"
        )
        
        with patch('backend.database.connection_manager.ASYNCPG_AVAILABLE', True):
            url = config.get_url(async_mode=True)
        
        expected = "postgresql+asyncpg://user:pass@localhost:5432/test_db"
        assert url == expected
    
    def test_get_url_mysql_async(self):
        """Test MySQL URL generation (async)"""
        config = DatabaseConfig(
            database_type=DatabaseType.MYSQL,
            host="localhost",
            port=3306,
            database="test_db",
            username="user",
            password="pass"
        )
        
        with patch('backend.database.connection_manager.AIOMYSQL_AVAILABLE', True):
            url = config.get_url(async_mode=True)
        
        expected = "mysql+aiomysql://user:pass@localhost:3306/test_db"
        assert url == expected
    
    def test_get_url_sqlite(self):
        """Test SQLite URL generation"""
        config = DatabaseConfig(
            database_type=DatabaseType.SQLITE,
            host="",
            port=0,
            database="/path/to/db.sqlite",
            username="",
            password=""
        )
        
        url = config.get_url(async_mode=True)
        expected = "sqlite+aiosqlite:////path/to/db.sqlite"
        assert url == expected
    
    def test_get_url_with_ssl(self):
        """Test URL generation with SSL"""
        config = DatabaseConfig(
            database_type=DatabaseType.POSTGRESQL,
            host="localhost",
            port=5432,
            database="test_db",
            username="user",
            password="pass",
            ssl_enabled=True,
            ssl_ca="/path/to/ca.crt",
            ssl_cert="/path/to/client.crt",
            ssl_key="/path/to/client.key"
        )
        
        with patch('backend.database.connection_manager.ASYNCPG_AVAILABLE', True):
            url = config.get_url(async_mode=True)
        
        assert "postgresql+asyncpg://user:pass@localhost:5432/test_db?" in url
        assert "sslca=/path/to/ca.crt" in url
        assert "sslcert=/path/to/client.crt" in url
        assert "sslkey=/path/to/client.key" in url
    
    def test_get_url_unsupported_database(self):
        """Test URL generation with unsupported database type"""
        config = DatabaseConfig(
            database_type=DatabaseType.MARIADB,  # Not implemented in get_url
            host="localhost",
            port=3306,
            database="test_db",
            username="user",
            password="pass"
        )
        
        with pytest.raises(ValueError, match="Unsupported database type"):
            config.get_url()


class TestDatabaseConvenienceFunctions:
    """Test convenience functions from base module"""
    
    @patch('backend.database.base.db_manager')
    async def test_init_db_function(self, mock_db_manager):
        """Test init_db convenience function"""
        mock_db_manager.init_db = AsyncMock()
        
        await init_db()
        
        mock_db_manager.init_db.assert_called_once()
    
    @patch('backend.database.base.db_manager')
    async def test_get_session_function(self, mock_db_manager):
        """Test get_session convenience function"""
        mock_session = AsyncMock()
        mock_db_manager.get_session.return_value.__aenter__ = AsyncMock(return_value=mock_session)
        mock_db_manager.get_session.return_value.__aexit__ = AsyncMock(return_value=None)
        
        async with get_session() as session:
            assert session is mock_session


if __name__ == "__main__":
    pytest.main([__file__, "-v"])