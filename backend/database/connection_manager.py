"""
Production database connection manager with proper pooling and failover.
Handles connection lifecycle, pooling, retries, and health monitoring.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
from contextlib import asynccontextmanager
import hashlib
import json

from sqlalchemy.ext.asyncio import (
    AsyncSession, AsyncEngine, create_async_engine,
    async_sessionmaker, AsyncConnection
)
from sqlalchemy.pool import NullPool, QueuePool, StaticPool
from sqlalchemy import event, pool, text, MetaData
from sqlalchemy.exc import (
    DBAPIError, OperationalError, DatabaseError,
    IntegrityError, DataError, ProgrammingError
)
from sqlalchemy.orm import Session

try:
    import asyncpg
    ASYNCPG_AVAILABLE = True
except ImportError:
    ASYNCPG_AVAILABLE = False

try:
    import aiomysql
    AIOMYSQL_AVAILABLE = True
except ImportError:
    AIOMYSQL_AVAILABLE = False

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Supported database types"""
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"
    MARIADB = "mariadb"


class ConnectionState(Enum):
    """Connection states"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    FAILED = "failed"
    RECONNECTING = "reconnecting"


@dataclass
class ConnectionPoolConfig:
    """Connection pool configuration"""
    pool_size: int = 20
    max_overflow: int = 10
    pool_timeout: float = 30.0
    pool_recycle: int = 3600
    pool_pre_ping: bool = True
    echo_pool: bool = False
    
    # Advanced pooling
    pool_use_lifo: bool = True  # Last-in-first-out for better cache locality
    connect_args: Dict[str, Any] = field(default_factory=dict)
    
    # Connection validation
    pool_reset_on_return: str = "rollback"  # rollback, commit, or None
    
    # Performance tuning
    statement_cache_size: int = 1024
    query_cache_size: int = 1024


@dataclass
class DatabaseConfig:
    """Complete database configuration"""
    database_type: DatabaseType
    host: str
    port: int
    database: str
    username: str
    password: str
    
    # Connection pooling
    pool_config: ConnectionPoolConfig = field(default_factory=ConnectionPoolConfig)
    
    # Failover configuration
    read_replicas: List[str] = field(default_factory=list)
    failover_timeout: float = 30.0
    
    # SSL/TLS
    ssl_enabled: bool = False
    ssl_ca: Optional[str] = None
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    
    # Query configuration
    statement_timeout: int = 30000  # milliseconds
    lock_timeout: int = 10000  # milliseconds
    idle_in_transaction_timeout: int = 60000  # milliseconds
    
    # Monitoring
    slow_query_threshold: float = 1.0  # seconds
    log_queries: bool = False
    
    def get_url(self, async_mode: bool = True) -> str:
        """Generate database URL"""
        if self.database_type == DatabaseType.POSTGRESQL:
            driver = "asyncpg" if async_mode and ASYNCPG_AVAILABLE else "psycopg2"
            protocol = "postgresql+asyncpg" if async_mode else "postgresql+psycopg2"
        elif self.database_type == DatabaseType.MYSQL:
            driver = "aiomysql" if async_mode and AIOMYSQL_AVAILABLE else "pymysql"
            protocol = "mysql+aiomysql" if async_mode else "mysql+pymysql"
        elif self.database_type == DatabaseType.SQLITE:
            return f"sqlite+aiosqlite:///{self.database}" if async_mode else f"sqlite:///{self.database}"
        else:
            raise ValueError(f"Unsupported database type: {self.database_type}")
        
        # Build URL with credentials
        url = f"{protocol}://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}"
        
        # Add SSL parameters if enabled
        if self.ssl_enabled:
            ssl_params = []
            if self.ssl_ca:
                ssl_params.append(f"sslca={self.ssl_ca}")
            if self.ssl_cert:
                ssl_params.append(f"sslcert={self.ssl_cert}")
            if self.ssl_key:
                ssl_params.append(f"sslkey={self.ssl_key}")
            
            if ssl_params:
                url += "?" + "&".join(ssl_params)
        
        return url


class DatabaseConnectionManager:
    """Production database connection manager"""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine: Optional[AsyncEngine] = None
        self.session_factory: Optional[async_sessionmaker] = None
        
        # Read replica engines
        self.read_engines: List[AsyncEngine] = []
        self.current_read_index = 0
        
        # Connection state
        self.state = ConnectionState.DISCONNECTED
        self.connected_at: Optional[datetime] = None
        self.last_error: Optional[Exception] = None
        
        # Statistics
        self.stats = {
            'connections_created': 0,
            'connections_failed': 0,
            'queries_executed': 0,
            'queries_failed': 0,
            'slow_queries': 0,
            'transactions_committed': 0,
            'transactions_rolled_back': 0,
            'connection_pool_size': 0,
            'connection_pool_overflow': 0
        }
        
        # Health check
        self._health_check_task: Optional[asyncio.Task] = None
        self._health_check_interval = 30.0
        
        # Query monitoring
        self._query_times: List[float] = []
        self._slow_queries: List[Dict[str, Any]] = []
    
    async def connect(self) -> bool:
        """Establish database connection"""
        if self.state == ConnectionState.CONNECTED:
            return True
        
        self.state = ConnectionState.CONNECTING
        
        try:
            # Create main engine
            self.engine = await self._create_engine(self.config.get_url())
            
            # Test connection
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            
            # Create session factory
            self.session_factory = async_sessionmaker(
                self.engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Setup read replicas
            for replica_url in self.config.read_replicas:
                try:
                    replica_engine = await self._create_engine(replica_url)
                    self.read_engines.append(replica_engine)
                except Exception as e:
                    logger.warning(f"Failed to connect to read replica {replica_url}: {e}")
            
            # Setup event listeners
            self._setup_event_listeners()
            
            # Start health check
            self._health_check_task = asyncio.create_task(self._health_check_loop())
            
            self.state = ConnectionState.CONNECTED
            self.connected_at = datetime.now()
            self.stats['connections_created'] += 1
            
            logger.info(f"Connected to {self.config.database_type.value} database at {self.config.host}:{self.config.port}")
            return True
            
        except Exception as e:
            self.state = ConnectionState.FAILED
            self.last_error = e
            self.stats['connections_failed'] += 1
            logger.error(f"Failed to connect to database: {e}")
            return False
    
    async def _create_engine(self, url: str) -> AsyncEngine:
        """Create async engine with proper configuration"""
        pool_config = self.config.pool_config
        
        # Prepare connect args
        connect_args = pool_config.connect_args.copy()
        
        # Add database-specific connect args
        if self.config.database_type == DatabaseType.POSTGRESQL and ASYNCPG_AVAILABLE:
            connect_args.update({
                'server_settings': {
                    'application_name': 'CHM',
                    'jit': 'off'  # Disable JIT for predictable performance
                },
                'statement_cache_size': pool_config.statement_cache_size,
                'max_cached_statement_lifetime': 300,
                'command_timeout': self.config.statement_timeout / 1000,
                'ssl': 'require' if self.config.ssl_enabled else None
            })
        elif self.config.database_type == DatabaseType.MYSQL and AIOMYSQL_AVAILABLE:
            connect_args.update({
                'autocommit': False,
                'charset': 'utf8mb4',
                'connect_timeout': self.config.failover_timeout,
                'read_timeout': self.config.statement_timeout / 1000,
                'write_timeout': self.config.statement_timeout / 1000
            })
        
        # Create engine
        engine = create_async_engine(
            url,
            poolclass=QueuePool,
            pool_size=pool_config.pool_size,
            max_overflow=pool_config.max_overflow,
            pool_timeout=pool_config.pool_timeout,
            pool_recycle=pool_config.pool_recycle,
            pool_pre_ping=pool_config.pool_pre_ping,
            pool_use_lifo=pool_config.pool_use_lifo,
            echo_pool=pool_config.echo_pool,
            connect_args=connect_args,
            pool_reset_on_return=pool_config.pool_reset_on_return,
            echo=self.config.log_queries
        )
        
        return engine
    
    def _setup_event_listeners(self):
        """Setup SQLAlchemy event listeners for monitoring"""
        if not self.engine:
            return
        
        # Connection events
        @event.listens_for(self.engine.sync_engine, "connect")
        def receive_connect(dbapi_conn, connection_record):
            """Handle new connection"""
            connection_record.info['connect_time'] = time.time()
            
            # Set connection parameters for PostgreSQL
            if self.config.database_type == DatabaseType.POSTGRESQL:
                with dbapi_conn.cursor() as cursor:
                    cursor.execute(f"SET statement_timeout = {self.config.statement_timeout}")
                    cursor.execute(f"SET lock_timeout = {self.config.lock_timeout}")
                    cursor.execute(f"SET idle_in_transaction_session_timeout = {self.config.idle_in_transaction_timeout}")
        
        @event.listens_for(self.engine.sync_engine, "checkout")
        def receive_checkout(dbapi_conn, connection_record, connection_proxy):
            """Handle connection checkout from pool"""
            self.stats['connection_pool_size'] = self.engine.pool.size()
            self.stats['connection_pool_overflow'] = self.engine.pool.overflow()
        
        # Query execution events
        @event.listens_for(self.engine.sync_engine, "before_execute")
        def receive_before_execute(conn, clauseelement, multiparams, params, execution_options):
            """Before query execution"""
            conn.info['query_start_time'] = time.time()
        
        @event.listens_for(self.engine.sync_engine, "after_execute")
        def receive_after_execute(conn, clauseelement, multiparams, params, execution_options, result):
            """After query execution"""
            query_time = time.time() - conn.info.get('query_start_time', time.time())
            self.stats['queries_executed'] += 1
            self._query_times.append(query_time)
            
            # Track slow queries
            if query_time > self.config.slow_query_threshold:
                self.stats['slow_queries'] += 1
                self._slow_queries.append({
                    'query': str(clauseelement),
                    'params': params,
                    'duration': query_time,
                    'timestamp': datetime.now()
                })
                
                # Keep only last 100 slow queries
                if len(self._slow_queries) > 100:
                    self._slow_queries = self._slow_queries[-100:]
                
                logger.warning(f"Slow query detected ({query_time:.2f}s): {str(clauseelement)[:100]}...")
    
    async def disconnect(self):
        """Disconnect from database"""
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        # Close read replicas
        for engine in self.read_engines:
            await engine.dispose()
        self.read_engines.clear()
        
        # Close main engine
        if self.engine:
            await self.engine.dispose()
            self.engine = None
        
        self.session_factory = None
        self.state = ConnectionState.DISCONNECTED
        self.connected_at = None
        
        logger.info("Disconnected from database")
    
    @asynccontextmanager
    async def get_session(self, read_only: bool = False):
        """Get database session with automatic cleanup"""
        if self.state != ConnectionState.CONNECTED:
            raise RuntimeError("Database not connected")
        
        # Use read replica for read-only operations
        if read_only and self.read_engines:
            engine = self._get_read_engine()
            async_session = async_sessionmaker(
                engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            session = async_session()
        else:
            session = self.session_factory()
        
        try:
            yield session
            await session.commit()
            self.stats['transactions_committed'] += 1
        except Exception as e:
            await session.rollback()
            self.stats['transactions_rolled_back'] += 1
            self.stats['queries_failed'] += 1
            raise
        finally:
            await session.close()
    
    def _get_read_engine(self) -> AsyncEngine:
        """Get next read replica engine (round-robin)"""
        if not self.read_engines:
            return self.engine
        
        engine = self.read_engines[self.current_read_index]
        self.current_read_index = (self.current_read_index + 1) % len(self.read_engines)
        return engine
    
    async def execute(self, query: str, params: Optional[Dict[str, Any]] = None, 
                     read_only: bool = False) -> Any:
        """Execute raw SQL query"""
        async with self.get_session(read_only=read_only) as session:
            result = await session.execute(text(query), params or {})
            return result
    
    async def execute_many(self, query: str, params_list: List[Dict[str, Any]]) -> List[Any]:
        """Execute query with multiple parameter sets"""
        results = []
        async with self.get_session() as session:
            for params in params_list:
                result = await session.execute(text(query), params)
                results.append(result)
        return results
    
    async def _health_check_loop(self):
        """Periodic health check"""
        while True:
            try:
                await asyncio.sleep(self._health_check_interval)
                
                # Check main connection
                try:
                    async with self.engine.connect() as conn:
                        await conn.execute(text("SELECT 1"))
                except Exception as e:
                    logger.error(f"Database health check failed: {e}")
                    self.state = ConnectionState.RECONNECTING
                    
                    # Try to reconnect
                    await self.reconnect()
                
                # Check read replicas
                for i, engine in enumerate(self.read_engines):
                    try:
                        async with engine.connect() as conn:
                            await conn.execute(text("SELECT 1"))
                    except Exception as e:
                        logger.warning(f"Read replica {i} health check failed: {e}")
                        # Could implement replica failover here
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
    
    async def reconnect(self, max_retries: int = 3, backoff: float = 2.0) -> bool:
        """Reconnect to database with exponential backoff"""
        for attempt in range(max_retries):
            try:
                logger.info(f"Reconnection attempt {attempt + 1}/{max_retries}")
                
                # Dispose existing engine
                if self.engine:
                    await self.engine.dispose()
                
                # Create new engine
                self.engine = await self._create_engine(self.config.get_url())
                
                # Test connection
                async with self.engine.connect() as conn:
                    await conn.execute(text("SELECT 1"))
                
                # Recreate session factory
                self.session_factory = async_sessionmaker(
                    self.engine,
                    class_=AsyncSession,
                    expire_on_commit=False
                )
                
                self.state = ConnectionState.CONNECTED
                logger.info("Successfully reconnected to database")
                return True
                
            except Exception as e:
                logger.error(f"Reconnection attempt {attempt + 1} failed: {e}")
                
                if attempt < max_retries - 1:
                    wait_time = backoff ** attempt
                    await asyncio.sleep(wait_time)
        
        self.state = ConnectionState.FAILED
        return False
    
    def get_pool_status(self) -> Dict[str, Any]:
        """Get connection pool status"""
        if not self.engine:
            return {}
        
        pool = self.engine.pool
        return {
            'size': pool.size(),
            'checked_in': pool.checkedin(),
            'overflow': pool.overflow(),
            'total': pool.size() + pool.overflow(),
            'max_overflow': self.config.pool_config.max_overflow
        }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get connection statistics"""
        stats = self.stats.copy()
        
        # Add computed statistics
        if self._query_times:
            stats['avg_query_time'] = sum(self._query_times) / len(self._query_times)
            stats['max_query_time'] = max(self._query_times)
            stats['min_query_time'] = min(self._query_times)
        
        stats['pool_status'] = self.get_pool_status()
        stats['slow_queries_list'] = self._slow_queries[-10:]  # Last 10 slow queries
        stats['connection_uptime'] = (
            (datetime.now() - self.connected_at).total_seconds()
            if self.connected_at else 0
        )
        
        return stats


class DatabaseTransactionManager:
    """Manage database transactions with proper isolation"""
    
    def __init__(self, connection_manager: DatabaseConnectionManager):
        self.connection_manager = connection_manager
    
    @asynccontextmanager
    async def transaction(self, isolation_level: Optional[str] = None):
        """Execute within a transaction with specified isolation level"""
        async with self.connection_manager.get_session() as session:
            if isolation_level:
                await session.execute(text(f"SET TRANSACTION ISOLATION LEVEL {isolation_level}"))
            
            async with session.begin():
                yield session
    
    @asynccontextmanager
    async def savepoint(self, session: AsyncSession, name: str):
        """Create a savepoint within a transaction"""
        sp = await session.begin_nested()
        try:
            yield sp
            await sp.commit()
        except Exception:
            await sp.rollback()
            raise
    
    async def with_retry(self, func: Callable, max_retries: int = 3, 
                        retry_on: Optional[List[type]] = None):
        """Execute function with automatic retry on specific exceptions"""
        retry_on = retry_on or [OperationalError, DBAPIError]
        
        for attempt in range(max_retries):
            try:
                return await func()
            except Exception as e:
                if type(e) not in retry_on or attempt == max_retries - 1:
                    raise
                
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"Transaction failed (attempt {attempt + 1}), retrying in {wait_time}s: {e}")
                await asyncio.sleep(wait_time)