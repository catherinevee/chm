"""
Connection Pool Manager for SNMP and SSH connections
"""

import asyncio
import time
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from contextlib import asynccontextmanager
import asyncssh
from pysnmp.hlapi import SnmpEngine
import weakref
from threading import Lock
import concurrent.futures

logger = logging.getLogger(__name__)


@dataclass
class ConnectionInfo:
    """Information about a pooled connection"""
    connection: Any
    created_at: datetime
    last_used: datetime
    use_count: int = 0
    is_healthy: bool = True
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    
    def touch(self):
        """Update last used time"""
        self.last_used = datetime.utcnow()
        self.use_count += 1


class SSHConnectionPool:
    """Connection pool for SSH connections"""
    
    def __init__(
        self,
        min_size: int = 2,
        max_size: int = 10,
        max_idle_time: int = 300,  # 5 minutes
        max_lifetime: int = 3600,  # 1 hour
        health_check_interval: int = 60  # 1 minute
    ):
        self.min_size = min_size
        self.max_size = max_size
        self.max_idle_time = timedelta(seconds=max_idle_time)
        self.max_lifetime = timedelta(seconds=max_lifetime)
        self.health_check_interval = health_check_interval
        
        # Pool storage: {connection_key: [ConnectionInfo, ...]}
        self._pools: Dict[str, List[ConnectionInfo]] = {}
        self._pool_locks: Dict[str, asyncio.Lock] = {}
        self._creating: Dict[str, asyncio.Lock] = {}
        
        # Statistics
        self.stats = {
            'connections_created': 0,
            'connections_reused': 0,
            'connections_closed': 0,
            'health_checks_performed': 0,
            'failed_connections': 0
        }
        
        # Background tasks
        self._health_check_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown = False
    
    def _get_connection_key(self, host: str, port: int, username: str) -> str:
        """Generate unique key for connection parameters"""
        return f"{host}:{port}:{username}"
    
    async def start(self):
        """Start background maintenance tasks"""
        if not self._health_check_task:
            self._health_check_task = asyncio.create_task(self._health_check_loop())
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("SSH connection pool started")
    
    async def stop(self):
        """Stop pool and close all connections"""
        self._shutdown = True
        
        # Cancel background tasks
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        for pool in self._pools.values():
            for conn_info in pool:
                await self._close_connection(conn_info)
        
        self._pools.clear()
        logger.info("SSH connection pool stopped")
    
    async def _create_connection(
        self,
        host: str,
        port: int,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        timeout: int = 30
    ) -> asyncssh.SSHClientConnection:
        """Create a new SSH connection"""
        try:
            connect_params = {
                'host': host,
                'port': port,
                'username': username,
                'known_hosts': None,
                'connect_timeout': timeout
            }
            
            if password:
                connect_params['password'] = password
            elif key_path:
                connect_params['client_keys'] = [key_path]
            
            conn = await asyncssh.connect(**connect_params)
            self.stats['connections_created'] += 1
            logger.debug(f"Created new SSH connection to {host}:{port}")
            return conn
            
        except Exception as e:
            self.stats['failed_connections'] += 1
            logger.error(f"Failed to create SSH connection to {host}:{port}: {e}")
            raise
    
    async def _close_connection(self, conn_info: ConnectionInfo):
        """Close an SSH connection"""
        try:
            if conn_info.connection:
                conn_info.connection.close()
                await conn_info.connection.wait_closed()
                self.stats['connections_closed'] += 1
        except Exception as e:
            logger.error(f"Error closing SSH connection: {e}")
    
    async def _check_connection_health(self, conn_info: ConnectionInfo) -> bool:
        """Check if connection is still healthy"""
        try:
            async with conn_info.lock:
                # Simple echo test
                result = await asyncio.wait_for(
                    conn_info.connection.run('echo test', check=True),
                    timeout=5
                )
                return result.exit_status == 0
        except Exception:
            return False
    
    @asynccontextmanager
    async def acquire(
        self,
        host: str,
        port: int = 22,
        username: str = None,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        timeout: int = 30
    ):
        """Acquire a connection from the pool"""
        conn_key = self._get_connection_key(host, port, username)
        
        # Ensure pool exists for this key
        if conn_key not in self._pools:
            self._pools[conn_key] = []
            self._pool_locks[conn_key] = asyncio.Lock()
        
        pool = self._pools[conn_key]
        pool_lock = self._pool_locks[conn_key]
        
        conn_info = None
        
        try:
            async with pool_lock:
                # Try to find a healthy, idle connection
                now = datetime.utcnow()
                for existing in pool[:]:
                    if existing.is_healthy and not existing.lock.locked():
                        # Check if connection is not too old
                        if now - existing.created_at < self.max_lifetime:
                            if now - existing.last_used < self.max_idle_time:
                                conn_info = existing
                                break
                        else:
                            # Connection too old, remove it
                            pool.remove(existing)
                            await self._close_connection(existing)
                
                # Create new connection if needed
                if not conn_info and len(pool) < self.max_size:
                    conn = await self._create_connection(
                        host, port, username, password, key_path, timeout
                    )
                    conn_info = ConnectionInfo(
                        connection=conn,
                        created_at=now,
                        last_used=now
                    )
                    pool.append(conn_info)
            
            if not conn_info:
                # Pool is full, wait for a connection
                retry_count = 0
                while retry_count < 10 and not conn_info:
                    await asyncio.sleep(0.5)
                    async with pool_lock:
                        for existing in pool:
                            if existing.is_healthy and not existing.lock.locked():
                                conn_info = existing
                                break
                    retry_count += 1
                
                if not conn_info:
                    raise Exception(f"No available connections in pool for {conn_key}")
            
            # Lock and use the connection
            async with conn_info.lock:
                conn_info.touch()
                self.stats['connections_reused'] += 1
                yield conn_info.connection
                
        except Exception as e:
            if conn_info:
                conn_info.is_healthy = False
            raise
    
    async def _health_check_loop(self):
        """Periodically check connection health"""
        while not self._shutdown:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                for pool in self._pools.values():
                    for conn_info in pool[:]:
                        if not conn_info.lock.locked():
                            is_healthy = await self._check_connection_health(conn_info)
                            conn_info.is_healthy = is_healthy
                            
                            if not is_healthy:
                                pool.remove(conn_info)
                                await self._close_connection(conn_info)
                
                self.stats['health_checks_performed'] += 1
                
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
    
    async def _cleanup_loop(self):
        """Periodically clean up idle connections"""
        while not self._shutdown:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                now = datetime.utcnow()
                
                for conn_key, pool in list(self._pools.items()):
                    async with self._pool_locks.get(conn_key, asyncio.Lock()):
                        # Remove idle and old connections
                        for conn_info in pool[:]:
                            if not conn_info.lock.locked():
                                # Check idle time
                                if now - conn_info.last_used > self.max_idle_time:
                                    pool.remove(conn_info)
                                    await self._close_connection(conn_info)
                                    logger.debug(f"Closed idle connection for {conn_key}")
                                # Check lifetime
                                elif now - conn_info.created_at > self.max_lifetime:
                                    pool.remove(conn_info)
                                    await self._close_connection(conn_info)
                                    logger.debug(f"Closed old connection for {conn_key}")
                        
                        # Maintain minimum pool size
                        while len(pool) < self.min_size and not self._shutdown:
                            try:
                                # Parse connection key
                                parts = conn_key.split(':')
                                if len(parts) >= 3:
                                    host, port, username = parts[0], int(parts[1]), parts[2]
                                    conn = await self._create_connection(
                                        host, port, username
                                    )
                                    conn_info = ConnectionInfo(
                                        connection=conn,
                                        created_at=now,
                                        last_used=now
                                    )
                                    pool.append(conn_info)
                            except Exception as e:
                                logger.error(f"Error maintaining pool size: {e}")
                                break
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        pool_info = {}
        for conn_key, pool in self._pools.items():
            pool_info[conn_key] = {
                'total': len(pool),
                'healthy': sum(1 for c in pool if c.is_healthy),
                'in_use': sum(1 for c in pool if c.lock.locked())
            }
        
        return {
            'pools': pool_info,
            'stats': self.stats,
            'config': {
                'min_size': self.min_size,
                'max_size': self.max_size,
                'max_idle_time': self.max_idle_time.total_seconds(),
                'max_lifetime': self.max_lifetime.total_seconds()
            }
        }


class SNMPConnectionPool:
    """Connection pool for SNMP engines with thread pool executor"""
    
    def __init__(
        self,
        max_workers: int = 20,
        engine_cache_size: int = 100,
        engine_ttl: int = 300  # 5 minutes
    ):
        self.max_workers = max_workers
        self.engine_cache_size = engine_cache_size
        self.engine_ttl = timedelta(seconds=engine_ttl)
        
        # Thread pool for SNMP operations
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        
        # SNMP engine cache
        self._engines: Dict[str, Tuple[SnmpEngine, datetime]] = {}
        self._engine_lock = Lock()
        
        # Statistics
        self.stats = {
            'engines_created': 0,
            'engines_reused': 0,
            'engines_evicted': 0,
            'operations_performed': 0
        }
        
        self._shutdown = False
        self._cleanup_task: Optional[asyncio.Task] = None
    
    def _get_engine_key(self, ip_address: str, community: str, version: str) -> str:
        """Generate unique key for SNMP parameters"""
        return f"{ip_address}:{community}:{version}"
    
    def get_or_create_engine(self, ip_address: str, community: str, version: str) -> SnmpEngine:
        """Get or create an SNMP engine"""
        engine_key = self._get_engine_key(ip_address, community, version)
        
        with self._engine_lock:
            # Check if engine exists and is not expired
            if engine_key in self._engines:
                engine, created_at = self._engines[engine_key]
                if datetime.utcnow() - created_at < self.engine_ttl:
                    self.stats['engines_reused'] += 1
                    # Update timestamp
                    self._engines[engine_key] = (engine, datetime.utcnow())
                    return engine
                else:
                    # Engine expired, remove it
                    del self._engines[engine_key]
                    self.stats['engines_evicted'] += 1
            
            # Create new engine
            engine = SnmpEngine()
            self._engines[engine_key] = (engine, datetime.utcnow())
            self.stats['engines_created'] += 1
            
            # Evict oldest engines if cache is full
            if len(self._engines) > self.engine_cache_size:
                oldest_key = min(
                    self._engines.keys(),
                    key=lambda k: self._engines[k][1]
                )
                del self._engines[oldest_key]
                self.stats['engines_evicted'] += 1
            
            return engine
    
    async def start(self):
        """Start the SNMP pool"""
        if not self._cleanup_task:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("SNMP connection pool started")
    
    async def stop(self):
        """Stop the SNMP pool"""
        self._shutdown = True
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Shutdown executor
        self.executor.shutdown(wait=False)
        
        # Clear engine cache
        with self._engine_lock:
            self._engines.clear()
        
        logger.info("SNMP connection pool stopped")
    
    async def _cleanup_loop(self):
        """Periodically clean up expired engines"""
        while not self._shutdown:
            try:
                await asyncio.sleep(60)  # Check every minute
                
                with self._engine_lock:
                    now = datetime.utcnow()
                    expired_keys = [
                        key for key, (_, created_at) in self._engines.items()
                        if now - created_at > self.engine_ttl
                    ]
                    
                    for key in expired_keys:
                        del self._engines[key]
                        self.stats['engines_evicted'] += 1
                    
                    if expired_keys:
                        logger.debug(f"Evicted {len(expired_keys)} expired SNMP engines")
                
            except Exception as e:
                logger.error(f"Error in SNMP cleanup loop: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pool statistics"""
        with self._engine_lock:
            engine_info = {
                'cached_engines': len(self._engines),
                'oldest_engine_age': (
                    (datetime.utcnow() - min(
                        (created_at for _, created_at in self._engines.values()),
                        default=datetime.utcnow()
                    )).total_seconds() if self._engines else 0
                )
            }
        
        return {
            'executor': {
                'max_workers': self.max_workers,
                'active_threads': self.executor._threads.__len__() if hasattr(self.executor, '_threads') else 0
            },
            'engines': engine_info,
            'stats': self.stats,
            'config': {
                'engine_cache_size': self.engine_cache_size,
                'engine_ttl': self.engine_ttl.total_seconds()
            }
        }


# Global connection pool instances
ssh_pool = SSHConnectionPool()
snmp_pool = SNMPConnectionPool()