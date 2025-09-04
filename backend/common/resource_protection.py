"""
Comprehensive resource protection and limits for network monitoring operations
"""

import asyncio
import psutil
import time
import logging
import functools
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass
from contextlib import asynccontextmanager
from collections import deque, defaultdict
import threading
import weakref

from backend.config import settings

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimits:
    """Resource limit configuration"""
    max_memory_mb: int = 1024  # Maximum memory usage in MB
    max_cpu_percent: float = 80.0  # Maximum CPU usage percentage
    max_open_files: int = 1000  # Maximum open file descriptors
    max_network_connections: int = 500  # Maximum concurrent network connections
    max_concurrent_operations: int = 100  # Maximum concurrent operations
    max_operation_duration: int = 300  # Maximum operation duration in seconds
    max_requests_per_minute: int = 1000  # Rate limiting
    max_queue_size: int = 10000  # Maximum queue size for operations
    memory_check_interval: float = 5.0  # Memory monitoring interval
    cleanup_threshold: float = 0.9  # Cleanup threshold (90% of limit)


@dataclass 
class ResourceMetrics:
    """Current resource usage metrics"""
    memory_mb: float
    memory_percent: float
    cpu_percent: float
    open_files: int
    network_connections: int
    concurrent_operations: int
    queue_size: int
    uptime_seconds: float
    last_cleanup: Optional[datetime] = None


class ResourceMonitor:
    """System resource monitoring and alerting"""
    
    def __init__(self, limits: ResourceLimits):
        self.limits = limits
        self.process = psutil.Process()
        self.start_time = datetime.now()
        self.monitoring = False
        self.monitor_task = None
        self._metrics_history = deque(maxlen=100)
        self._lock = asyncio.Lock()
        
    async def start_monitoring(self):
        """Start continuous resource monitoring"""
        if self.monitoring:
            return
            
        self.monitoring = True
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Resource monitoring started")
    
    async def stop_monitoring(self):
        """Stop resource monitoring"""
        self.monitoring = False
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Resource monitoring stopped")
    
    async def _monitor_loop(self):
        """Main monitoring loop"""
        try:
            while self.monitoring:
                try:
                    metrics = await self.get_current_metrics()
                    async with self._lock:
                        self._metrics_history.append((datetime.now(), metrics))
                    
                    # Check for resource violations
                    await self._check_limits(metrics)
                    
                    await asyncio.sleep(self.limits.memory_check_interval)
                    
                except Exception as e:
                    logger.error(f"Error in resource monitoring loop: {e}")
                    await asyncio.sleep(5.0)  # Back off on error
                    
        except asyncio.CancelledError:
            logger.debug("Resource monitoring cancelled")
    
    async def get_current_metrics(self) -> ResourceMetrics:
        """Get current system resource metrics"""
        try:
            # Memory metrics
            memory_info = self.process.memory_info()
            memory_mb = memory_info.rss / 1024 / 1024
            memory_percent = self.process.memory_percent()
            
            # CPU metrics
            cpu_percent = self.process.cpu_percent()
            
            # File descriptor count
            try:
                open_files = self.process.num_fds() if hasattr(self.process, 'num_fds') else 0
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                open_files = 0
            
            # Network connections
            try:
                connections = len(self.process.connections())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                connections = 0
            
            # Uptime
            uptime = (datetime.now() - self.start_time).total_seconds()
            
            return ResourceMetrics(
                memory_mb=memory_mb,
                memory_percent=memory_percent,
                cpu_percent=cpu_percent,
                open_files=open_files,
                network_connections=connections,
                concurrent_operations=0,  # Will be set by operation manager
                queue_size=0,  # Will be set by operation manager
                uptime_seconds=uptime
            )
            
        except Exception as e:
            logger.error(f"Error getting resource metrics: {e}")
            return ResourceMetrics(
                memory_mb=0, memory_percent=0, cpu_percent=0,
                open_files=0, network_connections=0,
                concurrent_operations=0, queue_size=0, uptime_seconds=0
            )
    
    async def _check_limits(self, metrics: ResourceMetrics):
        """Check if any resource limits are exceeded"""
        violations = []
        
        if metrics.memory_mb > self.limits.max_memory_mb:
            violations.append(f"Memory usage ({metrics.memory_mb:.1f} MB) exceeds limit ({self.limits.max_memory_mb} MB)")
        
        if metrics.cpu_percent > self.limits.max_cpu_percent:
            violations.append(f"CPU usage ({metrics.cpu_percent:.1f}%) exceeds limit ({self.limits.max_cpu_percent}%)")
        
        if metrics.open_files > self.limits.max_open_files:
            violations.append(f"Open files ({metrics.open_files}) exceeds limit ({self.limits.max_open_files})")
        
        if metrics.network_connections > self.limits.max_network_connections:
            violations.append(f"Network connections ({metrics.network_connections}) exceeds limit ({self.limits.max_network_connections})")
        
        if violations:
            logger.warning(f"Resource limit violations detected: {'; '.join(violations)}")
            
            # Trigger cleanup if we're above cleanup threshold
            memory_usage_ratio = metrics.memory_mb / self.limits.max_memory_mb
            if memory_usage_ratio > self.limits.cleanup_threshold:
                await self._trigger_emergency_cleanup()
    
    async def _trigger_emergency_cleanup(self):
        """Trigger emergency resource cleanup"""
        logger.warning("Triggering emergency resource cleanup")
        
        try:
            # Force garbage collection
            import gc
            collected = gc.collect()
            logger.info(f"Garbage collection freed {collected} objects")
            
            # Clear caches if available
            try:
                from backend.database.circuit_breaker_service import circuit_breaker_db_service
                if hasattr(circuit_breaker_db_service, '_cache'):
                    cache_size = len(circuit_breaker_db_service._cache)
                    circuit_breaker_db_service._cache.clear()
                    circuit_breaker_db_service._last_cache_update.clear()
                    logger.info(f"Cleared circuit breaker cache ({cache_size} entries)")
            except Exception as e:
                logger.debug(f"Could not clear circuit breaker cache: {e}")
            
            # Log cleanup completion
            metrics = await self.get_current_metrics()
            logger.info(f"Emergency cleanup completed. Current memory usage: {metrics.memory_mb:.1f} MB")
            
        except Exception as e:
            logger.error(f"Error during emergency cleanup: {e}")
    
    async def get_metrics_history(self, minutes: int = 10) -> List[Tuple[datetime, ResourceMetrics]]:
        """Get resource metrics history"""
        cutoff_time = datetime.now() - timedelta(minutes=minutes)
        async with self._lock:
            return [(timestamp, metrics) for timestamp, metrics in self._metrics_history 
                   if timestamp > cutoff_time]


class OperationManager:
    """Manages concurrent operations with resource protection"""
    
    def __init__(self, limits: ResourceLimits, monitor: ResourceMonitor):
        self.limits = limits
        self.monitor = monitor
        self._semaphore = asyncio.Semaphore(limits.max_concurrent_operations)
        self._operation_queue = asyncio.Queue(maxsize=limits.max_queue_size)
        self._active_operations = weakref.WeakSet()
        self._operation_counter = 0
        self._rate_limiter = RateLimiter(limits.max_requests_per_minute, 60)
    
    @asynccontextmanager
    async def acquire_operation_slot(self, operation_name: str = "unknown"):
        """Acquire a slot for operation execution"""
        # Check rate limiting first
        if not await self._rate_limiter.acquire():
            raise ResourceExhaustedException("Rate limit exceeded")
        
        # Check current resource usage
        metrics = await self.monitor.get_current_metrics()
        if metrics.memory_mb > self.limits.max_memory_mb * 0.95:  # 95% threshold
            raise ResourceExhaustedException("Memory usage too high")
        
        # Acquire semaphore
        await self._semaphore.acquire()
        
        operation = Operation(self._operation_counter, operation_name, datetime.now())
        self._operation_counter += 1
        self._active_operations.add(operation)
        
        try:
            logger.debug(f"Started operation {operation.id}: {operation_name}")
            yield operation
        finally:
            self._semaphore.release()
            logger.debug(f"Completed operation {operation.id}: {operation_name}")
    
    async def get_active_operations(self) -> List['Operation']:
        """Get list of currently active operations"""
        return list(self._active_operations)
    
    def get_queue_size(self) -> int:
        """Get current operation queue size"""
        return self._operation_queue.qsize()
    
    def get_concurrent_count(self) -> int:
        """Get current number of concurrent operations"""
        return len(self._active_operations)


class RateLimiter:
    """Token bucket rate limiter"""
    
    def __init__(self, max_tokens: int, refill_period: int):
        self.max_tokens = max_tokens
        self.refill_period = refill_period
        self.tokens = max_tokens
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens from the bucket"""
        async with self._lock:
            now = time.time()
            
            # Refill tokens based on elapsed time
            time_passed = now - self.last_refill
            tokens_to_add = int(time_passed * self.max_tokens / self.refill_period)
            self.tokens = min(self.max_tokens, self.tokens + tokens_to_add)
            self.last_refill = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False


@dataclass
class Operation:
    """Represents an active operation"""
    id: int
    name: str
    start_time: datetime
    
    def duration(self) -> float:
        """Get operation duration in seconds"""
        return (datetime.now() - self.start_time).total_seconds()


class ResourceExhaustedException(Exception):
    """Raised when resources are exhausted"""
    pass


class ConnectionPool:
    """Generic connection pool with resource limits"""
    
    def __init__(
        self,
        create_connection: Callable,
        max_connections: int = 50,
        max_idle_time: int = 300,
        connection_timeout: int = 30
    ):
        self.create_connection = create_connection
        self.max_connections = max_connections
        self.max_idle_time = max_idle_time
        self.connection_timeout = connection_timeout
        
        self._connections = deque()
        self._active_connections = set()
        self._connection_count = 0
        self._lock = asyncio.Lock()
        self._cleanup_task = None
        self._shutdown = False
    
    async def start(self):
        """Start the connection pool"""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info(f"Connection pool started with max {self.max_connections} connections")
    
    async def stop(self):
        """Stop the connection pool and close all connections"""
        self._shutdown = True
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        async with self._lock:
            while self._connections:
                conn, _ = self._connections.popleft()
                try:
                    await self._close_connection(conn)
                except Exception as e:
                    logger.warning(f"Error closing connection: {e}")
            
            # Wait for active connections to finish
            for conn in list(self._active_connections):
                try:
                    await self._close_connection(conn)
                except Exception as e:
                    logger.warning(f"Error closing active connection: {e}")
        
        logger.info("Connection pool stopped")
    
    @asynccontextmanager
    async def acquire(self):
        """Acquire a connection from the pool"""
        if self._shutdown:
            raise ResourceExhaustedException("Connection pool is shut down")
        
        connection = await self._get_connection()
        try:
            yield connection
        finally:
            await self._return_connection(connection)
    
    async def _get_connection(self):
        """Get a connection from the pool or create a new one"""
        async with self._lock:
            # Try to reuse an existing connection
            while self._connections:
                conn, last_used = self._connections.popleft()
                
                # Check if connection is still valid
                if await self._is_connection_valid(conn):
                    self._active_connections.add(conn)
                    return conn
                else:
                    # Connection is stale, close it
                    await self._close_connection(conn)
                    self._connection_count -= 1
            
            # Create new connection if under limit
            if self._connection_count < self.max_connections:
                try:
                    conn = await asyncio.wait_for(
                        self.create_connection(),
                        timeout=self.connection_timeout
                    )
                    self._connection_count += 1
                    self._active_connections.add(conn)
                    return conn
                except asyncio.TimeoutError:
                    raise ResourceExhaustedException("Connection creation timeout")
                except Exception as e:
                    raise ResourceExhaustedException(f"Failed to create connection: {e}")
            
            raise ResourceExhaustedException("Connection pool exhausted")
    
    async def _return_connection(self, connection):
        """Return a connection to the pool"""
        async with self._lock:
            if connection in self._active_connections:
                self._active_connections.remove(connection)
                
                if not self._shutdown and await self._is_connection_valid(connection):
                    # Return to pool
                    self._connections.append((connection, datetime.now()))
                else:
                    # Close invalid or shutdown connection
                    await self._close_connection(connection)
                    self._connection_count -= 1
    
    async def _is_connection_valid(self, connection) -> bool:
        """Check if a connection is still valid"""
        try:
            # This would be implementation-specific
            # For now, just return True
            return True
        except Exception:
            return False
    
    async def _close_connection(self, connection):
        """Close a connection"""
        try:
            if hasattr(connection, 'close'):
                await connection.close()
            elif hasattr(connection, 'disconnect'):
                await connection.disconnect()
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")
    
    async def _cleanup_loop(self):
        """Periodic cleanup of idle connections"""
        try:
            while not self._shutdown:
                await asyncio.sleep(60)  # Cleanup every minute
                await self._cleanup_idle_connections()
        except asyncio.CancelledError:
            pass
    
    async def _cleanup_idle_connections(self):
        """Remove idle connections that exceed max idle time"""
        if self._shutdown:
            return
        
        cutoff_time = datetime.now() - timedelta(seconds=self.max_idle_time)
        connections_to_remove = []
        
        async with self._lock:
            # Find connections to remove
            for i, (conn, last_used) in enumerate(self._connections):
                if last_used < cutoff_time:
                    connections_to_remove.append(i)
            
            # Remove from the end to maintain indices
            for i in reversed(connections_to_remove):
                conn, _ = self._connections[i]
                del self._connections[i]
                await self._close_connection(conn)
                self._connection_count -= 1
            
            if connections_to_remove:
                logger.debug(f"Cleaned up {len(connections_to_remove)} idle connections")


def resource_protected(
    max_memory_mb: Optional[int] = None,
    max_cpu_percent: Optional[float] = None,
    max_duration: Optional[int] = None,
    require_operation_slot: bool = True
):
    """
    Decorator for resource protection on functions
    
    Args:
        max_memory_mb: Maximum memory usage allowed during operation
        max_cpu_percent: Maximum CPU usage threshold
        max_duration: Maximum operation duration in seconds
        require_operation_slot: Whether to require an operation slot
    """
    def decorator(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Get global resource manager
            resource_manager = get_global_resource_manager()
            
            operation_name = f"{func.__module__}.{func.__name__}"
            
            # Check pre-conditions
            metrics = await resource_manager.monitor.get_current_metrics()
            
            if max_memory_mb and metrics.memory_mb > max_memory_mb:
                raise ResourceExhaustedException(f"Memory usage ({metrics.memory_mb:.1f} MB) exceeds limit ({max_memory_mb} MB)")
            
            if max_cpu_percent and metrics.cpu_percent > max_cpu_percent:
                raise ResourceExhaustedException(f"CPU usage ({metrics.cpu_percent:.1f}%) exceeds limit ({max_cpu_percent}%)")
            
            # Execute with operation management if required
            if require_operation_slot:
                async with resource_manager.operation_manager.acquire_operation_slot(operation_name):
                    if max_duration:
                        return await asyncio.wait_for(
                            func(*args, **kwargs),
                            timeout=max_duration
                        )
                    else:
                        return await func(*args, **kwargs)
            else:
                if max_duration:
                    return await asyncio.wait_for(
                        func(*args, **kwargs),
                        timeout=max_duration
                    )
                else:
                    return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, apply basic checks only
            resource_manager = get_global_resource_manager()
            
            # Basic resource check using synchronous methods
            try:
                process = psutil.Process()
                memory_mb = process.memory_info().rss / 1024 / 1024
                cpu_percent = process.cpu_percent()
                
                if max_memory_mb and memory_mb > max_memory_mb:
                    raise ResourceExhaustedException(f"Memory usage ({memory_mb:.1f} MB) exceeds limit ({max_memory_mb} MB)")
                
                if max_cpu_percent and cpu_percent > max_cpu_percent:
                    raise ResourceExhaustedException(f"CPU usage ({cpu_percent:.1f}%) exceeds limit ({max_cpu_percent}%)")
            
            except Exception as e:
                logger.warning(f"Could not check resources for sync function: {e}")
            
            return func(*args, **kwargs)
        
        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class GlobalResourceManager:
    """Global resource manager singleton"""
    
    def __init__(self):
        self.limits = ResourceLimits()
        self.monitor = ResourceMonitor(self.limits)
        self.operation_manager = OperationManager(self.limits, self.monitor)
        self._initialized = False
    
    async def initialize(self):
        """Initialize the resource manager"""
        if self._initialized:
            return
        
        # Load configuration from settings if available
        if hasattr(settings, 'resource_limits'):
            for attr, value in settings.resource_limits.items():
                if hasattr(self.limits, attr):
                    setattr(self.limits, attr, value)
        
        await self.monitor.start_monitoring()
        self._initialized = True
        logger.info("Global resource manager initialized")
    
    async def shutdown(self):
        """Shutdown the resource manager"""
        await self.monitor.stop_monitoring()
        self._initialized = False
        logger.info("Global resource manager shut down")
    
    async def get_status(self) -> Dict[str, Any]:
        """Get current resource manager status"""
        metrics = await self.monitor.get_current_metrics()
        
        # Update operation metrics
        metrics.concurrent_operations = self.operation_manager.get_concurrent_count()
        metrics.queue_size = self.operation_manager.get_queue_size()
        
        return {
            'initialized': self._initialized,
            'limits': {
                'max_memory_mb': self.limits.max_memory_mb,
                'max_cpu_percent': self.limits.max_cpu_percent,
                'max_concurrent_operations': self.limits.max_concurrent_operations,
                'max_network_connections': self.limits.max_network_connections
            },
            'current_usage': {
                'memory_mb': metrics.memory_mb,
                'memory_percent': metrics.memory_percent,
                'cpu_percent': metrics.cpu_percent,
                'open_files': metrics.open_files,
                'network_connections': metrics.network_connections,
                'concurrent_operations': metrics.concurrent_operations,
                'queue_size': metrics.queue_size,
                'uptime_seconds': metrics.uptime_seconds
            },
            'violations': [],  # Would be populated by checking limits
            'active_operations': len(await self.operation_manager.get_active_operations())
        }


# Global instance
_global_resource_manager = None
_manager_lock = threading.Lock()


def get_global_resource_manager() -> GlobalResourceManager:
    """Get or create the global resource manager"""
    global _global_resource_manager
    
    if _global_resource_manager is None:
        with _manager_lock:
            if _global_resource_manager is None:
                _global_resource_manager = GlobalResourceManager()
    
    return _global_resource_manager


# Initialize resource manager on module import
async def initialize_resource_protection():
    """Initialize global resource protection"""
    manager = get_global_resource_manager()
    await manager.initialize()


async def shutdown_resource_protection():
    """Shutdown global resource protection"""
    global _global_resource_manager
    if _global_resource_manager:
        await _global_resource_manager.shutdown()
        _global_resource_manager = None