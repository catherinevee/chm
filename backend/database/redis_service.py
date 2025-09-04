"""
Redis service for distributed state management and caching
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union, Callable
from contextlib import asynccontextmanager
import pickle
import hashlib

try:
    import redis.asyncio as redis
    from redis.asyncio import ConnectionPool, Redis
    from redis.exceptions import RedisError, ConnectionError, TimeoutError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None
    Redis = None
    ConnectionPool = None
    RedisError = Exception
    ConnectionError = Exception
    TimeoutError = Exception

from backend.config import settings

# Import result objects
from ..utils.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)

logger = logging.getLogger(__name__)


class RedisDistributedState:
    """Redis-based distributed state management for circuit breakers and caching"""
    
    def __init__(
        self,
        redis_url: Optional[str] = None,
        max_connections: int = 20,
        socket_timeout: int = 5,
        socket_connect_timeout: int = 5,
        retry_on_timeout: bool = True
    ):
        self.redis_url = redis_url or getattr(settings, 'redis_url', 'redis://localhost:6379/0')
        self.max_connections = max_connections
        self.socket_timeout = socket_timeout
        self.socket_connect_timeout = socket_connect_timeout
        self.retry_on_timeout = retry_on_timeout
        
        self.redis_client: Optional[Redis] = None
        self.connection_pool: Optional[ConnectionPool] = None
        self.is_connected = False
        self._lock = asyncio.Lock()
        
        # Fallback in-memory storage when Redis is unavailable
        self._memory_fallback = {}\n        self._memory_ttl = {}
        
        # Key prefixes for different data types
        self.CIRCUIT_BREAKER_PREFIX = "cb:"
        self.CACHE_PREFIX = "cache:"
        self.LOCK_PREFIX = "lock:"
        self.COUNTER_PREFIX = "counter:"
        self.SET_PREFIX = "set:"
    
    async def initialize(self) -> bool:
        """Initialize Redis connection"""
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, using memory-only fallback")
            return False
        
        try:
            async with self._lock:
                if self.is_connected:
                    return True
                
                # Create connection pool
                self.connection_pool = ConnectionPool.from_url(
                    self.redis_url,
                    max_connections=self.max_connections,
                    socket_timeout=self.socket_timeout,
                    socket_connect_timeout=self.socket_connect_timeout,
                    retry_on_timeout=self.retry_on_timeout,
                    health_check_interval=30
                )
                
                # Create Redis client
                self.redis_client = Redis(
                    connection_pool=self.connection_pool,
                    decode_responses=False  # We'll handle encoding manually
                )
                
                # Test connection
                await self.redis_client.ping()
                self.is_connected = True
                logger.info("Redis connection established")
                return True
                
        except Exception as e:
            logger.error(f"Failed to initialize Redis connection: {e}")
            self.is_connected = False
            return False
    
    async def disconnect(self):
        """Close Redis connection"""
        async with self._lock:
            if self.redis_client:
                await self.redis_client.close()
            if self.connection_pool:
                await self.connection_pool.disconnect()
            self.is_connected = False
            logger.info("Redis connection closed")
    
    @asynccontextmanager
    async def _get_redis(self):
        """Get Redis client with connection handling"""
        if not self.is_connected:
            await self.initialize()
        
        if self.is_connected and self.redis_client:
            try:
                yield self.redis_client
                return
            except (ConnectionError, TimeoutError) as e:
                logger.warning(f"Redis connection lost: {e}")
                self.is_connected = False
        
        # Fallback to memory storage
        logger.debug("Using memory fallback for Redis operation")
        yield None
    
    def _serialize_value(self, value: Any) -> bytes:
        """Serialize value for Redis storage"""
        if isinstance(value, (str, int, float, bool)):
            return json.dumps(value).encode('utf-8')
        else:
            # Use pickle for complex objects
            return pickle.dumps(value)
    
    def _deserialize_value(self, data: bytes) -> Any:
        """Deserialize value from Redis"""
        try:
            # Try JSON first
            return json.loads(data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Fall back to pickle
            return pickle.loads(data)
    
    def _memory_cleanup(self):
        """Clean up expired memory fallback entries"""
        current_time = datetime.now()
        expired_keys = [
            key for key, expiry in self._memory_ttl.items()
            if expiry and current_time > expiry
        ]
        for key in expired_keys:
            self._memory_fallback.pop(key, None)
            self._memory_ttl.pop(key, None)
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        nx: bool = False,
        xx: bool = False
    ) -> bool:
        """Set a key-value pair with optional TTL"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    serialized_value = self._serialize_value(value)
                    result = await redis_client.set(
                        key,
                        serialized_value,
                        ex=ttl,
                        nx=nx,
                        xx=xx
                    )
                    return bool(result)
                else:
                    # Memory fallback
                    self._memory_cleanup()
                    if nx and key in self._memory_fallback:
                        return False
                    if xx and key not in self._memory_fallback:
                        return False
                    
                    self._memory_fallback[key] = value
                    if ttl:
                        self._memory_ttl[key] = datetime.now() + timedelta(seconds=ttl)
                    else:
                        self._memory_ttl[key] = None
                    return True
                    
            except Exception as e:
                logger.error(f"Error setting Redis key {key}: {e}")
                return False
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get a value by key"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    data = await redis_client.get(key)
                    if data is None:
                        return default
                    return self._deserialize_value(data)
                else:
                    # Memory fallback
                    self._memory_cleanup()
                    return self._memory_fallback.get(key, default)
                    
            except Exception as e:
                logger.error(f"Error getting Redis key {key}: {e}")
                return default
    
    async def delete(self, *keys: str) -> int:
        """Delete one or more keys"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    return await redis_client.delete(*keys)
                else:
                    # Memory fallback
                    count = 0
                    for key in keys:
                        if key in self._memory_fallback:
                            del self._memory_fallback[key]
                            self._memory_ttl.pop(key, None)
                            count += 1
                    return count
                    
            except Exception as e:
                logger.error(f"Error deleting Redis keys: {e}")
                return 0
    
    async def exists(self, *keys: str) -> int:
        """Check if keys exist"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    return await redis_client.exists(*keys)
                else:
                    # Memory fallback
                    self._memory_cleanup()
                    return sum(1 for key in keys if key in self._memory_fallback)
                    
            except Exception as e:
                logger.error(f"Error checking Redis key existence: {e}")
                return 0
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set TTL for a key"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    return bool(await redis_client.expire(key, ttl))
                else:
                    # Memory fallback
                    if key in self._memory_fallback:
                        self._memory_ttl[key] = datetime.now() + timedelta(seconds=ttl)
                        return True
                    return False
                    
            except Exception as e:
                logger.error(f"Error setting TTL for Redis key {key}: {e}")
                return False
    
    async def incr(self, key: str, amount: int = 1) -> int:
        """Increment a counter"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    return await redis_client.incrby(key, amount)
                else:
                    # Memory fallback
                    current = self._memory_fallback.get(key, 0)
                    if not isinstance(current, int):
                        current = 0
                    new_value = current + amount
                    self._memory_fallback[key] = new_value
                    return new_value
                    
            except Exception as e:
                logger.error(f"Error incrementing Redis key {key}: {e}")
                return 0
    
    async def sadd(self, key: str, *members) -> int:
        """Add members to a set"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    return await redis_client.sadd(key, *members)
                else:
                    # Memory fallback
                    if key not in self._memory_fallback:
                        self._memory_fallback[key] = set()
                    elif not isinstance(self._memory_fallback[key], set):
                        self._memory_fallback[key] = set()
                    
                    before_size = len(self._memory_fallback[key])
                    self._memory_fallback[key].update(members)
                    after_size = len(self._memory_fallback[key])
                    return after_size - before_size
                    
            except Exception as e:
                logger.error(f"Error adding to Redis set {key}: {e}")
                return 0
    
    async def srem(self, key: str, *members) -> int:
        """Remove members from a set"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    return await redis_client.srem(key, *members)
                else:
                    # Memory fallback
                    if key not in self._memory_fallback or not isinstance(self._memory_fallback[key], set):
                        return 0
                    
                    count = 0
                    for member in members:
                        if member in self._memory_fallback[key]:
                            self._memory_fallback[key].remove(member)
                            count += 1
                    return count
                    
            except Exception as e:
                logger.error(f"Error removing from Redis set {key}: {e}")
                return 0
    
    async def smembers(self, key: str) -> set:
        """Get all members of a set"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    result = await redis_client.smembers(key)
                    return {member.decode('utf-8') if isinstance(member, bytes) else member for member in result}
                else:
                    # Memory fallback
                    self._memory_cleanup()
                    return self._memory_fallback.get(key, set()).copy()
                    
            except Exception as e:
                logger.error(f"Error getting Redis set {key}: {e}")
                return set()
    
    async def acquire_lock(
        self,
        lock_name: str,
        timeout: int = 10,
        blocking_timeout: int = 10
    ) -> Optional['RedisLock']:
        """Acquire a distributed lock"""
        lock_key = f"{self.LOCK_PREFIX}{lock_name}"
        lock_value = f"{id(self)}:{datetime.now().timestamp()}"
        
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    # Try to acquire lock with timeout
                    start_time = datetime.now()
                    while (datetime.now() - start_time).seconds < blocking_timeout:
                        if await redis_client.set(lock_key, lock_value, nx=True, ex=timeout):
                            return create_success_result(
                                data=RedisLock(self, lock_key, lock_value, timeout),
                                fallback_data=FallbackData(
                                    data=None,
                                    health_status=HealthStatus(
                                        level=HealthLevel.HEALTHY,
                                        message="Redis lock acquired successfully",
                                        details=f"Lock {lock_name} acquired with timeout {timeout}s"
                                    )
                                )
                            )
                        await asyncio.sleep(0.1)
                    return create_partial_success_result(
                        data=None,
                        error_code="LOCK_ACQUISITION_TIMEOUT",
                        message=f"Failed to acquire lock {lock_name} within blocking timeout",
                        fallback_data=FallbackData(
                            data=None,
                            health_status=HealthStatus(
                                level=HealthLevel.WARNING,
                                message="Lock acquisition timeout",
                                details=f"Blocking timeout {blocking_timeout}s exceeded for lock {lock_name}"
                            )
                        ),
                        suggestions=["Increase blocking timeout", "Check Redis performance", "Verify lock availability"]
                    )
                else:
                    # Memory fallback - simplified locking
                    if lock_key not in self._memory_fallback:
                        self._memory_fallback[lock_key] = lock_value
                        self._memory_ttl[lock_key] = datetime.now() + timedelta(seconds=timeout)
                        return create_success_result(
                            data=RedisLock(self, lock_key, lock_value, timeout, memory_fallback=True),
                            fallback_data=FallbackData(
                                data=None,
                                health_status=HealthStatus(
                                    level=HealthLevel.HEALTHY,
                                    message="Memory fallback lock acquired",
                                    details=f"Lock {lock_name} acquired using memory fallback with timeout {timeout}s"
                                )
                            )
                        )
                    return create_partial_success_result(
                        data=None,
                        error_code="LOCK_ALREADY_ACQUIRED",
                        message=f"Lock {lock_name} is already acquired by another process",
                        fallback_data=FallbackData(
                            data=None,
                            health_status=HealthStatus(
                                level=HealthLevel.WARNING,
                                message="Lock already acquired",
                                details=f"Lock {lock_name} is currently held by another process"
                            )
                        ),
                        suggestions=["Wait for lock release", "Use different lock name", "Check for stuck locks"]
                    )
                    
            except Exception as e:
                logger.error(f"Error acquiring lock {lock_name}: {e}")
                return create_failure_result(
                    error_code="LOCK_ACQUISITION_ERROR",
                    message=f"Error acquiring lock {lock_name}",
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.ERROR,
                            message="Lock acquisition error",
                            details=f"Error acquiring lock {lock_name}: {str(e)}"
                        )
                    ),
                    suggestions=["Check Redis connectivity", "Verify lock configuration", "Review error details"]
                )
    
    async def release_lock(self, lock_key: str, lock_value: str, memory_fallback: bool = False) -> bool:
        """Release a distributed lock"""
        try:
            if memory_fallback:
                # Memory fallback
                if self._memory_fallback.get(lock_key) == lock_value:
                    del self._memory_fallback[lock_key]
                    self._memory_ttl.pop(lock_key, None)
                    return True
                return False
            
            async with self._get_redis() as redis_client:
                if redis_client:
                    # Use Lua script to ensure atomic release
                    lua_script = """
                    if redis.call("get", KEYS[1]) == ARGV[1] then
                        return redis.call("del", KEYS[1])
                    else
                        return 0
                    end
                    """
                    result = await redis_client.eval(lua_script, 1, lock_key, lock_value)
                    return bool(result)
                
                return False
                
        except Exception as e:
            logger.error(f"Error releasing lock {lock_key}: {e}")
            return False
    
    async def get_info(self) -> Dict[str, Any]:
        """Get Redis connection info and stats"""
        async with self._get_redis() as redis_client:
            try:
                if redis_client:
                    info = await redis_client.info()
                    return {
                        'connected': True,
                        'redis_version': info.get('redis_version', 'unknown'),
                        'used_memory': info.get('used_memory_human', 'unknown'),
                        'connected_clients': info.get('connected_clients', 0),
                        'total_commands_processed': info.get('total_commands_processed', 0),
                        'keyspace_hits': info.get('keyspace_hits', 0),
                        'keyspace_misses': info.get('keyspace_misses', 0),
                        'uptime_in_seconds': info.get('uptime_in_seconds', 0)
                    }
                else:
                    return {
                        'connected': False,
                        'fallback_mode': True,
                        'memory_keys': len(self._memory_fallback),
                        'ttl_keys': len(self._memory_ttl)
                    }
                    
            except Exception as e:
                logger.error(f"Error getting Redis info: {e}")
                return {'connected': False, 'error': str(e)}


class RedisLock:
    """Distributed lock using Redis"""
    
    def __init__(
        self,
        redis_service: RedisDistributedState,
        lock_key: str,
        lock_value: str,
        timeout: int,
        memory_fallback: bool = False
    ):
        self.redis_service = redis_service
        self.lock_key = lock_key
        self.lock_value = lock_value
        self.timeout = timeout
        self.memory_fallback = memory_fallback
        self.acquired = True
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.release()
    
    async def release(self) -> bool:
        """Release the lock"""
        if self.acquired:
            result = await self.redis_service.release_lock(
                self.lock_key,
                self.lock_value,
                self.memory_fallback
            )
            self.acquired = False
            return result
        return False
    
    async def extend(self, additional_time: int) -> bool:
        """Extend lock timeout"""
        if not self.acquired:
            return False
        
        try:
            return await self.redis_service.expire(self.lock_key, additional_time)
        except Exception as e:
            logger.error(f"Error extending lock: {e}")
            return False


class RedisCircuitBreakerState:
    """Redis-backed circuit breaker state management"""
    
    def __init__(self, redis_service: RedisDistributedState):
        self.redis = redis_service
        self.CB_PREFIX = redis_service.CIRCUIT_BREAKER_PREFIX
    
    async def get_state(self, identifier: str) -> Dict[str, Any]:
        """Get circuit breaker state"""
        key = f"{self.CB_PREFIX}{identifier}"
        state_data = await self.redis.get(key)
        
        if state_data:
            return state_data
        
        # Return default state
        default_state = {
            'state': 'closed',
            'failure_count': 0,
            'success_count': 0,
            'last_failure_time': None,
            'last_success_time': None,
            'opened_at': None,
            'next_attempt_time': None,
            'total_calls': 0,
            'total_failures': 0
        }
        
        # Store default state
        await self.redis.set(key, default_state, ttl=3600)  # 1 hour TTL
        return default_state
    
    async def update_state(self, identifier: str, state_updates: Dict[str, Any]) -> bool:
        """Update circuit breaker state"""
        key = f"{self.CB_PREFIX}{identifier}"
        current_state = await self.get_state(identifier)
        
        # Merge updates
        updated_state = {**current_state, **state_updates}
        updated_state['updated_at'] = datetime.now().isoformat()
        
        # Store with TTL
        return await self.redis.set(key, updated_state, ttl=3600)
    
    async def increment_counter(self, identifier: str, counter_name: str) -> int:
        """Increment a counter atomically"""
        key = f"{self.CB_PREFIX}{identifier}:{counter_name}"
        return await self.redis.incr(key)
    
    async def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get all circuit breaker states (for monitoring)"""
        # This is a simplified implementation
        # In production, you'd want to use SCAN to avoid blocking
        results = {}
        async with self.redis._get_redis() as redis_client:
            if redis_client:
                try:
                    pattern = f"{self.CB_PREFIX}*"
                    keys = []
                    async for key in redis_client.scan_iter(match=pattern, count=100):
                        if isinstance(key, bytes):
                            key = key.decode('utf-8')
                        keys.append(key)
                    
                    for key in keys:
                        identifier = key[len(self.CB_PREFIX):]
                        if ':' not in identifier:  # Skip counter keys
                            state = await self.redis.get(key)
                            if state:
                                results[identifier] = state
                except Exception as e:
                    logger.error(f"Error getting all circuit breaker states: {e}")
        
        return results


# Global Redis service instance
redis_service = RedisDistributedState()
redis_circuit_breaker = RedisCircuitBreakerState(redis_service)


async def initialize_redis() -> bool:
    """Initialize Redis service"""
    return await redis_service.initialize()


async def cleanup_redis():
    """Cleanup Redis connections"""
    await redis_service.disconnect()