"""
Redis Cache Service - High-performance caching layer for CHM
"""

import asyncio
import json
import pickle
import logging
from typing import Any, Dict, List, Optional, Union
from datetime import datetime, timedelta
import redis.asyncio as redis
from redis.asyncio.lock import Lock
from redis.asyncio.connection import ConnectionPool
import hashlib

from backend.config import settings

logger = logging.getLogger(__name__)


class RedisCacheService:
    """
    Redis-based caching service with support for various data types and patterns
    """
    
    def __init__(self,
                 host: str = None,
                 port: int = None,
                 db: int = None,
                 password: str = None,
                 max_connections: int = 50):
        """
        Initialize Redis cache service
        
        Args:
            host: Redis host
            port: Redis port
            db: Redis database number
            password: Redis password
            max_connections: Maximum connection pool size
        """
        self.host = host or settings.REDIS_HOST or 'localhost'
        self.port = port or settings.REDIS_PORT or 6379
        self.db = db or settings.REDIS_DB or 0
        self.password = password or settings.REDIS_PASSWORD
        
        # Create connection pool
        self.pool = ConnectionPool(
            host=self.host,
            port=self.port,
            db=self.db,
            password=self.password,
            max_connections=max_connections,
            decode_responses=False  # Handle encoding ourselves
        )
        
        self.redis_client: Optional[redis.Redis] = None
        self.connected = False
        
    async def connect(self):
        """Establish Redis connection"""
        try:
            self.redis_client = redis.Redis(connection_pool=self.pool)
            
            # Test connection
            await self.redis_client.ping()
            self.connected = True
            
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            self.connected = False
            raise
    
    async def disconnect(self):
        """Close Redis connection"""
        if self.redis_client:
            await self.redis_client.close()
            await self.pool.disconnect()
            self.connected = False
            logger.info("Disconnected from Redis")
    
    async def get(self, key: str, default: Any = None) -> Any:
        """
        Get value from cache
        
        Args:
            key: Cache key
            default: Default value if key not found
            
        Returns:
            Cached value or default
        """
        if not self.connected:
            await self.connect()
        
        try:
            value = await self.redis_client.get(key)
            
            if value is None:
                return default
            
            # Try to deserialize
            return self._deserialize(value)
            
        except Exception as e:
            logger.error(f"Error getting key {key}: {str(e)}")
            return default
    
    async def set(self,
                  key: str,
                  value: Any,
                  ttl: int = None,
                  nx: bool = False,
                  xx: bool = False) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            nx: Only set if key doesn't exist
            xx: Only set if key exists
            
        Returns:
            True if set successfully
        """
        if not self.connected:
            await self.connect()
        
        try:
            # Serialize value
            serialized = self._serialize(value)
            
            # Set with options
            result = await self.redis_client.set(
                key,
                serialized,
                ex=ttl,
                nx=nx,
                xx=xx
            )
            
            return bool(result)
            
        except Exception as e:
            logger.error(f"Error setting key {key}: {str(e)}")
            return False
    
    async def delete(self, *keys: str) -> int:
        """
        Delete keys from cache
        
        Args:
            keys: Keys to delete
            
        Returns:
            Number of keys deleted
        """
        if not self.connected:
            await self.connect()
        
        try:
            return await self.redis_client.delete(*keys)
        except Exception as e:
            logger.error(f"Error deleting keys: {str(e)}")
            return 0
    
    async def exists(self, *keys: str) -> int:
        """
        Check if keys exist
        
        Args:
            keys: Keys to check
            
        Returns:
            Number of keys that exist
        """
        if not self.connected:
            await self.connect()
        
        try:
            return await self.redis_client.exists(*keys)
        except Exception as e:
            logger.error(f"Error checking existence: {str(e)}")
            return 0
    
    async def expire(self, key: str, ttl: int) -> bool:
        """
        Set TTL for a key
        
        Args:
            key: Cache key
            ttl: Time to live in seconds
            
        Returns:
            True if TTL was set
        """
        if not self.connected:
            await self.connect()
        
        try:
            return await self.redis_client.expire(key, ttl)
        except Exception as e:
            logger.error(f"Error setting TTL for {key}: {str(e)}")
            return False
    
    async def ttl(self, key: str) -> int:
        """
        Get TTL for a key
        
        Args:
            key: Cache key
            
        Returns:
            TTL in seconds, -1 if no TTL, -2 if key doesn't exist
        """
        if not self.connected:
            await self.connect()
        
        try:
            return await self.redis_client.ttl(key)
        except Exception as e:
            logger.error(f"Error getting TTL for {key}: {str(e)}")
            return -2
    
    # Hash operations
    async def hset(self, name: str, key: str, value: Any) -> int:
        """
        Set hash field
        
        Args:
            name: Hash name
            key: Field key
            value: Field value
            
        Returns:
            Number of fields added
        """
        if not self.connected:
            await self.connect()
        
        try:
            serialized = self._serialize(value)
            return await self.redis_client.hset(name, key, serialized)
        except Exception as e:
            logger.error(f"Error setting hash field: {str(e)}")
            return 0
    
    async def hget(self, name: str, key: str) -> Any:
        """
        Get hash field
        
        Args:
            name: Hash name
            key: Field key
            
        Returns:
            Field value
        """
        if not self.connected:
            await self.connect()
        
        try:
            value = await self.redis_client.hget(name, key)
            return self._deserialize(value) if value else None
        except Exception as e:
            logger.error(f"Error getting hash field: {str(e)}")
            return None
    
    async def hgetall(self, name: str) -> Dict[str, Any]:
        """
        Get all hash fields
        
        Args:
            name: Hash name
            
        Returns:
            Dictionary of all fields
        """
        if not self.connected:
            await self.connect()
        
        try:
            data = await self.redis_client.hgetall(name)
            return {
                k.decode('utf-8'): self._deserialize(v)
                for k, v in data.items()
            }
        except Exception as e:
            logger.error(f"Error getting hash: {str(e)}")
            return {}
    
    # List operations
    async def lpush(self, key: str, *values: Any) -> int:
        """
        Push values to list head
        
        Args:
            key: List key
            values: Values to push
            
        Returns:
            List length after push
        """
        if not self.connected:
            await self.connect()
        
        try:
            serialized = [self._serialize(v) for v in values]
            return await self.redis_client.lpush(key, *serialized)
        except Exception as e:
            logger.error(f"Error pushing to list: {str(e)}")
            return 0
    
    async def lrange(self, key: str, start: int, stop: int) -> List[Any]:
        """
        Get list range
        
        Args:
            key: List key
            start: Start index
            stop: Stop index
            
        Returns:
            List of values
        """
        if not self.connected:
            await self.connect()
        
        try:
            values = await self.redis_client.lrange(key, start, stop)
            return [self._deserialize(v) for v in values]
        except Exception as e:
            logger.error(f"Error getting list range: {str(e)}")
            return []
    
    # Set operations
    async def sadd(self, key: str, *values: Any) -> int:
        """
        Add values to set
        
        Args:
            key: Set key
            values: Values to add
            
        Returns:
            Number of values added
        """
        if not self.connected:
            await self.connect()
        
        try:
            serialized = [self._serialize(v) for v in values]
            return await self.redis_client.sadd(key, *serialized)
        except Exception as e:
            logger.error(f"Error adding to set: {str(e)}")
            return 0
    
    async def smembers(self, key: str) -> set:
        """
        Get all set members
        
        Args:
            key: Set key
            
        Returns:
            Set of values
        """
        if not self.connected:
            await self.connect()
        
        try:
            values = await self.redis_client.smembers(key)
            return {self._deserialize(v) for v in values}
        except Exception as e:
            logger.error(f"Error getting set members: {str(e)}")
            return set()
    
    # Sorted set operations
    async def zadd(self, key: str, mapping: Dict[Any, float]) -> int:
        """
        Add to sorted set
        
        Args:
            key: Sorted set key
            mapping: Value to score mapping
            
        Returns:
            Number of elements added
        """
        if not self.connected:
            await self.connect()
        
        try:
            # Serialize keys in mapping
            serialized_mapping = {
                self._serialize(k): v
                for k, v in mapping.items()
            }
            return await self.redis_client.zadd(key, serialized_mapping)
        except Exception as e:
            logger.error(f"Error adding to sorted set: {str(e)}")
            return 0
    
    async def zrange(self,
                     key: str,
                     start: int,
                     stop: int,
                     withscores: bool = False) -> Union[List[Any], List[tuple]]:
        """
        Get sorted set range
        
        Args:
            key: Sorted set key
            start: Start index
            stop: Stop index
            withscores: Include scores
            
        Returns:
            List of values or (value, score) tuples
        """
        if not self.connected:
            await self.connect()
        
        try:
            result = await self.redis_client.zrange(key, start, stop, withscores=withscores)
            
            if withscores:
                return [(self._deserialize(v), score) for v, score in result]
            else:
                return [self._deserialize(v) for v in result]
                
        except Exception as e:
            logger.error(f"Error getting sorted set range: {str(e)}")
            return []
    
    # Pub/Sub operations
    async def publish(self, channel: str, message: Any) -> int:
        """
        Publish message to channel
        
        Args:
            channel: Channel name
            message: Message to publish
            
        Returns:
            Number of subscribers that received the message
        """
        if not self.connected:
            await self.connect()
        
        try:
            serialized = self._serialize(message)
            return await self.redis_client.publish(channel, serialized)
        except Exception as e:
            logger.error(f"Error publishing message: {str(e)}")
            return 0
    
    async def subscribe(self, *channels: str):
        """
        Subscribe to channels
        
        Args:
            channels: Channel names
            
        Returns:
            PubSub object
        """
        if not self.connected:
            await self.connect()
        
        pubsub = self.redis_client.pubsub()
        await pubsub.subscribe(*channels)
        return pubsub
    
    # Locking
    async def acquire_lock(self,
                          name: str,
                          timeout: float = 10,
                          blocking: bool = True,
                          blocking_timeout: float = None) -> Optional[Lock]:
        """
        Acquire distributed lock
        
        Args:
            name: Lock name
            timeout: Lock timeout in seconds
            blocking: Whether to block waiting for lock
            blocking_timeout: How long to block
            
        Returns:
            Lock object if acquired, None otherwise
        """
        if not self.connected:
            await self.connect()
        
        try:
            lock = self.redis_client.lock(
                name,
                timeout=timeout,
                blocking_timeout=blocking_timeout
            )
            
            if await lock.acquire(blocking=blocking):
                return lock
            return None
            
        except Exception as e:
            logger.error(f"Error acquiring lock: {str(e)}")
            return None
    
    # Cache patterns
    async def cache_result(self,
                          key: str,
                          func: callable,
                          ttl: int = 300,
                          refresh: bool = False) -> Any:
        """
        Cache function result
        
        Args:
            key: Cache key
            func: Function to call if cache miss
            ttl: Cache TTL in seconds
            refresh: Force refresh cache
            
        Returns:
            Cached or computed result
        """
        if not refresh:
            # Try to get from cache
            cached = await self.get(key)
            if cached is not None:
                logger.debug(f"Cache hit for {key}")
                return cached
        
        # Compute result
        logger.debug(f"Cache miss for {key}, computing...")
        
        # Use lock to prevent cache stampede
        lock = await self.acquire_lock(f"lock:{key}", timeout=30)
        if lock:
            try:
                # Double-check cache after acquiring lock
                if not refresh:
                    cached = await self.get(key)
                    if cached is not None:
                        return cached
                
                # Compute result
                if asyncio.iscoroutinefunction(func):
                    result = await func()
                else:
                    result = func()
                
                # Cache result
                await self.set(key, result, ttl=ttl)
                
                return result
                
            finally:
                await lock.release()
        else:
            # Couldn't acquire lock, return cached value or None
            return await self.get(key)
    
    async def increment(self, key: str, amount: int = 1) -> int:
        """
        Increment counter
        
        Args:
            key: Counter key
            amount: Increment amount
            
        Returns:
            New counter value
        """
        if not self.connected:
            await self.connect()
        
        try:
            return await self.redis_client.incr(key, amount)
        except Exception as e:
            logger.error(f"Error incrementing counter: {str(e)}")
            return 0
    
    async def rate_limit(self,
                        key: str,
                        limit: int,
                        window: int = 60) -> bool:
        """
        Check rate limit
        
        Args:
            key: Rate limit key
            limit: Maximum requests in window
            window: Time window in seconds
            
        Returns:
            True if within limit, False if exceeded
        """
        if not self.connected:
            await self.connect()
        
        try:
            # Use sliding window with sorted sets
            now = datetime.utcnow().timestamp()
            window_start = now - window
            
            # Remove old entries
            await self.redis_client.zremrangebyscore(key, 0, window_start)
            
            # Count current entries
            current_count = await self.redis_client.zcard(key)
            
            if current_count < limit:
                # Add new entry
                await self.redis_client.zadd(key, {str(now): now})
                await self.redis_client.expire(key, window)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return True  # Allow on error
    
    def _serialize(self, value: Any) -> bytes:
        """
        Serialize value for storage
        
        Args:
            value: Value to serialize
            
        Returns:
            Serialized bytes
        """
        if isinstance(value, bytes):
            return value
        elif isinstance(value, str):
            return value.encode('utf-8')
        elif isinstance(value, (int, float)):
            return str(value).encode('utf-8')
        else:
            # Use pickle for complex types
            return pickle.dumps(value)
    
    def _deserialize(self, value: bytes) -> Any:
        """
        Deserialize value from storage
        
        Args:
            value: Serialized bytes
            
        Returns:
            Deserialized value
        """
        if not value:
            return None
        
        # Try to decode as string
        try:
            decoded = value.decode('utf-8')
            
            # Try to parse as number
            try:
                if '.' in decoded:
                    return float(decoded)
                return int(decoded)
            except ValueError:
                pass
            
            # Try to parse as JSON
            try:
                return json.loads(decoded)
            except json.JSONDecodeError:
                pass
            
            # Return as string
            return decoded
            
        except UnicodeDecodeError:
            # Try to unpickle
            try:
                return pickle.loads(value)
            except Exception as e:

                logger.debug(f"Exception: {e}")
                # Return raw bytes
                return value
    
    async def clear_pattern(self, pattern: str) -> int:
        """
        Delete all keys matching pattern
        
        Args:
            pattern: Key pattern (e.g., "cache:*")
            
        Returns:
            Number of keys deleted
        """
        if not self.connected:
            await self.connect()
        
        try:
            # Find all matching keys
            cursor = 0
            deleted = 0
            
            while True:
                cursor, keys = await self.redis_client.scan(
                    cursor,
                    match=pattern,
                    count=100
                )
                
                if keys:
                    deleted += await self.redis_client.delete(*keys)
                
                if cursor == 0:
                    break
            
            return deleted
            
        except Exception as e:
            logger.error(f"Error clearing pattern {pattern}: {str(e)}")
            return 0
    
    async def get_info(self) -> Dict[str, Any]:
        """
        Get Redis server information
        
        Returns:
            Server info dictionary
        """
        if not self.connected:
            await self.connect()
        
        try:
            info = await self.redis_client.info()
            return {
                'version': info.get('redis_version'),
                'used_memory': info.get('used_memory_human'),
                'connected_clients': info.get('connected_clients'),
                'total_commands': info.get('total_commands_processed'),
                'uptime_days': info.get('uptime_in_days'),
                'keyspace': info.get('db0', {})
            }
        except Exception as e:
            logger.error(f"Error getting Redis info: {str(e)}")
            return {}


# Global cache instance
cache_service = RedisCacheService()


# Cache decorators
def cached(ttl: int = 300, key_prefix: str = None):
    """
    Decorator to cache function results
    
    Args:
        ttl: Cache TTL in seconds
        key_prefix: Optional key prefix
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            key_parts = [key_prefix or func.__name__]
            
            # Add args to key
            for arg in args:
                if hasattr(arg, 'id'):
                    key_parts.append(str(arg.id))
                else:
                    key_parts.append(str(arg))
            
            # Add kwargs to key
            for k, v in sorted(kwargs.items()):
                key_parts.append(f"{k}={v}")
            
            cache_key = ":".join(key_parts)
            
            # Use cache_result method
            return await cache_service.cache_result(
                cache_key,
                lambda: func(*args, **kwargs),
                ttl=ttl
            )
        
        return wrapper
    return decorator


def rate_limited(limit: int, window: int = 60, key_func: callable = None):
    """
    Decorator to rate limit function calls
    
    Args:
        limit: Maximum calls in window
        window: Time window in seconds
        key_func: Function to generate rate limit key
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate rate limit key
            if key_func:
                key = key_func(*args, **kwargs)
            else:
                key = f"rate_limit:{func.__name__}"
            
            # Check rate limit
            if not await cache_service.rate_limit(key, limit, window):
                raise Exception(f"Rate limit exceeded for {key}")
            
            # Call function
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator