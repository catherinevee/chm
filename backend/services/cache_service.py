"""
Redis Cache Service for performance optimization
"""

import json
import pickle
from typing import Any, Optional, Union
import logging
from datetime import timedelta

# Try to import aioredis
try:
    import aioredis
    from aioredis import Redis
    AIOREDIS_AVAILABLE = True
except ImportError:
    aioredis = None
    Redis = None
    AIOREDIS_AVAILABLE = False

from backend.config import settings

logger = logging.getLogger(__name__)

class CacheService:
    """Service for Redis caching operations"""
    
    def __init__(self):
        self.redis_url = settings.redis_url
        self.pool_size = settings.redis_pool_size
        self.default_ttl = settings.redis_ttl
        self.enabled = bool(self.redis_url) and AIOREDIS_AVAILABLE
        self.redis: Optional[Redis] = None
        
        if not AIOREDIS_AVAILABLE:
            logger.warning("Cache service is disabled - aioredis not installed")
        elif not self.redis_url:
            logger.warning("Cache service is disabled - Redis URL not configured")
    
    async def connect(self):
        """Connect to Redis"""
        if not self.enabled:
            return
        
        try:
            self.redis = await aioredis.from_url(
                self.redis_url,
                max_connections=self.pool_size,
                decode_responses=False  # We'll handle encoding ourselves
            )
            
            # Test connection
            await self.redis.ping()
            logger.info("Redis cache connected successfully")
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.enabled = False
            self.redis = None
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis:
            await self.redis.close()
            self.redis = None
            logger.info("Redis cache disconnected")
    
    async def get(
        self,
        key: str,
        default: Any = None,
        deserialize: bool = True
    ) -> Any:
        """Get value from cache"""
        if not self.enabled or not self.redis:
            return default
        
        try:
            value = await self.redis.get(key)
            
            if value is None:
                return default
            
            if deserialize:
                try:
                    # Try JSON first
                    return json.loads(value)
                except (json.JSONDecodeError, TypeError):
                    try:
                        # Try pickle
                        return pickle.loads(value)
                    except:
                        # Return as string
                        return value.decode('utf-8') if isinstance(value, bytes) else value
            else:
                return value
                
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            return default
    
    async def set(
        self,
        key: str,
        value: Any,
        ttl: Optional[int] = None,
        serialize: bool = True
    ) -> bool:
        """Set value in cache"""
        if not self.enabled or not self.redis:
            return False
        
        try:
            if ttl is None:
                ttl = self.default_ttl
            
            if serialize:
                # Try JSON for simple types
                try:
                    value = json.dumps(value)
                except (TypeError, ValueError):
                    # Fall back to pickle for complex objects
                    value = pickle.dumps(value)
            
            if isinstance(value, str):
                value = value.encode('utf-8')
            
            await self.redis.set(key, value, ex=ttl)
            return True
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache"""
        if not self.enabled or not self.redis:
            return False
        
        try:
            result = await self.redis.delete(key)
            return bool(result)
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache"""
        if not self.enabled or not self.redis:
            return False
        
        try:
            return bool(await self.redis.exists(key))
            
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    async def expire(self, key: str, ttl: int) -> bool:
        """Set expiration for a key"""
        if not self.enabled or not self.redis:
            return False
        
        try:
            return bool(await self.redis.expire(key, ttl))
            
        except Exception as e:
            logger.error(f"Cache expire error for key {key}: {e}")
            return False
    
    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a counter"""
        if not self.enabled or not self.redis:
            # Return fallback increment data when cache is disabled
            fallback_data = FallbackData(
                data=0,
                source="cache_disabled_fallback",
                confidence=0.0,
                metadata={"key": key, "reason": "Cache disabled"}
            )
            
            return create_partial_success_result(
                data=0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="Cache is disabled",
                    fallback_available=True
                ),
                suggestions=[
                    "Cache is disabled",
                    "Enable Redis cache",
                    "Check Redis connection",
                    "Use fallback value"
                ]
            ).data
        
        try:
            return await self.redis.incr(key, amount)
            
        except Exception as e:
            logger.error(f"Cache increment error for key {key}: {e}")
            
            # Return fallback increment data when cache operation fails
            fallback_data = FallbackData(
                data=0,
                source="cache_operation_fallback",
                confidence=0.0,
                metadata={"key": key, "error": str(e)}
            )
            
            return create_partial_success_result(
                data=0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="Cache operation failed",
                    fallback_available=True
                ),
                suggestions=[
                    "Cache operation failed",
                    "Check Redis connection",
                    "Verify Redis configuration",
                    "Use fallback value"
                ]
            ).data
    
    async def decrement(self, key: str, amount: int = 1) -> int:
        """Decrement a counter"""
        if not self.enabled or not self.redis:
            # Return fallback decrement data when cache is disabled
            fallback_data = FallbackData(
                data=0,
                source="cache_disabled_fallback",
                confidence=0.0,
                metadata={"key": key, "reason": "Cache disabled"}
            )
            
            return create_partial_success_result(
                data=0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="Cache is disabled",
                    fallback_available=True
                ),
                suggestions=[
                    "Cache is disabled",
                    "Enable Redis cache",
                    "Check Redis connection",
                    "Use fallback value"
                ]
            ).data
        
        try:
            return await self.redis.decr(key, amount)
            
        except Exception as e:
            logger.error(f"Cache decrement error for key {key}: {e}")
            
            # Return fallback decrement data when cache operation fails
            fallback_data = FallbackData(
                data=0,
                source="cache_operation_fallback",
                confidence=0.0,
                metadata={"key": key, "error": str(e)}
            )
            
            return create_partial_success_result(
                data=0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="Cache operation failed",
                    fallback_available=True
                ),
                suggestions=[
                    "Cache operation failed",
                    "Check Redis connection",
                    "Verify Redis configuration",
                    "Use fallback value"
                ]
            ).data
    
    async def get_many(self, keys: list) -> dict:
        """Get multiple values from cache"""
        if not self.enabled or not self.redis or not keys:
            return {}
        
        try:
            values = await self.redis.mget(keys)
            result = {}
            
            for key, value in zip(keys, values):
                if value is not None:
                    try:
                        result[key] = json.loads(value)
                    except:
                        try:
                            result[key] = pickle.loads(value)
                        except:
                            result[key] = value.decode('utf-8') if isinstance(value, bytes) else value
            
            return result
            
        except Exception as e:
            logger.error(f"Cache get_many error: {e}")
            return {}
    
    async def set_many(self, mapping: dict, ttl: Optional[int] = None) -> bool:
        """Set multiple values in cache"""
        if not self.enabled or not self.redis or not mapping:
            return False
        
        if ttl is None:
            ttl = self.default_ttl
        
        try:
            pipe = self.redis.pipeline()
            
            for key, value in mapping.items():
                try:
                    value = json.dumps(value)
                except:
                    value = pickle.dumps(value)
                
                if isinstance(value, str):
                    value = value.encode('utf-8')
                
                pipe.set(key, value, ex=ttl)
            
            await pipe.execute()
            return True
            
        except Exception as e:
            logger.error(f"Cache set_many error: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Delete all keys matching a pattern"""
        if not self.enabled or not self.redis:
            return 0
        
        try:
            keys = []
            async for key in self.redis.scan_iter(match=pattern):
                keys.append(key)
            
            if keys:
                return await self.redis.delete(*keys)
            
            return 0
            
        except Exception as e:
            logger.error(f"Cache clear_pattern error for pattern {pattern}: {e}")
            return 0
    
    async def flush_all(self) -> bool:
        """Flush all cache data (use with caution)"""
        if not self.enabled or not self.redis:
            return False
        
        try:
            await self.redis.flushall()
            logger.warning("Cache flushed - all data cleared")
            return True
            
        except Exception as e:
            logger.error(f"Cache flush_all error: {e}")
            return False
    
    # Cache key generators for common use cases
    
    @staticmethod
    def device_key(device_id: str) -> str:
        """Generate cache key for device data"""
        return f"device:{device_id}"
    
    @staticmethod
    def metrics_key(device_id: str, metric_type: str) -> str:
        """Generate cache key for metrics data"""
        return f"metrics:{device_id}:{metric_type}"
    
    @staticmethod
    def user_key(user_id: str) -> str:
        """Generate cache key for user data"""
        return f"user:{user_id}"
    
    @staticmethod
    def session_key(session_id: str) -> str:
        """Generate cache key for session data"""
        return f"session:{session_id}"
    
    @staticmethod
    def rate_limit_key(identifier: str, endpoint: str) -> str:
        """Generate cache key for rate limiting"""
        return f"rate_limit:{identifier}:{endpoint}"

# Global cache service instance
cache_service = CacheService()

# Decorator for caching function results
def cached(ttl: int = 300, key_prefix: str = ""):
    """Decorator to cache function results"""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Generate cache key
            cache_key = f"{key_prefix}:{func.__name__}:{str(args)}:{str(kwargs)}"
            
            # Try to get from cache
            result = await cache_service.get(cache_key)
            if result is not None:
                logger.debug(f"Cache hit for {cache_key}")
                return result
            
            # Call function and cache result
            result = await func(*args, **kwargs)
            await cache_service.set(cache_key, result, ttl)
            logger.debug(f"Cached result for {cache_key}")
            
            return result
        
        return wrapper
    return decorator