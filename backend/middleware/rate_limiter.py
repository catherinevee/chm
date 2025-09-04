"""
Production-grade distributed rate limiting system.
Implements multiple algorithms with Redis backend for distributed enforcement.
"""

import asyncio
import time
import hashlib
import json
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import struct

try:
    import redis.asyncio as redis
    from redis.asyncio.lock import Lock as RedisLock
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    RedisLock = None
    REDIS_AVAILABLE = False

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)


class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms"""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    LEAKY_BUCKET = "leaky_bucket"
    SLIDING_LOG = "sliding_log"
    GCRA = "gcra"  # Generic Cell Rate Algorithm


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    requests_per_second: Optional[float] = None
    requests_per_minute: Optional[int] = None
    requests_per_hour: Optional[int] = None
    requests_per_day: Optional[int] = None
    
    burst_size: Optional[int] = None
    algorithm: RateLimitAlgorithm = RateLimitAlgorithm.SLIDING_WINDOW
    
    # Custom limits per endpoint
    endpoint_limits: Dict[str, 'RateLimitConfig'] = field(default_factory=dict)
    
    # User tier limits
    tier_limits: Dict[str, 'RateLimitConfig'] = field(default_factory=dict)
    
    # IP-based limits
    ip_limits: bool = True
    ip_whitelist: List[str] = field(default_factory=list)
    ip_blacklist: List[str] = field(default_factory=list)
    
    # Headers
    include_headers: bool = True
    header_prefix: str = "X-RateLimit"
    
    # Actions
    block_duration: int = 60  # seconds to block after limit exceeded
    return_retry_after: bool = True
    custom_response: Optional[Dict[str, Any]] = None


@dataclass
class RateLimitState:
    """Rate limit state for a key"""
    key: str
    remaining: int
    reset_at: float
    total: int
    window_start: float
    blocked_until: Optional[float] = None
    
    @property
    def is_blocked(self) -> bool:
        """Check if currently blocked"""
        if self.blocked_until:
            return time.time() < self.blocked_until
        return False


class RateLimiter:
    """Distributed rate limiter implementation"""
    
    def __init__(self,
                 redis_client: Optional[redis.Redis] = None,
                 redis_url: Optional[str] = None,
                 config: Optional[RateLimitConfig] = None,
                 key_prefix: str = "ratelimit"):
        
        self.redis_client = redis_client
        self.redis_url = redis_url
        self.config = config or RateLimitConfig()
        self.key_prefix = key_prefix
        
        # Local cache for performance
        self._local_cache: Dict[str, RateLimitState] = {}
        self._cache_ttl = 1.0  # seconds
        
        # Statistics
        self.stats = defaultdict(int)
        
        # Lua scripts for atomic operations
        self._lua_scripts: Dict[str, Any] = {}
        self._init_lua_scripts()
    
    async def initialize(self):
        """Initialize the rate limiter"""
        if not self.redis_client and self.redis_url and REDIS_AVAILABLE:
            self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
            
            # Test connection
            try:
                await self.redis_client.ping()
                logger.info("Rate limiter connected to Redis")
            except Exception as e:
                logger.error(f"Failed to connect to Redis: {e}")
                self.redis_client = None
    
    def _init_lua_scripts(self):
        """Initialize Lua scripts for atomic operations"""
        # Sliding window rate limit script
        self._lua_scripts['sliding_window'] = """
        local key = KEYS[1]
        local now = tonumber(ARGV[1])
        local window = tonumber(ARGV[2])
        local limit = tonumber(ARGV[3])
        
        local clearBefore = now - window
        
        -- Remove old entries
        redis.call('zremrangebyscore', key, 0, clearBefore)
        
        -- Count current entries
        local current = redis.call('zcard', key)
        
        if current < limit then
            -- Add new entry
            redis.call('zadd', key, now, now)
            redis.call('expire', key, window)
            return {1, limit - current - 1, current + 1}
        else
            return {0, 0, current}
        end
        """
        
        # Token bucket script
        self._lua_scripts['token_bucket'] = """
        local key = KEYS[1]
        local rate = tonumber(ARGV[1])
        local capacity = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        local requested = tonumber(ARGV[4])
        
        local bucket_data = redis.call('hmget', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket_data[1]) or capacity
        local last_refill = tonumber(bucket_data[2]) or now
        
        -- Calculate tokens to add
        local time_passed = math.max(0, now - last_refill)
        local tokens_to_add = time_passed * rate
        tokens = math.min(capacity, tokens + tokens_to_add)
        
        if tokens >= requested then
            tokens = tokens - requested
            redis.call('hmset', key, 'tokens', tokens, 'last_refill', now)
            redis.call('expire', key, capacity / rate + 1)
            return {1, tokens, capacity}
        else
            redis.call('hmset', key, 'tokens', tokens, 'last_refill', now)
            redis.call('expire', key, capacity / rate + 1)
            return {0, tokens, capacity}
        end
        """
        
        # GCRA (Generic Cell Rate Algorithm) script
        self._lua_scripts['gcra'] = """
        local key = KEYS[1]
        local emission_interval = tonumber(ARGV[1])
        local delay_tolerance = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        local tat = redis.call('get', key)
        if tat then
            tat = tonumber(tat)
        else
            tat = now
        end
        
        local new_tat = math.max(tat, now) + emission_interval
        local allow_at = new_tat - delay_tolerance
        
        if now >= allow_at then
            redis.call('set', key, new_tat)
            redis.call('expire', key, math.ceil(delay_tolerance))
            return {1, 0, emission_interval}
        else
            return {0, allow_at - now, emission_interval}
        end
        """
    
    async def check_rate_limit(self,
                               key: str,
                               algorithm: Optional[RateLimitAlgorithm] = None,
                               limit: Optional[int] = None,
                               window: Optional[int] = None) -> RateLimitState:
        """Check if rate limit allows request"""
        
        algorithm = algorithm or self.config.algorithm
        
        # Determine limit and window
        if not limit or not window:
            limit, window = self._get_limit_window()
        
        # Check cache first
        cache_key = f"{self.key_prefix}:{key}"
        if cache_key in self._local_cache:
            cached = self._local_cache[cache_key]
            if time.time() - cached.window_start < self._cache_ttl:
                self.stats['cache_hits'] += 1
                return cached
        
        self.stats['cache_misses'] += 1
        
        # Check Redis
        if self.redis_client:
            try:
                if algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                    result = await self._check_sliding_window(key, limit, window)
                elif algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                    result = await self._check_token_bucket(key, limit, window)
                elif algorithm == RateLimitAlgorithm.GCRA:
                    result = await self._check_gcra(key, limit, window)
                elif algorithm == RateLimitAlgorithm.FIXED_WINDOW:
                    result = await self._check_fixed_window(key, limit, window)
                elif algorithm == RateLimitAlgorithm.LEAKY_BUCKET:
                    result = await self._check_leaky_bucket(key, limit, window)
                else:
                    result = await self._check_sliding_log(key, limit, window)
                
                # Cache result
                self._local_cache[cache_key] = result
                
                # Clean old cache entries periodically
                if len(self._local_cache) > 10000:
                    self._clean_cache()
                
                return result
                
            except Exception as e:
                logger.error(f"Rate limit check failed: {e}")
                self.stats['errors'] += 1
                
                # Fail open (allow request) on Redis errors
                return RateLimitState(
                    key=key,
                    remaining=1,
                    reset_at=time.time() + window,
                    total=limit,
                    window_start=time.time()
                )
        else:
            # Fallback to local rate limiting
            return await self._check_local_rate_limit(key, limit, window)
    
    async def _check_sliding_window(self, key: str, limit: int, window: int) -> RateLimitState:
        """Sliding window rate limiting using sorted sets"""
        if not self.redis_client:
            return await self._check_local_rate_limit(key, limit, window)
        
        now = time.time()
        redis_key = f"{self.key_prefix}:sw:{key}"
        
        # Execute Lua script for atomicity
        if 'sliding_window' not in self._lua_scripts:
            self._init_lua_scripts()
        
        script = self.redis_client.register_script(self._lua_scripts['sliding_window'])
        result = await script(keys=[redis_key], args=[now, window, limit])
        
        allowed, remaining, current = result
        
        state = RateLimitState(
            key=key,
            remaining=remaining,
            reset_at=now + window,
            total=limit,
            window_start=now - window
        )
        
        if not allowed:
            self.stats['rate_limited'] += 1
            state.blocked_until = now + self.config.block_duration
        else:
            self.stats['allowed'] += 1
        
        return state
    
    async def _check_token_bucket(self, key: str, limit: int, window: int) -> RateLimitState:
        """Token bucket rate limiting"""
        if not self.redis_client:
            return await self._check_local_rate_limit(key, limit, window)
        
        now = time.time()
        redis_key = f"{self.key_prefix}:tb:{key}"
        
        # Calculate rate and capacity
        rate = limit / window  # tokens per second
        capacity = limit if not self.config.burst_size else self.config.burst_size
        
        script = self.redis_client.register_script(self._lua_scripts['token_bucket'])
        result = await script(keys=[redis_key], args=[rate, capacity, now, 1])
        
        allowed, tokens_remaining, capacity = result
        
        state = RateLimitState(
            key=key,
            remaining=int(tokens_remaining),
            reset_at=now + (capacity - tokens_remaining) / rate,
            total=capacity,
            window_start=now
        )
        
        if not allowed:
            self.stats['rate_limited'] += 1
            state.blocked_until = now + self.config.block_duration
        else:
            self.stats['allowed'] += 1
        
        return state
    
    async def _check_gcra(self, key: str, limit: int, window: int) -> RateLimitState:
        """Generic Cell Rate Algorithm (GCRA) rate limiting"""
        if not self.redis_client:
            return await self._check_local_rate_limit(key, limit, window)
        
        now = time.time()
        redis_key = f"{self.key_prefix}:gcra:{key}"
        
        # Calculate emission interval and delay tolerance
        emission_interval = window / limit
        delay_tolerance = window
        
        script = self.redis_client.register_script(self._lua_scripts['gcra'])
        result = await script(keys=[redis_key], args=[emission_interval, delay_tolerance, now])
        
        allowed, retry_after, interval = result
        
        state = RateLimitState(
            key=key,
            remaining=1 if allowed else 0,
            reset_at=now + retry_after if retry_after > 0 else now + interval,
            total=limit,
            window_start=now
        )
        
        if not allowed:
            self.stats['rate_limited'] += 1
            state.blocked_until = now + retry_after
        else:
            self.stats['allowed'] += 1
        
        return state
    
    async def _check_fixed_window(self, key: str, limit: int, window: int) -> RateLimitState:
        """Fixed window rate limiting"""
        if not self.redis_client:
            return await self._check_local_rate_limit(key, limit, window)
        
        now = time.time()
        window_id = int(now // window)
        redis_key = f"{self.key_prefix}:fw:{key}:{window_id}"
        
        # Increment counter
        pipe = self.redis_client.pipeline()
        pipe.incr(redis_key)
        pipe.expire(redis_key, window + 1)
        results = await pipe.execute()
        
        current_count = results[0]
        
        state = RateLimitState(
            key=key,
            remaining=max(0, limit - current_count),
            reset_at=(window_id + 1) * window,
            total=limit,
            window_start=window_id * window
        )
        
        if current_count > limit:
            self.stats['rate_limited'] += 1
            state.blocked_until = now + self.config.block_duration
            state.remaining = 0
        else:
            self.stats['allowed'] += 1
        
        return state
    
    async def _check_leaky_bucket(self, key: str, limit: int, window: int) -> RateLimitState:
        """Leaky bucket rate limiting"""
        if not self.redis_client:
            return await self._check_local_rate_limit(key, limit, window)
        
        now = time.time()
        redis_key = f"{self.key_prefix}:lb:{key}"
        
        # Leak rate (requests that leak out per second)
        leak_rate = limit / window
        
        # Get current bucket state
        pipe = self.redis_client.pipeline()
        pipe.hget(redis_key, 'level')
        pipe.hget(redis_key, 'last_leak')
        results = await pipe.execute()
        
        level = float(results[0]) if results[0] else 0.0
        last_leak = float(results[1]) if results[1] else now
        
        # Calculate leaked amount
        time_passed = now - last_leak
        leaked = time_passed * leak_rate
        level = max(0, level - leaked)
        
        # Check if we can add to bucket
        if level + 1 <= limit:
            level += 1
            allowed = True
        else:
            allowed = False
        
        # Update bucket state
        pipe = self.redis_client.pipeline()
        pipe.hset(redis_key, 'level', level)
        pipe.hset(redis_key, 'last_leak', now)
        pipe.expire(redis_key, window + 1)
        await pipe.execute()
        
        state = RateLimitState(
            key=key,
            remaining=int(limit - level),
            reset_at=now + (level / leak_rate),
            total=limit,
            window_start=now
        )
        
        if not allowed:
            self.stats['rate_limited'] += 1
            state.blocked_until = now + self.config.block_duration
        else:
            self.stats['allowed'] += 1
        
        return state
    
    async def _check_sliding_log(self, key: str, limit: int, window: int) -> RateLimitState:
        """Sliding log rate limiting (most accurate but memory intensive)"""
        if not self.redis_client:
            return await self._check_local_rate_limit(key, limit, window)
        
        now = time.time()
        redis_key = f"{self.key_prefix}:sl:{key}"
        
        # Use list to store timestamps
        pipe = self.redis_client.pipeline()
        
        # Get all timestamps in window
        pipe.lrange(redis_key, 0, -1)
        results = await pipe.execute()
        
        timestamps = [float(ts) for ts in results[0] if ts]
        
        # Filter timestamps within window
        cutoff = now - window
        valid_timestamps = [ts for ts in timestamps if ts > cutoff]
        
        if len(valid_timestamps) < limit:
            # Add new timestamp
            pipe = self.redis_client.pipeline()
            pipe.lpush(redis_key, now)
            pipe.ltrim(redis_key, 0, limit * 2)  # Keep some extra for efficiency
            pipe.expire(redis_key, window + 1)
            await pipe.execute()
            
            allowed = True
            remaining = limit - len(valid_timestamps) - 1
        else:
            allowed = False
            remaining = 0
        
        state = RateLimitState(
            key=key,
            remaining=remaining,
            reset_at=min(valid_timestamps) + window if valid_timestamps else now + window,
            total=limit,
            window_start=now - window
        )
        
        if not allowed:
            self.stats['rate_limited'] += 1
            state.blocked_until = now + self.config.block_duration
        else:
            self.stats['allowed'] += 1
        
        return state
    
    async def _check_local_rate_limit(self, key: str, limit: int, window: int) -> RateLimitState:
        """Fallback local rate limiting when Redis is unavailable"""
        # Simple in-memory sliding window
        now = time.time()
        
        if not hasattr(self, '_local_limiters'):
            self._local_limiters = {}
        
        if key not in self._local_limiters:
            self._local_limiters[key] = []
        
        # Clean old entries
        cutoff = now - window
        self._local_limiters[key] = [ts for ts in self._local_limiters[key] if ts > cutoff]
        
        if len(self._local_limiters[key]) < limit:
            self._local_limiters[key].append(now)
            allowed = True
            remaining = limit - len(self._local_limiters[key])
        else:
            allowed = False
            remaining = 0
        
        state = RateLimitState(
            key=key,
            remaining=remaining,
            reset_at=self._local_limiters[key][0] + window if self._local_limiters[key] else now + window,
            total=limit,
            window_start=now - window
        )
        
        if not allowed:
            state.blocked_until = now + self.config.block_duration
        
        return state
    
    def _get_limit_window(self) -> Tuple[int, int]:
        """Get limit and window from config"""
        if self.config.requests_per_second:
            return int(self.config.requests_per_second), 1
        elif self.config.requests_per_minute:
            return self.config.requests_per_minute, 60
        elif self.config.requests_per_hour:
            return self.config.requests_per_hour, 3600
        elif self.config.requests_per_day:
            return self.config.requests_per_day, 86400
        else:
            return 100, 60  # Default: 100 requests per minute
    
    def _clean_cache(self):
        """Clean expired cache entries"""
        now = time.time()
        expired = [
            k for k, v in self._local_cache.items()
            if now - v.window_start > self._cache_ttl
        ]
        for k in expired:
            del self._local_cache[k]
    
    def get_stats(self) -> Dict[str, int]:
        """Get rate limiter statistics"""
        return dict(self.stats)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting"""
    
    def __init__(self,
                 app: ASGIApp,
                 rate_limiter: RateLimiter,
                 get_key: Optional[Callable] = None,
                 exclude_paths: Optional[List[str]] = None):
        super().__init__(app)
        self.rate_limiter = rate_limiter
        self.get_key = get_key or self._default_get_key
        self.exclude_paths = exclude_paths or []
    
    def _default_get_key(self, request: Request) -> str:
        """Default key extraction (IP-based)"""
        # Try to get real IP from headers
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            ip = forwarded.split(",")[0].strip()
        else:
            ip = request.client.host if request.client else "unknown"
        
        # Include path in key for per-endpoint limits
        path = request.url.path
        return f"{ip}:{path}"
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting"""
        # Check if path is excluded
        if any(request.url.path.startswith(path) for path in self.exclude_paths):
            return await call_next(request)
        
        # Get rate limit key
        key = self.get_key(request)
        
        # Check for IP whitelist/blacklist
        ip = request.client.host if request.client else None
        if ip:
            if ip in self.rate_limiter.config.ip_blacklist:
                return JSONResponse(
                    status_code=403,
                    content={"error": "IP address blocked"}
                )
            
            if ip in self.rate_limiter.config.ip_whitelist:
                return await call_next(request)
        
        # Check endpoint-specific limits
        endpoint_config = None
        for pattern, config in self.rate_limiter.config.endpoint_limits.items():
            if request.url.path.startswith(pattern):
                endpoint_config = config
                break
        
        # Check rate limit
        if endpoint_config:
            state = await self.rate_limiter.check_rate_limit(
                key,
                algorithm=endpoint_config.algorithm,
                limit=endpoint_config.requests_per_minute,
                window=60
            )
        else:
            state = await self.rate_limiter.check_rate_limit(key)
        
        # Add rate limit headers
        if self.rate_limiter.config.include_headers:
            headers = {
                f"{self.rate_limiter.config.header_prefix}-Limit": str(state.total),
                f"{self.rate_limiter.config.header_prefix}-Remaining": str(state.remaining),
                f"{self.rate_limiter.config.header_prefix}-Reset": str(int(state.reset_at))
            }
        else:
            headers = {}
        
        # Check if blocked
        if state.is_blocked or state.remaining <= 0:
            # Rate limited
            if self.rate_limiter.config.return_retry_after:
                headers["Retry-After"] = str(int(state.reset_at - time.time()))
            
            if self.rate_limiter.config.custom_response:
                content = self.rate_limiter.config.custom_response
            else:
                content = {
                    "error": "Rate limit exceeded",
                    "retry_after": int(state.reset_at - time.time())
                }
            
            return JSONResponse(
                status_code=429,
                content=content,
                headers=headers
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        for header, value in headers.items():
            response.headers[header] = value
        
        return response


def create_rate_limiter(config: RateLimitConfig, 
                       redis_url: Optional[str] = None) -> RateLimiter:
    """Factory function to create rate limiter"""
    limiter = RateLimiter(
        redis_url=redis_url,
        config=config
    )
    
    # Initialize in background
    asyncio.create_task(limiter.initialize())
    
    return limiter