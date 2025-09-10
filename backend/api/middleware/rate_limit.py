"""
Rate limiting middleware for API protection
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from typing import Dict, Tuple, Optional
import time
import asyncio
from datetime import datetime, timedelta
from collections import defaultdict, deque
import logging
import hashlib

logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware using sliding window algorithm
    """
    
    def __init__(self, app, default_limit: int = 100, window_seconds: int = 60):
        super().__init__(app)
        self.default_limit = default_limit
        self.window_seconds = window_seconds
        
        # Store request timestamps for each client
        self.request_history: Dict[str, deque] = defaultdict(lambda: deque())
        
        # Custom limits for specific endpoints
        self.endpoint_limits = {
            "/api/v1/auth/login": (5, 60),  # 5 requests per minute
            "/api/v1/auth/register": (3, 60),  # 3 requests per minute
            "/api/v1/auth/password/reset": (3, 300),  # 3 requests per 5 minutes
            "/api/v1/discovery/start": (10, 3600),  # 10 per hour
            "/api/v1/import": (5, 60),  # 5 imports per minute
            "/api/v1/export": (10, 60),  # 10 exports per minute
            "/api/v1/devices": (50, 60),  # 50 requests per minute for device operations
            "/api/v1/metrics": (200, 60),  # 200 requests per minute for metrics
        }
        
        # Whitelist certain paths
        self.whitelist_paths = [
            "/",
            "/api/docs",
            "/api/redoc",
            "/api/openapi.json",
            "/api/v1/health",
            "/ws",  # WebSocket connections
        ]
        
        # Cache for user identification
        self.user_cache: Dict[str, Tuple[str, float]] = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Cleanup task
        self.cleanup_task = None
    
    def get_client_identifier(self, request: Request) -> str:
        """Get unique identifier for the client"""
        # Try to get authenticated user from token
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            # Create hash of token for privacy
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            identifier = f"user:{token_hash}"
        else:
            # Use IP address for unauthenticated requests
            client_ip = request.client.host if request.client else "unknown"
            
            # Handle proxy headers
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                client_ip = forwarded_for.split(",")[0].strip()
            
            real_ip = request.headers.get("X-Real-IP")
            if real_ip:
                client_ip = real_ip
            
            identifier = f"ip:{client_ip}"
        
        return identifier
    
    def get_endpoint_limit(self, path: str) -> Tuple[int, int]:
        """Get rate limit for specific endpoint"""
        # Check exact match first
        if path in self.endpoint_limits:
            return self.endpoint_limits[path]
        
        # Check prefix match for parameterized routes
        for endpoint_pattern, limit in self.endpoint_limits.items():
            if path.startswith(endpoint_pattern):
                return limit
        
        # Return default limit
        return (self.default_limit, self.window_seconds)
    
    def is_rate_limited(self, identifier: str, path: str) -> Tuple[bool, Dict[str, any]]:
        """Check if client has exceeded rate limit"""
        current_time = time.time()
        limit, window = self.get_endpoint_limit(path)
        
        # Get request history for this client
        history = self.request_history[identifier]
        
        # Remove old requests outside the window
        cutoff_time = current_time - window
        while history and history[0] < cutoff_time:
            history.popleft()
        
        # Check if limit exceeded
        if len(history) >= limit:
            # Calculate when the client can retry
            oldest_request = history[0]
            retry_after = int(oldest_request + window - current_time)
            
            return True, {
                "limit": limit,
                "window": window,
                "remaining": 0,
                "retry_after": max(1, retry_after),
                "reset_time": int(oldest_request + window)
            }
        
        # Add current request to history
        history.append(current_time)
        
        return False, {
            "limit": limit,
            "window": window,
            "remaining": limit - len(history),
            "retry_after": None,
            "reset_time": int(current_time + window)
        }
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting"""
        # Skip rate limiting for whitelisted paths
        if request.url.path in self.whitelist_paths:
            return await call_next(request)
        
        # Skip rate limiting for OPTIONS requests
        if request.method == "OPTIONS":
            return await call_next(request)
        
        # Get client identifier
        identifier = self.get_client_identifier(request)
        
        # Check rate limit
        is_limited, limit_info = self.is_rate_limited(identifier, request.url.path)
        
        if is_limited:
            # Log rate limit violation
            logger.warning(f"Rate limit exceeded for {identifier} on {request.url.path}")
            
            # Return 429 Too Many Requests
            return JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "type": "RateLimitExceeded",
                        "message": "Too many requests. Please try again later.",
                        "retry_after": limit_info["retry_after"],
                        "timestamp": datetime.utcnow().isoformat()
                    }
                },
                headers={
                    "X-RateLimit-Limit": str(limit_info["limit"]),
                    "X-RateLimit-Remaining": str(limit_info["remaining"]),
                    "X-RateLimit-Reset": str(limit_info["reset_time"]),
                    "Retry-After": str(limit_info["retry_after"])
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        response.headers["X-RateLimit-Limit"] = str(limit_info["limit"])
        response.headers["X-RateLimit-Remaining"] = str(limit_info["remaining"])
        response.headers["X-RateLimit-Reset"] = str(limit_info["reset_time"])
        
        return response
    
    async def cleanup_old_entries(self):
        """Periodically clean up old request history"""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                current_time = time.time()
                max_window = max(window for _, window in self.endpoint_limits.values())
                cutoff_time = current_time - max_window
                
                # Clean up request history
                empty_identifiers = []
                for identifier, history in self.request_history.items():
                    # Remove old entries
                    while history and history[0] < cutoff_time:
                        history.popleft()
                    
                    # Mark empty histories for removal
                    if not history:
                        empty_identifiers.append(identifier)
                
                # Remove empty histories
                for identifier in empty_identifiers:
                    del self.request_history[identifier]
                
                # Clean up user cache
                expired_cache_keys = [
                    key for key, (_, timestamp) in self.user_cache.items()
                    if current_time - timestamp > self.cache_ttl
                ]
                for key in expired_cache_keys:
                    del self.user_cache[key]
                
                logger.debug(f"Rate limiter cleanup: removed {len(empty_identifiers)} empty histories, "
                           f"{len(expired_cache_keys)} expired cache entries")
                
            except Exception as e:
                logger.error(f"Error in rate limiter cleanup: {e}")

class IPRateLimiter:
    """
    Simple IP-based rate limiter for specific operations
    """
    
    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(lambda: deque())
    
    def is_allowed(self, ip_address: str) -> bool:
        """Check if IP is allowed to make request"""
        current_time = time.time()
        request_times = self.requests[ip_address]
        
        # Remove old requests
        cutoff_time = current_time - self.window_seconds
        while request_times and request_times[0] < cutoff_time:
            request_times.popleft()
        
        # Check limit
        if len(request_times) >= self.max_requests:
            return False
        
        # Add current request
        request_times.append(current_time)
        return True
    
    def reset(self, ip_address: str):
        """Reset rate limit for specific IP"""
        if ip_address in self.requests:
            del self.requests[ip_address]
    
    def get_remaining(self, ip_address: str) -> int:
        """Get remaining requests for IP"""
        current_time = time.time()
        request_times = self.requests.get(ip_address, deque())
        
        # Count valid requests
        cutoff_time = current_time - self.window_seconds
        valid_requests = sum(1 for t in request_times if t >= cutoff_time)
        
        return max(0, self.max_requests - valid_requests)