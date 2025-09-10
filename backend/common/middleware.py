"""
Custom middleware for the application
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Callable, Dict, Optional

from fastapi import HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from backend.config import settings

# Try to import cache service, but don't fail if Redis is not available
try:
    from backend.services.cache_service import cache_service
except (ImportError, TypeError) as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Cache service not available: {e}")
    cache_service = None

logger = logging.getLogger(__name__)

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Rate limiting middleware to prevent API abuse
    """
    
    def __init__(
        self,
        app: ASGIApp,
        calls_per_minute: int = None,
        calls_per_hour: int = None
    ):
        super().__init__(app)
        self.calls_per_minute = calls_per_minute or settings.rate_limit_default
        self.calls_per_hour = calls_per_hour or (settings.rate_limit_default * 60)
        
        # In-memory storage for rate limiting (fallback if Redis not available)
        self.requests: Dict[str, list] = defaultdict(list)
        
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and apply rate limiting
        """
        # Skip rate limiting for health checks and docs
        if request.url.path in ["/health", "/api/docs", "/api/redoc", "/api/openapi.json"]:
            return await call_next(request)
        
        # Get client identifier (IP address or user ID)
        client_id = self._get_client_id(request)
        
        # Check rate limit
        if not await self._check_rate_limit(client_id, request.url.path):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Please try again later."
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.calls_per_minute)
        remaining = await self._get_remaining_calls(client_id)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(time.time()) + 60)
        
        return response
    
    def _get_client_id(self, request: Request) -> str:
        """
        Get client identifier from request
        """
        # Try to get user ID from JWT if authenticated
        if hasattr(request.state, "user") and request.state.user:
            return f"user:{request.state.user.id}"
        
        # Fall back to IP address
        client_ip = request.client.host if request.client else "unknown"
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            client_ip = forwarded.split(",")[0].strip()
        
        return f"ip:{client_ip}"
    
    async def _check_rate_limit(self, client_id: str, path: str) -> bool:
        """
        Check if client has exceeded rate limit
        """
        # Try to use Redis for distributed rate limiting
        if cache_service and hasattr(cache_service, 'enabled') and cache_service.enabled:
            return await self._check_rate_limit_redis(client_id, path)
        
        # Fall back to in-memory rate limiting
        return self._check_rate_limit_memory(client_id)
    
    async def _check_rate_limit_redis(self, client_id: str, path: str) -> bool:
        """
        Check rate limit using Redis
        """
        try:
            # Create keys for minute and hour windows
            minute_key = f"rate_limit:{client_id}:minute:{int(time.time() // 60)}"
            hour_key = f"rate_limit:{client_id}:hour:{int(time.time() // 3600)}"
            
            # Increment counters
            minute_count = await cache_service.increment(minute_key)
            hour_count = await cache_service.increment(hour_key)
            
            # Set expiration if this is the first request
            if minute_count == 1:
                await cache_service.expire(minute_key, 60)
            if hour_count == 1:
                await cache_service.expire(hour_key, 3600)
            
            # Check limits
            if minute_count > self.calls_per_minute:
                logger.warning(f"Rate limit exceeded for {client_id} (minute)")
                return False
            
            if hour_count > self.calls_per_hour:
                logger.warning(f"Rate limit exceeded for {client_id} (hour)")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Redis rate limit check failed: {e}")
            # Fall back to memory-based limiting
            return self._check_rate_limit_memory(client_id)
    
    def _check_rate_limit_memory(self, client_id: str) -> bool:
        """
        Check rate limit using in-memory storage
        """
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        
        # Clean old requests
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if req_time > hour_ago
        ]
        
        # Count requests in windows
        minute_requests = sum(
            1 for req_time in self.requests[client_id]
            if req_time > minute_ago
        )
        hour_requests = len(self.requests[client_id])
        
        # Check limits
        if minute_requests >= self.calls_per_minute:
            logger.warning(f"Rate limit exceeded for {client_id} (minute)")
            return False
        
        if hour_requests >= self.calls_per_hour:
            logger.warning(f"Rate limit exceeded for {client_id} (hour)")
            return False
        
        # Record this request
        self.requests[client_id].append(now)
        return True
    
    async def _get_remaining_calls(self, client_id: str) -> int:
        """
        Get remaining calls for client
        """
        if cache_service.enabled:
            try:
                minute_key = f"rate_limit:{client_id}:minute:{int(time.time() // 60)}"
                count = await cache_service.get(minute_key, 0)
                return max(0, self.calls_per_minute - int(count))
            except:
                pass
        
        # Fall back to memory
        now = datetime.now()
        minute_ago = now - timedelta(minutes=1)
        minute_requests = sum(
            1 for req_time in self.requests.get(client_id, [])
            if req_time > minute_ago
        )
        return max(0, self.calls_per_minute - minute_requests)


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for request/response logging
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Log request and response details
        """
        start_time = time.time()
        
        # Log request
        logger.info(
            f"Request: {request.method} {request.url.path} "
            f"from {request.client.host if request.client else 'unknown'}"
        )
        
        # Process request
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Log response
        logger.info(
            f"Response: {response.status_code} for {request.url.path} "
            f"in {process_time:.3f}s"
        )
        
        # Add processing time header
        response.headers["X-Process-Time"] = str(process_time)
        
        return response


class CompressionMiddleware(BaseHTTPMiddleware):
    """
    Middleware for response compression
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Compress response if client supports it
        """
        response = await call_next(request)
        
        # Check if client accepts gzip
        accept_encoding = request.headers.get("accept-encoding", "")
        if "gzip" in accept_encoding and response.status_code == 200:
            # Response compression would be handled by the server (nginx/uvicorn)
            response.headers["Vary"] = "Accept-Encoding"
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Add security headers to response
        """
        response = await call_next(request)
        
        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Add CSP header for production
        if settings.environment == "production":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self' ws: wss:;"
            )
        
        return response