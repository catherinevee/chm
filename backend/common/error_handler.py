"""
Comprehensive Error Handler - Global error handling and recovery system
"""

import asyncio
import logging
import sys
import traceback
from contextlib import asynccontextmanager
from datetime import datetime
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Type

import redis.exceptions
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import DataError, IntegrityError, SQLAlchemyError

logger = logging.getLogger(__name__)


class CHMException(Exception):
    """Base exception class for CHM application"""
    
    def __init__(self,
                 message: str,
                 code: str = None,
                 status_code: int = 500,
                 details: Dict[str, Any] = None):
        """
        Initialize CHM exception
        
        Args:
            message: Error message
            code: Error code for categorization
            status_code: HTTP status code
            details: Additional error details
        """
        self.message = message
        self.code = code or 'CHM_ERROR'
        self.status_code = status_code
        self.details = details or {}
        self.timestamp = datetime.utcnow()
        super().__init__(self.message)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary"""
        return {
            'error': {
                'message': self.message,
                'code': self.code,
                'status_code': self.status_code,
                'details': self.details,
                'timestamp': self.timestamp.isoformat()
            }
        }


class DeviceNotFoundException(CHMException):
    """Device not found exception"""
    def __init__(self, device_id: str):
        super().__init__(
            message=f"Device {device_id} not found",
            code='DEVICE_NOT_FOUND',
            status_code=404
        )


class DeviceConnectionException(CHMException):
    """Device connection failure exception"""
    def __init__(self, device: str, protocol: str, reason: str = None):
        super().__init__(
            message=f"Failed to connect to device {device} via {protocol}",
            code='DEVICE_CONNECTION_FAILED',
            status_code=503,
            details={'device': device, 'protocol': protocol, 'reason': reason}
        )


class AuthenticationException(CHMException):
    """Authentication failure exception"""
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(
            message=message,
            code='AUTHENTICATION_FAILED',
            status_code=401
        )


class AuthorizationException(CHMException):
    """Authorization failure exception"""
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(
            message=message,
            code='AUTHORIZATION_FAILED',
            status_code=403
        )


class ValidationException(CHMException):
    """Data validation exception"""
    def __init__(self, message: str, errors: List[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            code='VALIDATION_ERROR',
            status_code=400,
            details={'validation_errors': errors or []}
        )


class RateLimitException(CHMException):
    """Rate limit exceeded exception"""
    def __init__(self, limit: int, window: int):
        super().__init__(
            message=f"Rate limit exceeded: {limit} requests per {window} seconds",
            code='RATE_LIMIT_EXCEEDED',
            status_code=429,
            details={'limit': limit, 'window': window}
        )


class ServiceUnavailableException(CHMException):
    """Service unavailable exception"""
    def __init__(self, service: str, reason: str = None):
        super().__init__(
            message=f"Service {service} is unavailable",
            code='SERVICE_UNAVAILABLE',
            status_code=503,
            details={'service': service, 'reason': reason}
        )


class ConfigurationException(CHMException):
    """Configuration error exception"""
    def __init__(self, message: str):
        super().__init__(
            message=message,
            code='CONFIGURATION_ERROR',
            status_code=500
        )


class ErrorHandler:
    """
    Global error handler with recovery mechanisms
    """
    
    def __init__(self):
        self.error_callbacks: Dict[Type[Exception], List[Callable]] = {}
        self.recovery_strategies: Dict[Type[Exception], Callable] = {}
        self.error_stats: Dict[str, int] = {}
        
    def register_callback(self, exception_type: Type[Exception], callback: Callable):
        """
        Register error callback for specific exception type
        
        Args:
            exception_type: Exception class
            callback: Callback function
        """
        if exception_type not in self.error_callbacks:
            self.error_callbacks[exception_type] = []
        self.error_callbacks[exception_type].append(callback)
    
    def register_recovery(self, exception_type: Type[Exception], strategy: Callable):
        """
        Register recovery strategy for exception type
        
        Args:
            exception_type: Exception class
            strategy: Recovery strategy function
        """
        self.recovery_strategies[exception_type] = strategy
    
    async def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Handle error with callbacks and recovery
        
        Args:
            error: Exception to handle
            context: Error context
            
        Returns:
            Error response dictionary
        """
        error_type = type(error)
        error_name = f"{error_type.__module__}.{error_type.__name__}"
        
        # Update statistics
        self.error_stats[error_name] = self.error_stats.get(error_name, 0) + 1
        
        # Log error
        logger.error(
            f"Error occurred: {error_name}",
            exc_info=True,
            extra={'context': context}
        )
        
        # Execute callbacks
        callbacks = self.error_callbacks.get(error_type, [])
        for callback in callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(error, context)
                else:
                    callback(error, context)
            except Exception as e:
                logger.error(f"Error in callback: {str(e)}")
        
        # Try recovery strategy
        recovery = self.recovery_strategies.get(error_type)
        if recovery:
            try:
                if asyncio.iscoroutinefunction(recovery):
                    return await recovery(error, context)
                else:
                    return recovery(error, context)
            except Exception as e:
                logger.error(f"Recovery failed: {str(e)}")
        
        # Default error response
        if isinstance(error, CHMException):
            return error.to_dict()
        else:
            return {
                'error': {
                    'message': str(error),
                    'type': error_name,
                    'timestamp': datetime.utcnow().isoformat()
                }
            }
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get error statistics"""
        return {
            'error_counts': self.error_stats,
            'total_errors': sum(self.error_stats.values()),
            'unique_errors': len(self.error_stats)
        }


# Global error handler instance
error_handler = ErrorHandler()


def handle_exceptions(func):
    """
    Decorator to handle exceptions with retry logic
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        max_retries = kwargs.pop('max_retries', 3)
        retry_delay = kwargs.pop('retry_delay', 1)
        
        for attempt in range(max_retries):
            try:
                if asyncio.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
                    
            except Exception as e:
                logger.warning(
                    f"Attempt {attempt + 1}/{max_retries} failed for {func.__name__}: {str(e)}"
                )
                
                if attempt < max_retries - 1:
                    await asyncio.sleep(retry_delay * (2 ** attempt))  # Exponential backoff
                else:
                    # Final attempt failed
                    return await error_handler.handle_error(
                        e,
                        {'function': func.__name__, 'args': args, 'kwargs': kwargs}
                    )
        
    return wrapper


def with_fallback(fallback_value: Any = None):
    """
    Decorator to provide fallback value on error
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                raise NotImplementedError("Function not yet implemented")
                if result is None:
                    logger.warning(f"{func.__name__} returned None, using fallback value")
                    return fallback_value if fallback_value is not None else {}
                
                return result
                
            except Exception as e:
                logger.error(f"Error in {func.__name__}, using fallback: {str(e)}")
                return fallback_value if fallback_value is not None else {}
        
        return wrapper
    return decorator


@asynccontextmanager
async def error_context(operation: str, raise_on_error: bool = False):
    """
    Context manager for error handling
    
    Args:
        operation: Operation description
        raise_on_error: Whether to re-raise exceptions
    """
    try:
        logger.debug(f"Starting operation: {operation}")
        yield
        logger.debug(f"Completed operation: {operation}")
        
    except Exception as e:
        logger.error(f"Error in operation {operation}: {str(e)}")
        
        # Handle the error
        await error_handler.handle_error(
            e,
            {'operation': operation}
        )
        
        if raise_on_error:
            raise


class CircuitBreaker:
    """
    Circuit breaker pattern for fault tolerance
    """
    
    def __init__(self,
                 failure_threshold: int = 5,
                 recovery_timeout: int = 60,
                 expected_exception: Type[Exception] = Exception):
        """
        Initialize circuit breaker
        
        Args:
            failure_threshold: Number of failures before opening
            recovery_timeout: Seconds before attempting recovery
            expected_exception: Exception type to catch
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.expected_exception = expected_exception
        self.failure_count = 0
        self.last_failure_time = None
        self.state = 'closed'  # closed, open, half-open
    
    def __call__(self, func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Check circuit state
            if self.state == 'open':
                if self.last_failure_time:
                    time_since_failure = (datetime.utcnow() - self.last_failure_time).seconds
                    if time_since_failure < self.recovery_timeout:
                        raise ServiceUnavailableException(
                            func.__name__,
                            f"Circuit breaker is open (failures: {self.failure_count})"
                        )
                    else:
                        # Try half-open state
                        self.state = 'half-open'
            
            try:
                # Execute function
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Success - reset on half-open
                if self.state == 'half-open':
                    self.state = 'closed'
                    self.failure_count = 0
                    logger.info(f"Circuit breaker for {func.__name__} closed")
                
                return result
                
            except self.expected_exception as e:
                self.failure_count += 1
                self.last_failure_time = datetime.utcnow()
                
                if self.failure_count >= self.failure_threshold:
                    self.state = 'open'
                    logger.warning(f"Circuit breaker for {func.__name__} opened")
                
                raise
        
        return wrapper


# FastAPI exception handlers
async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """Handle Pydantic validation errors"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            'error': {
                'message': 'Validation error',
                'code': 'VALIDATION_ERROR',
                'details': exc.errors()
            }
        }
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            'error': {
                'message': exc.detail,
                'code': f'HTTP_{exc.status_code}',
                'path': request.url.path
            }
        }
    )


async def sqlalchemy_exception_handler(request: Request, exc: SQLAlchemyError) -> JSONResponse:
    """Handle SQLAlchemy exceptions"""
    if isinstance(exc, IntegrityError):
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={
                'error': {
                    'message': 'Database integrity error',
                    'code': 'INTEGRITY_ERROR',
                    'details': str(exc.orig)
                }
            }
        )
    elif isinstance(exc, DataError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                'error': {
                    'message': 'Invalid data for database operation',
                    'code': 'DATA_ERROR',
                    'details': str(exc.orig)
                }
            }
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                'error': {
                    'message': 'Database error',
                    'code': 'DATABASE_ERROR'
                }
            }
        )


async def redis_exception_handler(request: Request, exc: redis.exceptions.RedisError) -> JSONResponse:
    """Handle Redis exceptions"""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            'error': {
                'message': 'Cache service unavailable',
                'code': 'CACHE_ERROR',
                'details': str(exc)
            }
        }
    )


async def chm_exception_handler(request: Request, exc: CHMException) -> JSONResponse:
    """Handle CHM custom exceptions"""
    return JSONResponse(
        status_code=exc.status_code,
        content=exc.to_dict()
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all other exceptions"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            'error': {
                'message': 'An unexpected error occurred',
                'code': 'INTERNAL_ERROR',
                'request_id': request.headers.get('X-Request-ID')
            }
        }
    )


def setup_exception_handlers(app):
    """
    Setup exception handlers for FastAPI app
    
    Args:
        app: FastAPI application instance
    """
    app.add_exception_handler(ValidationError, validation_exception_handler)
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(SQLAlchemyError, sqlalchemy_exception_handler)
    app.add_exception_handler(redis.exceptions.RedisError, redis_exception_handler)
    app.add_exception_handler(CHMException, chm_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
    logger.info("Exception handlers configured")


# Recovery strategies
async def database_recovery(error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
    """Recovery strategy for database errors"""
    logger.info("Attempting database recovery")
    
    # Try to reconnect to database
    from backend.database.base import engine
    
    try:
        async with engine.begin() as conn:
            await conn.execute("SELECT 1")
        
        logger.info("Database connection recovered")
        return {'recovered': True, 'service': 'database'}
        
    except Exception as e:
        logger.error(f"Database recovery failed: {str(e)}")
        return {'recovered': False, 'service': 'database', 'error': str(e)}


async def redis_recovery(error: Exception, context: Dict[str, Any]) -> Dict[str, Any]:
    """Recovery strategy for Redis errors"""
    logger.info("Attempting Redis recovery")
    
    from backend.services.redis_cache_service import cache_service
    
    try:
        await cache_service.connect()
        logger.info("Redis connection recovered")
        return {'recovered': True, 'service': 'redis'}
        
    except Exception as e:
        logger.error(f"Redis recovery failed: {str(e)}")
        return {'recovered': False, 'service': 'redis', 'error': str(e)}


# Register recovery strategies
error_handler.register_recovery(SQLAlchemyError, database_recovery)
error_handler.register_recovery(redis.exceptions.RedisError, redis_recovery)