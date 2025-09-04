"""
Global exception handlers for the FastAPI application
"""

from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
import logging
from typing import Union
from datetime import datetime

from backend.common.exceptions import (
    CHMException,
    ValidationException,
    DeviceNotFoundException,
    DeviceAlreadyExistsException,
    InvalidIPAddressException,
    InvalidDeviceTypeException,
    SNMPConnectionException,
    MetricsCollectionException,
    NetworkDiscoveryException,
    SLACalculationException,
    DatabaseConnectionException,
    ImportException,
    NotificationException
)

logger = logging.getLogger(__name__)

async def chm_exception_handler(request: Request, exc: CHMException) -> JSONResponse:
    """Handle custom CHM exceptions"""
    
    # Map exception types to HTTP status codes
    status_code_map = {
        DeviceNotFoundException: 404,
        DeviceAlreadyExistsException: 409,
        InvalidIPAddressException: 400,
        InvalidDeviceTypeException: 400,
        ValidationException: 400,
        SNMPConnectionException: 503,
        MetricsCollectionException: 500,
        NetworkDiscoveryException: 500,
        SLACalculationException: 500,
        DatabaseConnectionException: 503,
        ImportException: 400,
        NotificationException: 500,
    }
    
    # Get appropriate status code
    status_code = status_code_map.get(type(exc), 500)
    
    # Log the exception
    if status_code >= 500:
        logger.error(f"Server error: {exc}", exc_info=True)
    else:
        logger.warning(f"Client error: {exc}")
    
    # Create error response
    error_response = {
        "error": {
            "type": exc.__class__.__name__,
            "message": str(exc),
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path,
            "method": request.method
        }
    }
    
    # Add request ID if available
    if hasattr(request.state, "request_id"):
        error_response["error"]["request_id"] = request.state.request_id
    
    return JSONResponse(
        status_code=status_code,
        content=error_response
    )

async def validation_exception_handler(request: Request, exc: ValidationException) -> JSONResponse:
    """Handle validation exceptions"""
    
    logger.warning(f"Validation error on {request.url.path}: {exc}")
    
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "type": "ValidationError",
                "message": str(exc),
                "timestamp": datetime.utcnow().isoformat(),
                "path": request.url.path,
                "method": request.method
            }
        }
    )

async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTP exceptions"""
    
    if exc.status_code >= 500:
        logger.error(f"HTTP {exc.status_code} error on {request.url.path}: {exc.detail}")
    else:
        logger.info(f"HTTP {exc.status_code} on {request.url.path}: {exc.detail}")
    
    error_response = {
        "error": {
            "type": "HTTPException",
            "status_code": exc.status_code,
            "message": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path,
            "method": request.method
        }
    }
    
    # Add request ID if available
    if hasattr(request.state, "request_id"):
        error_response["error"]["request_id"] = request.state.request_id
    
    # Add headers if present
    headers = getattr(exc, "headers", None)
    
    return JSONResponse(
        status_code=exc.status_code,
        content=error_response,
        headers=headers
    )

async def request_validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handle request validation errors from Pydantic"""
    
    logger.warning(f"Request validation error on {request.url.path}: {exc.errors()}")
    
    # Format validation errors
    errors = []
    for error in exc.errors():
        error_dict = {
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"]
        }
        errors.append(error_dict)
    
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "type": "RequestValidationError",
                "message": "Request validation failed",
                "errors": errors,
                "timestamp": datetime.utcnow().isoformat(),
                "path": request.url.path,
                "method": request.method
            }
        }
    )

async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle any unhandled exceptions"""
    
    # Log the full exception with traceback
    logger.error(f"Unhandled exception on {request.url.path}", exc_info=True)
    
    # Don't expose internal error details in production
    import os
    if os.getenv("ENVIRONMENT") == "production":
        message = "An internal server error occurred"
        details = None
    else:
        message = str(exc)
        details = {
            "exception_type": exc.__class__.__name__,
            "module": exc.__class__.__module__
        }
    
    error_response = {
        "error": {
            "type": "InternalServerError",
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.url.path,
            "method": request.method
        }
    }
    
    if details:
        error_response["error"]["details"] = details
    
    # Add request ID if available
    if hasattr(request.state, "request_id"):
        error_response["error"]["request_id"] = request.state.request_id
    
    return JSONResponse(
        status_code=500,
        content=error_response
    )

async def database_exception_handler(request: Request, exc: DatabaseConnectionException) -> JSONResponse:
    """Handle database connection exceptions"""
    
    logger.error(f"Database error on {request.url.path}: {exc}")
    
    return JSONResponse(
        status_code=503,
        content={
            "error": {
                "type": "DatabaseConnectionError",
                "message": "Database service is temporarily unavailable",
                "timestamp": datetime.utcnow().isoformat(),
                "path": request.url.path,
                "method": request.method
            }
        },
        headers={
            "Retry-After": "30"  # Suggest retry after 30 seconds
        }
    )

async def rate_limit_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle rate limit exceeded exceptions"""
    
    logger.warning(f"Rate limit exceeded for {request.client.host} on {request.url.path}")
    
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "type": "RateLimitExceeded",
                "message": "Too many requests. Please try again later.",
                "timestamp": datetime.utcnow().isoformat(),
                "path": request.url.path,
                "method": request.method
            }
        },
        headers={
            "Retry-After": "60",  # Suggest retry after 60 seconds
            "X-RateLimit-Limit": "100",
            "X-RateLimit-Remaining": "0",
            "X-RateLimit-Reset": str(int(datetime.utcnow().timestamp()) + 60)
        }
    )

# Error response models for OpenAPI documentation
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class ErrorDetail(BaseModel):
    field: str
    message: str
    type: str

class ErrorResponse(BaseModel):
    error: Dict[str, Any]
    
class ValidationErrorResponse(BaseModel):
    error: Dict[str, Any]
    
    class Config:
        schema_extra = {
            "example": {
                "error": {
                    "type": "ValidationError",
                    "message": "Validation failed",
                    "errors": [
                        {
                            "field": "ip_address",
                            "message": "Invalid IP address format",
                            "type": "value_error"
                        }
                    ],
                    "timestamp": "2024-01-15T10:30:00Z",
                    "path": "/api/v1/devices",
                    "method": "POST"
                }
            }
        }