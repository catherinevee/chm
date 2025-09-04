"""
Authentication dependencies for FastAPI endpoints
"""

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from backend.database.user_models import User
from backend.database.base import get_db

# Import result objects
from ...utils.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)

# Try to import AuthService
try:
    from backend.services.auth_service import AuthService
except ImportError:
    AuthService = None

logger = logging.getLogger(__name__)

# HTTP Bearer authentication scheme
security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency to get the current authenticated user from JWT token
    """
    if not AuthService:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authentication service not available"
        )
    
    token = credentials.credentials
    user = await AuthService.get_current_user(db, token)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account"
        )
    
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """
    Dependency to ensure the current user is active
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user

async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to ensure the current user is verified
    """
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email address"
        )
    return current_user

async def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Dependency to ensure the current user is a superuser
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions"
        )
    return current_user

class RequirePermission:
    """
    Dependency class to check for specific permissions
    """
    def __init__(self, resource: str, action: str):
        self.resource = resource
        self.action = action
    
    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """
        Check if the current user has the required permission
        """
        has_permission = await AuthService.check_permission(
            current_user,
            self.resource,
            self.action
        )
        
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Not enough permissions for {self.action} on {self.resource}"
            )
        
        return current_user

class RequireAnyPermission:
    """
    Dependency class to check for any of the specified permissions
    """
    def __init__(self, permissions: List[tuple]):
        self.permissions = permissions
    
    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """
        Check if the current user has any of the required permissions
        """
        for resource, action in self.permissions:
            has_permission = await AuthService.check_permission(
                current_user,
                self.resource,
                self.action
            )
            if has_permission:
                return current_user
        
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions for this operation"
        )

class RequireAllPermissions:
    """
    Dependency class to check for all specified permissions
    """
    def __init__(self, permissions: List[tuple]):
        self.permissions = permissions
    
    async def __call__(
        self,
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        """
        Check if the current user has all of the required permissions
        """
        for resource, action in self.permissions:
            has_permission = await AuthService.check_permission(
                current_user,
                self.resource,
                self.action
            )
            if not has_permission:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Not enough permissions for {self.action} on {self.resource}"
                )
        
        return current_user

async def get_optional_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Optional authentication - returns user if authenticated, result object otherwise
    """
    authorization = request.headers.get("Authorization")
    if not authorization:
        return create_partial_success_result(
            data=None,
            error_code="NO_AUTHORIZATION_HEADER",
            message="No authorization header provided",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.INFO,
                    message="No authentication required",
                    details="Request made without authorization header"
                )
            ),
            suggestions=["Include Bearer token in Authorization header", "Use valid JWT token", "Check authentication requirements"]
        )
    
    try:
        scheme, token = authorization.split(" ")
        if scheme.lower() != "bearer":
            return create_partial_success_result(
                data=None,
                error_code="INVALID_AUTHORIZATION_SCHEME",
                message="Invalid authorization scheme",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Invalid authorization format",
                        details=f"Expected 'Bearer' scheme, got '{scheme}'"
                    )
                ),
                suggestions=["Use 'Bearer' scheme", "Include valid JWT token", "Check authorization format"]
            )
        
        user = await AuthService.get_current_user(db, token)
        return create_success_result(
            data=user,
            fallback_data=FallbackData(
                data=user,
                health_status=HealthStatus(
                    level=HealthLevel.HEALTHY,
                    message="User authenticated successfully",
                    details=f"User {user.id if user else 'unknown'} authenticated"
                )
            )
        )
    except Exception as e:
        return create_failure_result(
            error_code="AUTHENTICATION_ERROR",
            message="Authentication failed",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.ERROR,
                    message="Authentication error occurred",
                    details=f"Exception during authentication: {str(e)}"
                )
            ),
            suggestions=["Check token validity", "Verify user exists", "Ensure proper authentication flow"]
        )

class RateLimitDependency:
    """
    Rate limiting dependency
    """
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.request_counts = {}
    
    async def __call__(
        self,
        request: Request,
        current_user: Optional[User] = Depends(get_optional_current_user)
    ):
        """
        Check rate limits for the current user or IP
        """
        # Use user ID if authenticated, otherwise use IP address
        if current_user:
            identifier = f"user:{current_user.id}"
        else:
            identifier = f"ip:{request.client.host}"
        
        # Implement rate limiting logic here
        # This is a simple in-memory implementation
        # In production, use Redis or similar
        
        import time
        current_time = time.time()
        
        if identifier not in self.request_counts:
            self.request_counts[identifier] = []
        
        # Remove old requests outside the window
        self.request_counts[identifier] = [
            timestamp for timestamp in self.request_counts[identifier]
            if current_time - timestamp < self.window_seconds
        ]
        
        # Check if limit exceeded
        if len(self.request_counts[identifier]) >= self.max_requests:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded"
            )
        
        # Add current request
        self.request_counts[identifier].append(current_time)

# Pre-configured permission dependencies for common operations
require_device_read = RequirePermission("devices", "read")
require_device_write = RequirePermission("devices", "write")
require_device_delete = RequirePermission("devices", "delete")

require_metrics_read = RequirePermission("metrics", "read")
require_metrics_write = RequirePermission("metrics", "write")

require_alerts_read = RequirePermission("alerts", "read")
require_alerts_write = RequirePermission("alerts", "write")
require_alerts_delete = RequirePermission("alerts", "delete")

require_discovery_read = RequirePermission("discovery", "read")
require_discovery_write = RequirePermission("discovery", "write")

require_users_read = RequirePermission("users", "read")
require_users_write = RequirePermission("users", "write")
require_users_delete = RequirePermission("users", "delete")

require_settings_read = RequirePermission("settings", "read")
require_settings_write = RequirePermission("settings", "write")

# Rate limiters for different endpoints
standard_rate_limit = RateLimitDependency(max_requests=100, window_seconds=60)
strict_rate_limit = RateLimitDependency(max_requests=10, window_seconds=60)
auth_rate_limit = RateLimitDependency(max_requests=5, window_seconds=60)