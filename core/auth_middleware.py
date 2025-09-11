"""
CHM Authentication Middleware
JWT token validation and user authentication middleware
"""

from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import logging

from .database import get_db
from .config import get_settings
from backend.services.auth_service import auth_service
from models.user import User

logger = logging.getLogger(__name__)
settings = get_settings()

# Security scheme
security = HTTPBearer()

class AuthMiddleware:
    """Authentication middleware for JWT token validation"""
    
    def __init__(self):
        self.auth_service = auth_service
    
    async def get_current_user(
        self, 
        credentials: HTTPAuthorizationCredentials = Depends(security),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        """Get current authenticated user from JWT token"""
        try:
            # Extract token from credentials
            token = credentials.credentials
            
            # Verify token
            token_data = await self.auth_service.verify_token(token, db=db)
            if not token_data:
                logger.warning("Invalid or expired token")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid or expired token",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Check token type (already checked in verify_token)
            if token_data.token_type != "access":
                logger.warning("Invalid token type")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token type",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Get user ID from token
            user_id = token_data.user_id
            if not user_id:
                logger.warning("No user ID in token")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid token payload",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Get user from database
            user = await self.auth_service.get_user_by_id(db, int(user_id))
            if not user:
                logger.warning(f"User not found: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Inactive user attempted access: {user_id}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account is inactive",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            # Update user activity
            user.update_activity()
            await db.commit()
            
            logger.debug(f"User authenticated: {user.username}")
            return user
            
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    async def get_current_active_user(
        self, 
        current_user: User = Depends(lambda: None)
    ) -> User:
        """Get current active user (alias for get_current_user)"""
        return current_user
    
    async def get_current_admin_user(
        self, 
        current_user: User = Depends(lambda: None)
    ) -> User:
        """Get current admin user"""
        if not current_user.is_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Admin privileges required"
            )
        return current_user
    
    async def get_current_operator_user(
        self, 
        current_user: User = Depends(lambda: None)
    ) -> User:
        """Get current operator or admin user"""
        if not current_user.is_operator:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operator privileges required"
            )
        return current_user

# Create global middleware instance
auth_middleware = AuthMiddleware()

# Convenience functions for dependency injection
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Dependency to get current authenticated user"""
    return await auth_middleware.get_current_user(credentials, db)

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to get current active user"""
    return current_user

async def get_current_admin_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to get current admin user"""
    return await auth_middleware.get_current_admin_user(current_user)

async def get_current_operator_user(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to get current operator user"""
    return await auth_middleware.get_current_operator_user(current_user)

# Optional authentication (doesn't raise exception if no token)
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Dependency to get current user optionally (no exception if no token)"""
    if not credentials:
        return None
    
    try:
        return await auth_middleware.get_current_user(credentials, db)
    except HTTPException:
        return None

__all__ = [
    "AuthMiddleware",
    "auth_middleware",
    "get_current_user",
    "get_current_active_user", 
    "get_current_admin_user",
    "get_current_operator_user",
    "get_current_user_optional"
]
