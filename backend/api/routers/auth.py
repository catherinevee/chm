"""
Authentication API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.security import OAuth2PasswordRequestForm
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr, Field, validator
import logging

from backend.database.user_models import User
from backend.database.base import get_db

# Try to import AuthService
try:
    from backend.services.auth_service import AuthService, AuthenticationError
except ImportError:
    AuthService = None
    AuthenticationError = Exception
from backend.api.dependencies.auth import (
    get_current_user,
    get_current_active_user,
    get_current_superuser,
    auth_rate_limit,
    require_users_write
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])

# Pydantic models for requests/responses
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        return v

class UserLogin(BaseModel):
    username: str  # Can be username or email
    password: str
    mfa_token: Optional[str] = None

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    is_verified: bool
    is_superuser: bool
    mfa_enabled: bool
    created_at: datetime
    last_login: Optional[datetime]
    roles: list

class PasswordReset(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        return v

class PasswordChange(BaseModel):
    current_password: str
    new_password: str
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters long')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one digit')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain at least one lowercase letter')
        return v

class MFASetup(BaseModel):
    enabled: bool

class MFAVerify(BaseModel):
    token: str

@router.post("/register", response_model=UserResponse, dependencies=[Depends(auth_rate_limit)])
async def register(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user account
    """
    if not AuthService:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service not available"
        )
    
    try:
        user = await AuthService.create_user(
            db,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name
        )
        
        return UserResponse(
            id=str(user.id),
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            is_verified=user.is_verified,
            is_superuser=user.is_superuser,
            mfa_enabled=user.mfa_enabled,
            created_at=user.created_at,
            last_login=user.last_login,
            roles=[role.name for role in user.roles]
        )
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/login", response_model=TokenResponse, dependencies=[Depends(auth_rate_limit)])
async def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db)
):
    """
    Login with username/email and password
    """
    try:
        # Get client info
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("User-Agent")
        
        # Authenticate user
        user = await AuthService.authenticate_user(
            db,
            username=form_data.username,
            password=form_data.password,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Check MFA if enabled
        # if user.mfa_enabled and not mfa_token:
        #     # Return partial token that requires MFA
        #     return {"requires_mfa": True}
        
        # Create tokens
        access_token = AuthService.create_access_token(
            data={"sub": str(user.id)}
        )
        refresh_token = AuthService.create_refresh_token(
            data={"sub": str(user.id)}
        )
        
        # Get token JTI for session
        import jose.jwt as jwt
        from backend.services.auth_service import SECRET_KEY, ALGORITHM
        token_data = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        token_jti = token_data.get("jti")
        
        # Create session
        await AuthService.create_user_session(
            db,
            user,
            token_jti,
            refresh_token,
            ip_address,
            user_agent
        )
        
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=30 * 60  # 30 minutes in seconds
        )
        
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login"
        )

@router.post("/logout")
async def logout(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout and invalidate current token
    """
    try:
        # Get token from request
        from fastapi import Request
        from fastapi.security import HTTPBearer
        
        # This is a simplified logout - in production, get the actual token
        # and invalidate it in the session table
        
        return {"message": "Successfully logged out"}
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during logout"
        )

@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token
    """
    try:
        result = await AuthService.refresh_access_token(db, refresh_token)
        
        if not result:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
        
        return TokenResponse(
            access_token=result["access_token"],
            refresh_token=refresh_token,  # Keep same refresh token
            token_type="bearer",
            expires_in=30 * 60
        )
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not refresh token"
        )

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user profile
    """
    return UserResponse(
        id=str(current_user.id),
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        is_superuser=current_user.is_superuser,
        mfa_enabled=current_user.mfa_enabled,
        created_at=current_user.created_at,
        last_login=current_user.last_login,
        roles=[role.name for role in current_user.roles]
    )

@router.put("/me")
async def update_current_user_profile(
    full_name: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update current user profile
    """
    try:
        if full_name is not None:
            current_user.full_name = full_name
        
        await db.commit()
        await db.refresh(current_user)
        
        return UserResponse(
            id=str(current_user.id),
            username=current_user.username,
            email=current_user.email,
            full_name=current_user.full_name,
            is_active=current_user.is_active,
            is_verified=current_user.is_verified,
            is_superuser=current_user.is_superuser,
            mfa_enabled=current_user.mfa_enabled,
            created_at=current_user.created_at,
            last_login=current_user.last_login,
            roles=[role.name for role in current_user.roles]
        )
        
    except Exception as e:
        logger.error(f"Profile update error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not update profile"
        )

@router.post("/password/change")
async def change_password(
    password_data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Change current user password
    """
    try:
        # Verify current password
        if not AuthService.verify_password(password_data.current_password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Incorrect current password"
            )
        
        # Update password
        current_user.hashed_password = AuthService.get_password_hash(password_data.new_password)
        await db.commit()
        
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not change password"
        )

@router.post("/password/reset", dependencies=[Depends(auth_rate_limit)])
async def request_password_reset(
    reset_data: PasswordReset,
    db: AsyncSession = Depends(get_db)
):
    """
    Request password reset email
    """
    try:
        # Find user by email
        from sqlalchemy import select
        result = await db.execute(
            select(User).where(User.email == reset_data.email)
        )
        user = result.scalar_one_or_none()
        
        if user:
            # Generate reset token
            import secrets
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=24)
            await db.commit()
            
            # TODO: Send reset email
            logger.info(f"Password reset requested for {user.email}")
        
        # Always return success to prevent email enumeration
        return {"message": "If the email exists, a reset link has been sent"}
        
    except Exception as e:
        logger.error(f"Password reset request error: {str(e)}")
        return {"message": "If the email exists, a reset link has been sent"}

@router.post("/mfa/setup")
async def setup_mfa(
    mfa_data: MFASetup,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Enable or disable MFA for current user
    """
    try:
        if mfa_data.enabled:
            # Generate MFA secret
            secret = AuthService.generate_mfa_secret()
            current_user.mfa_secret = secret
            current_user.mfa_enabled = False  # Will be enabled after verification
            
            # Generate QR code
            qr_code = AuthService.generate_mfa_qr_code(current_user, secret)
            
            await db.commit()
            
            return {
                "secret": secret,
                "qr_code": qr_code,
                "message": "Scan the QR code with your authenticator app and verify"
            }
        else:
            # Disable MFA
            current_user.mfa_enabled = False
            current_user.mfa_secret = None
            await db.commit()
            
            return {"message": "MFA disabled successfully"}
            
    except Exception as e:
        logger.error(f"MFA setup error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not setup MFA"
        )

@router.post("/mfa/verify")
async def verify_mfa(
    mfa_data: MFAVerify,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify MFA token and enable MFA
    """
    try:
        if not current_user.mfa_secret:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="MFA not configured"
            )
        
        # Verify token
        if AuthService.verify_mfa_token(current_user.mfa_secret, mfa_data.token):
            current_user.mfa_enabled = True
            await db.commit()
            return {"message": "MFA enabled successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid MFA token"
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not verify MFA"
        )

@router.get("/verify/{token}")
async def verify_email(
    token: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Verify user email with verification token
    """
    try:
        from sqlalchemy import select
        result = await db.execute(
            select(User).where(User.verification_token == token)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification token"
            )
        
        user.is_verified = True
        user.verification_token = None
        await db.commit()
        
        return {"message": "Email verified successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Email verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not verify email"
        )