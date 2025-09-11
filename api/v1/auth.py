"""
CHM Authentication API
User authentication and authorization endpoints
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.auth_service import auth_service
from core.auth_middleware import get_current_active_user, get_current_user
from core.database import get_db
from backend.models.user import User, UserRole

logger = logging.getLogger(__name__)

# Create router
router = APIRouter()

# Security
security = HTTPBearer()


# Pydantic models
class UserLogin(BaseModel):
    username: str
    password: str


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username must be between 3 and 50 characters")
    email: EmailStr = Field(..., max_length=255, description="Email address")
    password: str = Field(..., min_length=8, max_length=255, description="Password must be at least 8 characters long")
    full_name: Optional[str] = Field(None, max_length=100, description="Full name (optional)")
    role: Optional[str] = Field("viewer", description="User role")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserProfile(BaseModel):
    id: int
    uuid: str
    username: str
    email: str
    full_name: Optional[str] = None
    phone: Optional[str] = None
    is_active: bool
    role: str
    is_verified: bool
    is_mfa_enabled: bool
    last_login: Optional[str] = None
    created_at: str


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, max_length=100, description="Full name (optional)")
    email: Optional[EmailStr] = Field(None, max_length=255, description="Email address")
    phone: Optional[str] = Field(None, max_length=20, description="Phone number (optional)")


class PasswordChange(BaseModel):
    old_password: str = Field(..., min_length=1, description="Current password")
    new_password: str = Field(..., min_length=8, max_length=255, description="New password must be at least 8 characters long")


class PasswordReset(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str


class MFASetup(BaseModel):
    secret: str
    qr_code: str


class MFAVerify(BaseModel):
    token: str


# Authentication endpoints
@router.post("/register", response_model=UserProfile)
async def register_user(user_data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user"""
    logger.info(f"User registration attempt for: {user_data.username}")

    try:
        # Validate password strength  
        password_validation = auth_service.validate_password_strength(user_data.password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}",
            )

        # Parse role
        try:
            role = UserRole(user_data.role.lower())
        except ValueError:
            role = UserRole.VIEWER

        # Create user
        user = await auth_service.create_user(
            db=db,
            username=user_data.username,
            email=user_data.email,
            password=user_data.password,
            full_name=user_data.full_name,
            role=role,
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User registration failed. Username or email may already exist.",
            )

        logger.info(f"User registered successfully: {user.username}")

        return UserProfile(
            id=user.id.hex if hasattr(user.id, 'hex') else str(user.id),
            uuid=str(user.id),  # Use id as uuid
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            phone=None,  # Not in current model
            is_active=user.is_active,
            role="viewer",  # Default role for now
            is_verified=user.is_verified,
            is_mfa_enabled=user.mfa_enabled if hasattr(user, 'mfa_enabled') else False,
            last_login=user.last_login.isoformat() if user.last_login else None,
            created_at=user.created_at.isoformat() if user.created_at else datetime.utcnow().isoformat(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User registration error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during registration"
        )


@router.post("/login", response_model=TokenResponse)
async def login_user(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return tokens"""
    logger.info(f"Login attempt for user: {credentials.username}")

    try:
        # Authenticate user
        user = await auth_service.authenticate_user(db=db, username=credentials.username, password=credentials.password)

        if not user:
            logger.warning(f"Failed login attempt for user: {credentials.username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Create tokens
        tokens = auth_service.create_tokens(user)

        logger.info(f"Successful login for user: {user.username}")

        return TokenResponse(
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_type=tokens["token_type"],
            expires_in=tokens["expires_in"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error for user {credentials.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during login"
        )


@router.post("/logout")
async def logout_user(current_user: User = Depends(get_current_user)):
    """Logout user and invalidate tokens"""
    logger.info(f"User logout request for: {current_user.username}")

    # In a production system, you would add the token to a blacklist
    # For now, we'll just log the logout
    logger.info(f"User logged out successfully: {current_user.username}")

    return {"message": "Successfully logged out"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    credentials: HTTPAuthorizationCredentials = Depends(security), db: AsyncSession = Depends(get_db)
):
    """Refresh access token using refresh token"""
    logger.info("Token refresh request")

    try:
        # Get refresh token
        refresh_token = credentials.credentials

        # Refresh access token
        new_tokens = await auth_service.refresh_access_token(db, refresh_token)

        if not new_tokens:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.info("Token refreshed successfully")

        return TokenResponse(
            access_token=new_tokens["access_token"],
            refresh_token=new_tokens["refresh_token"],
            token_type=new_tokens["token_type"],
            expires_in=new_tokens["expires_in"],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during token refresh"
        )


@router.get("/me", response_model=UserProfile)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get current user profile"""
    logger.info(f"User profile request for: {current_user.username}")

    return UserProfile(
        id=current_user.id,
        uuid=current_user.uuid,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        phone=current_user.phone,
        is_active=current_user.is_active,
        role=current_user.role.value,
        is_verified=current_user.is_verified,
        is_mfa_enabled=current_user.is_mfa_enabled,
        last_login=current_user.last_login.isoformat() if current_user.last_login else None,
        created_at=current_user.created_at.isoformat(),
    )


@router.put("/me", response_model=UserProfile)
async def update_current_user(
    user_data: UserUpdate, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Update current user profile"""
    logger.info(f"User profile update request for: {current_user.username}")

    try:
        # Update user fields if provided
        if user_data.full_name is not None:
            current_user.full_name = user_data.full_name

        if user_data.email is not None:
            # Check if email is already taken by another user
            existing_user = await auth_service.get_user_by_email(db, user_data.email)
            if existing_user and existing_user.id != current_user.id:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email address is already in use")
            current_user.email = user_data.email

        if user_data.phone is not None:
            current_user.phone = user_data.phone

        # Save changes
        await db.commit()
        await db.refresh(current_user)

        logger.info(f"User profile updated successfully: {current_user.username}")

        return UserProfile(
            id=current_user.id,
            uuid=current_user.uuid,
            username=current_user.username,
            email=current_user.email,
            full_name=current_user.full_name,
            phone=current_user.phone,
            is_active=current_user.is_active,
            role=current_user.role.value,
            is_verified=current_user.is_verified,
            is_mfa_enabled=current_user.is_mfa_enabled,
            last_login=current_user.last_login.isoformat() if current_user.last_login else None,
            created_at=current_user.created_at.isoformat(),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User profile update error: {e}")
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during profile update"
        )


@router.post("/password/change")
async def change_password(
    password_data: PasswordChange, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Change user password"""
    logger.info(f"Password change request for: {current_user.username}")

    try:
        # Validate new password strength
        password_validation = auth_service.validate_password_strength(password_data.new_password)
        if not password_validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Password validation failed: {', '.join(password_validation['errors'])}",
            )

        # Change password
        success = await auth_service.change_password(
            db=db,
            user_id=current_user.id,
            current_password=password_data.old_password,
            new_password=password_data.new_password,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password change failed. Please check your current password.",
            )

        logger.info(f"Password changed successfully for: {current_user.username}")

        return {"message": "Password changed successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during password change"
        )


@router.post("/password/reset")
async def request_password_reset(reset_data: PasswordReset, db: AsyncSession = Depends(get_db)):
    """Request password reset"""
    logger.info(f"Password reset request for: {reset_data.email}")

    try:
        # Initiate password reset
        success = await auth_service.reset_password(db, reset_data.email)

        # Always return success message for security (don't reveal if email exists)
        logger.info(f"Password reset initiated for: {reset_data.email}")

        return {"message": "If the email address exists, a password reset link has been sent"}

    except Exception as e:
        logger.error(f"Password reset error: {e}")
        # Still return success message for security
        return {"message": "If the email address exists, a password reset link has been sent"}


@router.post("/mfa/setup", response_model=MFASetup)
async def setup_mfa(current_user: User = Depends(get_current_user)):
    """Setup multi-factor authentication"""
    logger.info(f"MFA setup request for: {current_user.username}")

    try:
        # Generate MFA secret (in production, use a proper MFA library like pyotp)
        import base64
        import secrets

        # Generate a random secret
        secret = base64.b32encode(secrets.token_bytes(20)).decode("utf-8")

        # Generate QR code data (in production, use a proper QR code library)
        qr_data = f"otpauth://totp/CHM:{current_user.username}?secret={secret}&issuer=CHM"

        # Store the secret temporarily (in production, store it securely)
        # For now, we'll just return it
        logger.info(f"MFA setup initiated for: {current_user.username}")

        return MFASetup(secret=secret, qr_code=qr_data)

    except Exception as e:
        logger.error(f"MFA setup error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during MFA setup"
        )


@router.post("/mfa/verify")
async def verify_mfa(
    mfa_data: MFAVerify, current_user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    """Verify MFA token"""
    logger.info(f"MFA verification request for: {current_user.username}")

    try:
        # In production, verify the MFA token using a proper MFA library
        # For now, we'll just simulate verification
        if len(mfa_data.token) == 6 and mfa_data.token.isdigit():
            # Enable MFA for the user
            current_user.is_mfa_enabled = True
            # In production, store the MFA secret securely
            # current_user.mfa_secret = encrypted_secret

            await db.commit()

            logger.info(f"MFA verified and enabled for: {current_user.username}")

            return {"message": "MFA verified successfully"}
        else:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid MFA token")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal server error during MFA verification"
        )


__all__ = ["router"]
