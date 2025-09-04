"""
CHM Authentication Service
JWT-based authentication with password hashing and security features
"""

import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Union
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging
import secrets
import hashlib

from ..core.config import get_settings
from ..models.user import User, UserRole, UserStatus
from ..core.database import get_db

logger = logging.getLogger(__name__)
settings = get_settings()

class AuthService:
    """Authentication service for CHM"""
    
    def __init__(self):
        self.secret_key = settings.secret_key
        self.algorithm = "HS256"
        self.access_token_expire_minutes = settings.access_token_expire_minutes
        self.refresh_token_expire_days = settings.refresh_token_expire_days
    
    def hash_password(self, password: str) -> str:
        """Hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')
    
    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict[str, Any]) -> str:
        """Create a JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=self.refresh_token_expire_days)
        
        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.JWTError as e:
            logger.error(f"JWT verification error: {e}")
            return None
    
    def extract_token_type(self, token: str) -> Optional[str]:
        """Extract token type from JWT"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_signature": False})
            return payload.get("type")
        except jwt.JWTError:
            return None
    
    async def authenticate_user(self, db: AsyncSession, username: str, password: str) -> Optional[User]:
        """Authenticate a user with username and password"""
        try:
            # Find user by username or email
            stmt = select(User).where(
                (User.username == username) | (User.email == username)
            )
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            
            if not user:
                return None
            
            # Check if user is active
            if not user.is_active:
                logger.warning(f"Login attempt for inactive user: {username}")
                return None
            
            # Check if account is locked
            if user.is_locked:
                logger.warning(f"Login attempt for locked user: {username}")
                return None
            
            # Check if password has expired
            if user.password_expired:
                logger.warning(f"Login attempt with expired password: {username}")
                return None
            
            # Verify password
            if not self.verify_password(password, user.hashed_password):
                # Increment failed login attempts
                user.increment_failed_login()
                await db.commit()
                logger.warning(f"Failed login attempt for user: {username}")
                return None
            
            # Reset failed login attempts on successful login
            user.reset_failed_login()
            user.update_last_login()
            await db.commit()
            
            logger.info(f"Successful login for user: {username}")
            return user
            
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            return None
    
    async def create_user(
        self, 
        db: AsyncSession, 
        username: str, 
        email: str, 
        password: str, 
        full_name: Optional[str] = None,
        role: UserRole = UserRole.VIEWER,
        created_by: Optional[int] = None
    ) -> Optional[User]:
        """Create a new user"""
        try:
            # Check if username already exists
            stmt = select(User).where(User.username == username)
            result = await db.execute(stmt)
            if result.scalar_one_or_none():
                logger.warning(f"Username already exists: {username}")
                return None
            
            # Check if email already exists
            stmt = select(User).where(User.email == email)
            result = await db.execute(stmt)
            if result.scalar_one_or_none():
                logger.warning(f"Email already exists: {email}")
                return None
            
            # Hash password
            hashed_password = self.hash_password(password)
            
            # Create user
            user = User(
                username=username,
                email=email,
                hashed_password=hashed_password,
                full_name=full_name,
                role=role,
                created_by=created_by
            )
            
            # Set password expiry
            user.set_password_expiry(days=90)
            
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            logger.info(f"User created successfully: {username}")
            return user
            
        except Exception as e:
            logger.error(f"Error creating user {username}: {e}")
            await db.rollback()
            return None
    
    async def change_password(
        self, 
        db: AsyncSession, 
        user_id: int, 
        current_password: str, 
        new_password: str
    ) -> bool:
        """Change user password"""
        try:
            # Get user
            stmt = select(User).where(User.id == user_id)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            
            if not user:
                logger.warning(f"Password change attempt for non-existent user: {user_id}")
                return False
            
            # Verify current password
            if not self.verify_password(current_password, user.hashed_password):
                logger.warning(f"Password change failed - incorrect current password for user: {user_id}")
                return False
            
            # Hash new password
            new_hashed_password = self.hash_password(new_password)
            
            # Update password
            user.hashed_password = new_hashed_password
            user.password_changed_at = datetime.utcnow()
            user.set_password_expiry(days=90)
            
            await db.commit()
            
            logger.info(f"Password changed successfully for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error changing password for user {user_id}: {e}")
            await db.rollback()
            return False
    
    async def reset_password(self, db: AsyncSession, email: str) -> bool:
        """Initiate password reset process"""
        try:
            # Find user by email
            stmt = select(User).where(User.email == email)
            result = await db.execute(stmt)
            user = result.scalar_one_or_none()
            
            if not user:
                logger.warning(f"Password reset attempt for non-existent email: {email}")
                return False
            
            if not user.is_active:
                logger.warning(f"Password reset attempt for inactive user: {email}")
                return False
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            reset_token_hash = hashlib.sha256(reset_token.encode()).hexdigest()
            
            # Store reset token hash and expiry (you might want to add these fields to User model)
            # For now, we'll just log the attempt
            
            logger.info(f"Password reset initiated for user: {email}")
            return True
            
        except Exception as e:
            logger.error(f"Error initiating password reset for {email}: {e}")
            return False
    
    async def get_user_by_id(self, db: AsyncSession, user_id: int) -> Optional[User]:
        """Get user by ID"""
        try:
            stmt = select(User).where(User.id == user_id)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error getting user by ID {user_id}: {e}")
            return None
    
    async def get_user_by_username(self, db: AsyncSession, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            stmt = select(User).where(User.username == username)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error getting user by username {username}: {e}")
            return None
    
    async def get_user_by_email(self, db: AsyncSession, email: str) -> Optional[User]:
        """Get user by email"""
        try:
            stmt = select(User).where(User.email == email)
            result = await db.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error getting user by email {email}: {e}")
            return None
    
    def create_tokens(self, user: User) -> Dict[str, str]:
        """Create access and refresh tokens for a user"""
        data = {
            "sub": str(user.id),
            "username": user.username,
            "email": user.email,
            "role": user.role.value,
            "is_active": user.is_active
        }
        
        access_token = self.create_access_token(data)
        refresh_token = self.create_refresh_token(data)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": self.access_token_expire_minutes * 60
        }
    
    async def refresh_access_token(self, db: AsyncSession, refresh_token: str) -> Optional[Dict[str, str]]:
        """Refresh access token using refresh token"""
        try:
            # Verify refresh token
            payload = self.verify_token(refresh_token)
            if not payload or payload.get("type") != "refresh":
                return None
            
            # Get user
            user_id = int(payload.get("sub"))
            user = await self.get_user_by_id(db, user_id)
            
            if not user or not user.is_active:
                return None
            
            # Create new tokens
            return self.create_tokens(user)
            
        except Exception as e:
            logger.error(f"Error refreshing access token: {e}")
            return None
    
    def validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password strength"""
        errors = []
        warnings = []
        
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        elif len(password) < 12:
            warnings.append("Consider using a password longer than 12 characters")
        
        if not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
        
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            warnings.append("Consider adding special characters for better security")
        
        # Check for common patterns
        common_patterns = ["password", "123456", "qwerty", "admin", "user"]
        if password.lower() in common_patterns:
            errors.append("Password is too common")
        
        is_valid = len(errors) == 0
        strength_score = max(0, 10 - len(errors) - len(warnings))
        
        return {
            "is_valid": is_valid,
            "strength_score": strength_score,
            "errors": errors,
            "warnings": warnings
        }

# Create global instance
auth_service = AuthService()
