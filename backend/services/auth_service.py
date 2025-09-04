"""
Authentication service for user management and JWT token handling
"""

import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from passlib.context import CryptContext
from jose import JWTError, jwt
import secrets
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
from sqlalchemy.orm import selectinload
import pyotp
import qrcode
import io
import base64
import logging

from backend.database.user_models import User, Role, Permission, UserSession, AuditLog
from backend.common.exceptions import (
    CHMException, ValidationException, NotificationException
)
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

# Security configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
PASSWORD_RESET_EXPIRE_HOURS = int(os.getenv("PASSWORD_RESET_EXPIRE_HOURS", "24"))
MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "30"))

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class AuthenticationError(CHMException):
    """Authentication related errors"""
    pass

class AuthorizationError(CHMException):
    """Authorization related errors"""
    pass

class AuthService:
    """Service for authentication and authorization"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def get_password_hash(password: str) -> str:
        """Hash a password"""
        return pwd_context.hash(password)
    
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4()),  # JWT ID for token invalidation
            "type": "access"
        })
        
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    def create_refresh_token(data: Dict[str, Any]) -> str:
        """Create a JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        to_encode.update({
            "exp": expire,
            "iat": datetime.utcnow(),
            "jti": str(uuid.uuid4()),
            "type": "refresh"
        })
        
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt
    
    @staticmethod
    async def authenticate_user(
        db: AsyncSession,
        username: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[User]:
        """Authenticate a user with username/email and password"""
        try:
            # Find user by username or email
            result = await db.execute(
                select(User).where(
                    or_(
                        User.username == username,
                        User.email == username
                    )
                ).options(selectinload(User.roles).selectinload(Role.permissions))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                # Return fallback user data when user not found
                fallback_data = FallbackData(
                    data=None,
                    source="user_not_found_fallback",
                    confidence=0.0,
                    metadata={"username": username, "reason": "User not found"}
                )
                
                return create_failure_result(
                    error=f"User {username} not found",
                    error_code="USER_NOT_FOUND",
                    fallback_data=fallback_data,
                    suggestions=[
                        "User not found",
                        "Check username spelling",
                        "Verify user exists",
                        "Contact administrator"
                    ]
                )
            
            # Check if account is locked
            if user.locked_until and user.locked_until > datetime.utcnow():
                raise AuthenticationError(f"Account locked until {user.locked_until}")
            
            # Verify password
            if not AuthService.verify_password(password, user.hashed_password):
                # Increment failed login attempts
                user.failed_login_attempts += 1
                
                # Lock account if too many failed attempts
                if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                    await db.commit()
                    raise AuthenticationError("Account locked due to too many failed login attempts")
                
                await db.commit()
                
                # Return fallback authentication data when password verification fails
                fallback_data = FallbackData(
                    data=None,
                    source="password_verification_fallback",
                    confidence=0.0,
                    metadata={"username": username, "failed_attempts": user.failed_login_attempts}
                )
                
                return create_failure_result(
                    error="Invalid password",
                    error_code="INVALID_PASSWORD",
                    fallback_data=fallback_data,
                    suggestions=[
                        "Invalid password",
                        "Check password spelling",
                        "Reset password if needed",
                        "Contact administrator"
                    ]
                )
            
            # Check if account is active
            if not user.is_active:
                raise AuthenticationError("Account is disabled")
            
            # Reset failed login attempts on successful login
            user.failed_login_attempts = 0
            user.locked_until = None
            user.last_login = datetime.utcnow()
            
            # Log successful authentication
            audit_log = AuditLog(
                user_id=user.id,
                action="login",
                resource_type="authentication",
                ip_address=ip_address,
                user_agent=user_agent,
                status="success"
            )
            db.add(audit_log)
            
            await db.commit()
            return user
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            raise
    
    @staticmethod
    async def create_user(
        db: AsyncSession,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        roles: Optional[List[str]] = None
    ) -> User:
        """Create a new user"""
        try:
            # Check if user already exists
            existing = await db.execute(
                select(User).where(
                    or_(
                        User.username == username,
                        User.email == email
                    )
                )
            )
            if existing.scalar_one_or_none():
                raise ValidationException("User with this username or email already exists")
            
            # Create user
            user = User(
                username=username,
                email=email,
                hashed_password=AuthService.get_password_hash(password),
                full_name=full_name,
                verification_token=secrets.token_urlsafe(32),
                api_key=secrets.token_urlsafe(32)
            )
            
            # Assign roles
            if roles:
                role_objs = await db.execute(
                    select(Role).where(Role.name.in_(roles))
                )
                user.roles = role_objs.scalars().all()
            else:
                # Assign default role
                default_role = await db.execute(
                    select(Role).where(Role.name == "user")
                )
                default_role_obj = default_role.scalar_one_or_none()
                if default_role_obj:
                    user.roles = [default_role_obj]
            
            db.add(user)
            await db.commit()
            await db.refresh(user)
            
            return user
            
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            raise
    
    @staticmethod
    async def create_user_session(
        db: AsyncSession,
        user: User,
        token_jti: str,
        refresh_token: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> UserSession:
        """Create a user session for token management"""
        try:
            # Invalidate old sessions from same IP/user agent
            if ip_address:
                old_sessions = await db.execute(
                    select(UserSession).where(
                        and_(
                            UserSession.user_id == user.id,
                            UserSession.ip_address == ip_address,
                            UserSession.is_active == True
                        )
                    )
                )
                for session in old_sessions.scalars():
                    session.is_active = False
            
            # Create new session
            session = UserSession(
                user_id=user.id,
                token_jti=token_jti,
                refresh_token=refresh_token,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
            )
            
            db.add(session)
            await db.commit()
            await db.refresh(session)
            
            return session
            
        except Exception as e:
            logger.error(f"Error creating user session: {str(e)}")
            raise
    
    @staticmethod
    async def verify_token(db: AsyncSession, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a JWT token"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            
            # Check if token is in active session
            token_jti = payload.get("jti")
            if token_jti:
                session = await db.execute(
                    select(UserSession).where(
                        and_(
                            UserSession.token_jti == token_jti,
                            UserSession.is_active == True,
                            UserSession.expires_at > datetime.utcnow()
                        )
                    )
                )
                if not session.scalar_one_or_none():
                    return create_failure_result(
                        fallback_data=FallbackData(
                            data=None,
                            health_status=HealthStatus(
                                level=HealthLevel.WARNING,
                                message="Token session not found",
                                details="Token session not found or expired",
                                timestamp=datetime.now().isoformat()
                            )
                        ),
                        error_code="TOKEN_SESSION_NOT_FOUND",
                        error_message="Token session not found or expired",
                        details="Token session not found or expired",
                        suggestions=["Token may be expired", "Check token validity", "Re-authenticate if needed"]
                    )
            
            return create_success_result(
                fallback_data=FallbackData(
                    data=payload,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Token verified successfully",
                        details="Token verification completed successfully",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
            
        except JWTError as e:
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="JWT verification failed",
                        details=f"JWT token verification failed: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="JWT_VERIFICATION_FAILED",
                error_message="JWT token verification failed",
                details=f"JWT token verification failed: {e}",
                suggestions=["Check token format", "Verify token signature", "Check token expiration", "Re-authenticate if needed"]
            )
    
    @staticmethod
    async def get_current_user(db: AsyncSession, token: str) -> Optional[User]:
        """Get current user from JWT token"""
        try:
            payload_result = await AuthService.verify_token(db, token)
            if not payload_result or not payload_result.success:
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="Token verification failed",
                            details="Failed to verify authentication token",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="TOKEN_VERIFICATION_FAILED",
                    error_message="Failed to verify authentication token",
                    details="Failed to verify authentication token",
                    suggestions=["Check token validity", "Re-authenticate if needed", "Check token expiration"]
                )
            
            payload = payload_result.data
            user_id = payload.get("sub")
            if not user_id:
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="Invalid token payload",
                            details="Token payload missing user ID",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="INVALID_TOKEN_PAYLOAD",
                    error_message="Invalid token payload",
                    details="Token payload missing user ID",
                    suggestions=["Check token format", "Re-authenticate if needed", "Contact administrator"]
                )
            
            result = await db.execute(
                select(User).where(
                    and_(
                        User.id == user_id,
                        User.is_active == True
                    )
                ).options(selectinload(User.roles).selectinload(Role.permissions))
            )
            
            user = result.scalar_one_or_none()
            if user:
                return create_success_result(
                    fallback_data=FallbackData(
                        data=user,
                        health_status=HealthStatus(
                            level=HealthLevel.HEALTHY,
                            message="User retrieved successfully",
                            details="Current user retrieved successfully from token",
                            timestamp=datetime.now().isoformat()
                        )
                    )
                )
            else:
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="User not found",
                            details="User not found or inactive",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="USER_NOT_FOUND",
                    error_message="User not found or inactive",
                    details="User not found or inactive",
                    suggestions=["Check user status", "Re-authenticate if needed", "Contact administrator"]
                )
            
        except Exception as e:
            logger.error(f"Error getting current user: {str(e)}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="Error retrieving current user",
                        details=f"Error retrieving current user: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="USER_RETRIEVAL_ERROR",
                error_message="Error retrieving current user",
                details=f"Error retrieving current user: {e}",
                suggestions=["Check database connection", "Review error logs", "Contact administrator"]
            )
    
    @staticmethod
    async def check_permission(
        user: User,
        resource: str,
        action: str
    ) -> bool:
        """Check if user has permission for resource and action"""
        try:
            # Superusers have all permissions
            if user.is_superuser:
                return True
            
            # Check role permissions
            for role in user.roles:
                for permission in role.permissions:
                    if permission.resource == resource and permission.action == action:
                        return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking permission: {str(e)}")
            return False
    
    @staticmethod
    async def invalidate_token(db: AsyncSession, token: str) -> bool:
        """Invalidate a JWT token by marking session as inactive"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            token_jti = payload.get("jti")
            
            if token_jti:
                result = await db.execute(
                    select(UserSession).where(UserSession.token_jti == token_jti)
                )
                session = result.scalar_one_or_none()
                if session:
                    session.is_active = False
                    await db.commit()
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error invalidating token: {str(e)}")
            return False
    
    @staticmethod
    async def refresh_access_token(
        db: AsyncSession,
        refresh_token: str
    ) -> Optional[Dict[str, str]]:
        """Refresh access token using refresh token"""
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            
            if payload.get("type") != "refresh":
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="Invalid token type",
                            details="Token is not a refresh token",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="INVALID_TOKEN_TYPE",
                    error_message="Invalid token type",
                    details="Token is not a refresh token",
                    suggestions=["Use refresh token", "Check token type", "Re-authenticate if needed"]
                )
            
            # Get session
            result = await db.execute(
                select(UserSession).where(
                    and_(
                        UserSession.refresh_token == refresh_token,
                        UserSession.is_active == True,
                        UserSession.expires_at > datetime.utcnow()
                    )
                ).options(selectinload(UserSession.user))
            )
            session = result.scalar_one_or_none()
            
            if not session:
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="Refresh session not found",
                            details="Refresh token session not found or expired",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="REFRESH_SESSION_NOT_FOUND",
                    error_message="Refresh session not found",
                    details="Refresh token session not found or expired",
                    suggestions=["Session may be expired", "Check token validity", "Re-authenticate if needed"]
                )
            
            # Create new access token
            access_token = AuthService.create_access_token(
                data={"sub": str(session.user.id)}
            )
            
            # Update session activity
            session.last_activity = datetime.utcnow()
            await db.commit()
            
            token_data = {
                "access_token": access_token,
                "token_type": "bearer"
            }
            
            return create_success_result(
                fallback_data=FallbackData(
                    data=token_data,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Access token refreshed successfully",
                        details="Access token refreshed successfully using refresh token",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
            
        except JWTError as e:
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="JWT refresh failed",
                        details=f"JWT refresh token verification failed: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="JWT_REFRESH_FAILED",
                error_message="JWT refresh token verification failed",
                details=f"JWT refresh token verification failed: {e}",
                suggestions=["Check refresh token format", "Verify token signature", "Check token expiration", "Re-authenticate if needed"]
            )
    
    @staticmethod
    def generate_mfa_secret() -> str:
        """Generate a secret key for MFA"""
        return pyotp.random_base32()
    
    @staticmethod
    def generate_mfa_qr_code(user: User, secret: str) -> str:
        """Generate QR code for MFA setup"""
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="CHM Network Monitor"
        )
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        
        return base64.b64encode(buf.getvalue()).decode()
    
    @staticmethod
    def verify_mfa_token(secret: str, token: str) -> bool:
        """Verify MFA token"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    @staticmethod
    async def initialize_default_roles(db: AsyncSession):
        """Initialize default roles and permissions"""
        try:
            # Define default permissions
            default_permissions = [
                # Devices
                ("devices", "read", "View devices"),
                ("devices", "write", "Create/update devices"),
                ("devices", "delete", "Delete devices"),
                
                # Metrics
                ("metrics", "read", "View metrics"),
                ("metrics", "write", "Collect metrics"),
                
                # Alerts
                ("alerts", "read", "View alerts"),
                ("alerts", "write", "Manage alerts"),
                ("alerts", "delete", "Delete alerts"),
                
                # Discovery
                ("discovery", "read", "View discovery jobs"),
                ("discovery", "write", "Run discovery jobs"),
                
                # Users (admin only)
                ("users", "read", "View users"),
                ("users", "write", "Create/update users"),
                ("users", "delete", "Delete users"),
                
                # Settings
                ("settings", "read", "View settings"),
                ("settings", "write", "Modify settings"),
            ]
            
            # Create permissions
            for resource, action, description in default_permissions:
                existing = await db.execute(
                    select(Permission).where(
                        and_(
                            Permission.resource == resource,
                            Permission.action == action
                        )
                    )
                )
                if not existing.scalar_one_or_none():
                    permission = Permission(
                        resource=resource,
                        action=action,
                        description=description
                    )
                    db.add(permission)
            
            await db.commit()
            
            # Define default roles with permissions
            default_roles = {
                "admin": {
                    "description": "Administrator with full access",
                    "is_system": True,
                    "permissions": [
                        ("devices", "read"), ("devices", "write"), ("devices", "delete"),
                        ("metrics", "read"), ("metrics", "write"),
                        ("alerts", "read"), ("alerts", "write"), ("alerts", "delete"),
                        ("discovery", "read"), ("discovery", "write"),
                        ("users", "read"), ("users", "write"), ("users", "delete"),
                        ("settings", "read"), ("settings", "write"),
                    ]
                },
                "operator": {
                    "description": "Operator with device and alert management",
                    "is_system": True,
                    "permissions": [
                        ("devices", "read"), ("devices", "write"),
                        ("metrics", "read"), ("metrics", "write"),
                        ("alerts", "read"), ("alerts", "write"),
                        ("discovery", "read"), ("discovery", "write"),
                        ("settings", "read"),
                    ]
                },
                "viewer": {
                    "description": "Read-only access",
                    "is_system": True,
                    "permissions": [
                        ("devices", "read"),
                        ("metrics", "read"),
                        ("alerts", "read"),
                        ("discovery", "read"),
                        ("settings", "read"),
                    ]
                },
                "user": {
                    "description": "Basic user role",
                    "is_system": True,
                    "permissions": [
                        ("devices", "read"),
                        ("metrics", "read"),
                        ("alerts", "read"),
                    ]
                }
            }
            
            # Create roles
            for role_name, role_config in default_roles.items():
                existing_role = await db.execute(
                    select(Role).where(Role.name == role_name)
                )
                role = existing_role.scalar_one_or_none()
                
                if not role:
                    role = Role(
                        name=role_name,
                        description=role_config["description"],
                        is_system=role_config["is_system"]
                    )
                    db.add(role)
                    await db.flush()
                
                # Assign permissions
                for resource, action in role_config["permissions"]:
                    perm_result = await db.execute(
                        select(Permission).where(
                            and_(
                                Permission.resource == resource,
                                Permission.action == action
                            )
                        )
                    )
                    permission = perm_result.scalar_one_or_none()
                    if permission and permission not in role.permissions:
                        role.permissions.append(permission)
            
            await db.commit()
            logger.info("Default roles and permissions initialized")
            
        except Exception as e:
            logger.error(f"Error initializing default roles: {str(e)}")
            await db.rollback()
            raise