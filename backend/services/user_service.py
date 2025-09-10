"""
Complete User Service with full CRUD operations and user management functionality
"""

from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime, timedelta
from uuid import UUID
import secrets
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete, and_, or_, func
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext
import re

from backend.database.user_models import User, Role, Permission, UserSession, AuditLog
from backend.common.exceptions import (
    ValidationException,
    DuplicateResourceException,
    ResourceNotFoundException,
    AuthenticationException,
    AccountLockedException,
    PasswordExpiredException,
    WeakPasswordException,
    EmailNotVerifiedException,
    PermissionDeniedException
)
from backend.common.result_objects import (
    create_success_result,
    create_failure_result,
    DatabaseResult,
    ServiceResult
)

logger = logging.getLogger(__name__)

# Password hashing configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserService:
    """Complete user management service with full CRUD operations"""
    
    def __init__(self, session: AsyncSession):
        """Initialize UserService with database session"""
        self.session = session
        self.max_login_attempts = 5
        self.lockout_duration_minutes = 30
        self.password_expiry_days = 90
        self.session_timeout_minutes = 30
        self.min_password_length = 8
        self.require_special_chars = True
        self.require_numbers = True
        self.require_uppercase = True
        self.password_history_count = 5
        
    # ==================== CREATE Operations ====================
    
    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        role_id: Optional[UUID] = None,
        department: Optional[str] = None,
        phone: Optional[str] = None,
        created_by: Optional[UUID] = None
    ) -> ServiceResult:
        """
        Create a new user with validation and security checks
        
        Args:
            username: Unique username
            email: User email address
            password: Plain text password (will be hashed)
            first_name: User's first name
            last_name: User's last name
            role_id: Role UUID to assign
            department: User's department
            phone: Phone number
            created_by: UUID of user creating this account
            
        Returns:
            ServiceResult with created user or error details
        """
        try:
            # Validate input data
            validation_result = await self._validate_user_data(
                username=username,
                email=email,
                password=password,
                phone=phone
            )
            if not validation_result['valid']:
                return ServiceResult(
                    service_name="UserService",
                    success=False,
                    error=validation_result['error'],
                    error_code="VALIDATION_ERROR"
                )
            
            # Check for duplicates
            existing = await self._check_existing_user(username, email)
            if existing:
                raise DuplicateResourceException(
                    f"User with username '{username}' or email '{email}' already exists",
                    resource_type="User",
                    duplicate_field="username or email"
                )
            
            # Validate password strength
            password_validation = self._validate_password_strength(password)
            if not password_validation['valid']:
                raise WeakPasswordException(
                    password_validation['error'],
                    requirements=self._get_password_requirements()
                )
            
            # Hash password
            password_hash = pwd_context.hash(password)
            
            # Generate verification token
            verification_token = secrets.token_urlsafe(32)
            
            # Create user object
            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                first_name=first_name,
                last_name=last_name,
                role_id=role_id,
                department=department,
                phone=phone,
                is_active=True,
                is_verified=False,
                verification_token=verification_token,
                created_at=datetime.utcnow(),
                password_changed_at=datetime.utcnow(),
                created_by=created_by
            )
            
            # Add to session and commit
            self.session.add(user)
            await self.session.commit()
            await self.session.refresh(user)
            
            # Log audit event
            await self._log_audit_event(
                user_id=user.id,
                action="USER_CREATED",
                details={"username": username, "email": email},
                performed_by=created_by
            )
            
            logger.info(f"User created successfully: {username}")
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={
                    "user": user,
                    "verification_token": verification_token,
                    "message": "User created successfully. Email verification required."
                }
            )
            
        except DuplicateResourceException as e:
            await self.session.rollback()
            logger.error(f"Duplicate user error: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="DUPLICATE_USER"
            )
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error creating user: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=f"Failed to create user: {str(e)}",
                error_code="CREATE_FAILED"
            )
    
    async def create_bulk_users(
        self,
        users_data: List[Dict[str, Any]],
        created_by: Optional[UUID] = None
    ) -> ServiceResult:
        """Create multiple users in a single transaction"""
        created_users = []
        errors = []
        
        try:
            for user_data in users_data:
                result = await self.create_user(
                    username=user_data.get('username'),
                    email=user_data.get('email'),
                    password=user_data.get('password'),
                    first_name=user_data.get('first_name'),
                    last_name=user_data.get('last_name'),
                    role_id=user_data.get('role_id'),
                    department=user_data.get('department'),
                    phone=user_data.get('phone'),
                    created_by=created_by
                )
                
                if result.success:
                    created_users.append(result.data['user'])
                else:
                    errors.append({
                        'username': user_data.get('username'),
                        'error': result.error
                    })
            
            if errors:
                return ServiceResult(
                    service_name="UserService",
                    success=False,
                    data={"created": created_users, "errors": errors},
                    error=f"Partial success: {len(created_users)} created, {len(errors)} failed"
                )
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"users": created_users}
            )
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Bulk user creation failed: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="BULK_CREATE_FAILED"
            )
    
    # ==================== READ Operations ====================
    
    async def get_user_by_id(self, user_id: UUID) -> ServiceResult:
        """Get user by ID with relationships"""
        try:
            query = select(User).where(User.id == user_id)
            result = await self.session.execute(query)
            user = result.scalar_one_or_none()
            
            if not user:
                raise ResourceNotFoundException(
                    f"User with ID {user_id} not found",
                    resource_type="User",
                    resource_id=str(user_id)
                )
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"user": user}
            )
            
        except ResourceNotFoundException as e:
            logger.warning(f"User not found: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="USER_NOT_FOUND"
            )
        except Exception as e:
            logger.error(f"Error fetching user: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="FETCH_FAILED"
            )
    
    async def get_user_by_username(self, username: str) -> ServiceResult:
        """Get user by username"""
        try:
            query = select(User).where(User.username == username)
            result = await self.session.execute(query)
            user = result.scalar_one_or_none()
            
            if not user:
                raise ResourceNotFoundException(
                    f"User with username '{username}' not found",
                    resource_type="User",
                    search_criteria={"username": username}
                )
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"user": user}
            )
            
        except Exception as e:
            logger.error(f"Error fetching user by username: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="FETCH_FAILED"
            )
    
    async def get_user_by_email(self, email: str) -> ServiceResult:
        """Get user by email"""
        try:
            query = select(User).where(User.email == email)
            result = await self.session.execute(query)
            user = result.scalar_one_or_none()
            
            if not user:
                raise ResourceNotFoundException(
                    f"User with email '{email}' not found",
                    resource_type="User",
                    search_criteria={"email": email}
                )
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"user": user}
            )
            
        except Exception as e:
            logger.error(f"Error fetching user by email: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="FETCH_FAILED"
            )
    
    async def get_all_users(
        self,
        skip: int = 0,
        limit: int = 100,
        filters: Optional[Dict[str, Any]] = None,
        sort_by: str = "created_at",
        sort_order: str = "desc"
    ) -> ServiceResult:
        """
        Get all users with pagination and filtering
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            filters: Dictionary of filters to apply
            sort_by: Field to sort by
            sort_order: Sort order (asc/desc)
            
        Returns:
            ServiceResult with list of users and pagination info
        """
        try:
            # Build base query
            query = select(User)
            
            # Apply filters
            if filters:
                conditions = []
                if filters.get('is_active') is not None:
                    conditions.append(User.is_active == filters['is_active'])
                if filters.get('is_verified') is not None:
                    conditions.append(User.is_verified == filters['is_verified'])
                if filters.get('role_id'):
                    conditions.append(User.role_id == filters['role_id'])
                if filters.get('department'):
                    conditions.append(User.department == filters['department'])
                if filters.get('search'):
                    search = f"%{filters['search']}%"
                    conditions.append(
                        or_(
                            User.username.ilike(search),
                            User.email.ilike(search),
                            User.first_name.ilike(search),
                            User.last_name.ilike(search)
                        )
                    )
                
                if conditions:
                    query = query.where(and_(*conditions))
            
            # Apply sorting
            sort_column = getattr(User, sort_by, User.created_at)
            if sort_order.lower() == 'desc':
                query = query.order_by(sort_column.desc())
            else:
                query = query.order_by(sort_column.asc())
            
            # Get total count
            count_query = select(func.count()).select_from(User)
            if filters and conditions:
                count_query = count_query.where(and_(*conditions))
            total_result = await self.session.execute(count_query)
            total = total_result.scalar()
            
            # Apply pagination
            query = query.offset(skip).limit(limit)
            
            # Execute query
            result = await self.session.execute(query)
            users = result.scalars().all()
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={
                    "users": users,
                    "pagination": {
                        "total": total,
                        "skip": skip,
                        "limit": limit,
                        "pages": (total + limit - 1) // limit
                    }
                }
            )
            
        except Exception as e:
            logger.error(f"Error fetching users: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="FETCH_FAILED"
            )
    
    async def search_users(self, query: str, limit: int = 10) -> ServiceResult:
        """Search users by username, email, or name"""
        try:
            search_pattern = f"%{query}%"
            db_query = select(User).where(
                or_(
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern),
                    User.first_name.ilike(search_pattern),
                    User.last_name.ilike(search_pattern),
                    func.concat(User.first_name, ' ', User.last_name).ilike(search_pattern)
                )
            ).limit(limit)
            
            result = await self.session.execute(db_query)
            users = result.scalars().all()
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"users": users, "count": len(users)}
            )
            
        except Exception as e:
            logger.error(f"Error searching users: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="SEARCH_FAILED"
            )
    
    # ==================== UPDATE Operations ====================
    
    async def update_user(
        self,
        user_id: UUID,
        update_data: Dict[str, Any],
        updated_by: Optional[UUID] = None
    ) -> ServiceResult:
        """
        Update user information
        
        Args:
            user_id: UUID of user to update
            update_data: Dictionary of fields to update
            updated_by: UUID of user performing update
            
        Returns:
            ServiceResult with updated user
        """
        try:
            # Get existing user
            user_result = await self.get_user_by_id(user_id)
            if not user_result.success:
                return user_result
            
            user = user_result.data['user']
            
            # Validate update data
            if 'email' in update_data:
                email_valid = self._validate_email(update_data['email'])
                if not email_valid['valid']:
                    raise ValidationException(email_valid['error'])
                
                # Check if email is already taken
                existing = await self._check_existing_user(None, update_data['email'])
                if existing and existing.id != user_id:
                    raise DuplicateResourceException(
                        f"Email '{update_data['email']}' is already in use",
                        resource_type="User",
                        duplicate_field="email"
                    )
            
            if 'username' in update_data:
                # Check if username is already taken
                existing = await self._check_existing_user(update_data['username'], None)
                if existing and existing.id != user_id:
                    raise DuplicateResourceException(
                        f"Username '{update_data['username']}' is already in use",
                        resource_type="User",
                        duplicate_field="username"
                    )
            
            # Update allowed fields
            allowed_fields = [
                'email', 'first_name', 'last_name', 'department',
                'phone', 'role_id', 'is_active', 'timezone',
                'language', 'notification_preferences'
            ]
            
            for field, value in update_data.items():
                if field in allowed_fields and hasattr(user, field):
                    setattr(user, field, value)
            
            user.updated_at = datetime.utcnow()
            user.updated_by = updated_by
            
            await self.session.commit()
            await self.session.refresh(user)
            
            # Log audit event
            await self._log_audit_event(
                user_id=user_id,
                action="USER_UPDATED",
                details={"updated_fields": list(update_data.keys())},
                performed_by=updated_by
            )
            
            logger.info(f"User {user_id} updated successfully")
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"user": user}
            )
            
        except (ValidationException, DuplicateResourceException) as e:
            await self.session.rollback()
            logger.error(f"Update validation error: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="UPDATE_VALIDATION_ERROR"
            )
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error updating user: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="UPDATE_FAILED"
            )
    
    async def update_password(
        self,
        user_id: UUID,
        old_password: str,
        new_password: str
    ) -> ServiceResult:
        """Update user password with validation"""
        try:
            # Get user
            user_result = await self.get_user_by_id(user_id)
            if not user_result.success:
                return user_result
            
            user = user_result.data['user']
            
            # Verify old password
            if not pwd_context.verify(old_password, user.password_hash):
                raise AuthenticationException(
                    "Current password is incorrect",
                    username=user.username
                )
            
            # Validate new password
            password_validation = self._validate_password_strength(new_password)
            if not password_validation['valid']:
                raise WeakPasswordException(
                    password_validation['error'],
                    requirements=self._get_password_requirements()
                )
            
            # Check password history
            if await self._is_password_in_history(user_id, new_password):
                raise ValidationException(
                    f"Password has been used recently. Please choose a different password."
                )
            
            # Update password
            user.password_hash = pwd_context.hash(new_password)
            user.password_changed_at = datetime.utcnow()
            user.password_expired = False
            user.force_password_change = False
            
            # Store old password in history
            await self._add_password_to_history(user_id, old_password)
            
            await self.session.commit()
            
            # Log audit event
            await self._log_audit_event(
                user_id=user_id,
                action="PASSWORD_CHANGED",
                details={"method": "user_initiated"},
                performed_by=user_id
            )
            
            logger.info(f"Password updated for user {user_id}")
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"message": "Password updated successfully"}
            )
            
        except (AuthenticationException, WeakPasswordException, ValidationException) as e:
            await self.session.rollback()
            logger.error(f"Password update error: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="PASSWORD_UPDATE_FAILED"
            )
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error updating password: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="UPDATE_FAILED"
            )
    
    async def verify_email(self, token: str) -> ServiceResult:
        """Verify user email with token"""
        try:
            query = select(User).where(User.verification_token == token)
            result = await self.session.execute(query)
            user = result.scalar_one_or_none()
            
            if not user:
                raise ResourceNotFoundException(
                    "Invalid or expired verification token",
                    resource_type="VerificationToken"
                )
            
            user.is_verified = True
            user.verification_token = None
            user.verified_at = datetime.utcnow()
            
            await self.session.commit()
            
            # Log audit event
            await self._log_audit_event(
                user_id=user.id,
                action="EMAIL_VERIFIED",
                details={"email": user.email},
                performed_by=user.id
            )
            
            logger.info(f"Email verified for user {user.id}")
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"user": user, "message": "Email verified successfully"}
            )
            
        except ResourceNotFoundException as e:
            logger.warning(f"Invalid verification token: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="INVALID_TOKEN"
            )
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error verifying email: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="VERIFICATION_FAILED"
            )
    
    # ==================== DELETE Operations ====================
    
    async def delete_user(
        self,
        user_id: UUID,
        soft_delete: bool = True,
        deleted_by: Optional[UUID] = None
    ) -> ServiceResult:
        """
        Delete user (soft or hard delete)
        
        Args:
            user_id: UUID of user to delete
            soft_delete: If True, mark as deleted; if False, permanently delete
            deleted_by: UUID of user performing deletion
            
        Returns:
            ServiceResult indicating success or failure
        """
        try:
            # Get user
            user_result = await self.get_user_by_id(user_id)
            if not user_result.success:
                return user_result
            
            user = user_result.data['user']
            
            if soft_delete:
                # Soft delete - mark as deleted
                user.is_deleted = True
                user.deleted_at = datetime.utcnow()
                user.deleted_by = deleted_by
                user.is_active = False
                
                await self.session.commit()
                
                action = "USER_SOFT_DELETED"
                message = "User marked as deleted"
            else:
                # Hard delete - permanently remove
                await self.session.delete(user)
                await self.session.commit()
                
                action = "USER_HARD_DELETED"
                message = "User permanently deleted"
            
            # Log audit event
            await self._log_audit_event(
                user_id=user_id,
                action=action,
                details={"username": user.username},
                performed_by=deleted_by
            )
            
            logger.info(f"User {user_id} deleted (soft={soft_delete})")
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"message": message}
            )
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error deleting user: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="DELETE_FAILED"
            )
    
    async def restore_user(
        self,
        user_id: UUID,
        restored_by: Optional[UUID] = None
    ) -> ServiceResult:
        """Restore a soft-deleted user"""
        try:
            # Get user including deleted
            query = select(User).where(
                and_(User.id == user_id, User.is_deleted == True)
            )
            result = await self.session.execute(query)
            user = result.scalar_one_or_none()
            
            if not user:
                raise ResourceNotFoundException(
                    f"Deleted user with ID {user_id} not found",
                    resource_type="User",
                    resource_id=str(user_id)
                )
            
            # Restore user
            user.is_deleted = False
            user.deleted_at = None
            user.deleted_by = None
            user.is_active = True
            
            await self.session.commit()
            
            # Log audit event
            await self._log_audit_event(
                user_id=user_id,
                action="USER_RESTORED",
                details={"username": user.username},
                performed_by=restored_by
            )
            
            logger.info(f"User {user_id} restored")
            
            return ServiceResult(
                service_name="UserService",
                success=True,
                data={"user": user, "message": "User restored successfully"}
            )
            
        except ResourceNotFoundException as e:
            logger.warning(f"User not found for restoration: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="USER_NOT_FOUND"
            )
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Error restoring user: {e}")
            return ServiceResult(
                service_name="UserService",
                success=False,
                error=str(e),
                error_code="RESTORE_FAILED"
            )
    
    # ==================== Helper Methods ====================
    
    async def _validate_user_data(
        self,
        username: str,
        email: str,
        password: str,
        phone: Optional[str] = None
    ) -> Dict[str, Any]:
        """Validate user input data"""
        # Validate username
        if not username or len(username) < 3:
            return {"valid": False, "error": "Username must be at least 3 characters long"}
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return {"valid": False, "error": "Username can only contain letters, numbers, underscore and hyphen"}
        
        # Validate email
        email_validation = self._validate_email(email)
        if not email_validation['valid']:
            return email_validation
        
        # Validate phone if provided
        if phone:
            phone_validation = self._validate_phone(phone)
            if not phone_validation['valid']:
                return phone_validation
        
        return {"valid": True}
    
    def _validate_email(self, email: str) -> Dict[str, Any]:
        """Validate email format"""
        if not email:
            return {"valid": False, "error": "Email is required"}
        
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return {"valid": False, "error": "Invalid email format"}
        
        return {"valid": True}
    
    def _validate_phone(self, phone: str) -> Dict[str, Any]:
        """Validate phone number format"""
        # Remove common separators
        clean_phone = re.sub(r'[\s\-\(\)]+', '', phone)
        
        # Check if it's a valid phone number (basic validation)
        if not re.match(r'^\+?\d{10,15}$', clean_phone):
            return {"valid": False, "error": "Invalid phone number format"}
        
        return {"valid": True}
    
    def _validate_password_strength(self, password: str) -> Dict[str, Any]:
        """Validate password meets security requirements"""
        errors = []
        
        if len(password) < self.min_password_length:
            errors.append(f"Password must be at least {self.min_password_length} characters long")
        
        if self.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if self.require_numbers and not re.search(r'\d', password):
            errors.append("Password must contain at least one number")
        
        if self.require_special_chars and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # Check for common passwords
        common_passwords = ['password', '123456', 'password123', 'admin', 'letmein']
        if password.lower() in common_passwords:
            errors.append("Password is too common. Please choose a stronger password")
        
        if errors:
            return {"valid": False, "error": ". ".join(errors)}
        
        return {"valid": True}
    
    def _get_password_requirements(self) -> Dict[str, Any]:
        """Get password requirements for display"""
        return {
            "min_length": self.min_password_length,
            "require_uppercase": self.require_uppercase,
            "require_numbers": self.require_numbers,
            "require_special_chars": self.require_special_chars,
            "password_history_count": self.password_history_count
        }
    
    async def _check_existing_user(
        self,
        username: Optional[str] = None,
        email: Optional[str] = None
    ) -> Optional[User]:
        """Check if user with username or email already exists"""
        conditions = []
        if username:
            conditions.append(User.username == username)
        if email:
            conditions.append(User.email == email)
        
        if not conditions:
            return None
        
        query = select(User).where(or_(*conditions))
        result = await self.session.execute(query)
        return result.scalar_one_or_none()
    
    async def _is_password_in_history(self, user_id: UUID, password: str) -> bool:
        """Check if password has been used recently"""
        # This would check password history table
        # For now, return False (not implemented)
        return False
    
    async def _add_password_to_history(self, user_id: UUID, password_hash: str):
        """Add password to history table"""
        # This would add to password history table
        # Implementation depends on password history model
        pass
    
    async def _log_audit_event(
        self,
        user_id: UUID,
        action: str,
        details: Dict[str, Any],
        performed_by: Optional[UUID] = None
    ):
        """Log audit event for user actions"""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                details=details,
                performed_by=performed_by or user_id,
                timestamp=datetime.utcnow(),
                ip_address=None,  # Would be set from request context
                user_agent=None   # Would be set from request context
            )
            self.session.add(audit_log)
            await self.session.commit()
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
            # Don't fail the main operation if audit logging fails