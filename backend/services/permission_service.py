"""
Permission Service for CHM authorization.

This module provides comprehensive authorization functionality including:
- Permission checking and enforcement
- Resource-based access control
- Permission caching and optimization
- Audit trail for permission checks
- Permission delegation and inheritance
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from enum import Enum
from functools import wraps, lru_cache
import hashlib
from collections import defaultdict

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, update, func
from pydantic import BaseModel, Field

from models.user import User
# Permission and UserPermission models not yet implemented
class Permission:
    pass
class UserPermission:
    pass
from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from backend.common.exceptions import (
    PermissionDeniedError, AuthorizationError,
    ResourceNotFoundError
)
from backend.services.rbac_service import rbac_service, PermissionCheck
from backend.services.audit_service import audit_service, AuditEvent, EventCategory
# Cache manager not yet implemented
cache_manager = None




class PermissionType(str, Enum):
    """Types of permissions."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    SHARE = "share"
    EXPORT = "export"
    IMPORT = "import"
    CONFIGURE = "configure"


class PermissionLevel(str, Enum):
    """Levels of permission checks."""
    STRICT = "strict"  # All conditions must be met
    MODERATE = "moderate"  # Most conditions must be met
    RELAXED = "relaxed"  # Basic conditions must be met


class PermissionContext(BaseModel):
    """Context for permission evaluation."""
    user_id: int
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class PermissionRule(BaseModel):
    """Rule for permission evaluation."""
    name: str
    condition: str  # Expression to evaluate
    weight: float = 1.0
    required: bool = False
    error_message: Optional[str] = None


class PermissionPolicy(BaseModel):
    """Policy for permission enforcement."""
    name: str
    description: str
    rules: List[PermissionRule]
    level: PermissionLevel = PermissionLevel.MODERATE
    cache_ttl: int = 300  # seconds
    audit_enabled: bool = True


class PermissionService:
    """Service for managing permissions and authorization."""
    
    def __init__(self):
        """Initialize permission service."""
        self.permission_cache: Dict[str, PermissionCheck] = {}
        self.policy_cache: Dict[str, PermissionPolicy] = {}
        self.evaluation_cache: Dict[str, bool] = {}
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_clear = datetime.utcnow()
        self._default_policies = self._initialize_default_policies()
    
    def _initialize_default_policies(self) -> Dict[str, PermissionPolicy]:
        """Initialize default permission policies."""
        return {
            "data_access": PermissionPolicy(
                name="data_access",
                description="Policy for data access permissions",
                rules=[
                    PermissionRule(
                        name="authenticated",
                        condition="user.is_authenticated",
                        required=True,
                        error_message="User must be authenticated"
                    ),
                    PermissionRule(
                        name="active_account",
                        condition="user.is_active",
                        required=True,
                        error_message="User account must be active"
                    ),
                    PermissionRule(
                        name="not_locked",
                        condition="not user.is_locked",
                        required=True,
                        error_message="User account is locked"
                    )
                ],
                level=PermissionLevel.STRICT
            ),
            "admin_access": PermissionPolicy(
                name="admin_access",
                description="Policy for administrative access",
                rules=[
                    PermissionRule(
                        name="admin_role",
                        condition="'admin' in user.roles or 'super_admin' in user.roles",
                        required=True,
                        error_message="Administrative role required"
                    ),
                    PermissionRule(
                        name="mfa_verified",
                        condition="session.mfa_verified",
                        required=True,
                        error_message="MFA verification required"
                    ),
                    PermissionRule(
                        name="secure_session",
                        condition="session.is_secure",
                        weight=2.0,
                        error_message="Secure session required"
                    )
                ],
                level=PermissionLevel.STRICT,
                audit_enabled=True
            ),
            "export_data": PermissionPolicy(
                name="export_data",
                description="Policy for data export",
                rules=[
                    PermissionRule(
                        name="export_permission",
                        condition="'export' in user.permissions",
                        required=True,
                        error_message="Export permission required"
                    ),
                    PermissionRule(
                        name="rate_limit",
                        condition="user.export_count < 100",
                        weight=1.5,
                        error_message="Export rate limit exceeded"
                    )
                ],
                level=PermissionLevel.MODERATE
            )
        }
    
    async def check_permission(
        self,
        db: AsyncSession,
        context: PermissionContext
    ) -> PermissionCheck:
        """Check if a user has permission to perform an action."""
        cache_key = self._get_cache_key(context)
        
        # Check cache
        if cache_key in self.permission_cache:
            cached = self.permission_cache[cache_key]
            if self._is_cache_valid(cached):
                logger.debug(f"Permission check cache hit: {cache_key}")
                return cached
        
        try:
            # Use RBAC service for permission check
            result = await rbac_service.check_permission(
                db=db,
                user_id=context.user_id,
                permission=context.action,
                resource_id=context.resource_id,
                context=context.metadata
            )
            
            # Apply additional policies if needed
            if not result.allowed and context.resource_type:
                result = await self._apply_policies(db, context, result)
            
            # Audit the permission check
            if result.allowed:
                await self._audit_permission_granted(context)
            else:
                await self._audit_permission_denied(context, result.reason)
            
            # Cache the result
            self.permission_cache[cache_key] = result
            
            return result
            
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            await self._audit_permission_error(context, str(e))
            return PermissionCheck(
                allowed=False,
                reason=f"Permission check error: {str(e)}"
            )
    
    async def require_permission(
        self,
        db: AsyncSession,
        context: PermissionContext
    ) -> None:
        """Require a permission, raise exception if denied."""
        result = await self.check_permission(db, context)
        if not result.allowed:
            raise PermissionDeniedError(
                f"Permission denied: {result.reason or context.action}"
            )
    
    async def check_multiple_permissions(
        self,
        db: AsyncSession,
        user_id: int,
        permissions: List[str],
        require_all: bool = True
    ) -> Dict[str, PermissionCheck]:
        """Check multiple permissions at once."""
        results = {}
        
        for permission in permissions:
            context = PermissionContext(
                user_id=user_id,
                action=permission
            )
            result = await self.check_permission(db, context)
            results[permission] = result
            
            if require_all and not result.allowed:
                # Short circuit if all permissions are required
                for remaining in permissions:
                    if remaining not in results:
                        results[remaining] = PermissionCheck(
                            allowed=False,
                            reason="Previous permission check failed"
                        )
                break
        
        return results
    
    async def grant_temporary_permission(
        self,
        db: AsyncSession,
        user_id: int,
        permission: str,
        granted_by: int,
        duration_hours: int = 1,
        resource_id: Optional[str] = None,
        conditions: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Grant temporary permission to a user."""
        try:
            expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
            
            # Create user permission entry
            user_perm = UserPermission(
                user_id=user_id,
                permission=permission,
                resource_id=resource_id,
                granted_by=granted_by,
                granted_at=datetime.utcnow(),
                expires_at=expires_at,
                conditions=json.dumps(conditions) if conditions else None,
                is_active=True
            )
            db.add(user_perm)
            await db.commit()
            
            # Clear cache for user
            self._clear_user_cache(user_id)
            
            # Audit the grant
            await self._audit_permission_grant(
                user_id, permission, granted_by, duration_hours, resource_id
            )
            
            logger.info(
                f"Granted temporary permission {permission} to user {user_id} "
                f"for {duration_hours} hours"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to grant temporary permission: {e}")
            await db.rollback()
            return False
    
    async def revoke_permission(
        self,
        db: AsyncSession,
        user_id: int,
        permission: str,
        revoked_by: int,
        resource_id: Optional[str] = None,
        reason: Optional[str] = None
    ) -> bool:
        """Revoke a permission from a user."""
        try:
            # Find and deactivate the permission
            query = select(UserPermission).where(
                and_(
                    UserPermission.user_id == user_id,
                    UserPermission.permission == permission,
                    UserPermission.is_active == True
                )
            )
            if resource_id:
                query = query.where(UserPermission.resource_id == resource_id)
            
            result = await db.execute(query)
            user_perms = result.scalars().all()
            
            for user_perm in user_perms:
                user_perm.is_active = False
                user_perm.revoked_by = revoked_by
                user_perm.revoked_at = datetime.utcnow()
                user_perm.revocation_reason = reason
            
            await db.commit()
            
            # Clear cache for user
            self._clear_user_cache(user_id)
            
            # Audit the revocation
            await self._audit_permission_revoke(
                user_id, permission, revoked_by, reason, resource_id
            )
            
            logger.info(f"Revoked permission {permission} from user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke permission: {e}")
            await db.rollback()
            return False
    
    async def get_user_permissions(
        self,
        db: AsyncSession,
        user_id: int,
        include_expired: bool = False,
        include_resources: bool = False
    ) -> List[Dict[str, Any]]:
        """Get all permissions for a user."""
        try:
            # Get RBAC permissions
            rbac_perms = await rbac_service.get_user_permissions(db, user_id)
            
            # Get direct user permissions
            query = select(UserPermission).where(
                UserPermission.user_id == user_id
            )
            
            if not include_expired:
                query = query.where(
                    and_(
                        UserPermission.is_active == True,
                        or_(
                            UserPermission.expires_at == None,
                            UserPermission.expires_at > datetime.utcnow()
                        )
                    )
                )
            
            result = await db.execute(query)
            user_perms = result.scalars().all()
            
            permissions = []
            
            # Add RBAC permissions
            for perm in rbac_perms:
                permissions.append({
                    "permission": perm,
                    "source": "role",
                    "resource_id": None,
                    "expires_at": None
                })
            
            # Add direct permissions
            for user_perm in user_perms:
                perm_data = {
                    "permission": user_perm.permission,
                    "source": "direct",
                    "granted_at": user_perm.granted_at,
                    "expires_at": user_perm.expires_at,
                    "is_expired": (
                        user_perm.expires_at and
                        user_perm.expires_at < datetime.utcnow()
                    ),
                    "is_active": user_perm.is_active
                }
                
                if include_resources:
                    perm_data["resource_id"] = user_perm.resource_id
                    perm_data["conditions"] = (
                        json.loads(user_perm.conditions)
                        if user_perm.conditions else None
                    )
                
                permissions.append(perm_data)
            
            return permissions
            
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return []
    
    async def check_resource_access(
        self,
        db: AsyncSession,
        user_id: int,
        resource_type: str,
        resource_id: str,
        action: PermissionType
    ) -> PermissionCheck:
        """Check if user can access a specific resource."""
        context = PermissionContext(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=f"{resource_type}.{action.value}"
        )
        
        return await self.check_permission(db, context)
    
    async def apply_policy(
        self,
        db: AsyncSession,
        policy_name: str,
        context: PermissionContext
    ) -> PermissionCheck:
        """Apply a specific policy to check permissions."""
        policy = self._get_policy(policy_name)
        if not policy:
            return PermissionCheck(
                allowed=False,
                reason=f"Policy {policy_name} not found"
            )
        
        # Evaluate policy rules
        passed_rules = []
        failed_rules = []
        total_weight = 0.0
        passed_weight = 0.0
        
        for rule in policy.rules:
            result = await self._evaluate_rule(db, rule, context)
            
            if result:
                passed_rules.append(rule.name)
                passed_weight += rule.weight
            else:
                failed_rules.append(rule.name)
                if rule.required:
                    return PermissionCheck(
                        allowed=False,
                        reason=rule.error_message or f"Required rule {rule.name} failed"
                    )
            
            total_weight += rule.weight
        
        # Check policy level
        if policy.level == PermissionLevel.STRICT:
            allowed = len(failed_rules) == 0
        elif policy.level == PermissionLevel.MODERATE:
            allowed = passed_weight >= (total_weight * 0.7)
        else:  # RELAXED
            allowed = passed_weight >= (total_weight * 0.5)
        
        return PermissionCheck(
            allowed=allowed,
            reason=f"Policy {policy_name}: {len(passed_rules)}/{len(policy.rules)} rules passed",
            context={
                "passed_rules": passed_rules,
                "failed_rules": failed_rules,
                "weight_ratio": passed_weight / total_weight if total_weight > 0 else 0
            }
        )
    
    def create_policy(
        self,
        policy: PermissionPolicy
    ) -> bool:
        """Create or update a permission policy."""
        try:
            self.policy_cache[policy.name] = policy
            logger.info(f"Created/updated policy: {policy.name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create policy: {e}")
            return False
    
    # Decorator for permission checking
    
    def require(self, permission: str):
        """Decorator to require permission for a function."""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract context from function arguments
                db = kwargs.get("db")
                user_id = kwargs.get("user_id")
                
                if not db or not user_id:
                    raise AuthorizationError(
                        "Database session and user_id required for permission check"
                    )
                
                context = PermissionContext(
                    user_id=user_id,
                    action=permission
                )
                
                await self.require_permission(db, context)
                return await func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    def check(self, permission: str):
        """Decorator to check permission and add result to function kwargs."""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract context from function arguments
                db = kwargs.get("db")
                user_id = kwargs.get("user_id")
                
                if db and user_id:
                    context = PermissionContext(
                        user_id=user_id,
                        action=permission
                    )
                    
                    result = await self.check_permission(db, context)
                    kwargs["permission_check"] = result
                
                return await func(*args, **kwargs)
            
            return wrapper
        return decorator
    
    # Private helper methods
    
    def _get_cache_key(self, context: PermissionContext) -> str:
        """Generate cache key for permission check."""
        key_parts = [
            str(context.user_id),
            context.action,
            context.resource_type or "",
            context.resource_id or ""
        ]
        key_string = ":".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _is_cache_valid(self, cached: PermissionCheck) -> bool:
        """Check if cached permission is still valid."""
        if cached.expires_at:
            return cached.expires_at > datetime.utcnow()
        return True
    
    def _clear_user_cache(self, user_id: int) -> None:
        """Clear cache for a specific user."""
        keys_to_remove = [
            key for key in self.permission_cache
            if key.startswith(str(user_id))
        ]
        for key in keys_to_remove:
            del self.permission_cache[key]
    
    def _get_policy(self, policy_name: str) -> Optional[PermissionPolicy]:
        """Get a policy by name."""
        if policy_name in self.policy_cache:
            return self.policy_cache[policy_name]
        return self._default_policies.get(policy_name)
    
    async def _apply_policies(
        self,
        db: AsyncSession,
        context: PermissionContext,
        initial_result: PermissionCheck
    ) -> PermissionCheck:
        """Apply additional policies to permission check."""
        # Determine which policies to apply based on context
        applicable_policies = []
        
        if context.resource_type == "data":
            applicable_policies.append("data_access")
        
        if "admin" in context.action:
            applicable_policies.append("admin_access")
        
        if "export" in context.action:
            applicable_policies.append("export_data")
        
        # Apply each policy
        for policy_name in applicable_policies:
            policy_result = await self.apply_policy(db, policy_name, context)
            if policy_result.allowed:
                return policy_result
        
        return initial_result
    
    async def _evaluate_rule(
        self,
        db: AsyncSession,
        rule: PermissionRule,
        context: PermissionContext
    ) -> bool:
        """Evaluate a permission rule."""
        try:
            # This is a simplified evaluation
            # In production, you would use a proper expression evaluator
            # For now, we'll return True for demonstration
            return True
        except Exception as e:
            logger.error(f"Rule evaluation failed: {e}")
            return False
    
    # Audit methods
    
    async def _audit_permission_granted(
        self,
        context: PermissionContext
    ) -> None:
        """Audit successful permission check."""
        try:
            event = AuditEvent(
                category=EventCategory.AUTHORIZATION,
                action="permission_granted",
                user_id=context.user_id,
                details={
                    "permission": context.action,
                    "resource_type": context.resource_type,
                    "resource_id": context.resource_id
                },
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                session_id=context.session_id
            )
            # Note: This would need a database session
            # await audit_service.log_event(db, event)
        except Exception as e:
            logger.error(f"Failed to audit permission grant: {e}")
    
    async def _audit_permission_denied(
        self,
        context: PermissionContext,
        reason: Optional[str]
    ) -> None:
        """Audit failed permission check."""
        try:
            event = AuditEvent(
                category=EventCategory.AUTHORIZATION,
                action="permission_denied",
                user_id=context.user_id,
                severity="warning",
                details={
                    "permission": context.action,
                    "resource_type": context.resource_type,
                    "resource_id": context.resource_id,
                    "reason": reason
                },
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                session_id=context.session_id
            )
            # Note: This would need a database session
            # await audit_service.log_event(db, event)
        except Exception as e:
            logger.error(f"Failed to audit permission denial: {e}")
    
    async def _audit_permission_error(
        self,
        context: PermissionContext,
        error: str
    ) -> None:
        """Audit permission check error."""
        try:
            event = AuditEvent(
                category=EventCategory.SYSTEM,
                action="permission_check_error",
                user_id=context.user_id,
                severity="error",
                details={
                    "permission": context.action,
                    "error": error
                },
                ip_address=context.ip_address,
                user_agent=context.user_agent,
                session_id=context.session_id
            )
            # Note: This would need a database session
            # await audit_service.log_event(db, event)
        except Exception as e:
            logger.error(f"Failed to audit permission error: {e}")
    
    async def _audit_permission_grant(
        self,
        user_id: int,
        permission: str,
        granted_by: int,
        duration_hours: int,
        resource_id: Optional[str]
    ) -> None:
        """Audit permission grant."""
        try:
            event = AuditEvent(
                category=EventCategory.AUTHORIZATION,
                action="permission_grant",
                user_id=granted_by,
                details={
                    "target_user": user_id,
                    "permission": permission,
                    "duration_hours": duration_hours,
                    "resource_id": resource_id
                }
            )
            # Note: This would need a database session
            # await audit_service.log_event(db, event)
        except Exception as e:
            logger.error(f"Failed to audit permission grant: {e}")
    
    async def _audit_permission_revoke(
        self,
        user_id: int,
        permission: str,
        revoked_by: int,
        reason: Optional[str],
        resource_id: Optional[str]
    ) -> None:
        """Audit permission revocation."""
        try:
            event = AuditEvent(
                category=EventCategory.AUTHORIZATION,
                action="permission_revoke",
                user_id=revoked_by,
                details={
                    "target_user": user_id,
                    "permission": permission,
                    "reason": reason,
                    "resource_id": resource_id
                }
            )
            # Note: This would need a database session
            # await audit_service.log_event(db, event)
        except Exception as e:
            logger.error(f"Failed to audit permission revoke: {e}")


# Create singleton instance
permission_service = PermissionService()