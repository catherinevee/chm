"""
Role-Based Access Control (RBAC) Service for CHM.

This module provides comprehensive RBAC functionality including:
- Role management with hierarchical permissions
- Permission checking and enforcement
- Dynamic role assignment
- Resource-based access control
- Role delegation and inheritance
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum
import re
from functools import lru_cache
import hashlib

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, update, delete, func
from sqlalchemy.orm import selectinload, joinedload
from pydantic import BaseModel, Field, validator

from models.user import User, UserRole
# These models are not yet implemented - using placeholders
class Role:
    pass
class Permission:
    pass
class UserRoleModel:
    pass
class RolePermission:
    pass
class Resource:
    pass
class ResourcePermission:
    pass
class RoleHierarchy:
    pass
class DelegatedRole:
    pass
from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from backend.common.exceptions import (
    AuthorizationError, RoleNotFoundError,
    PermissionDeniedError, ResourceNotFoundError
)
# Cache manager not yet implemented
cache_manager = None




class AccessLevel(str, Enum):
    """Access levels for resources."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    ADMIN = "admin"


class ResourceType(str, Enum):
    """Types of resources in the system."""
    DEVICE = "device"
    METRIC = "metric"
    ALERT = "alert"
    REPORT = "report"
    USER = "user"
    SYSTEM = "system"
    AUDIT = "audit"
    CONFIGURATION = "configuration"


class PermissionScope(str, Enum):
    """Scopes for permissions."""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    DEPARTMENT = "department"
    TEAM = "team"
    PERSONAL = "personal"


class RoleConfig(BaseModel):
    """Configuration for a role."""
    name: str
    description: str
    permissions: List[str]
    parent_role: Optional[str] = None
    is_system: bool = False
    max_users: Optional[int] = None
    expires_after: Optional[int] = None  # Days
    requires_mfa: bool = False
    allowed_ips: Optional[List[str]] = None
    time_restrictions: Optional[Dict[str, Any]] = None


class PermissionCheck(BaseModel):
    """Result of a permission check."""
    allowed: bool
    reason: Optional[str] = None
    context: Optional[Dict[str, Any]] = None
    expires_at: Optional[datetime] = None


class RBACService:
    """Service for managing roles and permissions."""
    
    # Default system roles
    SYSTEM_ROLES = {
        "super_admin": {
            "description": "Full system access",
            "permissions": ["*"],
            "is_system": True,
            "requires_mfa": True
        },
        "admin": {
            "description": "Administrative access",
            "permissions": [
                "user.*", "device.*", "alert.*", "report.*",
                "configuration.read", "configuration.write",
                "audit.read"
            ],
            "is_system": True,
            "requires_mfa": True
        },
        "operator": {
            "description": "Operational access",
            "permissions": [
                "device.read", "device.write",
                "alert.read", "alert.write",
                "report.read", "metric.*"
            ],
            "is_system": True
        },
        "analyst": {
            "description": "Analysis and reporting access",
            "permissions": [
                "device.read", "alert.read",
                "report.*", "metric.read",
                "audit.read"
            ],
            "is_system": True
        },
        "viewer": {
            "description": "Read-only access",
            "permissions": [
                "device.read", "alert.read",
                "report.read", "metric.read"
            ],
            "is_system": True
        }
    }
    
    def __init__(self):
        """Initialize RBAC service."""
        self.permission_cache: Dict[int, Set[str]] = {}
        self.role_cache: Dict[str, RoleConfig] = {}
        self.resource_cache: Dict[str, Dict] = {}
        self._cache_ttl = 300  # 5 minutes
        self._last_cache_clear = datetime.utcnow()
    
    async def initialize_system_roles(self, db: AsyncSession) -> bool:
        """Initialize default system roles and permissions."""
        try:
            for role_name, role_config in self.SYSTEM_ROLES.items():
                # Check if role exists
                result = await db.execute(
                    select(Role).where(Role.name == role_name)
                )
                existing_role = result.scalar_one_or_none()
                
                if not existing_role:
                    # Create role
                    new_role = Role(
                        name=role_name,
                        description=role_config["description"],
                        is_system=role_config["is_system"],
                        requires_mfa=role_config.get("requires_mfa", False),
                        created_at=datetime.utcnow()
                    )
                    db.add(new_role)
                    await db.flush()
                    
                    # Add permissions
                    for perm_pattern in role_config["permissions"]:
                        await self._add_permission_to_role(
                            db, new_role.id, perm_pattern
                        )
                    
                    logger.info(f"Created system role: {role_name}")
            
            await db.commit()
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize system roles: {e}")
            await db.rollback()
            return False
    
    async def create_role(
        self,
        db: AsyncSession,
        role_config: RoleConfig
    ) -> Optional[Role]:
        """Create a new role."""
        try:
            # Check if role already exists
            result = await db.execute(
                select(Role).where(Role.name == role_config.name)
            )
            if result.scalar_one_or_none():
                raise ValueError(f"Role {role_config.name} already exists")
            
            # Create role
            new_role = Role(
                name=role_config.name,
                description=role_config.description,
                is_system=role_config.is_system,
                parent_role_id=None,
                max_users=role_config.max_users,
                expires_after_days=role_config.expires_after,
                requires_mfa=role_config.requires_mfa,
                allowed_ips=json.dumps(role_config.allowed_ips) if role_config.allowed_ips else None,
                time_restrictions=json.dumps(role_config.time_restrictions) if role_config.time_restrictions else None,
                created_at=datetime.utcnow()
            )
            
            # Set parent role if specified
            if role_config.parent_role:
                parent = await self.get_role_by_name(db, role_config.parent_role)
                if parent:
                    new_role.parent_role_id = parent.id
            
            db.add(new_role)
            await db.flush()
            
            # Add permissions
            for perm_pattern in role_config.permissions:
                await self._add_permission_to_role(
                    db, new_role.id, perm_pattern
                )
            
            await db.commit()
            
            # Clear cache
            self._clear_cache()
            
            logger.info(f"Created role: {role_config.name}")
            return new_role
            
        except Exception as e:
            logger.error(f"Failed to create role: {e}")
            await db.rollback()
            return None
    
    async def assign_role_to_user(
        self,
        db: AsyncSession,
        user_id: int,
        role_name: str,
        granted_by: int,
        expires_at: Optional[datetime] = None,
        conditions: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Assign a role to a user."""
        try:
            # Get role
            role = await self.get_role_by_name(db, role_name)
            if not role:
                raise RoleNotFoundError(f"Role {role_name} not found")
            
            # Check if user already has this role
            result = await db.execute(
                select(UserRoleModel).where(
                    and_(
                        UserRoleModel.user_id == user_id,
                        UserRoleModel.role_id == role.id,
                        UserRoleModel.is_active == True
                    )
                )
            )
            if result.scalar_one_or_none():
                logger.warning(f"User {user_id} already has role {role_name}")
                return True
            
            # Check max users limit
            if role.max_users:
                count_result = await db.execute(
                    select(func.count()).select_from(UserRoleModel).where(
                        and_(
                            UserRoleModel.role_id == role.id,
                            UserRoleModel.is_active == True
                        )
                    )
                )
                current_count = count_result.scalar()
                if current_count >= role.max_users:
                    raise PermissionDeniedError(
                        f"Role {role_name} has reached maximum users limit"
                    )
            
            # Create user-role assignment
            user_role = UserRoleModel(
                user_id=user_id,
                role_id=role.id,
                granted_by=granted_by,
                granted_at=datetime.utcnow(),
                expires_at=expires_at or (
                    datetime.utcnow() + timedelta(days=role.expires_after_days)
                    if role.expires_after_days else None
                ),
                conditions=json.dumps(conditions) if conditions else None,
                is_active=True
            )
            db.add(user_role)
            await db.commit()
            
            # Clear cache for user
            if user_id in self.permission_cache:
                del self.permission_cache[user_id]
            
            logger.info(f"Assigned role {role_name} to user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to assign role: {e}")
            await db.rollback()
            return False
    
    async def revoke_role_from_user(
        self,
        db: AsyncSession,
        user_id: int,
        role_name: str,
        revoked_by: int,
        reason: Optional[str] = None
    ) -> bool:
        """Revoke a role from a user."""
        try:
            # Get role
            role = await self.get_role_by_name(db, role_name)
            if not role:
                raise RoleNotFoundError(f"Role {role_name} not found")
            
            # Find active user-role assignment
            result = await db.execute(
                select(UserRoleModel).where(
                    and_(
                        UserRoleModel.user_id == user_id,
                        UserRoleModel.role_id == role.id,
                        UserRoleModel.is_active == True
                    )
                )
            )
            user_role = result.scalar_one_or_none()
            
            if not user_role:
                logger.warning(f"User {user_id} does not have role {role_name}")
                return True
            
            # Revoke role
            user_role.is_active = False
            user_role.revoked_by = revoked_by
            user_role.revoked_at = datetime.utcnow()
            user_role.revocation_reason = reason
            
            await db.commit()
            
            # Clear cache for user
            if user_id in self.permission_cache:
                del self.permission_cache[user_id]
            
            logger.info(f"Revoked role {role_name} from user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke role: {e}")
            await db.rollback()
            return False
    
    async def check_permission(
        self,
        db: AsyncSession,
        user_id: int,
        permission: str,
        resource_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> PermissionCheck:
        """Check if a user has a specific permission."""
        try:
            # Get user's permissions
            user_permissions = await self.get_user_permissions(db, user_id)
            
            # Check for wildcard or exact match
            if "*" in user_permissions or permission in user_permissions:
                return PermissionCheck(
                    allowed=True,
                    reason="Direct permission grant",
                    context=context
                )
            
            # Check for pattern match (e.g., "device.*" matches "device.read")
            for user_perm in user_permissions:
                if self._permission_matches(permission, user_perm):
                    return PermissionCheck(
                        allowed=True,
                        reason=f"Permission matched pattern: {user_perm}",
                        context=context
                    )
            
            # Check resource-specific permissions if resource_id provided
            if resource_id:
                resource_check = await self._check_resource_permission(
                    db, user_id, permission, resource_id, context
                )
                if resource_check.allowed:
                    return resource_check
            
            # Check delegated permissions
            delegated_check = await self._check_delegated_permission(
                db, user_id, permission, context
            )
            if delegated_check.allowed:
                return delegated_check
            
            return PermissionCheck(
                allowed=False,
                reason="Permission denied",
                context=context
            )
            
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return PermissionCheck(
                allowed=False,
                reason=f"Permission check error: {str(e)}",
                context=context
            )
    
    async def get_user_permissions(
        self,
        db: AsyncSession,
        user_id: int
    ) -> Set[str]:
        """Get all permissions for a user."""
        # Check cache
        if user_id in self.permission_cache:
            cache_age = (datetime.utcnow() - self._last_cache_clear).seconds
            if cache_age < self._cache_ttl:
                return self.permission_cache[user_id]
        
        try:
            permissions = set()
            
            # Get user's active roles
            result = await db.execute(
                select(UserRoleModel).options(
                    joinedload(UserRoleModel.role).joinedload(Role.permissions)
                ).where(
                    and_(
                        UserRoleModel.user_id == user_id,
                        UserRoleModel.is_active == True,
                        or_(
                            UserRoleModel.expires_at == None,
                            UserRoleModel.expires_at > datetime.utcnow()
                        )
                    )
                )
            )
            user_roles = result.scalars().all()
            
            # Collect permissions from all roles
            for user_role in user_roles:
                if user_role.role:
                    # Check role conditions
                    if not await self._check_role_conditions(
                        user_role.role, user_role.conditions
                    ):
                        continue
                    
                    # Add role permissions
                    for role_perm in user_role.role.permissions:
                        if role_perm.permission:
                            permissions.add(role_perm.permission.name)
                    
                    # Add inherited permissions from parent roles
                    parent_perms = await self._get_parent_role_permissions(
                        db, user_role.role
                    )
                    permissions.update(parent_perms)
            
            # Cache permissions
            self.permission_cache[user_id] = permissions
            
            return permissions
            
        except Exception as e:
            logger.error(f"Failed to get user permissions: {e}")
            return set()
    
    async def get_user_roles(
        self,
        db: AsyncSession,
        user_id: int
    ) -> List[Dict[str, Any]]:
        """Get all roles assigned to a user."""
        try:
            result = await db.execute(
                select(UserRoleModel).options(
                    joinedload(UserRoleModel.role)
                ).where(
                    and_(
                        UserRoleModel.user_id == user_id,
                        UserRoleModel.is_active == True
                    )
                )
            )
            user_roles = result.scalars().all()
            
            roles = []
            for user_role in user_roles:
                if user_role.role:
                    roles.append({
                        "name": user_role.role.name,
                        "description": user_role.role.description,
                        "granted_at": user_role.granted_at,
                        "expires_at": user_role.expires_at,
                        "is_expired": (
                            user_role.expires_at and 
                            user_role.expires_at < datetime.utcnow()
                        ),
                        "conditions": json.loads(user_role.conditions) if user_role.conditions else None
                    })
            
            return roles
            
        except Exception as e:
            logger.error(f"Failed to get user roles: {e}")
            return []
    
    async def get_role_by_name(
        self,
        db: AsyncSession,
        role_name: str
    ) -> Optional[Role]:
        """Get a role by name."""
        try:
            result = await db.execute(
                select(Role).where(Role.name == role_name)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Failed to get role: {e}")
            return None
    
    async def create_resource_permission(
        self,
        db: AsyncSession,
        resource_type: ResourceType,
        resource_id: str,
        user_id: int,
        permission: str,
        granted_by: int,
        expires_at: Optional[datetime] = None
    ) -> bool:
        """Grant permission on a specific resource to a user."""
        try:
            # Check if resource exists
            result = await db.execute(
                select(Resource).where(
                    and_(
                        Resource.resource_type == resource_type.value,
                        Resource.resource_id == resource_id
                    )
                )
            )
            resource = result.scalar_one_or_none()
            
            if not resource:
                # Create resource entry
                resource = Resource(
                    resource_type=resource_type.value,
                    resource_id=resource_id,
                    created_at=datetime.utcnow()
                )
                db.add(resource)
                await db.flush()
            
            # Create resource permission
            resource_perm = ResourcePermission(
                resource_id=resource.id,
                user_id=user_id,
                permission=permission,
                granted_by=granted_by,
                granted_at=datetime.utcnow(),
                expires_at=expires_at,
                is_active=True
            )
            db.add(resource_perm)
            await db.commit()
            
            # Clear cache
            if user_id in self.permission_cache:
                del self.permission_cache[user_id]
            
            logger.info(
                f"Granted {permission} on {resource_type.value}:{resource_id} to user {user_id}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to create resource permission: {e}")
            await db.rollback()
            return False
    
    async def delegate_role(
        self,
        db: AsyncSession,
        from_user_id: int,
        to_user_id: int,
        role_name: str,
        duration_hours: int = 24,
        permissions_subset: Optional[List[str]] = None
    ) -> bool:
        """Delegate a role temporarily from one user to another."""
        try:
            # Check if from_user has the role
            from_user_roles = await self.get_user_roles(db, from_user_id)
            if not any(r["name"] == role_name for r in from_user_roles):
                raise PermissionDeniedError(
                    f"User {from_user_id} does not have role {role_name} to delegate"
                )
            
            # Get role
            role = await self.get_role_by_name(db, role_name)
            if not role:
                raise RoleNotFoundError(f"Role {role_name} not found")
            
            # Create delegation
            delegation = DelegatedRole(
                from_user_id=from_user_id,
                to_user_id=to_user_id,
                role_id=role.id,
                delegated_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(hours=duration_hours),
                permissions_subset=json.dumps(permissions_subset) if permissions_subset else None,
                is_active=True
            )
            db.add(delegation)
            await db.commit()
            
            # Clear cache for to_user
            if to_user_id in self.permission_cache:
                del self.permission_cache[to_user_id]
            
            logger.info(
                f"Delegated role {role_name} from user {from_user_id} to {to_user_id}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to delegate role: {e}")
            await db.rollback()
            return False
    
    # Private helper methods
    
    async def _add_permission_to_role(
        self,
        db: AsyncSession,
        role_id: int,
        permission_pattern: str
    ) -> None:
        """Add a permission to a role."""
        # Check if permission exists
        result = await db.execute(
            select(Permission).where(Permission.name == permission_pattern)
        )
        permission = result.scalar_one_or_none()
        
        if not permission:
            # Create permission
            permission = Permission(
                name=permission_pattern,
                description=f"Permission: {permission_pattern}",
                created_at=datetime.utcnow()
            )
            db.add(permission)
            await db.flush()
        
        # Create role-permission mapping
        role_perm = RolePermission(
            role_id=role_id,
            permission_id=permission.id
        )
        db.add(role_perm)
    
    def _permission_matches(self, permission: str, pattern: str) -> bool:
        """Check if a permission matches a pattern."""
        if pattern == "*":
            return True
        
        # Convert pattern to regex
        # "device.*" -> "^device\..*$"
        # "device.*.read" -> "^device\..*\.read$"
        regex_pattern = pattern.replace(".", r"\.")
        regex_pattern = regex_pattern.replace("*", ".*")
        regex_pattern = f"^{regex_pattern}$"
        
        return bool(re.match(regex_pattern, permission))
    
    async def _check_resource_permission(
        self,
        db: AsyncSession,
        user_id: int,
        permission: str,
        resource_id: str,
        context: Optional[Dict[str, Any]]
    ) -> PermissionCheck:
        """Check resource-specific permissions."""
        try:
            result = await db.execute(
                select(ResourcePermission).join(Resource).where(
                    and_(
                        Resource.resource_id == resource_id,
                        ResourcePermission.user_id == user_id,
                        ResourcePermission.permission == permission,
                        ResourcePermission.is_active == True,
                        or_(
                            ResourcePermission.expires_at == None,
                            ResourcePermission.expires_at > datetime.utcnow()
                        )
                    )
                )
            )
            resource_perm = result.scalar_one_or_none()
            
            if resource_perm:
                return PermissionCheck(
                    allowed=True,
                    reason=f"Resource-specific permission for {resource_id}",
                    context=context,
                    expires_at=resource_perm.expires_at
                )
            
        except Exception as e:
            logger.error(f"Resource permission check failed: {e}")
        
        return PermissionCheck(allowed=False)
    
    async def _check_delegated_permission(
        self,
        db: AsyncSession,
        user_id: int,
        permission: str,
        context: Optional[Dict[str, Any]]
    ) -> PermissionCheck:
        """Check delegated permissions."""
        try:
            result = await db.execute(
                select(DelegatedRole).options(
                    joinedload(DelegatedRole.role).joinedload(Role.permissions)
                ).where(
                    and_(
                        DelegatedRole.to_user_id == user_id,
                        DelegatedRole.is_active == True,
                        DelegatedRole.expires_at > datetime.utcnow()
                    )
                )
            )
            delegations = result.scalars().all()
            
            for delegation in delegations:
                if delegation.role:
                    # Check if permission is in subset (if specified)
                    if delegation.permissions_subset:
                        subset = json.loads(delegation.permissions_subset)
                        if permission not in subset:
                            continue
                    
                    # Check role permissions
                    for role_perm in delegation.role.permissions:
                        if role_perm.permission:
                            if self._permission_matches(
                                permission, role_perm.permission.name
                            ):
                                return PermissionCheck(
                                    allowed=True,
                                    reason=f"Delegated permission from user {delegation.from_user_id}",
                                    context=context,
                                    expires_at=delegation.expires_at
                                )
            
        except Exception as e:
            logger.error(f"Delegated permission check failed: {e}")
        
        return PermissionCheck(allowed=False)
    
    async def _get_parent_role_permissions(
        self,
        db: AsyncSession,
        role: Role
    ) -> Set[str]:
        """Get permissions from parent roles recursively."""
        permissions = set()
        
        if role.parent_role_id:
            result = await db.execute(
                select(Role).options(
                    joinedload(Role.permissions).joinedload(RolePermission.permission)
                ).where(Role.id == role.parent_role_id)
            )
            parent_role = result.scalar_one_or_none()
            
            if parent_role:
                for role_perm in parent_role.permissions:
                    if role_perm.permission:
                        permissions.add(role_perm.permission.name)
                
                # Recursively get parent's parent permissions
                parent_perms = await self._get_parent_role_permissions(
                    db, parent_role
                )
                permissions.update(parent_perms)
        
        return permissions
    
    async def _check_role_conditions(
        self,
        role: Role,
        user_conditions: Optional[str]
    ) -> bool:
        """Check if role conditions are met."""
        # Check IP restrictions
        if role.allowed_ips:
            # This would need the current user's IP from context
            # For now, we'll assume it passes
            pass
        
        # Check time restrictions
        if role.time_restrictions:
            restrictions = json.loads(role.time_restrictions)
            current_time = datetime.utcnow()
            
            # Example: {"allowed_hours": [9, 17], "allowed_days": [1, 2, 3, 4, 5]}
            if "allowed_hours" in restrictions:
                hour_range = restrictions["allowed_hours"]
                if not (hour_range[0] <= current_time.hour < hour_range[1]):
                    return False
            
            if "allowed_days" in restrictions:
                if current_time.weekday() not in restrictions["allowed_days"]:
                    return False
        
        # Check user-specific conditions
        if user_conditions:
            conditions = json.loads(user_conditions)
            # Implement custom condition checking logic
            # For now, we'll assume conditions are met
            pass
        
        return True
    
    def _clear_cache(self) -> None:
        """Clear permission cache."""
        self.permission_cache.clear()
        self.role_cache.clear()
        self.resource_cache.clear()
        self._last_cache_clear = datetime.utcnow()


# Create singleton instance
rbac_service = RBACService()