"""
Production-grade Role-Based Access Control (RBAC) system.
Implements hierarchical roles, dynamic permissions, and policy-based access control.
"""

import asyncio
import json
import time
import hashlib
from typing import Dict, List, Set, Optional, Any, Tuple, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import re
import fnmatch

from ...common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

from sqlalchemy import Column, String, Boolean, DateTime, JSON, ForeignKey, Table, Integer
from sqlalchemy.orm import relationship
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import UUID, ARRAY

from backend.database.base import Base

logger = logging.getLogger(__name__)


class PermissionType(Enum):
    """Types of permissions"""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    MANAGE = "manage"
    ADMIN = "admin"


class ResourceType(Enum):
    """Types of resources"""
    DEVICE = "device"
    METRIC = "metric"
    ALERT = "alert"
    USER = "user"
    ROLE = "role"
    CONFIGURATION = "configuration"
    REPORT = "report"
    API = "api"
    SYSTEM = "system"


class PolicyEffect(Enum):
    """Policy effects"""
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class Permission:
    """Individual permission"""
    id: str
    name: str
    resource_type: ResourceType
    permission_type: PermissionType
    resource_pattern: str = "*"  # Glob pattern for resource matching
    conditions: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    
    def matches_resource(self, resource: str) -> bool:
        """Check if permission matches a resource"""
        return fnmatch.fnmatch(resource, self.resource_pattern)
    
    def to_string(self) -> str:
        """Convert to string representation"""
        return f"{self.resource_type.value}:{self.permission_type.value}:{self.resource_pattern}"
    
    @classmethod
    def from_string(cls, perm_string: str) -> 'Permission':
        """Create from string representation"""
        parts = perm_string.split(":")
        if len(parts) != 3:
            raise ValueError(f"Invalid permission string: {perm_string}")
        
        return cls(
            id=hashlib.md5(perm_string.encode()).hexdigest(),
            name=perm_string,
            resource_type=ResourceType(parts[0]),
            permission_type=PermissionType(parts[1]),
            resource_pattern=parts[2]
        )


@dataclass
class Role:
    """Role definition"""
    id: str
    name: str
    display_name: str
    description: str
    permissions: List[Permission] = field(default_factory=list)
    parent_roles: List[str] = field(default_factory=list)  # For role hierarchy
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_system: bool = False  # System roles cannot be modified
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def has_permission(self, permission: Union[str, Permission]) -> bool:
        """Check if role has a permission"""
        if isinstance(permission, str):
            permission = Permission.from_string(permission)
        
        for perm in self.permissions:
            if (perm.resource_type == permission.resource_type and
                perm.permission_type == permission.permission_type and
                perm.matches_resource(permission.resource_pattern)):
                return True
        return False
    
    def get_all_permissions(self, role_manager: 'RoleManager') -> List[Permission]:
        """Get all permissions including inherited ones"""
        all_permissions = self.permissions.copy()
        
        # Add inherited permissions
        for parent_id in self.parent_roles:
            parent_role = role_manager.get_role(parent_id)
            if parent_role:
                all_permissions.extend(parent_role.get_all_permissions(role_manager))
        
        # Deduplicate
        seen = set()
        unique_permissions = []
        for perm in all_permissions:
            perm_str = perm.to_string()
            if perm_str not in seen:
                seen.add(perm_str)
                unique_permissions.append(perm)
        
        return unique_permissions


@dataclass
class Policy:
    """Access control policy"""
    id: str
    name: str
    description: str
    effect: PolicyEffect
    principals: List[str] = field(default_factory=list)  # Users or roles
    resources: List[str] = field(default_factory=list)  # Resource patterns
    actions: List[str] = field(default_factory=list)  # Permission types
    conditions: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0  # Higher priority policies are evaluated first
    is_active: bool = True
    
    def matches(self, 
                principal: str,
                resource: str,
                action: str,
                context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if policy matches the request"""
        # Check principal
        principal_match = any(
            fnmatch.fnmatch(principal, pattern) for pattern in self.principals
        ) if self.principals else True
        
        # Check resource
        resource_match = any(
            fnmatch.fnmatch(resource, pattern) for pattern in self.resources
        ) if self.resources else True
        
        # Check action
        action_match = any(
            fnmatch.fnmatch(action, pattern) for pattern in self.actions
        ) if self.actions else True
        
        # Check conditions
        conditions_match = self._evaluate_conditions(context or {})
        
        return principal_match and resource_match and action_match and conditions_match
    
    def _evaluate_conditions(self, context: Dict[str, Any]) -> bool:
        """Evaluate policy conditions"""
        if not self.conditions:
            return True
        
        for key, condition in self.conditions.items():
            if key not in context:
                return False
            
            # Support different condition operators
            if isinstance(condition, dict):
                if "equals" in condition:
                    if context[key] != condition["equals"]:
                        return False
                if "not_equals" in condition:
                    if context[key] == condition["not_equals"]:
                        return False
                if "in" in condition:
                    if context[key] not in condition["in"]:
                        return False
                if "not_in" in condition:
                    if context[key] in condition["not_in"]:
                        return False
                if "greater_than" in condition:
                    if context[key] <= condition["greater_than"]:
                        return False
                if "less_than" in condition:
                    if context[key] >= condition["less_than"]:
                        return False
                if "regex" in condition:
                    if not re.match(condition["regex"], str(context[key])):
                        return False
            else:
                # Simple equality check
                if context[key] != condition:
                    return False
        
        return True


# Database Models
role_permissions_table = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', String, ForeignKey('roles.id')),
    Column('permission_id', String, ForeignKey('permissions.id'))
)

user_roles_table = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', String, ForeignKey('users.id')),
    Column('role_id', String, ForeignKey('roles.id'))
)


class PermissionModel(Base):
    """Permission database model"""
    __tablename__ = 'permissions'
    
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    resource_type = Column(String, nullable=False)
    permission_type = Column(String, nullable=False)
    resource_pattern = Column(String, default="*")
    conditions = Column(JSON, default={})
    description = Column(String)
    
    roles = relationship("RoleModel", secondary=role_permissions_table, back_populates="permissions")


class RoleModel(Base):
    """Role database model"""
    __tablename__ = 'roles'
    
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    display_name = Column(String)
    description = Column(String)
    parent_roles = Column(ARRAY(String), default=[])
    metadata = Column(JSON, default={})
    is_system = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    permissions = relationship("PermissionModel", secondary=role_permissions_table, back_populates="roles")
    users = relationship("UserModel", secondary=user_roles_table, back_populates="roles")


class PolicyModel(Base):
    """Policy database model"""
    __tablename__ = 'policies'
    
    id = Column(String, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    effect = Column(String, nullable=False)
    principals = Column(ARRAY(String), default=[])
    resources = Column(ARRAY(String), default=[])
    actions = Column(ARRAY(String), default=[])
    conditions = Column(JSON, default={})
    priority = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class RBACManager:
    """Main RBAC management system"""
    
    def __init__(self,
                 session_factory: Optional[Any] = None,
                 redis_client: Optional[redis.Redis] = None,
                 cache_ttl: int = 300):
        self.session_factory = session_factory
        self.redis_client = redis_client
        self.cache_ttl = cache_ttl
        
        # In-memory caches
        self._roles_cache: Dict[str, Role] = {}
        self._permissions_cache: Dict[str, Permission] = {}
        self._policies_cache: Dict[str, Policy] = {}
        self._user_roles_cache: Dict[str, List[str]] = {}
        self._cache_timestamps: Dict[str, float] = {}
        
        # System roles
        self._init_system_roles()
        
        # Statistics
        self.stats = defaultdict(int)
    
    def _init_system_roles(self):
        """Initialize system roles"""
        # Super Admin
        self._roles_cache["super_admin"] = Role(
            id="super_admin",
            name="super_admin",
            display_name="Super Administrator",
            description="Full system access",
            permissions=[
                Permission.from_string("*:*:*")  # All permissions
            ],
            is_system=True
        )
        
        # Admin
        self._roles_cache["admin"] = Role(
            id="admin",
            name="admin",
            display_name="Administrator",
            description="Administrative access",
            permissions=[
                Permission.from_string("user:*:*"),
                Permission.from_string("role:*:*"),
                Permission.from_string("configuration:*:*"),
                Permission.from_string("system:manage:*")
            ],
            is_system=True
        )
        
        # Operator
        self._roles_cache["operator"] = Role(
            id="operator",
            name="operator",
            display_name="Operator",
            description="Operational access",
            permissions=[
                Permission.from_string("device:*:*"),
                Permission.from_string("metric:read:*"),
                Permission.from_string("alert:*:*"),
                Permission.from_string("report:read:*")
            ],
            is_system=True
        )
        
        # Viewer
        self._roles_cache["viewer"] = Role(
            id="viewer",
            name="viewer",
            display_name="Viewer",
            description="Read-only access",
            permissions=[
                Permission.from_string("*:read:*")
            ],
            is_system=True
        )
    
    async def check_permission(self,
                              user_id: str,
                              resource_type: ResourceType,
                              permission_type: PermissionType,
                              resource: str = "*",
                              context: Optional[Dict[str, Any]] = None) -> bool:
        """Check if user has permission"""
        self.stats['permission_checks'] += 1
        
        # Check cache first
        cache_key = f"perm:{user_id}:{resource_type.value}:{permission_type.value}:{resource}"
        cached = await self._get_cached(cache_key)
        if cached is not None:
            self.stats['cache_hits'] += 1
            return cached
        
        # Get user roles
        user_roles = await self.get_user_roles(user_id)
        
        # Check policies first (they can override roles)
        policy_result = await self._evaluate_policies(
            user_id,
            f"{resource_type.value}:{resource}",
            permission_type.value,
            context
        )
        
        if policy_result is not None:
            await self._set_cached(cache_key, policy_result)
            return policy_result
        
        # Check role permissions
        for role_id in user_roles:
            role = await self.get_role(role_id)
            if not role or not role.is_active:
                continue
            
            # Get all permissions including inherited
            all_permissions = role.get_all_permissions(self)
            
            for perm in all_permissions:
                if (perm.resource_type == resource_type and
                    perm.permission_type == permission_type and
                    perm.matches_resource(resource)):
                    
                    # Check permission conditions
                    if self._evaluate_permission_conditions(perm, context):
                        await self._set_cached(cache_key, True)
                        return True
        
        await self._set_cached(cache_key, False)
        return False
    
    async def _evaluate_policies(self,
                                principal: str,
                                resource: str,
                                action: str,
                                context: Optional[Dict[str, Any]] = None) -> Optional[bool]:
        """Evaluate policies for access decision"""
        policies = await self.get_all_policies()
        
        # Sort by priority (higher first)
        sorted_policies = sorted(policies, key=lambda p: p.priority, reverse=True)
        
        for policy in sorted_policies:
            if not policy.is_active:
                continue
            
            if policy.matches(principal, resource, action, context):
                # Explicit deny takes precedence
                if policy.effect == PolicyEffect.DENY:
                    self.stats['policy_denies'] += 1
                    return False
                elif policy.effect == PolicyEffect.ALLOW:
                    self.stats['policy_allows'] += 1
                    return True
        
        # No matching policy - return default deny with fallback information
        fallback_data = FallbackData(
            data=False,  # Default deny when no policy matches
            source="policy_fallback",
            confidence=0.5,
            metadata={
                "reason": "No matching policy found",
                "principal": principal,
                "resource": resource,
                "action": action,
                "context_keys": list(context.keys()) if context else []
            }
        )
        
        return create_partial_success_result(
            data=False,  # Default deny
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="No matching policy found, using default deny",
                fallback_available=True
            ),
            suggestions=[
                "No access control policy found for this request",
                "Check if policies are properly configured",
                "Verify user roles and permissions",
                "Consider creating a default policy",
                "Review access control configuration"
            ]
        )
    
    def _evaluate_permission_conditions(self,
                                       permission: Permission,
                                       context: Optional[Dict[str, Any]] = None) -> bool:
        """Evaluate permission conditions"""
        if not permission.conditions:
            return True
        
        if not context:
            return False
        
        # Similar to policy condition evaluation
        for key, value in permission.conditions.items():
            if key not in context or context[key] != value:
                return False
        
        return True
    
    async def grant_role(self, user_id: str, role_id: str):
        """Grant role to user"""
        if self.session_factory:
            async with self.session_factory() as session:
                # Check if already granted
                existing = await session.execute(
                    f"SELECT 1 FROM user_roles WHERE user_id = :user_id AND role_id = :role_id",
                    {"user_id": user_id, "role_id": role_id}
                )
                
                if not existing.scalar():
                    await session.execute(
                        "INSERT INTO user_roles (user_id, role_id) VALUES (:user_id, :role_id)",
                        {"user_id": user_id, "role_id": role_id}
                    )
                    await session.commit()
        
        # Update cache
        if user_id not in self._user_roles_cache:
            self._user_roles_cache[user_id] = []
        
        if role_id not in self._user_roles_cache[user_id]:
            self._user_roles_cache[user_id].append(role_id)
        
        # Invalidate permission cache
        await self._invalidate_user_cache(user_id)
        
        self.stats['roles_granted'] += 1
    
    async def revoke_role(self, user_id: str, role_id: str):
        """Revoke role from user"""
        if self.session_factory:
            async with self.session_factory() as session:
                await session.execute(
                    "DELETE FROM user_roles WHERE user_id = :user_id AND role_id = :role_id",
                    {"user_id": user_id, "role_id": role_id}
                )
                await session.commit()
        
        # Update cache
        if user_id in self._user_roles_cache:
            self._user_roles_cache[user_id] = [
                r for r in self._user_roles_cache[user_id] if r != role_id
            ]
        
        # Invalidate permission cache
        await self._invalidate_user_cache(user_id)
        
        self.stats['roles_revoked'] += 1
    
    async def get_user_roles(self, user_id: str) -> List[str]:
        """Get all roles for a user"""
        # Check cache
        if user_id in self._user_roles_cache:
            cache_time = self._cache_timestamps.get(f"user_roles:{user_id}", 0)
            if time.time() - cache_time < self.cache_ttl:
                return self._user_roles_cache[user_id]
        
        roles = []
        
        if self.session_factory:
            async with self.session_factory() as session:
                result = await session.execute(
                    "SELECT role_id FROM user_roles WHERE user_id = :user_id",
                    {"user_id": user_id}
                )
                roles = [row[0] for row in result]
        
        # Update cache
        self._user_roles_cache[user_id] = roles
        self._cache_timestamps[f"user_roles:{user_id}"] = time.time()
        
        return roles
    
    async def get_user_permissions(self, user_id: str) -> List[Permission]:
        """Get all permissions for a user"""
        permissions = []
        user_roles = await self.get_user_roles(user_id)
        
        for role_id in user_roles:
            role = await self.get_role(role_id)
            if role and role.is_active:
                permissions.extend(role.get_all_permissions(self))
        
        # Deduplicate
        seen = set()
        unique_permissions = []
        for perm in permissions:
            perm_str = perm.to_string()
            if perm_str not in seen:
                seen.add(perm_str)
                unique_permissions.append(perm)
        
        return unique_permissions
    
    async def create_role(self, role: Role):
        """Create a new role"""
        if role.id in self._roles_cache:
            raise ValueError(f"Role {role.id} already exists")
        
        if self.session_factory:
            async with self.session_factory() as session:
                role_model = RoleModel(
                    id=role.id,
                    name=role.name,
                    display_name=role.display_name,
                    description=role.description,
                    parent_roles=role.parent_roles,
                    metadata=role.metadata,
                    is_system=role.is_system,
                    is_active=role.is_active
                )
                session.add(role_model)
                
                # Add permissions
                for perm in role.permissions:
                    # Ensure permission exists
                    perm_model = await session.get(PermissionModel, perm.id)
                    if not perm_model:
                        perm_model = PermissionModel(
                            id=perm.id,
                            name=perm.name,
                            resource_type=perm.resource_type.value,
                            permission_type=perm.permission_type.value,
                            resource_pattern=perm.resource_pattern,
                            conditions=perm.conditions,
                            description=perm.description
                        )
                        session.add(perm_model)
                    
                    role_model.permissions.append(perm_model)
                
                await session.commit()
        
        # Update cache
        self._roles_cache[role.id] = role
        
        self.stats['roles_created'] += 1
    
    async def update_role(self, role: Role):
        """Update an existing role"""
        if role.is_system:
            raise ValueError("Cannot modify system roles")
        
        if self.session_factory:
            async with self.session_factory() as session:
                role_model = await session.get(RoleModel, role.id)
                if role_model:
                    role_model.name = role.name
                    role_model.display_name = role.display_name
                    role_model.description = role.description
                    role_model.parent_roles = role.parent_roles
                    role_model.metadata = role.metadata
                    role_model.is_active = role.is_active
                    role_model.updated_at = datetime.now()
                    
                    await session.commit()
        
        # Update cache
        self._roles_cache[role.id] = role
        
        # Invalidate related caches
        await self._invalidate_role_cache(role.id)
        
        self.stats['roles_updated'] += 1
    
    async def delete_role(self, role_id: str):
        """Delete a role"""
        role = await self.get_role(role_id)
        if role and role.is_system:
            raise ValueError("Cannot delete system roles")
        
        if self.session_factory:
            async with self.session_factory() as session:
                role_model = await session.get(RoleModel, role_id)
                if role_model:
                    await session.delete(role_model)
                    await session.commit()
        
        # Remove from cache
        if role_id in self._roles_cache:
            del self._roles_cache[role_id]
        
        # Invalidate related caches
        await self._invalidate_role_cache(role_id)
        
        self.stats['roles_deleted'] += 1
    
    async def get_role(self, role_id: str) -> Optional[Role]:
        """Get a role by ID"""
        # Check cache
        if role_id in self._roles_cache:
            return self._roles_cache[role_id]
        
        if self.session_factory:
            async with self.session_factory() as session:
                role_model = await session.get(RoleModel, role_id)
                if role_model:
                    permissions = []
                    for perm_model in role_model.permissions:
                        permissions.append(Permission(
                            id=perm_model.id,
                            name=perm_model.name,
                            resource_type=ResourceType(perm_model.resource_type),
                            permission_type=PermissionType(perm_model.permission_type),
                            resource_pattern=perm_model.resource_pattern,
                            conditions=perm_model.conditions,
                            description=perm_model.description
                        ))
                    
                    role = Role(
                        id=role_model.id,
                        name=role_model.name,
                        display_name=role_model.display_name,
                        description=role_model.description,
                        permissions=permissions,
                        parent_roles=role_model.parent_roles,
                        metadata=role_model.metadata,
                        is_system=role_model.is_system,
                        is_active=role_model.is_active,
                        created_at=role_model.created_at,
                        updated_at=role_model.updated_at
                    )
                    
                    # Update cache
                    self._roles_cache[role_id] = role
                    
                    return role
        
        return create_partial_success_result(
            data=None,
            error_code="ROLE_NOT_FOUND",
            message=f"Role with ID {role_id} not found",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="Role not found",
                    details=f"No role exists with ID {role_id}"
                )
            ),
            suggestions=["Check role ID", "Verify role exists", "Ensure proper role creation"]
        )
    
    def get_role(self, role_id: str) -> Optional[Role]:
        """Synchronous role getter for internal use"""
        return self._roles_cache.get(role_id)
    
    async def create_policy(self, policy: Policy):
        """Create a new policy"""
        if self.session_factory:
            async with self.session_factory() as session:
                policy_model = PolicyModel(
                    id=policy.id,
                    name=policy.name,
                    description=policy.description,
                    effect=policy.effect.value,
                    principals=policy.principals,
                    resources=policy.resources,
                    actions=policy.actions,
                    conditions=policy.conditions,
                    priority=policy.priority,
                    is_active=policy.is_active
                )
                session.add(policy_model)
                await session.commit()
        
        # Update cache
        self._policies_cache[policy.id] = policy
        
        self.stats['policies_created'] += 1
    
    async def get_all_policies(self) -> List[Policy]:
        """Get all active policies"""
        # Check if cache is fresh
        cache_time = self._cache_timestamps.get("all_policies", 0)
        if time.time() - cache_time < self.cache_ttl and self._policies_cache:
            return list(self._policies_cache.values())
        
        policies = []
        
        if self.session_factory:
            async with self.session_factory() as session:
                result = await session.execute(
                    "SELECT * FROM policies WHERE is_active = true"
                )
                
                for row in result:
                    policy = Policy(
                        id=row.id,
                        name=row.name,
                        description=row.description,
                        effect=PolicyEffect(row.effect),
                        principals=row.principals,
                        resources=row.resources,
                        actions=row.actions,
                        conditions=row.conditions,
                        priority=row.priority,
                        is_active=row.is_active
                    )
                    policies.append(policy)
                    self._policies_cache[policy.id] = policy
        
        self._cache_timestamps["all_policies"] = time.time()
        
        return policies
    
    async def _get_cached(self, key: str) -> Optional[bool]:
        """Get cached permission result"""
        if self.redis_client:
            try:
                result = await self.redis_client.get(key)
                if result:
                    return result == "1"
            except Exception as e:
                logger.warning(f"Cache get failed: {e}")
        
        return create_partial_success_result(
            data=None,
            error_code="CACHE_MISS",
            message="Cached permission result not found",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="Cache miss for permission",
                    details="No cached permission result available"
                )
            ),
            suggestions=["Check cache configuration", "Verify Redis connectivity", "Review cache TTL settings"]
        )
    
    async def _set_cached(self, key: str, value: bool):
        """Set cached permission result"""
        if self.redis_client:
            try:
                await self.redis_client.setex(
                    key,
                    self.cache_ttl,
                    "1" if value else "0"
                )
            except Exception as e:
                logger.warning(f"Cache set failed: {e}")
    
    async def _invalidate_user_cache(self, user_id: str):
        """Invalidate all cache entries for a user"""
        if self.redis_client:
            try:
                pattern = f"perm:{user_id}:*"
                cursor = 0
                
                while True:
                    cursor, keys = await self.redis_client.scan(
                        cursor, match=pattern, count=100
                    )
                    
                    if keys:
                        await self.redis_client.delete(*keys)
                    
                    if cursor == 0:
                        break
                        
            except Exception as e:
                logger.warning(f"Cache invalidation failed: {e}")
    
    async def _invalidate_role_cache(self, role_id: str):
        """Invalidate cache for all users with a role"""
        # Find all users with this role
        users_to_invalidate = []
        
        for user_id, roles in self._user_roles_cache.items():
            if role_id in roles:
                users_to_invalidate.append(user_id)
        
        # Invalidate each user's cache
        for user_id in users_to_invalidate:
            await self._invalidate_user_cache(user_id)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get RBAC statistics"""
        return dict(self.stats)


# FastAPI dependencies
async def check_permission(
    resource_type: ResourceType,
    permission_type: PermissionType,
    resource: str = "*"
):
    """Dependency to check permissions"""
    async def permission_checker(
        current_user: Any,  # From JWT auth
        rbac_manager: RBACManager
    ):
        has_permission = await rbac_manager.check_permission(
            user_id=current_user.sub,
            resource_type=resource_type,
            permission_type=permission_type,
            resource=resource
        )
        
        if not has_permission:
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {resource_type.value}:{permission_type.value}:{resource}"
            )
        
        return current_user
    
    return permission_checker