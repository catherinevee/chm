"""
Access Control Service for CHM Security & Compliance System

This service provides comprehensive access control capabilities including:
- Role-Based Access Control (RBAC) management
- Permission evaluation and enforcement
- Security policy enforcement
- Session management and monitoring
- Multi-factor authentication integration
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import ipaddress
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload, joinedload

from ..models.security import (
    SecurityRole, SecurityPermission, RolePermission, UserRole,
    SecurityPolicy, SecurityAuditLog, SecurityLevel
)
from ..models.user import User, UserRole as UserRoleEnum, UserStatus
from ..models.result_objects import AccessResult, OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class AccessRequest:
    """Access request details"""
    user_id: int
    resource_type: str
    resource_id: Optional[str] = None
    action: str = "read"
    context: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class PermissionCheck:
    """Permission check result"""
    granted: bool
    reason: Optional[str] = None
    required_permissions: List[str] = None
    user_permissions: List[str] = None
    policy_violations: List[str] = None


@dataclass
class SessionInfo:
    """User session information"""
    session_id: str
    user_id: int
    username: str
    roles: List[str]
    permissions: List[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    ip_address: str
    user_agent: str
    is_active: bool


class AccessControlService:
    """Service for comprehensive access control and authorization"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._permission_cache = {}
        self._role_cache = {}
        self._policy_cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def check_access(self, request: AccessRequest) -> PermissionCheck:
        """Check if user has access to perform action on resource"""
        try:
            # Get user and their roles
            user = await self._get_user_with_roles(request.user_id)
            if not user:
                return PermissionCheck(
                    granted=False,
                    reason="User not found"
                )
            
            # Check if user is active
            if not user.is_active:
                return PermissionCheck(
                    granted=False,
                    reason="User account is inactive"
                )
            
            # Get user permissions
            user_permissions = await self._get_user_permissions(request.user_id)
            
            # Check basic permissions
            required_permission = f"{request.resource_type}:{request.action}"
            has_permission = await self._has_permission(user_permissions, required_permission, request.resource_id)
            
            if not has_permission:
                return PermissionCheck(
                    granted=False,
                    reason=f"Missing required permission: {required_permission}",
                    required_permissions=[required_permission],
                    user_permissions=user_permissions
                )
            
            # Check security policies
            policy_violations = await self._check_security_policies(request, user, user_permissions)
            if policy_violations:
                return PermissionCheck(
                    granted=False,
                    reason="Security policy violation",
                    policy_violations=policy_violations,
                    user_permissions=user_permissions
                )
            
            # Check time-based access control
            time_violation = await self._check_time_based_access(user, request)
            if time_violation:
                return PermissionCheck(
                    granted=False,
                    reason=f"Time-based access violation: {time_violation}",
                    user_permissions=user_permissions
                )
            
            # Check IP-based access control
            ip_violation = await self._check_ip_based_access(user, request)
            if ip_violation:
                return PermissionCheck(
                    granted=False,
                    reason=f"IP-based access violation: {ip_violation}",
                    user_permissions=user_permissions
                )
            
            # Log successful access
            await self._log_access_event(request, user, True, None)
            
            return PermissionCheck(
                granted=True,
                user_permissions=user_permissions
            )
            
        except Exception as e:
            logger.error(f"Error checking access for user {request.user_id}: {str(e)}")
            return PermissionCheck(
                granted=False,
                reason=f"Access check failed: {str(e)}"
            )
    
    async def grant_role(self, user_id: int, role_id: int, granted_by: int, 
                        expires_at: Optional[datetime] = None) -> AccessResult:
        """Grant a role to a user"""
        try:
            # Check if user exists
            user = await self._get_user(user_id)
            if not user:
                return AccessResult(
                    success=False,
                    error="User not found"
                )
            
            # Check if role exists
            role = await self._get_role(role_id)
            if not role:
                return AccessResult(
                    success=False,
                    error="Role not found"
                )
            
            # Check if user already has this role
            existing_assignment = await self.db_session.execute(
                select(UserRole).where(
                    and_(
                        UserRole.user_id == user_id,
                        UserRole.role_id == role_id,
                        UserRole.is_active == True
                    )
                )
            )
            
            if existing_assignment.scalar_one_or_none():
                return AccessResult(
                    success=False,
                    error="User already has this role"
                )
            
            # Create role assignment
            user_role = UserRole(
                user_id=user_id,
                role_id=role_id,
                assigned_by=granted_by,
                expires_at=expires_at,
                is_active=True
            )
            
            self.db_session.add(user_role)
            await self.db_session.commit()
            
            # Log the role grant
            await self._log_security_event(
                event_type="role_granted",
                user_id=user_id,
                resource_type="role",
                resource_id=str(role_id),
                action="grant",
                success=True,
                event_data={"role_name": role.name, "granted_by": granted_by}
            )
            
            # Clear caches
            self._clear_user_cache(user_id)
            
            return AccessResult(
                success=True,
                message=f"Role '{role.name}' granted to user {user_id}"
            )
            
        except Exception as e:
            logger.error(f"Error granting role {role_id} to user {user_id}: {str(e)}")
            await self.db_session.rollback()
            return AccessResult(
                success=False,
                error=f"Failed to grant role: {str(e)}"
            )
    
    async def revoke_role(self, user_id: int, role_id: int, revoked_by: int) -> AccessResult:
        """Revoke a role from a user"""
        try:
            # Find active role assignment
            user_role = await self.db_session.execute(
                select(UserRole).where(
                    and_(
                        UserRole.user_id == user_id,
                        UserRole.role_id == role_id,
                        UserRole.is_active == True
                    )
                )
            )
            user_role = user_role.scalar_one_or_none()
            
            if not user_role:
                return AccessResult(
                    success=False,
                    error="User does not have this role"
                )
            
            # Deactivate the role assignment
            user_role.is_active = False
            user_role.expires_at = datetime.now()
            
            await self.db_session.commit()
            
            # Get role name for logging
            role = await self._get_role(role_id)
            role_name = role.name if role else str(role_id)
            
            # Log the role revocation
            await self._log_security_event(
                event_type="role_revoked",
                user_id=user_id,
                resource_type="role",
                resource_id=str(role_id),
                action="revoke",
                success=True,
                event_data={"role_name": role_name, "revoked_by": revoked_by}
            )
            
            # Clear caches
            self._clear_user_cache(user_id)
            
            return AccessResult(
                success=True,
                message=f"Role '{role_name}' revoked from user {user_id}"
            )
            
        except Exception as e:
            logger.error(f"Error revoking role {role_id} from user {user_id}: {str(e)}")
            await self.db_session.rollback()
            return AccessResult(
                success=False,
                error=f"Failed to revoke role: {str(e)}"
            )
    
    async def create_role(self, name: str, description: str, security_level: SecurityLevel,
                         created_by: int, permissions: List[int] = None) -> AccessResult:
        """Create a new security role"""
        try:
            # Check if role name already exists
            existing_role = await self.db_session.execute(
                select(SecurityRole).where(SecurityRole.name == name)
            )
            if existing_role.scalar_one_or_none():
                return AccessResult(
                    success=False,
                    error="Role name already exists"
                )
            
            # Create the role
            role = SecurityRole(
                name=name,
                description=description,
                security_level=security_level,
                created_by=created_by
            )
            
            self.db_session.add(role)
            await self.db_session.flush()  # Get the role ID
            
            # Add permissions if provided
            if permissions:
                for permission_id in permissions:
                    role_permission = RolePermission(
                        role_id=role.id,
                        permission_id=permission_id,
                        granted_by=created_by
                    )
                    self.db_session.add(role_permission)
            
            await self.db_session.commit()
            
            # Log role creation
            await self._log_security_event(
                event_type="role_created",
                user_id=created_by,
                resource_type="role",
                resource_id=str(role.id),
                action="create",
                success=True,
                event_data={"role_name": name, "security_level": security_level}
            )
            
            # Clear caches
            self._clear_role_cache()
            
            return AccessResult(
                success=True,
                message=f"Role '{name}' created successfully",
                data={"role_id": role.id}
            )
            
        except Exception as e:
            logger.error(f"Error creating role '{name}': {str(e)}")
            await self.db_session.rollback()
            return AccessResult(
                success=False,
                error=f"Failed to create role: {str(e)}"
            )
    
    async def get_user_sessions(self, user_id: int) -> List[SessionInfo]:
        """Get active sessions for a user"""
        try:
            # This would typically query a session store (Redis, database, etc.)
            # For now, we'll return a placeholder implementation
            
            # Get user roles and permissions
            user_permissions = await self._get_user_permissions(user_id)
            user_roles = await self._get_user_roles(user_id)
            
            # Mock session data - in production, this would come from session store
            sessions = []
            if user_permissions:  # Only create mock session if user has permissions
                session = SessionInfo(
                    session_id="mock_session_123",
                    user_id=user_id,
                    username="mock_user",
                    roles=user_roles,
                    permissions=user_permissions,
                    created_at=datetime.now() - timedelta(hours=1),
                    last_activity=datetime.now(),
                    expires_at=datetime.now() + timedelta(hours=8),
                    ip_address="192.168.1.100",
                    user_agent="Mozilla/5.0...",
                    is_active=True
                )
                sessions.append(session)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Error getting sessions for user {user_id}: {str(e)}")
            return []
    
    async def terminate_session(self, session_id: str, terminated_by: int) -> AccessResult:
        """Terminate a user session"""
        try:
            # In production, this would update the session store
            # For now, we'll log the termination attempt
            
            await self._log_security_event(
                event_type="session_terminated",
                user_id=terminated_by,
                resource_type="session",
                resource_id=session_id,
                action="terminate",
                success=True,
                event_data={"terminated_by": terminated_by}
            )
            
            return AccessResult(
                success=True,
                message=f"Session {session_id} terminated"
            )
            
        except Exception as e:
            logger.error(f"Error terminating session {session_id}: {str(e)}")
            return AccessResult(
                success=False,
                error=f"Failed to terminate session: {str(e)}"
            )
    
    # Private helper methods
    
    async def _get_user_with_roles(self, user_id: int) -> Optional[User]:
        """Get user with their roles loaded"""
        result = await self.db_session.execute(
            select(User).options(selectinload(User.security_roles)).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def _get_user(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        result = await self.db_session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()
    
    async def _get_role(self, role_id: int) -> Optional[SecurityRole]:
        """Get role by ID"""
        result = await self.db_session.execute(
            select(SecurityRole).where(SecurityRole.id == role_id)
        )
        return result.scalar_one_or_none()
    
    async def _get_user_permissions(self, user_id: int) -> List[str]:
        """Get all permissions for a user"""
        cache_key = f"user_permissions_{user_id}"
        if cache_key in self._permission_cache:
            cached_data, timestamp = self._permission_cache[cache_key]
            if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                return cached_data
        
        # Query user permissions through roles
        query = select(SecurityPermission.name).join(
            RolePermission, SecurityPermission.id == RolePermission.permission_id
        ).join(
            UserRole, RolePermission.role_id == UserRole.role_id
        ).where(
            and_(
                UserRole.user_id == user_id,
                UserRole.is_active == True,
                RolePermission.is_active == True,
                SecurityPermission.is_active == True
            )
        )
        
        result = await self.db_session.execute(query)
        permissions = [row[0] for row in result.fetchall()]
        
        # Cache the result
        self._permission_cache[cache_key] = (permissions, datetime.now())
        
        return permissions
    
    async def _get_user_roles(self, user_id: int) -> List[str]:
        """Get all role names for a user"""
        query = select(SecurityRole.name).join(
            UserRole, SecurityRole.id == UserRole.role_id
        ).where(
            and_(
                UserRole.user_id == user_id,
                UserRole.is_active == True,
                SecurityRole.is_active == True
            )
        )
        
        result = await self.db_session.execute(query)
        return [row[0] for row in result.fetchall()]
    
    async def _has_permission(self, user_permissions: List[str], required_permission: str, 
                             resource_id: Optional[str] = None) -> bool:
        """Check if user has specific permission"""
        # Direct permission match
        if required_permission in user_permissions:
            return True
        
        # Wildcard permission match (e.g., "device:*" matches "device:read")
        resource_type = required_permission.split(':')[0]
        wildcard_permission = f"{resource_type}:*"
        if wildcard_permission in user_permissions:
            return True
        
        # Resource-specific permission match
        if resource_id:
            specific_permission = f"{required_permission}:{resource_id}"
            if specific_permission in user_permissions:
                return True
        
        return False
    
    async def _check_security_policies(self, request: AccessRequest, user: User, 
                                      user_permissions: List[str]) -> List[str]:
        """Check security policies for violations"""
        violations = []
        
        try:
            # Get applicable policies
            policies = await self._get_security_policies()
            
            for policy in policies:
                if not policy.is_active:
                    continue
                
                # Check if policy applies to this user/request
                if not self._policy_applies(policy, request, user):
                    continue
                
                # Evaluate policy rules
                violation = await self._evaluate_policy(policy, request, user, user_permissions)
                if violation:
                    violations.append(violation)
            
            return violations
            
        except Exception as e:
            logger.error(f"Error checking security policies: {str(e)}")
            return ["Policy evaluation failed"]
    
    async def _get_security_policies(self) -> List[SecurityPolicy]:
        """Get active security policies"""
        cache_key = "security_policies"
        if cache_key in self._policy_cache:
            cached_data, timestamp = self._policy_cache[cache_key]
            if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                return cached_data
        
        result = await self.db_session.execute(
            select(SecurityPolicy).where(
                and_(
                    SecurityPolicy.is_active == True,
                    SecurityPolicy.effective_from <= datetime.now(),
                    or_(
                        SecurityPolicy.effective_until.is_(None),
                        SecurityPolicy.effective_until > datetime.now()
                    )
                )
            ).order_by(SecurityPolicy.priority.asc())
        )
        
        policies = result.scalars().all()
        
        # Cache the result
        self._policy_cache[cache_key] = (policies, datetime.now())
        
        return policies
    
    def _policy_applies(self, policy: SecurityPolicy, request: AccessRequest, user: User) -> bool:
        """Check if policy applies to the request"""
        # Check target roles
        if policy.target_roles:
            user_roles = [role.name for role in user.security_roles]
            if not any(role in policy.target_roles for role in user_roles):
                return False
        
        # Check target resources
        if policy.target_resources:
            if request.resource_type not in policy.target_resources:
                return False
        
        # Check target users
        if policy.target_users:
            if request.user_id not in policy.target_users:
                return False
        
        return True
    
    async def _evaluate_policy(self, policy: SecurityPolicy, request: AccessRequest, 
                              user: User, user_permissions: List[str]) -> Optional[str]:
        """Evaluate a security policy"""
        try:
            rules = policy.policy_rules
            if not rules:
                return None
            
            # Simple rule evaluation - in production, this would be more sophisticated
            for rule in rules.get('rules', []):
                if rule.get('type') == 'time_restriction':
                    if not self._check_time_restriction(rule, request):
                        return f"Time restriction violation: {rule.get('message', 'Access not allowed at this time')}"
                
                elif rule.get('type') == 'ip_restriction':
                    if not self._check_ip_restriction(rule, request):
                        return f"IP restriction violation: {rule.get('message', 'Access not allowed from this IP')}"
                
                elif rule.get('type') == 'resource_limit':
                    if not await self._check_resource_limit(rule, request):
                        return f"Resource limit violation: {rule.get('message', 'Resource access limit exceeded')}"
            
            return None
            
        except Exception as e:
            logger.error(f"Error evaluating policy {policy.id}: {str(e)}")
            return f"Policy evaluation error: {str(e)}"
    
    def _check_time_restriction(self, rule: Dict[str, Any], request: AccessRequest) -> bool:
        """Check time-based restrictions"""
        allowed_hours = rule.get('allowed_hours', [])
        if not allowed_hours:
            return True
        
        current_hour = datetime.now().hour
        return current_hour in allowed_hours
    
    def _check_ip_restriction(self, rule: Dict[str, Any], request: AccessRequest) -> bool:
        """Check IP-based restrictions"""
        allowed_ips = rule.get('allowed_ips', [])
        if not allowed_ips or not request.ip_address:
            return True
        
        try:
            request_ip = ipaddress.ip_address(request.ip_address)
            for allowed_ip in allowed_ips:
                if request_ip in ipaddress.ip_network(allowed_ip, strict=False):
                    return True
            return False
        except ValueError:
            return False
    
    async def _check_resource_limit(self, rule: Dict[str, Any], request: AccessRequest) -> bool:
        """Check resource access limits"""
        max_requests = rule.get('max_requests', 0)
        time_window = rule.get('time_window_minutes', 60)
        
        if max_requests <= 0:
            return True
        
        # Count recent requests for this user and resource
        since_time = datetime.now() - timedelta(minutes=time_window)
        
        result = await self.db_session.execute(
            select(func.count(SecurityAuditLog.id)).where(
                and_(
                    SecurityAuditLog.user_id == request.user_id,
                    SecurityAuditLog.resource_type == request.resource_type,
                    SecurityAuditLog.action == request.action,
                    SecurityAuditLog.timestamp >= since_time,
                    SecurityAuditLog.success == True
                )
            )
        )
        
        request_count = result.scalar() or 0
        return request_count < max_requests
    
    async def _check_time_based_access(self, user: User, request: AccessRequest) -> Optional[str]:
        """Check time-based access control for user roles"""
        for role in user.security_roles:
            if role.allowed_time_windows:
                current_time = datetime.now().time()
                allowed = False
                
                for window in role.allowed_time_windows:
                    start_time = datetime.strptime(window['start'], '%H:%M').time()
                    end_time = datetime.strptime(window['end'], '%H:%M').time()
                    
                    if start_time <= current_time <= end_time:
                        allowed = True
                        break
                
                if not allowed:
                    return f"Access not allowed outside role '{role.name}' time windows"
        
        return None
    
    async def _check_ip_based_access(self, user: User, request: AccessRequest) -> Optional[str]:
        """Check IP-based access control for user roles"""
        if not request.ip_address:
            return None
        
        for role in user.security_roles:
            if role.allowed_ip_ranges:
                try:
                    request_ip = ipaddress.ip_address(request.ip_address)
                    allowed = False
                    
                    for ip_range in role.allowed_ip_ranges:
                        if request_ip in ipaddress.ip_network(ip_range, strict=False):
                            allowed = True
                            break
                    
                    if not allowed:
                        return f"Access not allowed from IP {request.ip_address} for role '{role.name}'"
                        
                except ValueError:
                    return f"Invalid IP address format: {request.ip_address}"
        
        return None
    
    async def _log_access_event(self, request: AccessRequest, user: User, 
                               success: bool, failure_reason: Optional[str]):
        """Log access control event"""
        await self._log_security_event(
            event_type="access_control",
            user_id=request.user_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            action=request.action,
            success=success,
            failure_reason=failure_reason,
            ip_address=request.ip_address,
            user_agent=request.user_agent,
            session_id=request.session_id,
            event_data=request.context
        )
    
    async def _log_security_event(self, event_type: str, user_id: int, resource_type: str,
                                 action: str, success: bool, resource_id: Optional[str] = None,
                                 failure_reason: Optional[str] = None, ip_address: Optional[str] = None,
                                 user_agent: Optional[str] = None, session_id: Optional[str] = None,
                                 event_data: Optional[Dict[str, Any]] = None):
        """Log security event to audit log"""
        try:
            audit_log = SecurityAuditLog(
                event_type=event_type,
                event_category="access_control",
                event_action=action,
                user_id=user_id,
                resource_type=resource_type,
                resource_id=resource_id,
                success=success,
                failure_reason=failure_reason,
                ip_address=ip_address,
                user_agent=user_agent,
                event_data=event_data
            )
            
            self.db_session.add(audit_log)
            await self.db_session.commit()
            
        except Exception as e:
            logger.error(f"Error logging security event: {str(e)}")
            await self.db_session.rollback()
    
    def _clear_user_cache(self, user_id: int):
        """Clear user-specific caches"""
        cache_keys_to_remove = [key for key in self._permission_cache.keys() 
                               if key.startswith(f"user_permissions_{user_id}")]
        for key in cache_keys_to_remove:
            self._permission_cache.pop(key, None)
    
    def _clear_role_cache(self):
        """Clear role-related caches"""
        self._role_cache.clear()
        self._policy_cache.clear()
