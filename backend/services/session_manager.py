"""
Session Manager for Redis-based Session Storage
Handles user sessions, device tracking, and concurrent session management
"""

import json
import logging
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
import hashlib

try:
    import redis.asyncio as redis
    from redis.asyncio import Redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    Redis = None

from backend.config import settings
from backend.common.exceptions import (
    SessionException,
    AuthenticationException,
    ValidationException
)

logger = logging.getLogger(__name__)


@dataclass
class SessionData:
    """Session data model"""
    session_id: str
    user_id: int
    username: str
    role: str
    permissions: List[str]
    ip_address: str
    user_agent: str
    device_id: str
    device_type: str
    device_name: str
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    is_active: bool = True
    mfa_verified: bool = False
    metadata: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        # Convert datetime to ISO format
        data['created_at'] = self.created_at.isoformat()
        data['last_activity'] = self.last_activity.isoformat()
        data['expires_at'] = self.expires_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SessionData':
        """Create from dictionary"""
        # Convert ISO format to datetime
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['last_activity'] = datetime.fromisoformat(data['last_activity'])
        data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)


class SessionManager:
    """Manager for Redis-based user sessions"""
    
    def __init__(self):
        """Initialize session manager"""
        self.redis_client: Optional[Redis] = None
        self.session_ttl = settings.session_ttl or 3600  # 1 hour default
        self.max_sessions_per_user = settings.max_sessions_per_user or 5
        self.max_devices_per_user = settings.max_devices_per_user or 10
        self.session_prefix = "session:"
        self.user_sessions_prefix = "user_sessions:"
        self.device_prefix = "device:"
        self.active_sessions_key = "active_sessions"
        
        # Session settings
        self.enable_device_tracking = True
        self.enable_session_history = True
        self.enable_concurrent_sessions = True
        self.enable_session_renewal = True
        
        # Security settings
        self.require_mfa_for_sensitive = True
        self.session_fingerprinting = True
        self.ip_validation = True
        
        logger.info("SessionManager initialized")
    
    async def connect(self) -> bool:
        """
        Connect to Redis
        
        Returns:
            True if connected successfully
        """
        if not REDIS_AVAILABLE:
            logger.warning("Redis not available, sessions will not persist")
            return False
        
        try:
            self.redis_client = redis.from_url(
                settings.redis_url or "redis://localhost:6379",
                decode_responses=True,
                socket_keepalive=True,
                socket_keepalive_options={
                    1: 1,  # TCP_KEEPIDLE
                    2: 1,  # TCP_KEEPINTVL
                    3: 5,  # TCP_KEEPCNT
                }
            )
            
            # Test connection
            await self.redis_client.ping()
            logger.info("Connected to Redis for session management")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            self.redis_client = None
            return False
    
    async def disconnect(self):
        """Disconnect from Redis"""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
            logger.info("Disconnected from Redis")
    
    async def create_session(
        self,
        user_id: int,
        username: str,
        role: str,
        permissions: List[str],
        ip_address: str,
        user_agent: str,
        device_info: Optional[Dict[str, str]] = None,
        mfa_verified: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[SessionData]:
        """
        Create new user session
        
        Args:
            user_id: User ID
            username: Username
            role: User role
            permissions: User permissions
            ip_address: Client IP address
            user_agent: Client user agent
            device_info: Device information
            mfa_verified: MFA verification status
            metadata: Additional metadata
            
        Returns:
            SessionData if created successfully
        """
        try:
            # Generate session ID
            session_id = self._generate_session_id()
            
            # Generate device ID
            device_id = self._generate_device_id(user_agent, ip_address)
            device_type = self._detect_device_type(user_agent)
            device_name = device_info.get('name', device_type) if device_info else device_type
            
            # Check concurrent sessions
            if not await self._check_concurrent_sessions(user_id):
                raise SessionException("Maximum concurrent sessions reached")
            
            # Create session data
            now = datetime.utcnow()
            session_data = SessionData(
                session_id=session_id,
                user_id=user_id,
                username=username,
                role=role,
                permissions=permissions,
                ip_address=ip_address,
                user_agent=user_agent,
                device_id=device_id,
                device_type=device_type,
                device_name=device_name,
                created_at=now,
                last_activity=now,
                expires_at=now + timedelta(seconds=self.session_ttl),
                is_active=True,
                mfa_verified=mfa_verified,
                metadata=metadata or {}
            )
            
            # Store in Redis if available
            if self.redis_client:
                # Store session data
                session_key = f"{self.session_prefix}{session_id}"
                await self.redis_client.setex(
                    session_key,
                    self.session_ttl,
                    json.dumps(session_data.to_dict())
                )
                
                # Add to user's sessions
                user_sessions_key = f"{self.user_sessions_prefix}{user_id}"
                await self.redis_client.sadd(user_sessions_key, session_id)
                await self.redis_client.expire(user_sessions_key, self.session_ttl * 2)
                
                # Track device
                if self.enable_device_tracking:
                    await self._track_device(user_id, device_id, device_info)
                
                # Add to active sessions
                await self.redis_client.sadd(self.active_sessions_key, session_id)
                
                # Log session creation
                logger.info(f"Session created for user {username} (ID: {user_id})")
            
            return session_data
            
        except Exception as e:
            logger.error(f"Failed to create session: {e}")
            raise SessionException(f"Failed to create session: {str(e)}")
    
    async def get_session(self, session_id: str) -> Optional[SessionData]:
        """
        Get session by ID
        
        Args:
            session_id: Session ID
            
        Returns:
            SessionData if found and valid
        """
        if not self.redis_client:
            return None
        
        try:
            session_key = f"{self.session_prefix}{session_id}"
            session_data = await self.redis_client.get(session_key)
            
            if not session_data:
                return None
            
            session = SessionData.from_dict(json.loads(session_data))
            
            # Check if expired
            if datetime.utcnow() > session.expires_at:
                await self.invalidate_session(session_id)
                return None
            
            # Check if active
            if not session.is_active:
                return None
            
            return session
            
        except Exception as e:
            logger.error(f"Failed to get session: {e}")
            return None
    
    async def update_activity(
        self,
        session_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> bool:
        """
        Update session last activity
        
        Args:
            session_id: Session ID
            ip_address: New IP address
            user_agent: New user agent
            
        Returns:
            True if updated successfully
        """
        try:
            session = await self.get_session(session_id)
            if not session:
                return False
            
            # Validate IP if required
            if self.ip_validation and ip_address and ip_address != session.ip_address:
                logger.warning(f"IP address changed for session {session_id}")
                # Could invalidate session or require re-authentication
            
            # Update activity
            session.last_activity = datetime.utcnow()
            
            # Renew session if enabled
            if self.enable_session_renewal:
                session.expires_at = datetime.utcnow() + timedelta(seconds=self.session_ttl)
            
            # Update in Redis
            if self.redis_client:
                session_key = f"{self.session_prefix}{session_id}"
                await self.redis_client.setex(
                    session_key,
                    self.session_ttl,
                    json.dumps(session.to_dict())
                )
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to update session activity: {e}")
            return False
    
    async def invalidate_session(self, session_id: str) -> bool:
        """
        Invalidate session
        
        Args:
            session_id: Session ID
            
        Returns:
            True if invalidated successfully
        """
        if not self.redis_client:
            return False
        
        try:
            # Get session data first
            session = await self.get_session(session_id)
            if session:
                # Remove from user sessions
                user_sessions_key = f"{self.user_sessions_prefix}{session.user_id}"
                await self.redis_client.srem(user_sessions_key, session_id)
                
                # Store in history if enabled
                if self.enable_session_history:
                    await self._store_session_history(session)
            
            # Delete session
            session_key = f"{self.session_prefix}{session_id}"
            await self.redis_client.delete(session_key)
            
            # Remove from active sessions
            await self.redis_client.srem(self.active_sessions_key, session_id)
            
            logger.info(f"Session {session_id} invalidated")
            return True
            
        except Exception as e:
            logger.error(f"Failed to invalidate session: {e}")
            return False
    
    async def invalidate_user_sessions(
        self,
        user_id: int,
        except_session: Optional[str] = None
    ) -> int:
        """
        Invalidate all sessions for a user
        
        Args:
            user_id: User ID
            except_session: Session ID to keep
            
        Returns:
            Number of sessions invalidated
        """
        if not self.redis_client:
            return 0
        
        try:
            user_sessions_key = f"{self.user_sessions_prefix}{user_id}"
            session_ids = await self.redis_client.smembers(user_sessions_key)
            
            invalidated = 0
            for session_id in session_ids:
                if session_id != except_session:
                    if await self.invalidate_session(session_id):
                        invalidated += 1
            
            logger.info(f"Invalidated {invalidated} sessions for user {user_id}")
            return invalidated
            
        except Exception as e:
            logger.error(f"Failed to invalidate user sessions: {e}")
            return 0
    
    async def get_user_sessions(
        self,
        user_id: int,
        active_only: bool = True
    ) -> List[SessionData]:
        """
        Get all sessions for a user
        
        Args:
            user_id: User ID
            active_only: Only return active sessions
            
        Returns:
            List of SessionData
        """
        if not self.redis_client:
            return []
        
        try:
            user_sessions_key = f"{self.user_sessions_prefix}{user_id}"
            session_ids = await self.redis_client.smembers(user_sessions_key)
            
            sessions = []
            for session_id in session_ids:
                session = await self.get_session(session_id)
                if session and (not active_only or session.is_active):
                    sessions.append(session)
            
            # Sort by last activity
            sessions.sort(key=lambda s: s.last_activity, reverse=True)
            
            return sessions
            
        except Exception as e:
            logger.error(f"Failed to get user sessions: {e}")
            return []
    
    async def get_active_sessions_count(self) -> int:
        """
        Get count of active sessions
        
        Returns:
            Number of active sessions
        """
        if not self.redis_client:
            return 0
        
        try:
            return await self.redis_client.scard(self.active_sessions_key)
        except Exception as e:
            logger.error(f"Failed to get active sessions count: {e}")
            return 0
    
    async def get_user_devices(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all devices for a user
        
        Args:
            user_id: User ID
            
        Returns:
            List of device information
        """
        if not self.redis_client or not self.enable_device_tracking:
            return []
        
        try:
            devices_key = f"{self.device_prefix}{user_id}:devices"
            device_ids = await self.redis_client.smembers(devices_key)
            
            devices = []
            for device_id in device_ids:
                device_key = f"{self.device_prefix}{user_id}:{device_id}"
                device_data = await self.redis_client.get(device_key)
                if device_data:
                    devices.append(json.loads(device_data))
            
            return devices
            
        except Exception as e:
            logger.error(f"Failed to get user devices: {e}")
            return []
    
    async def revoke_device(self, user_id: int, device_id: str) -> bool:
        """
        Revoke device access
        
        Args:
            user_id: User ID
            device_id: Device ID
            
        Returns:
            True if revoked successfully
        """
        if not self.redis_client or not self.enable_device_tracking:
            return False
        
        try:
            # Remove device
            devices_key = f"{self.device_prefix}{user_id}:devices"
            device_key = f"{self.device_prefix}{user_id}:{device_id}"
            
            await self.redis_client.srem(devices_key, device_id)
            await self.redis_client.delete(device_key)
            
            # Invalidate sessions from this device
            sessions = await self.get_user_sessions(user_id)
            for session in sessions:
                if session.device_id == device_id:
                    await self.invalidate_session(session.session_id)
            
            logger.info(f"Device {device_id} revoked for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke device: {e}")
            return False
    
    async def verify_mfa(self, session_id: str) -> bool:
        """
        Mark session as MFA verified
        
        Args:
            session_id: Session ID
            
        Returns:
            True if verified successfully
        """
        try:
            session = await self.get_session(session_id)
            if not session:
                return False
            
            session.mfa_verified = True
            
            # Update in Redis
            if self.redis_client:
                session_key = f"{self.session_prefix}{session_id}"
                await self.redis_client.setex(
                    session_key,
                    self.session_ttl,
                    json.dumps(session.to_dict())
                )
            
            logger.info(f"Session {session_id} MFA verified")
            return True
            
        except Exception as e:
            logger.error(f"Failed to verify MFA: {e}")
            return False
    
    async def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions
        
        Returns:
            Number of sessions cleaned
        """
        if not self.redis_client:
            return 0
        
        try:
            session_ids = await self.redis_client.smembers(self.active_sessions_key)
            
            cleaned = 0
            for session_id in session_ids:
                session = await self.get_session(session_id)
                if not session or datetime.utcnow() > session.expires_at:
                    await self.invalidate_session(session_id)
                    cleaned += 1
            
            logger.info(f"Cleaned up {cleaned} expired sessions")
            return cleaned
            
        except Exception as e:
            logger.error(f"Failed to cleanup sessions: {e}")
            return 0
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return secrets.token_urlsafe(32)
    
    def _generate_device_id(self, user_agent: str, ip_address: str) -> str:
        """Generate device ID from user agent and IP"""
        data = f"{user_agent}:{ip_address}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _detect_device_type(self, user_agent: str) -> str:
        """Detect device type from user agent"""
        user_agent_lower = user_agent.lower()
        
        if 'mobile' in user_agent_lower or 'android' in user_agent_lower:
            return 'mobile'
        elif 'tablet' in user_agent_lower or 'ipad' in user_agent_lower:
            return 'tablet'
        elif 'bot' in user_agent_lower or 'crawler' in user_agent_lower:
            return 'bot'
        else:
            return 'desktop'
    
    async def _check_concurrent_sessions(self, user_id: int) -> bool:
        """
        Check if user can create new session
        
        Args:
            user_id: User ID
            
        Returns:
            True if allowed
        """
        if not self.enable_concurrent_sessions:
            # Invalidate all existing sessions
            await self.invalidate_user_sessions(user_id)
            return True
        
        sessions = await self.get_user_sessions(user_id)
        if len(sessions) >= self.max_sessions_per_user:
            # Remove oldest session
            if sessions:
                oldest = min(sessions, key=lambda s: s.last_activity)
                await self.invalidate_session(oldest.session_id)
        
        return True
    
    async def _track_device(
        self,
        user_id: int,
        device_id: str,
        device_info: Optional[Dict[str, str]] = None
    ):
        """Track user device"""
        if not self.redis_client:
            return
        
        try:
            devices_key = f"{self.device_prefix}{user_id}:devices"
            device_key = f"{self.device_prefix}{user_id}:{device_id}"
            
            # Check device limit
            device_count = await self.redis_client.scard(devices_key)
            if device_count >= self.max_devices_per_user:
                # Remove oldest device
                devices = await self.get_user_devices(user_id)
                if devices:
                    oldest = min(devices, key=lambda d: d.get('last_seen', ''))
                    await self.revoke_device(user_id, oldest['id'])
            
            # Store device info
            device_data = {
                'id': device_id,
                'name': device_info.get('name', 'Unknown Device') if device_info else 'Unknown Device',
                'type': device_info.get('type', 'unknown') if device_info else 'unknown',
                'last_seen': datetime.utcnow().isoformat(),
                'first_seen': datetime.utcnow().isoformat()
            }
            
            # Update if exists
            existing = await self.redis_client.get(device_key)
            if existing:
                existing_data = json.loads(existing)
                device_data['first_seen'] = existing_data.get('first_seen', device_data['first_seen'])
            
            await self.redis_client.setex(
                device_key,
                self.session_ttl * 30,  # Keep device info for 30x session TTL
                json.dumps(device_data)
            )
            await self.redis_client.sadd(devices_key, device_id)
            
        except Exception as e:
            logger.error(f"Failed to track device: {e}")
    
    async def _store_session_history(self, session: SessionData):
        """Store session in history"""
        if not self.redis_client:
            return
        
        try:
            history_key = f"session_history:{session.user_id}"
            history_data = {
                'session_id': session.session_id,
                'created_at': session.created_at.isoformat(),
                'ended_at': datetime.utcnow().isoformat(),
                'duration': (datetime.utcnow() - session.created_at).total_seconds(),
                'ip_address': session.ip_address,
                'device_type': session.device_type
            }
            
            # Store in sorted set with timestamp as score
            await self.redis_client.zadd(
                history_key,
                {json.dumps(history_data): datetime.utcnow().timestamp()}
            )
            
            # Keep only last 100 sessions
            await self.redis_client.zremrangebyrank(history_key, 0, -101)
            
            # Set expiry
            await self.redis_client.expire(history_key, 86400 * 30)  # 30 days
            
        except Exception as e:
            logger.error(f"Failed to store session history: {e}")


# Global session manager instance
session_manager = SessionManager()