"""
Production JWT authentication system with refresh tokens.
Implements secure token generation, validation, and rotation.
"""

import jwt
import secrets
import hashlib
import time
import json
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta, timezone
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import base64
import os

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

logger = logging.getLogger(__name__)


class TokenType(Enum):
    """JWT token types"""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"
    SERVICE = "service"  # For service-to-service auth


class Algorithm(Enum):
    """JWT signing algorithms"""
    HS256 = "HS256"  # HMAC with SHA-256
    HS384 = "HS384"  # HMAC with SHA-384
    HS512 = "HS512"  # HMAC with SHA-512
    RS256 = "RS256"  # RSA with SHA-256
    RS384 = "RS384"  # RSA with SHA-384
    RS512 = "RS512"  # RSA with SHA-512
    ES256 = "ES256"  # ECDSA with SHA-256
    ES384 = "ES384"  # ECDSA with SHA-384
    ES512 = "ES512"  # ECDSA with SHA-512


@dataclass
class JWTConfig:
    """JWT configuration"""
    # Token settings
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 30
    api_key_expire_days: int = 365
    
    # Security
    algorithm: Algorithm = Algorithm.RS256
    secret_key: Optional[str] = None  # For HMAC algorithms
    private_key: Optional[str] = None  # For RSA/ECDSA
    public_key: Optional[str] = None  # For RSA/ECDSA
    
    # Key rotation
    enable_key_rotation: bool = True
    key_rotation_interval_days: int = 90
    old_key_grace_period_days: int = 7
    
    # Token security
    require_audience: bool = True
    audience: str = "chm-api"
    require_issuer: bool = True
    issuer: str = "chm-auth"
    
    # Refresh token settings
    refresh_token_reuse_detection: bool = True
    refresh_token_family_tracking: bool = True
    max_refresh_token_reuse: int = 1
    
    # Blacklist settings
    enable_blacklist: bool = True
    blacklist_check_redis: bool = True
    
    # Additional claims
    include_permissions: bool = True
    include_roles: bool = True
    include_metadata: bool = True
    
    # Security headers
    require_jti: bool = True  # JWT ID for tracking
    require_iat: bool = True  # Issued at time
    require_nbf: bool = True  # Not before time
    
    # Rate limiting
    max_tokens_per_user: int = 10
    max_refresh_per_hour: int = 10


@dataclass
class TokenClaims:
    """JWT token claims"""
    sub: str  # Subject (user ID)
    type: TokenType
    exp: int  # Expiration time
    iat: int  # Issued at
    nbf: int  # Not before
    jti: str  # JWT ID
    
    # Optional standard claims
    iss: Optional[str] = None  # Issuer
    aud: Optional[Union[str, List[str]]] = None  # Audience
    
    # Custom claims
    roles: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Refresh token specific
    family_id: Optional[str] = None  # For refresh token families
    parent_jti: Optional[str] = None  # Parent token ID
    refresh_count: int = 0  # Number of times refreshed
    
    # Device/session info
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JWT payload"""
        data = {
            'sub': self.sub,
            'type': self.type.value,
            'exp': self.exp,
            'iat': self.iat,
            'nbf': self.nbf,
            'jti': self.jti
        }
        
        if self.iss:
            data['iss'] = self.iss
        if self.aud:
            data['aud'] = self.aud
        if self.roles:
            data['roles'] = self.roles
        if self.permissions:
            data['permissions'] = self.permissions
        if self.metadata:
            data['metadata'] = self.metadata
        if self.family_id:
            data['family_id'] = self.family_id
        if self.parent_jti:
            data['parent_jti'] = self.parent_jti
        if self.refresh_count > 0:
            data['refresh_count'] = self.refresh_count
        if self.device_id:
            data['device_id'] = self.device_id
        if self.ip_address:
            data['ip_address'] = self.ip_address
        if self.user_agent:
            data['user_agent'] = self.user_agent
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TokenClaims':
        """Create from dictionary"""
        return cls(
            sub=data['sub'],
            type=TokenType(data['type']),
            exp=data['exp'],
            iat=data['iat'],
            nbf=data.get('nbf', data['iat']),
            jti=data['jti'],
            iss=data.get('iss'),
            aud=data.get('aud'),
            roles=data.get('roles', []),
            permissions=data.get('permissions', []),
            metadata=data.get('metadata', {}),
            family_id=data.get('family_id'),
            parent_jti=data.get('parent_jti'),
            refresh_count=data.get('refresh_count', 0),
            device_id=data.get('device_id'),
            ip_address=data.get('ip_address'),
            user_agent=data.get('user_agent')
        )


class JWTManager:
    """JWT token manager with key rotation and refresh token handling"""
    
    def __init__(self,
                 config: JWTConfig,
                 redis_client: Optional[redis.Redis] = None):
        self.config = config
        self.redis_client = redis_client
        
        # Initialize keys
        self._init_keys()
        
        # Token families for refresh token tracking
        self._token_families: Dict[str, List[str]] = {}
        
        # Blacklist
        self._blacklist: Set[str] = set()
        
        # Statistics
        self.stats = {
            'tokens_issued': 0,
            'tokens_refreshed': 0,
            'tokens_revoked': 0,
            'validation_failures': 0,
            'key_rotations': 0
        }
    
    def _init_keys(self):
        """Initialize cryptographic keys"""
        if self.config.algorithm in [Algorithm.HS256, Algorithm.HS384, Algorithm.HS512]:
            # HMAC algorithms need secret key
            if not self.config.secret_key:
                # Generate secure random key
                self.config.secret_key = secrets.token_urlsafe(64)
                logger.warning("Generated new secret key for JWT")
            
            self.current_key = self.config.secret_key
            self.old_keys = []
            
        elif self.config.algorithm in [Algorithm.RS256, Algorithm.RS384, Algorithm.RS512]:
            # RSA algorithms need key pair
            if not self.config.private_key or not self.config.public_key:
                # Generate RSA key pair
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                
                self.config.private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ).decode('utf-8')
                
                self.config.public_key = private_key.public_key().public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8')
                
                logger.warning("Generated new RSA key pair for JWT")
            
            self.current_private_key = self.config.private_key
            self.current_public_key = self.config.public_key
            self.old_public_keys = []
    
    async def create_access_token(self,
                                 user_id: str,
                                 roles: Optional[List[str]] = None,
                                 permissions: Optional[List[str]] = None,
                                 metadata: Optional[Dict[str, Any]] = None,
                                 device_info: Optional[Dict[str, str]] = None) -> str:
        """Create access token"""
        now = datetime.now(timezone.utc)
        
        claims = TokenClaims(
            sub=user_id,
            type=TokenType.ACCESS,
            exp=int((now + timedelta(minutes=self.config.access_token_expire_minutes)).timestamp()),
            iat=int(now.timestamp()),
            nbf=int(now.timestamp()),
            jti=secrets.token_urlsafe(32),
            iss=self.config.issuer if self.config.require_issuer else None,
            aud=self.config.audience if self.config.require_audience else None,
            roles=roles or [],
            permissions=permissions or [],
            metadata=metadata or {}
        )
        
        if device_info:
            claims.device_id = device_info.get('device_id')
            claims.ip_address = device_info.get('ip_address')
            claims.user_agent = device_info.get('user_agent')
        
        # Create token
        token = self._encode_token(claims)
        
        # Store in Redis if available
        if self.redis_client:
            await self._store_token_metadata(claims)
        
        self.stats['tokens_issued'] += 1
        
        return token
    
    async def create_refresh_token(self,
                                  user_id: str,
                                  access_token_jti: str,
                                  family_id: Optional[str] = None,
                                  device_info: Optional[Dict[str, str]] = None) -> str:
        """Create refresh token"""
        now = datetime.now(timezone.utc)
        
        # Create or reuse family ID
        if not family_id:
            family_id = secrets.token_urlsafe(32)
        
        claims = TokenClaims(
            sub=user_id,
            type=TokenType.REFRESH,
            exp=int((now + timedelta(days=self.config.refresh_token_expire_days)).timestamp()),
            iat=int(now.timestamp()),
            nbf=int(now.timestamp()),
            jti=secrets.token_urlsafe(32),
            iss=self.config.issuer if self.config.require_issuer else None,
            aud=self.config.audience if self.config.require_audience else None,
            family_id=family_id,
            parent_jti=access_token_jti,
            refresh_count=0
        )
        
        if device_info:
            claims.device_id = device_info.get('device_id')
            claims.ip_address = device_info.get('ip_address')
            claims.user_agent = device_info.get('user_agent')
        
        # Track token family
        if self.config.refresh_token_family_tracking:
            await self._track_token_family(family_id, claims.jti)
        
        # Create token
        token = self._encode_token(claims)
        
        # Store in Redis if available
        if self.redis_client:
            await self._store_token_metadata(claims)
        
        return token
    
    async def refresh_tokens(self,
                           refresh_token: str,
                           device_info: Optional[Dict[str, str]] = None) -> Tuple[str, str]:
        """Refresh both access and refresh tokens"""
        # Validate refresh token
        claims = await self.validate_token(refresh_token, TokenType.REFRESH)
        
        # Check for token reuse
        if self.config.refresh_token_reuse_detection:
            is_reused = await self._check_token_reuse(claims.jti)
            if is_reused:
                # Potential security breach - revoke entire family
                await self._revoke_token_family(claims.family_id)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Refresh token reuse detected - all tokens revoked"
                )
        
        # Mark old refresh token as used
        await self._mark_token_used(claims.jti)
        
        # Create new access token
        access_token = await self.create_access_token(
            user_id=claims.sub,
            roles=claims.roles,
            permissions=claims.permissions,
            metadata=claims.metadata,
            device_info=device_info or {
                'device_id': claims.device_id,
                'ip_address': claims.ip_address,
                'user_agent': claims.user_agent
            }
        )
        
        # Create new refresh token
        new_refresh_token = await self.create_refresh_token(
            user_id=claims.sub,
            access_token_jti=self._get_token_jti(access_token),
            family_id=claims.family_id,
            device_info=device_info
        )
        
        # Update refresh count
        new_claims = await self.validate_token(new_refresh_token, TokenType.REFRESH)
        new_claims.refresh_count = claims.refresh_count + 1
        
        self.stats['tokens_refreshed'] += 1
        
        return access_token, new_refresh_token
    
    async def validate_token(self,
                           token: str,
                           expected_type: Optional[TokenType] = None,
                           verify_exp: bool = True) -> TokenClaims:
        """Validate JWT token"""
        try:
            # Decode token
            payload = self._decode_token(token, verify_exp)
            
            # Parse claims
            claims = TokenClaims.from_dict(payload)
            
            # Check token type
            if expected_type and claims.type != expected_type:
                raise jwt.InvalidTokenError(f"Expected {expected_type.value} token, got {claims.type.value}")
            
            # Check blacklist
            if self.config.enable_blacklist:
                is_blacklisted = await self._is_blacklisted(claims.jti)
                if is_blacklisted:
                    raise jwt.InvalidTokenError("Token has been revoked")
            
            # Additional validations
            now = datetime.now(timezone.utc).timestamp()
            
            if self.config.require_nbf and claims.nbf > now:
                raise jwt.InvalidTokenError("Token not yet valid")
            
            if self.config.require_issuer and claims.iss != self.config.issuer:
                raise jwt.InvalidTokenError(f"Invalid issuer: {claims.iss}")
            
            if self.config.require_audience and claims.aud != self.config.audience:
                raise jwt.InvalidTokenError(f"Invalid audience: {claims.aud}")
            
            return claims
            
        except jwt.ExpiredSignatureError:
            self.stats['validation_failures'] += 1
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.InvalidTokenError as e:
            self.stats['validation_failures'] += 1
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e)
            )
        except Exception as e:
            self.stats['validation_failures'] += 1
            logger.error(f"Token validation error: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    
    async def revoke_token(self, token: str):
        """Revoke a token by adding to blacklist"""
        try:
            claims = await self.validate_token(token, verify_exp=False)
            await self._blacklist_token(claims.jti, claims.exp)
            
            # If refresh token, revoke entire family
            if claims.type == TokenType.REFRESH and claims.family_id:
                await self._revoke_token_family(claims.family_id)
            
            self.stats['tokens_revoked'] += 1
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
    
    async def revoke_all_user_tokens(self, user_id: str):
        """Revoke all tokens for a user"""
        if self.redis_client:
            # Get all user tokens from Redis
            pattern = f"jwt:user:{user_id}:*"
            cursor = 0
            
            while True:
                cursor, keys = await self.redis_client.scan(
                    cursor, match=pattern, count=100
                )
                
                for key in keys:
                    token_data = await self.redis_client.get(key)
                    if token_data:
                        data = json.loads(token_data)
                        await self._blacklist_token(data['jti'], data['exp'])
                
                if cursor == 0:
                    break
    
    def _encode_token(self, claims: TokenClaims) -> str:
        """Encode token with current key"""
        payload = claims.to_dict()
        
        if self.config.algorithm in [Algorithm.HS256, Algorithm.HS384, Algorithm.HS512]:
            # HMAC signing
            return jwt.encode(
                payload,
                self.current_key,
                algorithm=self.config.algorithm.value
            )
        else:
            # RSA signing
            return jwt.encode(
                payload,
                self.current_private_key,
                algorithm=self.config.algorithm.value
            )
    
    def _decode_token(self, token: str, verify_exp: bool = True) -> Dict[str, Any]:
        """Decode token trying current and old keys"""
        options = {
            'verify_exp': verify_exp,
            'verify_aud': self.config.require_audience,
            'verify_iss': self.config.require_issuer
        }
        
        # Try current key first
        try:
            if self.config.algorithm in [Algorithm.HS256, Algorithm.HS384, Algorithm.HS512]:
                return jwt.decode(
                    token,
                    self.current_key,
                    algorithms=[self.config.algorithm.value],
                    options=options,
                    audience=self.config.audience if self.config.require_audience else None,
                    issuer=self.config.issuer if self.config.require_issuer else None
                )
            else:
                return jwt.decode(
                    token,
                    self.current_public_key,
                    algorithms=[self.config.algorithm.value],
                    options=options,
                    audience=self.config.audience if self.config.require_audience else None,
                    issuer=self.config.issuer if self.config.require_issuer else None
                )
        except jwt.InvalidSignatureError:
            # Try old keys during grace period
            if self.config.algorithm in [Algorithm.HS256, Algorithm.HS384, Algorithm.HS512]:
                for old_key in self.old_keys:
                    try:
                        return jwt.decode(
                            token,
                            old_key,
                            algorithms=[self.config.algorithm.value],
                            options=options,
                            audience=self.config.audience if self.config.require_audience else None,
                            issuer=self.config.issuer if self.config.require_issuer else None
                        )
                    except jwt.InvalidSignatureError:
                        continue
            else:
                for old_key in self.old_public_keys:
                    try:
                        return jwt.decode(
                            token,
                            old_key,
                            algorithms=[self.config.algorithm.value],
                            options=options,
                            audience=self.config.audience if self.config.require_audience else None,
                            issuer=self.config.issuer if self.config.require_issuer else None
                        )
                    except jwt.InvalidSignatureError:
                        continue
            
            raise
    
    def _get_token_jti(self, token: str) -> str:
        """Extract JTI from token without full validation"""
        # Decode without verification just to get JTI
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get('jti', '')
    
    async def _store_token_metadata(self, claims: TokenClaims):
        """Store token metadata in Redis"""
        if not self.redis_client:
            return
        
        try:
            # Store by JTI
            jti_key = f"jwt:jti:{claims.jti}"
            await self.redis_client.setex(
                jti_key,
                claims.exp - int(time.time()),
                json.dumps({
                    'sub': claims.sub,
                    'type': claims.type.value,
                    'exp': claims.exp,
                    'family_id': claims.family_id
                })
            )
            
            # Store by user
            user_key = f"jwt:user:{claims.sub}:{claims.jti}"
            await self.redis_client.setex(
                user_key,
                claims.exp - int(time.time()),
                json.dumps({
                    'jti': claims.jti,
                    'type': claims.type.value,
                    'exp': claims.exp
                })
            )
            
        except Exception as e:
            logger.warning(f"Failed to store token metadata: {e}")
    
    async def _track_token_family(self, family_id: str, jti: str):
        """Track refresh token family"""
        if self.redis_client:
            try:
                family_key = f"jwt:family:{family_id}"
                await self.redis_client.sadd(family_key, jti)
                await self.redis_client.expire(
                    family_key,
                    self.config.refresh_token_expire_days * 86400
                )
            except Exception as e:
                logger.warning(f"Failed to track token family: {e}")
        else:
            # Local tracking
            if family_id not in self._token_families:
                self._token_families[family_id] = []
            self._token_families[family_id].append(jti)
    
    async def _check_token_reuse(self, jti: str) -> bool:
        """Check if refresh token has been reused"""
        if self.redis_client:
            try:
                used_key = f"jwt:used:{jti}"
                exists = await self.redis_client.exists(used_key)
                return bool(exists)
            except Exception:
                return False
        else:
            # Local check
            return jti in self._blacklist
    
    async def _mark_token_used(self, jti: str):
        """Mark refresh token as used"""
        if self.redis_client:
            try:
                used_key = f"jwt:used:{jti}"
                await self.redis_client.setex(
                    used_key,
                    self.config.refresh_token_expire_days * 86400,
                    "1"
                )
            except Exception as e:
                logger.warning(f"Failed to mark token as used: {e}")
        else:
            # Local tracking
            self._blacklist.add(jti)
    
    async def _revoke_token_family(self, family_id: str):
        """Revoke entire token family"""
        if not family_id:
            return
        
        if self.redis_client:
            try:
                family_key = f"jwt:family:{family_id}"
                members = await self.redis_client.smembers(family_key)
                
                for jti in members:
                    await self._blacklist_token(jti, int(time.time()) + 86400)
                
                await self.redis_client.delete(family_key)
                
            except Exception as e:
                logger.warning(f"Failed to revoke token family: {e}")
        else:
            # Local revocation
            if family_id in self._token_families:
                for jti in self._token_families[family_id]:
                    self._blacklist.add(jti)
                del self._token_families[family_id]
    
    async def _blacklist_token(self, jti: str, exp: int):
        """Add token to blacklist"""
        if self.redis_client:
            try:
                blacklist_key = f"jwt:blacklist:{jti}"
                ttl = max(exp - int(time.time()), 0)
                
                if ttl > 0:
                    await self.redis_client.setex(blacklist_key, ttl, "1")
                    
            except Exception as e:
                logger.warning(f"Failed to blacklist token: {e}")
        else:
            # Local blacklist
            self._blacklist.add(jti)
    
    async def _is_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted"""
        if self.redis_client and self.config.blacklist_check_redis:
            try:
                blacklist_key = f"jwt:blacklist:{jti}"
                exists = await self.redis_client.exists(blacklist_key)
                return bool(exists)
            except Exception:
                return False
        else:
            return jti in self._blacklist
    
    async def rotate_keys(self):
        """Rotate cryptographic keys"""
        if not self.config.enable_key_rotation:
            return
        
        logger.info("Rotating JWT keys")
        
        if self.config.algorithm in [Algorithm.HS256, Algorithm.HS384, Algorithm.HS512]:
            # Keep old key for grace period
            self.old_keys.append(self.current_key)
            
            # Limit old keys
            if len(self.old_keys) > 3:
                self.old_keys = self.old_keys[-3:]
            
            # Generate new key
            self.current_key = secrets.token_urlsafe(64)
            self.config.secret_key = self.current_key
            
        else:
            # Keep old public key
            self.old_public_keys.append(self.current_public_key)
            
            # Limit old keys
            if len(self.old_public_keys) > 3:
                self.old_public_keys = self.old_public_keys[-3:]
            
            # Generate new key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            self.current_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            
            self.current_public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.config.private_key = self.current_private_key
            self.config.public_key = self.current_public_key
        
        self.stats['key_rotations'] += 1
        
        # Store new keys in secure storage if available
        if self.redis_client:
            await self._store_keys()
    
    async def _store_keys(self):
        """Store keys in Redis (encrypted)"""
        try:
            from ..database.connections import db_manager
            import json
            from cryptography.fernet import Fernet
            import base64
            
            # Get encryption key from environment or generate one
            encryption_key = os.getenv('JWT_ENCRYPTION_KEY')
            if not encryption_key:
                # Generate a new key if none exists
                encryption_key = Fernet.generate_key().decode()
                logger.warning("Generated new JWT encryption key - store this securely!")
            
            # Ensure the key is properly formatted
            if isinstance(encryption_key, str):
                encryption_key = encryption_key.encode()
            
            # Pad or truncate key to 32 bytes for Fernet
            key_bytes = encryption_key[:32].ljust(32, b'0')
            fernet = Fernet(base64.urlsafe_b64encode(key_bytes))
            
            # Encrypt each key before storage
            encrypted_keys = {}
            for key_name, key_value in self.keys.items():
                encrypted_value = fernet.encrypt(key_value.encode())
                encrypted_keys[key_name] = encrypted_value.decode()
            
            # Store in Redis
            redis_client = await db_manager.get_redis_client()
            if redis_client:
                await redis_client.hset("jwt_keys", mapping=encrypted_keys)
                logger.info(f"Stored {len(encrypted_keys)} encrypted JWT keys in Redis")
            else:
                logger.warning("Redis not available, keys not persisted")
            
        except Exception as e:
            logger.error(f"Failed to store JWT keys: {e}")
            raise


# FastAPI dependencies
security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security),
    jwt_manager: JWTManager = Depends()
) -> TokenClaims:
    """FastAPI dependency to get current user from JWT"""
    token = credentials.credentials
    
    try:
        claims = await jwt_manager.validate_token(token, TokenType.ACCESS)
        return claims
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_permissions(*required_permissions: str):
    """Dependency to require specific permissions"""
    async def permission_checker(current_user: TokenClaims = Depends(get_current_user)):
        for permission in required_permissions:
            if permission not in current_user.permissions:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required permission: {permission}"
                )
        return current_user
    return permission_checker


def require_roles(*required_roles: str):
    """Dependency to require specific roles"""
    async def role_checker(current_user: TokenClaims = Depends(get_current_user)):
        for role in required_roles:
            if role not in current_user.roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Missing required role: {role}"
                )
        return current_user
    return role_checker