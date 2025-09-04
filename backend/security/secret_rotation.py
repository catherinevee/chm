"""
Comprehensive secret rotation mechanism with automated key management,
version tracking, and secure distribution across services.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, Union

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import redis.asyncio as redis
    from redis.asyncio import Redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import hvac  # HashiCorp Vault client
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False


from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Types of secrets that can be rotated."""
    API_KEY = "api_key"
    DATABASE_PASSWORD = "database_password"
    JWT_SIGNING_KEY = "jwt_signing_key"
    ENCRYPTION_KEY = "encryption_key"
    TLS_CERTIFICATE = "tls_certificate"
    SERVICE_TOKEN = "service_token"
    OAUTH_CLIENT_SECRET = "oauth_client_secret"
    WEBHOOK_SECRET = "webhook_secret"


class RotationStrategy(Enum):
    """Rotation strategies."""
    TIME_BASED = "time_based"
    USAGE_BASED = "usage_based"
    EVENT_BASED = "event_based"
    MANUAL = "manual"


class SecretStatus(Enum):
    """Secret lifecycle status."""
    ACTIVE = "active"
    PENDING = "pending"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class SecretVersion:
    """Represents a version of a secret."""
    version_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    secret_id: str = ""
    secret_type: SecretType = SecretType.API_KEY
    value: str = ""
    status: SecretStatus = SecretStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    activated_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    usage_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'version_id': self.version_id,
            'secret_id': self.secret_id,
            'secret_type': self.secret_type.value,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'activated_at': self.activated_at.isoformat() if self.activated_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'usage_count': self.usage_count,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecretVersion':
        return cls(
            version_id=data['version_id'],
            secret_id=data['secret_id'],
            secret_type=SecretType(data['secret_type']),
            value=data.get('value', ''),
            status=SecretStatus(data['status']),
            created_at=datetime.fromisoformat(data['created_at']),
            activated_at=datetime.fromisoformat(data['activated_at']) if data.get('activated_at') else None,
            expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
            usage_count=data.get('usage_count', 0),
            metadata=data.get('metadata', {})
        )


@dataclass
class RotationPolicy:
    """Defines rotation policy for a secret."""
    secret_id: str
    secret_type: SecretType
    strategy: RotationStrategy
    rotation_interval: timedelta = field(default=timedelta(days=90))
    max_usage_count: Optional[int] = None
    grace_period: timedelta = field(default=timedelta(hours=24))
    auto_activate: bool = True
    notification_channels: List[str] = field(default_factory=list)
    custom_generator: Optional[Callable[[], str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'secret_id': self.secret_id,
            'secret_type': self.secret_type.value,
            'strategy': self.strategy.value,
            'rotation_interval_seconds': self.rotation_interval.total_seconds(),
            'max_usage_count': self.max_usage_count,
            'grace_period_seconds': self.grace_period.total_seconds(),
            'auto_activate': self.auto_activate,
            'notification_channels': self.notification_channels
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RotationPolicy':
        return cls(
            secret_id=data['secret_id'],
            secret_type=SecretType(data['secret_type']),
            strategy=RotationStrategy(data['strategy']),
            rotation_interval=timedelta(seconds=data.get('rotation_interval_seconds', 7776000)),  # 90 days
            max_usage_count=data.get('max_usage_count'),
            grace_period=timedelta(seconds=data.get('grace_period_seconds', 86400)),  # 24 hours
            auto_activate=data.get('auto_activate', True),
            notification_channels=data.get('notification_channels', [])
        )


class SecretGenerator:
    """Generates secrets based on type and requirements."""
    
    @staticmethod
    def generate_api_key(length: int = 32) -> str:
        """Generate a random API key."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_password(
        length: int = 16,
        include_symbols: bool = True,
        exclude_ambiguous: bool = True
    ) -> str:
        """Generate a secure password."""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        
        if include_symbols:
            chars += "!@#$%^&*"
        
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('O', '').replace('l', '').replace('1', '')
        
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_jwt_key() -> Dict[str, str]:
        """Generate RSA key pair for JWT signing."""
        if not CRYPTO_AVAILABLE:
            # Fallback to symmetric key
            key = Fernet.generate_key()
            return {
                'algorithm': 'HS256',
                'key': key.decode()
            }
        
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            'algorithm': 'RS256',
            'private_key': private_pem.decode(),
            'public_key': public_pem.decode()
        }
    
    @staticmethod
    def generate_encryption_key(algorithm: str = 'AES-256') -> str:
        """Generate encryption key."""
        if algorithm == 'AES-256':
            return base64.b64encode(secrets.token_bytes(32)).decode()
        elif algorithm == 'AES-128':
            return base64.b64encode(secrets.token_bytes(16)).decode()
        elif algorithm == 'Fernet':
            return Fernet.generate_key().decode()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def generate_webhook_secret(length: int = 32) -> str:
        """Generate webhook secret."""
        return secrets.token_hex(length)


class SecretStorage:
    """Abstract storage interface for secrets."""
    
    async def store_secret(self, version: SecretVersion) -> bool:
        """Store a secret version."""
        raise NotImplementedError
    
    async def get_secret(self, secret_id: str, version_id: Optional[str] = None) -> Optional[SecretVersion]:
        """Retrieve a secret version."""
        raise NotImplementedError
    
    async def list_versions(self, secret_id: str) -> List[SecretVersion]:
        """List all versions of a secret."""
        raise NotImplementedError
    
    async def update_secret_status(self, secret_id: str, version_id: str, status: SecretStatus) -> bool:
        """Update secret status."""
        raise NotImplementedError
    
    async def delete_secret(self, secret_id: str, version_id: str) -> bool:
        """Delete a secret version."""
        raise NotImplementedError


class RedisSecretStorage(SecretStorage):
    """Redis-based secret storage."""
    
    def __init__(self, redis_client: 'Redis', key_prefix: str = "secrets"):
        if not REDIS_AVAILABLE:
            raise ImportError("Redis is required for RedisSecretStorage")
        
        self.redis_client = redis_client
        self.key_prefix = key_prefix
    
    def _get_key(self, secret_id: str, version_id: Optional[str] = None) -> str:
        """Get Redis key for secret."""
        if version_id:
            return f"{self.key_prefix}:{secret_id}:{version_id}"
        else:
            return f"{self.key_prefix}:{secret_id}:*"
    
    async def store_secret(self, version: SecretVersion) -> bool:
        """Store secret in Redis."""
        key = self._get_key(version.secret_id, version.version_id)
        data = json.dumps(version.to_dict())
        
        # Store the secret data
        await self.redis_client.set(key, data)
        
        # Add to secret versions set
        versions_key = f"{self.key_prefix}:versions:{version.secret_id}"
        await self.redis_client.sadd(versions_key, version.version_id)
        
        # Set expiration if specified
        if version.expires_at:
            expire_seconds = int((version.expires_at - datetime.now(timezone.utc)).total_seconds())
            if expire_seconds > 0:
                await self.redis_client.expire(key, expire_seconds)
        
        return True
    
    async def get_secret(self, secret_id: str, version_id: Optional[str] = None) -> Optional[SecretVersion]:
        """Get secret from Redis."""
        if version_id:
            key = self._get_key(secret_id, version_id)
            data = await self.redis_client.get(key)
            
            if data:
                if isinstance(data, bytes):
                    data = data.decode()
                secret_data = json.loads(data)
                return SecretVersion.from_dict(secret_data)
        else:
            # Get active version
            versions = await self.list_versions(secret_id)
            active_versions = [v for v in versions if v.status == SecretStatus.ACTIVE]
            
            if active_versions:
                # Return the most recent active version
                return max(active_versions, key=lambda x: x.created_at)
        
        return create_failure_result(
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="No active secret version found",
                    details=f"No active version found for secret {secret_id}",
                    timestamp=datetime.now(timezone.utc).isoformat()
                )
            ),
            error_code="NO_ACTIVE_SECRET_VERSION",
            error_message=f"No active version found for secret {secret_id}",
            details=f"No active version found for secret {secret_id}",
            suggestions=["Check if secret exists", "Verify secret status", "Activate a secret version"]
        )
    
    async def list_versions(self, secret_id: str) -> List[SecretVersion]:
        """List all versions from Redis."""
        versions_key = f"{self.key_prefix}:versions:{secret_id}"
        version_ids = await self.redis_client.smembers(versions_key)
        
        versions = []
        for version_id in version_ids:
            if isinstance(version_id, bytes):
                version_id = version_id.decode()
            
            version = await self.get_secret(secret_id, version_id)
            if version:
                versions.append(version)
        
        return sorted(versions, key=lambda x: x.created_at, reverse=True)
    
    async def update_secret_status(self, secret_id: str, version_id: str, status: SecretStatus) -> bool:
        """Update secret status in Redis."""
        version = await self.get_secret(secret_id, version_id)
        if not version:
            return False
        
        version.status = status
        return await self.store_secret(version)
    
    async def delete_secret(self, secret_id: str, version_id: str) -> bool:
        """Delete secret from Redis."""
        key = self._get_key(secret_id, version_id)
        versions_key = f"{self.key_prefix}:versions:{secret_id}"
        
        # Remove from versions set
        await self.redis_client.srem(versions_key, version_id)
        
        # Delete the secret data
        deleted = await self.redis_client.delete(key)
        return deleted > 0


class VaultSecretStorage(SecretStorage):
    """HashiCorp Vault secret storage."""
    
    def __init__(
        self,
        vault_url: str,
        vault_token: str,
        mount_point: str = "secret",
        version: str = "v2"
    ):
        if not VAULT_AVAILABLE:
            raise ImportError("hvac is required for VaultSecretStorage")
        
        self.client = hvac.Client(url=vault_url, token=vault_token)
        self.mount_point = mount_point
        self.version = version
    
    async def store_secret(self, version: SecretVersion) -> bool:
        """Store secret in Vault."""
        try:
            path = f"{version.secret_id}/{version.version_id}"
            
            secret_data = version.to_dict()
            secret_data['value'] = version.value  # Include the actual secret value
            
            if self.version == "v2":
                response = self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret={'data': secret_data},
                    mount_point=self.mount_point
                )
            else:
                response = self.client.secrets.kv.v1.create_or_update_secret(
                    path=path,
                    secret=secret_data,
                    mount_point=self.mount_point
                )
            
            return response.get('data') is not None
        except Exception as e:
            logger.error(f"Failed to store secret in Vault: {e}")
            return False
    
    async def get_secret(self, secret_id: str, version_id: Optional[str] = None) -> Optional[SecretVersion]:
        """Get secret from Vault."""
        try:
            if version_id:
                path = f"{secret_id}/{version_id}"
            else:
                # Get latest version
                path = secret_id
            
            if self.version == "v2":
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    mount_point=self.mount_point
                )
                secret_data = response['data']['data']
            else:
                response = self.client.secrets.kv.v1.read_secret(
                    path=path,
                    mount_point=self.mount_point
                )
                secret_data = response['data']
            
            return SecretVersion.from_dict(secret_data)
        except Exception as e:
            logger.error(f"Failed to get secret from Vault: {e}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="Failed to get secret from Vault",
                        details=f"Error retrieving secret from Vault: {e}",
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
                ),
                error_code="VAULT_SECRET_RETRIEVAL_FAILED",
                error_message=f"Failed to get secret from Vault",
                details=f"Error retrieving secret from Vault: {e}",
                suggestions=["Check Vault connectivity", "Verify authentication token", "Check secret path", "Review Vault logs"]
            )
    
    async def list_versions(self, secret_id: str) -> List[SecretVersion]:
        """List versions from Vault."""
        try:
            # In Vault KV v2, we can list metadata
            if self.version == "v2":
                response = self.client.secrets.kv.v2.read_secret_metadata(
                    path=secret_id,
                    mount_point=self.mount_point
                )
                versions_data = response.get('data', {}).get('versions', {})
                
                versions = []
                for version_num, version_info in versions_data.items():
                    if not version_info.get('destroyed', False):
                        version = await self.get_secret(secret_id, version_num)
                        if version:
                            versions.append(version)
                
                return versions
            else:
                # For KV v1, we need a different approach
                # This is a simplified implementation
                version = await self.get_secret(secret_id)
                return [version] if version else []
        except Exception as e:
            logger.error(f"Failed to list versions from Vault: {e}")
            return []
    
    async def update_secret_status(self, secret_id: str, version_id: str, status: SecretStatus) -> bool:
        """Update secret status in Vault."""
        version = await self.get_secret(secret_id, version_id)
        if not version:
            return False
        
        version.status = status
        return await self.store_secret(version)
    
    async def delete_secret(self, secret_id: str, version_id: str) -> bool:
        """Delete secret from Vault."""
        try:
            path = f"{secret_id}/{version_id}"
            
            if self.version == "v2":
                response = self.client.secrets.kv.v2.delete_secret_versions(
                    path=secret_id,
                    versions=[version_id],
                    mount_point=self.mount_point
                )
            else:
                response = self.client.secrets.kv.v1.delete_secret(
                    path=path,
                    mount_point=self.mount_point
                )
            
            return True
        except Exception as e:
            logger.error(f"Failed to delete secret from Vault: {e}")
            return False


class RotationScheduler:
    """Schedules and manages secret rotations."""
    
    def __init__(
        self,
        storage: SecretStorage,
        notification_handler: Optional[Callable] = None
    ):
        self.storage = storage
        self.notification_handler = notification_handler
        self._policies: Dict[str, RotationPolicy] = {}
        self._scheduler_task: Optional[asyncio.Task] = None
        self._shutdown = False
    
    def add_policy(self, policy: RotationPolicy):
        """Add a rotation policy."""
        self._policies[policy.secret_id] = policy
        logger.info(f"Added rotation policy for {policy.secret_id}")
    
    def remove_policy(self, secret_id: str):
        """Remove a rotation policy."""
        if secret_id in self._policies:
            del self._policies[secret_id]
            logger.info(f"Removed rotation policy for {secret_id}")
    
    async def start(self):
        """Start the rotation scheduler."""
        if self._scheduler_task:
            return
        
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Started rotation scheduler")
    
    async def stop(self):
        """Stop the rotation scheduler."""
        self._shutdown = True
        
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped rotation scheduler")
    
    async def _scheduler_loop(self):
        """Main scheduler loop."""
        while not self._shutdown:
            try:
                await self._check_rotations()
                await asyncio.sleep(3600)  # Check hourly
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
                await asyncio.sleep(300)  # Retry after 5 minutes
    
    async def _check_rotations(self):
        """Check if any secrets need rotation."""
        for secret_id, policy in self._policies.items():
            try:
                if await self._needs_rotation(secret_id, policy):
                    await self.rotate_secret(secret_id)
            except Exception as e:
                logger.error(f"Error checking rotation for {secret_id}: {e}")
    
    async def _needs_rotation(self, secret_id: str, policy: RotationPolicy) -> bool:
        """Check if a secret needs rotation."""
        versions = await self.storage.list_versions(secret_id)
        active_versions = [v for v in versions if v.status == SecretStatus.ACTIVE]
        
        if not active_versions:
            return True  # No active version exists
        
        latest_version = max(active_versions, key=lambda x: x.created_at)
        
        # Time-based rotation
        if policy.strategy == RotationStrategy.TIME_BASED:
            time_since_creation = datetime.now(timezone.utc) - latest_version.created_at
            return time_since_creation >= policy.rotation_interval
        
        # Usage-based rotation
        elif policy.strategy == RotationStrategy.USAGE_BASED:
            if policy.max_usage_count and latest_version.usage_count >= policy.max_usage_count:
                return True
        
        # Check expiration
        if latest_version.expires_at and latest_version.expires_at <= datetime.now(timezone.utc):
            return True
        
        return False
    
    async def rotate_secret(self, secret_id: str) -> Optional[SecretVersion]:
        """Rotate a secret."""
        policy = self._policies.get(secret_id)
        if not policy:
            logger.error(f"No policy found for secret {secret_id}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="No rotation policy found",
                        details=f"No rotation policy found for secret {secret_id}",
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
                ),
                error_code="NO_ROTATION_POLICY",
                error_message=f"No rotation policy found for secret {secret_id}",
                details=f"No rotation policy found for secret {secret_id}",
                suggestions=["Create a rotation policy", "Check policy configuration", "Verify secret ID"]
            )
        
        logger.info(f"Starting rotation for secret {secret_id}")
        
        try:
            # Generate new secret
            new_value = await self._generate_secret_value(policy)
            
            # Create new version
            new_version = SecretVersion(
                secret_id=secret_id,
                secret_type=policy.secret_type,
                value=new_value,
                status=SecretStatus.PENDING,
                expires_at=datetime.now(timezone.utc) + policy.rotation_interval
            )
            
            # Store new version
            if not await self.storage.store_secret(new_version):
                logger.error(f"Failed to store new version for {secret_id}")
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.CRITICAL,
                            message="Failed to store new secret version",
                            details=f"Failed to store new version for secret {secret_id}",
                            timestamp=datetime.now(timezone.utc).isoformat()
                        )
                    ),
                    error_code="SECRET_STORAGE_FAILED",
                    error_message=f"Failed to store new version for secret {secret_id}",
                    details=f"Failed to store new version for secret {secret_id}",
                    suggestions=["Check storage connectivity", "Verify storage permissions", "Check storage configuration", "Review storage logs"]
                )
            
            # Activate new version if auto-activation is enabled
            if policy.auto_activate:
                await self._activate_version(secret_id, new_version.version_id)
            
            # Send notifications
            if self.notification_handler and policy.notification_channels:
                await self.notification_handler(
                    secret_id, new_version, policy.notification_channels
                )
            
            logger.info(f"Successfully rotated secret {secret_id}")
            return new_version
        
        except Exception as e:
            logger.error(f"Failed to rotate secret {secret_id}: {e}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="Secret rotation failed",
                        details=f"Failed to rotate secret {secret_id}: {e}",
                        timestamp=datetime.now(timezone.utc).isoformat()
                    )
                ),
                error_code="SECRET_ROTATION_FAILED",
                error_message=f"Failed to rotate secret {secret_id}",
                details=f"Secret rotation failed: {e}",
                suggestions=["Check rotation policy", "Verify storage access", "Check notification settings", "Review error logs"]
            )
    
    async def _generate_secret_value(self, policy: RotationPolicy) -> str:
        """Generate new secret value based on type."""
        if policy.custom_generator:
            return policy.custom_generator()
        
        generator = SecretGenerator()
        
        if policy.secret_type == SecretType.API_KEY:
            return generator.generate_api_key()
        elif policy.secret_type == SecretType.DATABASE_PASSWORD:
            return generator.generate_password(length=24, include_symbols=True)
        elif policy.secret_type == SecretType.JWT_SIGNING_KEY:
            key_data = generator.generate_jwt_key()
            return json.dumps(key_data)
        elif policy.secret_type == SecretType.ENCRYPTION_KEY:
            return generator.generate_encryption_key()
        elif policy.secret_type == SecretType.SERVICE_TOKEN:
            return generator.generate_api_key(length=48)
        elif policy.secret_type == SecretType.WEBHOOK_SECRET:
            return generator.generate_webhook_secret()
        else:
            return generator.generate_api_key()
    
    async def _activate_version(self, secret_id: str, version_id: str):
        """Activate a secret version."""
        # Get current active versions
        versions = await self.storage.list_versions(secret_id)
        active_versions = [v for v in versions if v.status == SecretStatus.ACTIVE]
        
        # Deprecate old active versions
        for version in active_versions:
            await self.storage.update_secret_status(
                secret_id, version.version_id, SecretStatus.DEPRECATED
            )
        
        # Activate new version
        await self.storage.update_secret_status(
            secret_id, version_id, SecretStatus.ACTIVE
        )
        
        # Schedule graceful transition
        policy = self._policies.get(secret_id)
        if policy and policy.grace_period:
            asyncio.create_task(
                self._schedule_old_version_cleanup(secret_id, active_versions, policy.grace_period)
            )
    
    async def _schedule_old_version_cleanup(
        self,
        secret_id: str,
        old_versions: List[SecretVersion],
        grace_period: timedelta
    ):
        """Schedule cleanup of old versions after grace period."""
        await asyncio.sleep(grace_period.total_seconds())
        
        for version in old_versions:
            if version.status == SecretStatus.DEPRECATED:
                await self.storage.update_secret_status(
                    secret_id, version.version_id, SecretStatus.REVOKED
                )
                
                logger.info(
                    f"Revoked old version {version.version_id} of secret {secret_id} "
                    f"after grace period"
                )


class SecretRotationManager:
    """Main secret rotation manager."""
    
    def __init__(
        self,
        storage: SecretStorage,
        scheduler: Optional[RotationScheduler] = None
    ):
        self.storage = storage
        self.scheduler = scheduler or RotationScheduler(storage)
        self._started = False
    
    async def start(self):
        """Start the rotation manager."""
        if self._started:
            return
        
        await self.scheduler.start()
        self._started = True
        logger.info("Started secret rotation manager")
    
    async def stop(self):
        """Stop the rotation manager."""
        if not self._started:
            return
        
        await self.scheduler.stop()
        self._started = False
        logger.info("Stopped secret rotation manager")
    
    def create_rotation_policy(
        self,
        secret_id: str,
        secret_type: SecretType,
        strategy: RotationStrategy = RotationStrategy.TIME_BASED,
        rotation_interval: timedelta = timedelta(days=90),
        **kwargs
    ) -> RotationPolicy:
        """Create a rotation policy."""
        policy = RotationPolicy(
            secret_id=secret_id,
            secret_type=secret_type,
            strategy=strategy,
            rotation_interval=rotation_interval,
            **kwargs
        )
        
        self.scheduler.add_policy(policy)
        return policy
    
    async def get_secret(
        self,
        secret_id: str,
        version_id: Optional[str] = None
    ) -> Optional[SecretVersion]:
        """Get a secret version."""
        version = await self.storage.get_secret(secret_id, version_id)
        
        # Update usage count for active secrets
        if version and version.status == SecretStatus.ACTIVE:
            version.usage_count += 1
            await self.storage.store_secret(version)
        
        return version
    
    async def manual_rotation(self, secret_id: str) -> Optional[SecretVersion]:
        """Manually trigger rotation."""
        return await self.scheduler.rotate_secret(secret_id)
    
    async def get_rotation_status(self, secret_id: str) -> Dict[str, Any]:
        """Get rotation status for a secret."""
        versions = await self.storage.list_versions(secret_id)
        policy = self.scheduler._policies.get(secret_id)
        
        active_versions = [v for v in versions if v.status == SecretStatus.ACTIVE]
        latest_active = max(active_versions, key=lambda x: x.created_at) if active_versions else None
        
        status = {
            'secret_id': secret_id,
            'total_versions': len(versions),
            'active_versions': len(active_versions),
            'latest_version': latest_active.to_dict() if latest_active else None,
            'policy': policy.to_dict() if policy else None
        }
        
        if latest_active and policy:
            time_since_creation = datetime.now(timezone.utc) - latest_active.created_at
            status['time_since_creation'] = time_since_creation.total_seconds()
            status['next_rotation'] = (
                latest_active.created_at + policy.rotation_interval
            ).isoformat()
            status['needs_rotation'] = await self.scheduler._needs_rotation(secret_id, policy)
        
        return status