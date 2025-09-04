"""
Security utilities for encryption and authentication
Enhanced with credential encryption, key rotation, and secure storage
"""

from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os
import secrets
import base64
import json
import logging
from typing import Optional, Dict, Any, List

# Import result objects
from ..utils.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)

logger = logging.getLogger(__name__)

# Password hashing with stronger configuration
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # Increased rounds for better security
)

# Encryption configuration
class CredentialEncryption:
    """Enhanced encryption for sensitive credentials"""
    
    def __init__(self):
        # Primary encryption key
        self.primary_key = self._get_or_create_key("ENCRYPTION_KEY")
        
        # Rotation keys for key rotation support
        self.rotation_keys = self._get_rotation_keys()
        
        # Setup multi-fernet for key rotation
        all_keys = [Fernet(self.primary_key)] + [Fernet(k) for k in self.rotation_keys]
        self.cipher_suite = MultiFernet(all_keys)
        
        # Separate cipher for SNMP credentials with different key
        self.snmp_key = self._get_or_create_key("SNMP_ENCRYPTION_KEY")
        self.snmp_cipher = Fernet(self.snmp_key)
    
    def _get_or_create_key(self, env_var: str) -> bytes:
        """Get or create encryption key from environment"""
        key = os.getenv(env_var)
        if key:
            # Decode from base64 if stored as string
            try:
                return base64.urlsafe_b64decode(key)
            except Exception:
                # If not valid base64, derive key from string
                return self._derive_key(key)
        else:
            # Generate new key
            new_key = Fernet.generate_key()
            logger.warning(f"Generated new encryption key for {env_var}. "
                         f"Set {env_var}={base64.urlsafe_b64encode(new_key).decode()} in environment")
            return new_key
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'chm-salt-v1',  # Should be unique per deployment
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _get_rotation_keys(self) -> List[bytes]:
        """Get rotation keys for key rotation support"""
        rotation_keys = []
        for i in range(1, 4):  # Support up to 3 rotation keys
            key = os.getenv(f"ENCRYPTION_KEY_ROTATION_{i}")
            if key:
                try:
                    rotation_keys.append(base64.urlsafe_b64decode(key))
                except Exception:
                    rotation_keys.append(self._derive_key(key))
        return rotation_keys
    
    def encrypt_credential(self, credential: str, metadata: Optional[Dict] = None) -> str:
        """Encrypt credential with optional metadata"""
        try:
            # Create payload with credential and metadata
            payload = {
                "credential": credential,
                "encrypted_at": datetime.utcnow().isoformat(),
                "version": "1.0"
            }
            if metadata:
                payload["metadata"] = metadata
            
            # Encrypt payload
            encrypted = self.cipher_suite.encrypt(json.dumps(payload).encode())
            return base64.urlsafe_b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    def decrypt_credential(self, encrypted_credential: str) -> tuple:
        """Decrypt credential and return credential with metadata"""
        try:
            # Decode and decrypt
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_credential)
            decrypted = self.cipher_suite.decrypt(encrypted_bytes)
            
            # Parse payload
            payload = json.loads(decrypted.decode())
            credential = payload.get("credential")
            metadata = payload.get("metadata", {})
            
            return credential, metadata
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise
    
    def encrypt_snmp_credential(self, community: str, version: str = "2c") -> str:
        """Encrypt SNMP credentials specifically"""
        try:
            payload = {
                "community": community,
                "version": version,
                "encrypted_at": datetime.utcnow().isoformat()
            }
            encrypted = self.snmp_cipher.encrypt(json.dumps(payload).encode())
            return base64.urlsafe_b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"SNMP encryption error: {str(e)}")
            raise
    
    def decrypt_snmp_credential(self, encrypted: str) -> Dict[str, str]:
        """Decrypt SNMP credentials"""
        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted)
            decrypted = self.snmp_cipher.decrypt(encrypted_bytes)
            return json.loads(decrypted.decode())
            
        except Exception as e:
            logger.error(f"SNMP decryption error: {str(e)}")
            raise
    
    def rotate_encryption(self, encrypted_credential: str) -> str:
        """Re-encrypt credential with current primary key"""
        try:
            # Decrypt with old keys
            credential, metadata = self.decrypt_credential(encrypted_credential)
            
            # Re-encrypt with primary key only
            primary_cipher = Fernet(self.primary_key)
            payload = {
                "credential": credential,
                "encrypted_at": datetime.utcnow().isoformat(),
                "version": "1.0",
                "rotated": True
            }
            if metadata:
                payload["metadata"] = metadata
            
            encrypted = primary_cipher.encrypt(json.dumps(payload).encode())
            return base64.urlsafe_b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Key rotation error: {str(e)}")
            raise

# Initialize encryption handler
credential_encryption = CredentialEncryption()

# Legacy encryption functions for backward compatibility
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", Fernet.generate_key())
cipher_suite = Fernet(ENCRYPTION_KEY) if isinstance(ENCRYPTION_KEY, bytes) else Fernet(base64.urlsafe_b64decode(ENCRYPTION_KEY) if isinstance(ENCRYPTION_KEY, str) else Fernet.generate_key())

# JWT settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data"""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data"""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()

def hash_password(password: str) -> str:
    """Hash password for storage"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """Verify JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return create_success_result(
            data=payload,
            fallback_data=FallbackData(
                data={},
                health_status=HealthStatus(
                    level=HealthLevel.UNKNOWN,
                    message="Token verification failed, using empty payload",
                    details="JWT decode error occurred"
                )
            )
        )
    except JWTError:
        return create_failure_result(
            error_code="JWT_VERIFICATION_FAILED",
            message="Failed to verify JWT token",
            fallback_data=FallbackData(
                data={},
                health_status=HealthStatus(
                    level=HealthLevel.ERROR,
                    message="JWT verification failed",
                    details="Invalid or expired token"
                )
            ),
            suggestions=["Check token validity", "Ensure token is not expired", "Verify token format"]
        )

# Additional security utilities
class SecureCredentialStore:
    """Secure storage for device credentials"""
    
    @staticmethod
    async def store_device_credential(db, device_id: str, credential_type: str, credential: str):
        """Store encrypted device credential"""
        from backend.database.models import Device
        from sqlalchemy import select
        
        # Encrypt credential
        encrypted = credential_encryption.encrypt_credential(
            credential,
            metadata={"type": credential_type, "device_id": device_id}
        )
        
        # Store in database (you'll need to add credential fields to Device model)
        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        
        if device:
            if credential_type == "snmp_community":
                device.snmp_community_encrypted = encrypted
            elif credential_type == "ssh_password":
                device.ssh_password_encrypted = encrypted
            elif credential_type == "api_key":
                device.api_key_encrypted = encrypted
            
            await db.commit()
    
    @staticmethod
    async def get_device_credential(db, device_id: str, credential_type: str):
        """Retrieve and decrypt device credential"""
        from backend.database.models import Device
        from sqlalchemy import select
        
        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        
        if not device:
            return create_failure_result(
                error_code="DEVICE_NOT_FOUND",
                message=f"Device with ID {device_id} not found",
                fallback_data=FallbackData(
                    data="",
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Device not found, returning empty credential",
                        details=f"No device exists with ID {device_id}"
                    )
                ),
                suggestions=["Verify device ID", "Check device exists in database", "Ensure proper device registration"]
            )
        
        encrypted = None
        if credential_type == "snmp_community":
            encrypted = getattr(device, 'snmp_community_encrypted', None)
        elif credential_type == "ssh_password":
            encrypted = getattr(device, 'ssh_password_encrypted', None)
        elif credential_type == "api_key":
            encrypted = getattr(device, 'api_key_encrypted', None)
        
        if encrypted:
            try:
                credential, _ = credential_encryption.decrypt_credential(encrypted)
                return create_success_result(
                    data=credential,
                    fallback_data=FallbackData(
                        data=credential,
                        health_status=HealthStatus(
                            level=HealthLevel.HEALTHY,
                            message="Credential retrieved successfully",
                            details=f"Retrieved {credential_type} for device {device_id}"
                        )
                    )
                )
            except Exception as e:
                return create_failure_result(
                    error_code="CREDENTIAL_DECRYPTION_FAILED",
                    message=f"Failed to decrypt {credential_type} credential",
                    fallback_data=FallbackData(
                        data="",
                        health_status=HealthStatus(
                            level=HealthLevel.ERROR,
                            message="Credential decryption failed",
                            details=f"Error decrypting {credential_type}: {str(e)}"
                        )
                    ),
                    suggestions=["Check encryption keys", "Verify credential format", "Ensure proper key rotation"]
                )
        
        return create_partial_success_result(
            data="",
            error_code="NO_CREDENTIAL_FOUND",
            message=f"No {credential_type} credential found for device {device_id}",
            fallback_data=FallbackData(
                data="",
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No credential available",
                    details=f"Device {device_id} has no {credential_type} credential stored"
                )
            ),
            suggestions=["Store credential for device", "Check credential type", "Verify device configuration"]
        )

def generate_api_key() -> str:
    """Generate a secure API key"""
    return secrets.token_urlsafe(32)

def generate_device_token() -> str:
    """Generate a secure device authentication token"""
    return secrets.token_hex(32)

def hash_api_key(api_key: str) -> str:
    """Hash API key for storage"""
    return pwd_context.hash(api_key)

def verify_api_key(api_key: str, hashed_key: str) -> bool:
    """Verify API key against hash"""
    return pwd_context.verify(api_key, hashed_key)

def sanitize_log_data(data: Any) -> Any:
    """Sanitize sensitive data before logging"""
    if isinstance(data, dict):
        sanitized = {}
        sensitive_keys = [
            'password', 'token', 'secret', 'key', 'credential',
            'community', 'api_key', 'private_key', 'certificate'
        ]
        
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = '***REDACTED***'
            elif isinstance(value, (dict, list)):
                sanitized[key] = sanitize_log_data(value)
            else:
                sanitized[key] = value
        return sanitized
    elif isinstance(data, list):
        return [sanitize_log_data(item) for item in data]
    else:
        return data
