"""
Production-grade encryption at rest system.
Implements field-level encryption, key management, and secure data handling.
"""

import os
import base64
import json
import hashlib
import hmac
import secrets
import struct
from typing import Any, Dict, List, Optional, Union, Tuple, Type
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
from functools import lru_cache
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.fernet import Fernet, MultiFernet
from cryptography.x509 import load_pem_x509_certificate

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

try:
    import hvac  # HashiCorp Vault client
    VAULT_AVAILABLE = True
except ImportError:
    hvac = None
    VAULT_AVAILABLE = False

from sqlalchemy import TypeDecorator, String, Text, LargeBinary
from sqlalchemy.ext.hybrid import hybrid_property

from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""
    AES_256_GCM = "aes-256-gcm"
    AES_256_CBC = "aes-256-cbc"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    FERNET = "fernet"
    RSA_OAEP = "rsa-oaep"


class KeyDerivationFunction(Enum):
    """Key derivation functions"""
    PBKDF2 = "pbkdf2"
    SCRYPT = "scrypt"
    ARGON2 = "argon2"


@dataclass
class EncryptionConfig:
    """Encryption configuration"""
    # Algorithm settings
    algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM
    key_derivation: KeyDerivationFunction = KeyDerivationFunction.SCRYPT
    
    # Key management
    master_key: Optional[bytes] = None
    key_rotation_interval_days: int = 90
    key_version: int = 1
    
    # Security settings
    use_hardware_security_module: bool = False
    use_key_encryption_key: bool = True
    enable_field_level_encryption: bool = True
    
    # Performance
    cache_derived_keys: bool = True
    cache_size: int = 1000
    
    # Audit
    audit_encryption_operations: bool = True
    log_key_usage: bool = False  # Be careful with this
    
    # Vault integration
    use_vault: bool = False
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    vault_mount_point: str = "secret"
    vault_key_name: str = "encryption-key"
    
    # Compliance
    enable_data_residency: bool = False
    data_classification_levels: List[str] = field(default_factory=lambda: ["public", "internal", "confidential", "restricted"])


@dataclass
class EncryptedData:
    """Container for encrypted data with metadata"""
    ciphertext: bytes
    nonce: Optional[bytes] = None
    tag: Optional[bytes] = None
    salt: Optional[bytes] = None
    key_version: int = 1
    algorithm: str = "aes-256-gcm"
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes for storage"""
        # Format: version(1) | algorithm(1) | key_version(2) | timestamp(8) | 
        #         nonce_len(2) | nonce | tag_len(2) | tag | salt_len(2) | salt | 
        #         metadata_len(4) | metadata | ciphertext
        
        algorithm_byte = {
            "aes-256-gcm": 1,
            "aes-256-cbc": 2,
            "chacha20-poly1305": 3,
            "fernet": 4,
            "rsa-oaep": 5
        }.get(self.algorithm, 0)
        
        parts = [
            struct.pack('B', 1),  # Format version
            struct.pack('B', algorithm_byte),
            struct.pack('H', self.key_version),
            struct.pack('d', self.timestamp)
        ]
        
        # Add nonce
        if self.nonce:
            parts.extend([
                struct.pack('H', len(self.nonce)),
                self.nonce
            ])
        else:
            parts.append(struct.pack('H', 0))
        
        # Add tag
        if self.tag:
            parts.extend([
                struct.pack('H', len(self.tag)),
                self.tag
            ])
        else:
            parts.append(struct.pack('H', 0))
        
        # Add salt
        if self.salt:
            parts.extend([
                struct.pack('H', len(self.salt)),
                self.salt
            ])
        else:
            parts.append(struct.pack('H', 0))
        
        # Add metadata
        metadata_bytes = json.dumps(self.metadata).encode() if self.metadata else b''
        parts.extend([
            struct.pack('I', len(metadata_bytes)),
            metadata_bytes
        ])
        
        # Add ciphertext
        parts.append(self.ciphertext)
        
        return b''.join(parts)
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'EncryptedData':
        """Deserialize from bytes"""
        offset = 0
        
        # Read version
        version = struct.unpack('B', data[offset:offset+1])[0]
        offset += 1
        
        if version != 1:
            raise ValueError(f"Unsupported format version: {version}")
        
        # Read algorithm
        algorithm_byte = struct.unpack('B', data[offset:offset+1])[0]
        offset += 1
        
        algorithm_map = {
            1: "aes-256-gcm",
            2: "aes-256-cbc",
            3: "chacha20-poly1305",
            4: "fernet",
            5: "rsa-oaep"
        }
        algorithm = algorithm_map.get(algorithm_byte, "unknown")
        
        # Read key version
        key_version = struct.unpack('H', data[offset:offset+2])[0]
        offset += 2
        
        # Read timestamp
        timestamp = struct.unpack('d', data[offset:offset+8])[0]
        offset += 8
        
        # Read nonce
        nonce_len = struct.unpack('H', data[offset:offset+2])[0]
        offset += 2
        nonce = data[offset:offset+nonce_len] if nonce_len > 0 else None
        offset += nonce_len
        
        # Read tag
        tag_len = struct.unpack('H', data[offset:offset+2])[0]
        offset += 2
        tag = data[offset:offset+tag_len] if tag_len > 0 else None
        offset += tag_len
        
        # Read salt
        salt_len = struct.unpack('H', data[offset:offset+2])[0]
        offset += 2
        salt = data[offset:offset+salt_len] if salt_len > 0 else None
        offset += salt_len
        
        # Read metadata
        metadata_len = struct.unpack('I', data[offset:offset+4])[0]
        offset += 4
        metadata = json.loads(data[offset:offset+metadata_len].decode()) if metadata_len > 0 else {}
        offset += metadata_len
        
        # Read ciphertext
        ciphertext = data[offset:]
        
        return cls(
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            salt=salt,
            key_version=key_version,
            algorithm=algorithm,
            timestamp=timestamp,
            metadata=metadata
        )


class EncryptionManager:
    """Main encryption management system"""
    
    def __init__(self,
                 config: EncryptionConfig,
                 redis_client: Optional[redis.Redis] = None):
        self.config = config
        self.redis_client = redis_client
        
        # Initialize keys
        self._init_keys()
        
        # Key cache
        self._key_cache: Dict[str, Tuple[bytes, float]] = {}
        self._cache_lock = threading.Lock()
        
        # Vault client
        self._vault_client = None
        if self.config.use_vault and VAULT_AVAILABLE:
            self._init_vault()
        
        # Statistics
        self.stats = {
            'encryptions': 0,
            'decryptions': 0,
            'key_derivations': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'errors': 0
        }
    
    def _init_keys(self):
        """Initialize encryption keys"""
        if not self.config.master_key:
            # Generate master key
            if self.config.algorithm == EncryptionAlgorithm.FERNET:
                self.config.master_key = Fernet.generate_key()
            else:
                self.config.master_key = secrets.token_bytes(32)
            
            logger.warning("Generated new master encryption key")
        
        # Initialize key encryption key if enabled
        if self.config.use_key_encryption_key:
            self._kek = self._derive_kek()
    
    def _init_vault(self):
        """Initialize HashiCorp Vault client"""
        try:
            self._vault_client = hvac.Client(
                url=self.config.vault_url,
                token=self.config.vault_token
            )
            
            if not self._vault_client.is_authenticated():
                logger.error("Vault authentication failed")
                self._vault_client = None
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            self._vault_client = None
    
    def _derive_kek(self) -> bytes:
        """Derive key encryption key"""
        # Use machine-specific data for KEK derivation
        machine_id = hashlib.sha256(
            f"{os.environ.get('COMPUTERNAME', '')}{os.environ.get('USERNAME', '')}".encode()
        ).digest()
        
        kdf = Scrypt(
            salt=machine_id,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=default_backend()
        )
        
        return kdf.derive(self.config.master_key)
    
    def encrypt(self,
                plaintext: Union[str, bytes],
                classification: str = "internal",
                context: Optional[Dict[str, Any]] = None) -> EncryptedData:
        """Encrypt data"""
        self.stats['encryptions'] += 1
        
        try:
            # Convert string to bytes
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Get encryption key
            key = self._get_encryption_key(classification, context)
            
            # Encrypt based on algorithm
            if self.config.algorithm == EncryptionAlgorithm.AES_256_GCM:
                encrypted = self._encrypt_aes_gcm(plaintext, key)
            elif self.config.algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
                encrypted = self._encrypt_chacha20(plaintext, key)
            elif self.config.algorithm == EncryptionAlgorithm.FERNET:
                encrypted = self._encrypt_fernet(plaintext, key)
            else:
                encrypted = self._encrypt_aes_cbc(plaintext, key)
            
            # Add metadata
            encrypted.metadata = {
                'classification': classification,
                'encrypted_at': datetime.now().isoformat()
            }
            
            if context:
                encrypted.metadata['context'] = context
            
            # Audit if enabled
            if self.config.audit_encryption_operations:
                self._audit_operation('encrypt', classification, len(plaintext))
            
            return encrypted
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Encryption failed: {e}")
            raise
    
    def decrypt(self,
                encrypted_data: Union[EncryptedData, bytes],
                context: Optional[Dict[str, Any]] = None) -> bytes:
        """Decrypt data"""
        self.stats['decryptions'] += 1
        
        try:
            # Parse encrypted data if bytes
            if isinstance(encrypted_data, bytes):
                encrypted_data = EncryptedData.from_bytes(encrypted_data)
            
            # Get decryption key
            classification = encrypted_data.metadata.get('classification', 'internal')
            key = self._get_decryption_key(
                classification,
                encrypted_data.key_version,
                context
            )
            
            # Decrypt based on algorithm
            if encrypted_data.algorithm == "aes-256-gcm":
                plaintext = self._decrypt_aes_gcm(encrypted_data, key)
            elif encrypted_data.algorithm == "chacha20-poly1305":
                plaintext = self._decrypt_chacha20(encrypted_data, key)
            elif encrypted_data.algorithm == "fernet":
                plaintext = self._decrypt_fernet(encrypted_data, key)
            else:
                plaintext = self._decrypt_aes_cbc(encrypted_data, key)
            
            # Audit if enabled
            if self.config.audit_encryption_operations:
                self._audit_operation('decrypt', classification, len(plaintext))
            
            return plaintext
            
        except Exception as e:
            self.stats['errors'] += 1
            logger.error(f"Decryption failed: {e}")
            raise
    
    def _encrypt_aes_gcm(self, plaintext: bytes, key: bytes) -> EncryptedData:
        """Encrypt using AES-256-GCM"""
        # Generate nonce
        nonce = os.urandom(12)
        
        # Create cipher
        aesgcm = AESGCM(key)
        
        # Encrypt
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        return EncryptedData(
            ciphertext=ciphertext,
            nonce=nonce,
            algorithm="aes-256-gcm",
            key_version=self.config.key_version
        )
    
    def _decrypt_aes_gcm(self, encrypted_data: EncryptedData, key: bytes) -> bytes:
        """Decrypt using AES-256-GCM"""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(encrypted_data.nonce, encrypted_data.ciphertext, None)
    
    def _encrypt_chacha20(self, plaintext: bytes, key: bytes) -> EncryptedData:
        """Encrypt using ChaCha20-Poly1305"""
        # Generate nonce
        nonce = os.urandom(12)
        
        # Create cipher
        chacha = ChaCha20Poly1305(key)
        
        # Encrypt
        ciphertext = chacha.encrypt(nonce, plaintext, None)
        
        return EncryptedData(
            ciphertext=ciphertext,
            nonce=nonce,
            algorithm="chacha20-poly1305",
            key_version=self.config.key_version
        )
    
    def _decrypt_chacha20(self, encrypted_data: EncryptedData, key: bytes) -> bytes:
        """Decrypt using ChaCha20-Poly1305"""
        chacha = ChaCha20Poly1305(key)
        return chacha.decrypt(encrypted_data.nonce, encrypted_data.ciphertext, None)
    
    def _encrypt_fernet(self, plaintext: bytes, key: bytes) -> EncryptedData:
        """Encrypt using Fernet"""
        # Ensure key is proper format
        if len(key) != 32:
            key = base64.urlsafe_b64encode(key[:32].ljust(32, b'\0'))
        else:
            key = base64.urlsafe_b64encode(key)
        
        f = Fernet(key)
        ciphertext = f.encrypt(plaintext)
        
        return EncryptedData(
            ciphertext=ciphertext,
            algorithm="fernet",
            key_version=self.config.key_version
        )
    
    def _decrypt_fernet(self, encrypted_data: EncryptedData, key: bytes) -> bytes:
        """Decrypt using Fernet"""
        if len(key) != 32:
            key = base64.urlsafe_b64encode(key[:32].ljust(32, b'\0'))
        else:
            key = base64.urlsafe_b64encode(key)
        
        f = Fernet(key)
        return f.decrypt(encrypted_data.ciphertext)
    
    def _encrypt_aes_cbc(self, plaintext: bytes, key: bytes) -> EncryptedData:
        """Encrypt using AES-256-CBC"""
        # Generate IV
        iv = os.urandom(16)
        
        # Pad plaintext
        padder = padding.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return EncryptedData(
            ciphertext=ciphertext,
            nonce=iv,
            algorithm="aes-256-cbc",
            key_version=self.config.key_version
        )
    
    def _decrypt_aes_cbc(self, encrypted_data: EncryptedData, key: bytes) -> bytes:
        """Decrypt using AES-256-CBC"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(encrypted_data.nonce),
            backend=default_backend()
        )
        
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(encrypted_data.ciphertext) + decryptor.finalize()
        
        # Remove padding
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    def _get_encryption_key(self,
                           classification: str,
                           context: Optional[Dict[str, Any]] = None) -> bytes:
        """Get or derive encryption key"""
        # Check cache
        cache_key = f"{classification}:{self.config.key_version}"
        
        with self._cache_lock:
            if cache_key in self._key_cache:
                key, timestamp = self._key_cache[cache_key]
                if time.time() - timestamp < 3600:  # 1 hour cache
                    self.stats['cache_hits'] += 1
                    return key
        
        self.stats['cache_misses'] += 1
        
        # Derive key
        key = self._derive_key(classification, self.config.key_version, context)
        
        # Update cache
        with self._cache_lock:
            self._key_cache[cache_key] = (key, time.time())
            
            # Limit cache size
            if len(self._key_cache) > self.config.cache_size:
                # Remove oldest entries
                sorted_items = sorted(self._key_cache.items(), key=lambda x: x[1][1])
                for k, _ in sorted_items[:len(self._key_cache) - self.config.cache_size]:
                    del self._key_cache[k]
        
        return key
    
    def _get_decryption_key(self,
                           classification: str,
                           key_version: int,
                           context: Optional[Dict[str, Any]] = None) -> bytes:
        """Get decryption key for specific version"""
        # Similar to encryption key but with version support
        cache_key = f"{classification}:{key_version}"
        
        with self._cache_lock:
            if cache_key in self._key_cache:
                key, timestamp = self._key_cache[cache_key]
                if time.time() - timestamp < 3600:
                    self.stats['cache_hits'] += 1
                    return key
        
        self.stats['cache_misses'] += 1
        
        # Get key from vault or derive
        if self._vault_client:
            key = self._get_key_from_vault(classification, key_version)
        else:
            key = self._derive_key(classification, key_version, context)
        
        # Update cache
        with self._cache_lock:
            self._key_cache[cache_key] = (key, time.time())
        
        return key
    
    def _derive_key(self,
                   classification: str,
                   key_version: int,
                   context: Optional[Dict[str, Any]] = None) -> bytes:
        """Derive encryption key"""
        self.stats['key_derivations'] += 1
        
        # Create salt from classification and version
        salt = hashlib.sha256(f"{classification}:{key_version}".encode()).digest()
        
        # Add context to salt if provided
        if context:
            context_bytes = json.dumps(context, sort_keys=True).encode()
            salt = hashlib.sha256(salt + context_bytes).digest()
        
        # Derive key based on KDF
        if self.config.key_derivation == KeyDerivationFunction.SCRYPT:
            kdf = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
                backend=default_backend()
            )
        else:  # PBKDF2
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
        
        # Use KEK if enabled
        base_key = self._kek if self.config.use_key_encryption_key else self.config.master_key
        
        return kdf.derive(base_key)
    
    def _get_key_from_vault(self,
                          classification: str,
                          key_version: int) -> bytes:
        """Get encryption key from Vault"""
        if not self._vault_client:
            raise RuntimeError("Vault client not initialized")
        
        try:
            # Read key from Vault
            path = f"{self.config.vault_mount_point}/{self.config.vault_key_name}/{classification}/v{key_version}"
            response = self._vault_client.read(path)
            
            if response and 'data' in response:
                key_data = response['data'].get('key')
                if key_data:
                    return base64.b64decode(key_data)
            
            # Key not found, generate and store
            key = secrets.token_bytes(32)
            
            self._vault_client.write(
                path,
                key=base64.b64encode(key).decode(),
                classification=classification,
                version=key_version,
                created_at=datetime.now().isoformat()
            )
            
            return key
            
        except Exception as e:
            logger.error(f"Failed to get key from Vault: {e}")
            # Fall back to local derivation
            return self._derive_key(classification, key_version, None)
    
    def _audit_operation(self,
                        operation: str,
                        classification: str,
                        data_size: int):
        """Audit encryption operation"""
        audit_entry = {
            'timestamp': datetime.now().isoformat(),
            'operation': operation,
            'classification': classification,
            'data_size': data_size,
            'key_version': self.config.key_version,
            'algorithm': self.config.algorithm.value
        }
        
        # Log audit entry (in production, send to audit system)
        logger.info(f"Encryption audit: {json.dumps(audit_entry)}")
    
    async def rotate_keys(self):
        """Rotate encryption keys"""
        logger.info("Starting key rotation")
        
        # Increment key version
        self.config.key_version += 1
        
        # Generate new master key
        if self.config.algorithm == EncryptionAlgorithm.FERNET:
            new_key = Fernet.generate_key()
        else:
            new_key = secrets.token_bytes(32)
        
        # Store old key for decryption
        if self._vault_client:
            # Store in Vault
            path = f"{self.config.vault_mount_point}/archived-keys/v{self.config.key_version - 1}"
            self._vault_client.write(
                path,
                key=base64.b64encode(self.config.master_key).decode(),
                archived_at=datetime.now().isoformat()
            )
        
        # Update master key
        self.config.master_key = new_key
        
        # Update KEK if enabled
        if self.config.use_key_encryption_key:
            self._kek = self._derive_kek()
        
        # Clear key cache
        with self._cache_lock:
            self._key_cache.clear()
        
        logger.info(f"Key rotation completed. New version: {self.config.key_version}")


class EncryptedType(TypeDecorator):
    """SQLAlchemy type for encrypted fields"""
    
    impl = Text
    cache_ok = True
    
    def __init__(self, encryption_manager: EncryptionManager, classification: str = "internal"):
        self.encryption_manager = encryption_manager
        self.classification = classification
        super().__init__()
    
    def process_bind_param(self, value, dialect):
        """Encrypt before storing in database"""
        if value is None:
            raise ProcessingError(f"Failed to process in {func_name}")
        
        encrypted = self.encryption_manager.encrypt(value, self.classification)
        return base64.b64encode(encrypted.to_bytes()).decode('utf-8')
    
    def process_result_value(self, value, dialect):
        """Decrypt after loading from database"""
        if value is None:
            raise ProcessingError(f"Failed to process in {func_name}")
        
        encrypted_bytes = base64.b64decode(value)
        encrypted_data = EncryptedData.from_bytes(encrypted_bytes)
        decrypted = self.encryption_manager.decrypt(encrypted_data)
        
        return decrypted.decode('utf-8')


def create_encrypted_field(encryption_manager: EncryptionManager,
                          classification: str = "internal"):
    """Factory function to create encrypted database fields"""
    return EncryptedType(encryption_manager, classification)