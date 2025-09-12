"""
SSH security management for secure device access
"""

import asyncio
import os
import logging
from pathlib import Path
import tempfile
import stat
from typing import Dict, Any, Optional, List, Tuple, Union
from datetime import datetime, timedelta
import hashlib
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

try:
    import paramiko
    from paramiko import SSHClient, AutoAddPolicy, RSAKey, DSSKey, ECDSAKey, Ed25519Key
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    paramiko = None
    SSHClient = None

from backend.config import settings
from backend.common.exceptions import CHMException
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)


class SSHSecurityException(CHMException):
    """SSH security related exceptions"""
    def __init__(self, message: str, error_code: str = "SSH_SECURITY_ERROR"):
        super().__init__(message=message, error_code=error_code)


class SSHKeyManager:
    """Secure SSH key management with encryption and rotation"""
    
    def __init__(self, key_storage_path: Optional[str] = None):
        self.key_storage_path = Path(key_storage_path or getattr(settings, 'ssh_key_path', '/tmp/chm_ssh_keys'))
        self.key_storage_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        
        # Encryption key for storing private keys
        self._master_key = None
        self._key_cache = {}
        self._key_cache_expiry = {}
        self.cache_ttl = 300  # 5 minutes
        
        # Key rotation settings
        self.key_rotation_days = 90
        self.key_backup_count = 3
        
        logger.info(f"SSH key manager initialized with storage path: {self.key_storage_path}")
    
    def _get_master_key(self) -> bytes:
        """Get or create master encryption key"""
        if self._master_key:
            return self._master_key
        
        master_key_file = self.key_storage_path / '.master_key'
        
        if master_key_file.exists():
            # Load existing master key
            try:
                with open(master_key_file, 'rb') as f:
                    self._master_key = f.read()
                logger.debug("Loaded existing master key")
            except Exception as e:
                raise SSHSecurityException(f"Failed to load master key: {e}")
        else:
            # Generate new master key
            self._master_key = secrets.token_bytes(32)  # 256-bit key
            
            try:
                with open(master_key_file, 'wb') as f:
                    f.write(self._master_key)
                os.chmod(master_key_file, 0o600)  # Owner read/write only
                logger.info("Generated new master key")
            except Exception as e:
                raise SSHSecurityException(f"Failed to save master key: {e}")
        
        return self._master_key
    
    def _encrypt_data(self, data: bytes, password: Optional[str] = None) -> bytes:
        """Encrypt data using master key or password"""
        if password:
            # Use password-based encryption
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        else:
            # Use master key
            key = self._get_master_key()
            salt = b''
        
        # Generate random IV
        iv = secrets.token_bytes(16)
        
        # Encrypt with AES-256-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padded_data = data + bytes([padding_length]) * padding_length
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return: salt + iv + encrypted_data
        return salt + iv + encrypted_data
    
    def _decrypt_data(self, encrypted_data: bytes, password: Optional[str] = None) -> bytes:
        """Decrypt data using master key or password"""
        if password:
            # Extract salt (first 16 bytes)
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
        else:
            # Use master key (no salt)
            key = self._get_master_key()
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
        
        # Decrypt with AES-256-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    async def generate_key_pair(
        self,
        key_name: str,
        key_type: str = 'rsa',
        key_size: int = 2048,
        passphrase: Optional[str] = None
    ) -> Dict[str, str]:
        """Generate a new SSH key pair"""
        if not PARAMIKO_AVAILABLE:
            raise SSHSecurityException("Paramiko not available for key generation")
        
        try:
            # Generate key based on type
            if key_type.lower() == 'rsa':
                private_key = RSAKey.generate(key_size)
            elif key_type.lower() == 'dss':
                private_key = DSSKey.generate(1024)  # DSS keys are typically 1024 bits
            elif key_type.lower() == 'ecdsa':
                private_key = ECDSAKey.generate()
            elif key_type.lower() == 'ed25519':
                private_key = Ed25519Key.generate()
            else:
                raise SSHSecurityException(f"Unsupported key type: {key_type}")
            
            # Get private key in OpenSSH format
            private_key_str = private_key.get_base64()
            
            # Get public key in OpenSSH format
            public_key = f"{private_key.get_name()} {private_key.get_base64()}"
            
            # Store the key pair securely
            await self._store_key_pair(
                key_name, private_key_str, public_key, passphrase
            )
            
            logger.info(f"Generated {key_type} key pair: {key_name}")
            
            return {
                'key_name': key_name,
                'key_type': key_type,
                'public_key': public_key,
                'fingerprint': self._get_key_fingerprint(private_key),
                'created_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to generate key pair {key_name}: {e}")
            raise SSHSecurityException(f"Key generation failed: {e}")
    
    async def _store_key_pair(
        self,
        key_name: str,
        private_key: str,
        public_key: str,
        passphrase: Optional[str] = None
    ):
        """Store key pair securely"""
        key_dir = self.key_storage_path / key_name
        key_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Store private key (encrypted)
        private_key_path = key_dir / 'private_key'
        encrypted_private_key = self._encrypt_data(
            private_key.encode(), passphrase
        )
        
        with open(private_key_path, 'wb') as f:
            f.write(encrypted_private_key)
        os.chmod(private_key_path, 0o600)
        
        # Store public key (not encrypted)
        public_key_path = key_dir / 'public_key'
        with open(public_key_path, 'w') as f:
            f.write(public_key)
        os.chmod(public_key_path, 0o644)
        
        # Store metadata
        metadata = {
            'key_name': key_name,
            'created_at': datetime.now().isoformat(),
            'encrypted': passphrase is not None,
            'last_used': None
        }
        
        metadata_path = key_dir / 'metadata.json'
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        os.chmod(metadata_path, 0o600)
    
    async def load_private_key(
        self,
        key_name: str,
        passphrase: Optional[str] = None
    ):
        """Load and decrypt a private key"""
        # Check cache first
        cache_key = f"{key_name}:{passphrase or 'no_pass'}"
        if (cache_key in self._key_cache and 
            cache_key in self._key_cache_expiry and
            datetime.now() < self._key_cache_expiry[cache_key]):
            return create_success_result(
                fallback_data=FallbackData(
                    data=self._key_cache[cache_key],
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Private key loaded from cache",
                        details=f"Private key {key_name} retrieved from cache",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
        
        try:
            private_key_path = self.key_storage_path / key_name / 'private_key'
            
            if not private_key_path.exists():
                logger.warning(f"Private key not found: {key_name}")
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.CRITICAL,
                            message="Private key not found",
                            details=f"Private key file does not exist: {key_name}",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="PRIVATE_KEY_NOT_FOUND",
                    error_message=f"Private key not found: {key_name}",
                    details=f"Private key file does not exist: {key_name}",
                    suggestions=["Verify the key name exists", "Check key storage path", "Generate new key pair if needed"]
                )
            
            # Load encrypted private key
            with open(private_key_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt private key
            private_key_bytes = self._decrypt_data(encrypted_data, passphrase)
            private_key_str = private_key_bytes.decode()
            
            # Cache the key
            self._key_cache[cache_key] = private_key_str
            self._key_cache_expiry[cache_key] = datetime.now() + timedelta(seconds=self.cache_ttl)
            
            # Update last used timestamp
            await self._update_key_metadata(key_name, {'last_used': datetime.now().isoformat()})
            
            return create_success_result(
                fallback_data=FallbackData(
                    data=private_key_str,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Private key loaded successfully",
                        details=f"Private key {key_name} loaded and decrypted",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
            
        except Exception as e:
            logger.error(f"Failed to load private key {key_name}: {e}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="Failed to load private key",
                        details=f"Error loading private key {key_name}: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="PRIVATE_KEY_LOAD_FAILED",
                error_message=f"Failed to load private key {key_name}",
                details=f"Error loading private key: {e}",
                suggestions=["Check file permissions", "Verify encryption key", "Check passphrase if used"]
            )
    
    async def load_public_key(self, key_name: str):
        """Load a public key"""
        try:
            public_key_path = self.key_storage_path / key_name / 'public_key'
            
            if not public_key_path.exists():
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.CRITICAL,
                            message="Public key not found",
                            details=f"Public key file does not exist: {key_name}",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="PUBLIC_KEY_NOT_FOUND",
                    error_message=f"Public key not found: {key_name}",
                    details=f"Public key file does not exist: {key_name}",
                    suggestions=["Verify the key name exists", "Check key storage path", "Generate new key pair if needed"]
                )
            
            with open(public_key_path, 'r') as f:
                public_key = f.read().strip()
                
            return create_success_result(
                fallback_data=FallbackData(
                    data=public_key,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Public key loaded successfully",
                        details=f"Public key {key_name} loaded",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
                
        except Exception as e:
            logger.error(f"Failed to load public key {key_name}: {e}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="Failed to load public key",
                        details=f"Error loading public key {key_name}: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="PUBLIC_KEY_LOAD_FAILED",
                error_message=f"Failed to load public key {key_name}",
                details=f"Error loading public key: {e}",
                suggestions=["Check file permissions", "Verify file integrity", "Check file encoding"]
            )
    
    async def list_keys(self) -> List[Dict[str, Any]]:
        """List all stored SSH keys"""
        keys = []
        
        for key_dir in self.key_storage_path.iterdir():
            if key_dir.is_dir() and (key_dir / 'metadata.json').exists():
                try:
                    with open(key_dir / 'metadata.json', 'r') as f:
                        metadata = json.load(f)
                    
                    # Add key size and type info if available
                    public_key_result = await self.load_public_key(key_dir.name)
                    if public_key_result.success and public_key_result.fallback_data.data:
                        public_key = public_key_result.fallback_data.data
                        parts = public_key.split()
                        if len(parts) >= 2:
                            metadata['key_type'] = parts[0]
                            metadata['public_key_preview'] = parts[1][:20] + '...'
                    
                    keys.append(metadata)
                    
                except Exception as e:
                    logger.warning(f"Failed to load metadata for key {key_dir.name}: {e}")
        
        return sorted(keys, key=lambda x: x.get('created_at', ''))
    
    async def delete_key(self, key_name: str) -> bool:
        """Delete an SSH key pair"""
        try:
            key_dir = self.key_storage_path / key_name
            
            if not key_dir.exists():
                logger.warning(f"Key {key_name} not found")
                return False
            
            # Remove from cache
            keys_to_remove = [k for k in self._key_cache.keys() if k.startswith(f"{key_name}:")]
            for k in keys_to_remove:
                del self._key_cache[k]
                self._key_cache_expiry.pop(k, None)
            
            # Securely delete files
            for file_path in key_dir.rglob('*'):
                if file_path.is_file():
                    # Overwrite file with random data before deletion
                    file_size = file_path.stat().st_size
                    with open(file_path, 'wb') as f:
                        f.write(secrets.token_bytes(file_size))
                    file_path.unlink()
            
            key_dir.rmdir()
            logger.info(f"Deleted SSH key: {key_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete key {key_name}: {e}")
            return False
    
    async def rotate_key(
        self,
        key_name: str,
        key_type: str = 'rsa',
        key_size: int = 2048,
        passphrase: Optional[str] = None
    ) -> Dict[str, Any]:
        """Rotate an existing SSH key"""
        try:
            # Backup old key if it exists
            if (self.key_storage_path / key_name).exists():
                backup_name = f"{key_name}_backup_{int(datetime.now().timestamp())}"
                backup_dir = self.key_storage_path / backup_name
                (self.key_storage_path / key_name).rename(backup_dir)
                logger.info(f"Backed up old key {key_name} to {backup_name}")
                
                # Clean up old backups
                await self._cleanup_old_backups(key_name)
            
            # Generate new key
            result = await self.generate_key_pair(key_name, key_type, key_size, passphrase)
            result['rotated'] = True
            result['rotated_at'] = datetime.now().isoformat()
            
            logger.info(f"Rotated SSH key: {key_name}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to rotate key {key_name}: {e}")
            raise SSHSecurityException(f"Key rotation failed: {e}")
    
    async def _cleanup_old_backups(self, key_name: str):
        """Clean up old backup keys"""
        backup_dirs = []
        
        for path in self.key_storage_path.iterdir():
            if path.is_dir() and path.name.startswith(f"{key_name}_backup_"):
                try:
                    timestamp = int(path.name.split('_')[-1])
                    backup_dirs.append((timestamp, path))
                except ValueError:
                    continue
        
        # Sort by timestamp and keep only the most recent backups
        backup_dirs.sort(reverse=True)
        
        if len(backup_dirs) > self.key_backup_count:
            for _, old_backup in backup_dirs[self.key_backup_count:]:
                try:
                    # Securely delete old backup
                    for file_path in old_backup.rglob('*'):
                        if file_path.is_file():
                            file_size = file_path.stat().st_size
                            with open(file_path, 'wb') as f:
                                f.write(secrets.token_bytes(file_size))
                            file_path.unlink()
                    old_backup.rmdir()
                    logger.debug(f"Cleaned up old backup: {old_backup.name}")
                except Exception as e:
                    logger.warning(f"Failed to clean up backup {old_backup}: {e}")
    
    def _get_key_fingerprint(self, key) -> str:
        """Get SSH key fingerprint"""
        try:
            if hasattr(key, 'get_fingerprint'):
                return key.get_fingerprint().hex()
            else:
                # Fallback fingerprint calculation
                key_data = base64.b64decode(key.get_base64())
                return hashlib.md5(key_data).hexdigest()
        except Exception as e:
            logger.warning(f"Failed to get key fingerprint: {e}")
            return "unknown"
    
    async def _update_key_metadata(self, key_name: str, updates: Dict[str, Any]):
        """Update key metadata"""
        try:
            metadata_path = self.key_storage_path / key_name / 'metadata.json'
            
            if metadata_path.exists():
                with open(metadata_path, 'r') as f:
                    metadata = json.load(f)
                
                metadata.update(updates)
                
                with open(metadata_path, 'w') as f:
                    json.dump(metadata, f, indent=2)
                
        except Exception as e:
            logger.warning(f"Failed to update metadata for {key_name}: {e}")
    
    async def export_public_key(self, key_name: str, format_type: str = 'openssh'):
        """Export public key in specified format"""
        public_key_result = await self.load_public_key(key_name)
        
        if not public_key_result.success:
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="Failed to export public key",
                        details=f"Cannot export public key {key_name}: key not found",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="PUBLIC_KEY_EXPORT_FAILED",
                error_message=f"Failed to export public key {key_name}",
                details="Public key not found for export",
                suggestions=["Verify the key name exists", "Check key storage path", "Generate new key pair if needed"]
            )
        
        public_key = public_key_result.fallback_data.data
        
        if format_type.lower() == 'openssh':
            return create_success_result(
                fallback_data=FallbackData(
                    data=public_key,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Public key exported successfully",
                        details=f"Public key {key_name} exported in OpenSSH format",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
        elif format_type.lower() == 'authorized_keys':
            # Add any restrictions or options if needed
            return create_success_result(
                fallback_data=FallbackData(
                    data=public_key,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Public key exported successfully",
                        details=f"Public key {key_name} exported in authorized_keys format",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
        elif format_type.lower() == 'ssh2':
            # Convert to SSH2 format (RFC 4716)
            parts = public_key.split()
            if len(parts) >= 2:
                key_data = parts[1]
                ssh2_format = f"---- BEGIN SSH2 PUBLIC KEY ----\n{key_data}\n---- END SSH2 PUBLIC KEY ----"
                return create_success_result(
                    fallback_data=FallbackData(
                        data=ssh2_format,
                        health_status=HealthStatus(
                            level=HealthLevel.HEALTHY,
                            message="Public key exported successfully",
                            details=f"Public key {key_name} exported in SSH2 format",
                            timestamp=datetime.now().isoformat()
                        )
                    )
                )
        
        return create_failure_result(
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Unsupported export format",
                    details=f"Format {format_type} is not supported for public key export",
                    timestamp=datetime.now().isoformat()
                )
            ),
            error_code="UNSUPPORTED_EXPORT_FORMAT",
            error_message=f"Unsupported export format: {format_type}",
            details=f"Format {format_type} is not supported for public key export",
            suggestions=["Use 'openssh', 'authorized_keys', or 'ssh2' format"]
        )
    
    async def check_key_rotation_needed(self) -> List[Dict[str, Any]]:
        """Check which keys need rotation"""
        keys_needing_rotation = []
        keys = await self.list_keys()
        
        cutoff_date = datetime.now() - timedelta(days=self.key_rotation_days)
        
        for key_info in keys:
            try:
                created_at = datetime.fromisoformat(key_info['created_at'])
                if created_at < cutoff_date:
                    days_old = (datetime.now() - created_at).days
                    key_info['days_old'] = days_old
                    key_info['rotation_overdue'] = True
                    keys_needing_rotation.append(key_info)
            except Exception as e:
                logger.warning(f"Could not parse creation date for key {key_info.get('key_name')}: {e}")
        
        return keys_needing_rotation
    
    def clear_key_cache(self):
        """Clear the key cache"""
        self._key_cache.clear()
        self._key_cache_expiry.clear()
        logger.debug("SSH key cache cleared")


class SSHHostKeyManager:
    """Manage SSH host keys for secure connections"""
    
    def __init__(self, host_keys_path: Optional[str] = None):
        self.host_keys_path = Path(host_keys_path or getattr(settings, 'ssh_host_keys_path', '/tmp/chm_host_keys'))
        self.host_keys_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.known_hosts_file = self.host_keys_path / 'known_hosts'
        self.host_key_cache = {}
    
    async def add_host_key(self, hostname: str, port: int, key_type: str, key_data: str) -> bool:
        """Add a host key to known_hosts"""
        try:
            host_entry = f"[{hostname}]:{port} {key_type} {key_data}\n"
            
            # Check if host key already exists
            if await self._host_key_exists(hostname, port, key_type):
                logger.debug(f"Host key already exists for {hostname}:{port} ({key_type})")
                return True
            
            # Append to known_hosts file
            with open(self.known_hosts_file, 'a') as f:
                f.write(host_entry)
            
            # Set secure permissions
            os.chmod(self.known_hosts_file, 0o600)
            
            # Clear cache for this host
            cache_key = f"{hostname}:{port}"
            if cache_key in self.host_key_cache:
                del self.host_key_cache[cache_key]
            
            logger.info(f"Added host key for {hostname}:{port} ({key_type})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add host key for {hostname}:{port}: {e}")
            return False
    
    async def _host_key_exists(self, hostname: str, port: int, key_type: str) -> bool:
        """Check if a host key already exists"""
        try:
            if not self.known_hosts_file.exists():
                return False
            
            host_pattern = f"[{hostname}]:{port} {key_type}"
            
            with open(self.known_hosts_file, 'r') as f:
                for line in f:
                    if line.strip().startswith(host_pattern):
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking host key existence: {e}")
            return False
    
    async def verify_host_key(self, hostname: str, port: int, presented_key: str) -> bool:
        """Verify a presented host key against known_hosts"""
        try:
            if not self.known_hosts_file.exists():
                logger.warning(f"No known_hosts file found for verification of {hostname}:{port}")
                return False
            
            host_pattern = f"[{hostname}]:{port}"
            
            with open(self.known_hosts_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(host_pattern):
                        # Extract the key data
                        parts = line.split()
                        if len(parts) >= 3:
                            stored_key = parts[2]
                            if stored_key == presented_key:
                                return True
            
            logger.warning(f"Host key verification failed for {hostname}:{port}")
            return False
            
        except Exception as e:
            logger.error(f"Error verifying host key for {hostname}:{port}: {e}")
            return False
    
    async def remove_host_key(self, hostname: str, port: int) -> bool:
        """Remove a host key from known_hosts"""
        try:
            if not self.known_hosts_file.exists():
                return True
            
            host_pattern = f"[{hostname}]:{port}"
            updated_lines = []
            removed_count = 0
            
            with open(self.known_hosts_file, 'r') as f:
                for line in f:
                    if not line.strip().startswith(host_pattern):
                        updated_lines.append(line)
                    else:
                        removed_count += 1
            
            # Write back the updated file
            with open(self.known_hosts_file, 'w') as f:
                f.writelines(updated_lines)
            
            # Clear cache
            cache_key = f"{hostname}:{port}"
            if cache_key in self.host_key_cache:
                del self.host_key_cache[cache_key]
            
            logger.info(f"Removed {removed_count} host key(s) for {hostname}:{port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove host key for {hostname}:{port}: {e}")
            return False
    
    async def get_host_keys(self, hostname: str, port: int) -> List[Dict[str, str]]:
        """Get all host keys for a specific host"""
        try:
            cache_key = f"{hostname}:{port}"
            if cache_key in self.host_key_cache:
                return self.host_key_cache[cache_key]
            
            if not self.known_hosts_file.exists():
                return []
            
            host_pattern = f"[{hostname}]:{port}"
            host_keys = []
            
            with open(self.known_hosts_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith(host_pattern):
                        parts = line.split()
                        if len(parts) >= 3:
                            host_keys.append({
                                'key_type': parts[1],
                                'key_data': parts[2],
                                'fingerprint': self._get_key_fingerprint(parts[2])
                            })
            
            # Cache the results
            self.host_key_cache[cache_key] = host_keys
            return host_keys
            
        except Exception as e:
            logger.error(f"Failed to get host keys for {hostname}:{port}: {e}")
            return []
    
    def _get_key_fingerprint(self, key_data: str) -> str:
        """Calculate SSH key fingerprint"""
        try:
            key_bytes = base64.b64decode(key_data)
            return hashlib.md5(key_bytes).hexdigest()
        except Exception as e:
            logger.warning(f"Failed to calculate key fingerprint: {e}")
            return "unknown"


class SecureSSHConnection:
    """Secure SSH connection wrapper with key management"""
    
    def __init__(self, key_manager: SSHKeyManager, host_key_manager: SSHHostKeyManager):
        self.key_manager = key_manager
        self.host_key_manager = host_key_manager
    
    async def create_secure_connection(
        self,
        hostname: str,
        port: int = 22,
        username: str = None,
        key_name: str = None,
        passphrase: str = None,
        verify_host_key: bool = True,
        timeout: int = 30
    ):
        """Create a secure SSH connection"""
        if not PARAMIKO_AVAILABLE:
            raise SSHSecurityException("Paramiko not available for SSH connections")
        
        try:
            client = SSHClient()
            
            # Configure host key policy
            if verify_host_key:
                client.load_host_keys(str(self.host_key_manager.known_hosts_file))
                client.set_missing_host_key_policy(paramiko.RejectPolicy())
            else:
                client.set_missing_host_key_policy(AutoAddPolicy())
            
            # Load private key if specified
            private_key = None
            if key_name:
                private_key_result = await self.key_manager.load_private_key(key_name, passphrase)
                if not private_key_result.success:
                    raise SSHSecurityException(f"Failed to load private key: {key_name}")
                
                private_key_str = private_key_result.fallback_data.data
                
                # Create temporary key file
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
                    f.write(private_key_str)
                    temp_key_path = f.name
                
                try:
                    os.chmod(temp_key_path, 0o600)
                    
                    # Load the key
                    try:
                        private_key = RSAKey.from_private_key_file(temp_key_path, password=passphrase)
                    except Exception as e:

                        logger.debug(f"Exception: {e}")
                        try:
                            private_key = DSSKey.from_private_key_file(temp_key_path, password=passphrase)
                        except Exception as e:

                            logger.debug(f"Exception: {e}")
                            try:
                                private_key = ECDSAKey.from_private_key_file(temp_key_path, password=passphrase)
                            except Exception as e:

                                logger.debug(f"Exception: {e}")
                                private_key = Ed25519Key.from_private_key_file(temp_key_path, password=passphrase)
                                
                finally:
                    # Securely delete temporary key file
                    if os.path.exists(temp_key_path):
                        with open(temp_key_path, 'wb') as f:
                            f.write(secrets.token_bytes(os.path.getsize(temp_key_path)))
                        os.unlink(temp_key_path)
            
            # Connect
            client.connect(
                hostname=hostname,
                port=port,
                username=username,
                pkey=private_key,
                timeout=timeout,
                look_for_keys=False,  # Don't use default key locations
                allow_agent=False     # Don't use SSH agent
            )
            
            logger.info(f"Established secure SSH connection to {hostname}:{port}")
            return create_success_result(
                fallback_data=FallbackData(
                    data=client,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="SSH connection established successfully",
                        details=f"Secure SSH connection to {hostname}:{port} established",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
            
        except Exception as e:
            logger.error(f"Failed to create secure SSH connection to {hostname}:{port}: {e}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.CRITICAL,
                        message="SSH connection failed",
                        details=f"Failed to establish SSH connection to {hostname}:{port}: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="SSH_CONNECTION_FAILED",
                error_message=f"Failed to create SSH connection to {hostname}:{port}",
                details=f"SSH connection error: {e}",
                suggestions=["Check network connectivity", "Verify credentials", "Check firewall settings", "Verify host key"]
            )


# Global instances
ssh_key_manager = SSHKeyManager()
ssh_host_key_manager = SSHHostKeyManager()
secure_ssh_connection = SecureSSHConnection(ssh_key_manager, ssh_host_key_manager)


async def initialize_ssh_security():
    """Initialize SSH security subsystem"""
    logger.info("SSH security subsystem initialized")


async def cleanup_ssh_security():
    """Cleanup SSH security subsystem"""
    ssh_key_manager.clear_key_cache()
    logger.info("SSH security subsystem cleaned up")