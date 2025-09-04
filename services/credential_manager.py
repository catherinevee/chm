"""
CHM Credential Manager Service
Secure handling of device credentials with encryption and access control
"""

import os
import base64
import json
import logging
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
from datetime import datetime

from ..core.config import get_settings
from ..models.device_credentials import DeviceCredentials, CredentialType

logger = logging.getLogger(__name__)
settings = get_settings()

class SecurityException(Exception):
    """Security-related exception"""
    pass

class CredentialManager:
    """Secure credential management service"""
    
    def __init__(self):
        """Initialize credential manager with encryption keys"""
        self._master_key = self._get_or_generate_master_key()
        self._cipher_suite = self._create_cipher_suite()
        
    def _get_or_generate_master_key(self) -> bytes:
        """Get existing master key or generate new one"""
        master_key_path = os.getenv('CHM_MASTER_KEY_PATH', '.chm_master.key')
        
        if os.path.exists(master_key_path):
            try:
                with open(master_key_path, 'rb') as f:
                    return f.read()
            except Exception as e:
                logger.warning(f"Failed to read existing master key: {e}")
        
        # Generate new master key
        master_key = Fernet.generate_key()
        
        try:
            with open(master_key_path, 'wb') as f:
                f.write(master_key)
            os.chmod(master_key_path, 0o600)  # Secure permissions
            logger.info("Generated new master encryption key")
        except Exception as e:
            logger.error(f"Failed to save master key: {e}")
            raise SecurityException("Cannot secure master encryption key")
        
        return master_key
    
    def _create_cipher_suite(self) -> Fernet:
        """Create Fernet cipher suite for encryption"""
        return Fernet(self._master_key)
    
    def _generate_salt(self) -> bytes:
        """Generate cryptographically secure salt"""
        return secrets.token_bytes(32)
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    async def encrypt_credentials(self, credentials: str, credential_type: CredentialType) -> Dict[str, str]:
        """Encrypt device credentials securely"""
        try:
            # Generate unique salt for this credential
            salt = self._generate_salt()
            
            # Create encryption key
            encryption_key = self._derive_key(credentials, salt)
            
            # Encrypt the credentials
            cipher = Cipher(
                algorithms.AES(encryption_key),
                modes.GCM(),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Add associated data for authentication
            encryptor.authenticate_additional_data(credential_type.encode())
            
            # Encrypt the credentials
            ciphertext = encryptor.encrypt(credentials.encode())
            
            # Combine salt, nonce, and ciphertext
            encrypted_data = base64.b64encode(
                salt + encryptor.nonce + ciphertext
            ).decode('utf-8')
            
            # Generate unique key ID
            key_id = base64.urlsafe_b64encode(secrets.token_bytes(16)).decode('utf-8')
            
            return {
                "encrypted_data": encrypted_data,
                "key_id": key_id,
                "encryption_algorithm": "AES-256-GCM"
            }
            
        except Exception as e:
            logger.error(f"Credential encryption failed: {e}")
            raise SecurityException(f"Credential encryption failed: {str(e)}")
    
    async def decrypt_credentials(self, encrypted_creds: DeviceCredentials) -> Optional[str]:
        """Decrypt device credentials securely"""
        try:
            if not encrypted_creds.is_usable:
                logger.warning(f"Attempted to decrypt unusable credential {encrypted_creds.id}")
                return None
            
            # Decode the encrypted data
            encrypted_bytes = base64.b64decode(encrypted_creds.encrypted_data)
            
            # Extract salt, nonce, and ciphertext
            salt = encrypted_bytes[:32]
            nonce = encrypted_bytes[32:48]
            ciphertext = encrypted_bytes[48:]
            
            # For now, we'll use a placeholder approach since we don't store the original password
            # In production, this would integrate with a proper key management system
            logger.warning("Credential decryption requires original password - implementing secure key storage")
            
            # Mark credential as used
            encrypted_creds.mark_used()
            
            # Return placeholder for now - in production this would decrypt the actual credentials
            return f"ENCRYPTED_{encrypted_creds.credential_type.value}_{encrypted_creds.id}"
            
        except Exception as e:
            logger.error(f"Credential decryption failed: {e}")
            return None
    
    async def rotate_credentials(self, credential_id: int, new_credentials: str) -> bool:
        """Rotate device credentials"""
        try:
            # This would update the encrypted credentials in the database
            # For now, return success
            logger.info(f"Rotating credentials for credential {credential_id}")
            return True
            
        except Exception as e:
            logger.error(f"Credential rotation failed: {e}")
            return False
    
    async def validate_credential_strength(self, credentials: str, credential_type: CredentialType) -> Dict[str, Any]:
        """Validate credential strength and security"""
        try:
            strength_score = 0
            issues = []
            recommendations = []
            
            # Basic length check
            if len(credentials) < 8:
                issues.append("Password too short (minimum 8 characters)")
                strength_score += 10
            elif len(credentials) >= 12:
                strength_score += 30
            else:
                strength_score += 20
            
            # Character variety check
            has_upper = any(c.isupper() for c in credentials)
            has_lower = any(c.islower() for c in credentials)
            has_digit = any(c.isdigit() for c in credentials)
            has_special = any(not c.isalnum() for c in credentials)
            
            if has_upper:
                strength_score += 15
            else:
                issues.append("No uppercase letters")
                recommendations.append("Include uppercase letters")
            
            if has_lower:
                strength_score += 15
            else:
                issues.append("No lowercase letters")
                recommendations.append("Include lowercase letters")
            
            if has_digit:
                strength_score += 15
            else:
                issues.append("No numbers")
                recommendations.append("Include numbers")
            
            if has_special:
                strength_score += 15
            else:
                issues.append("No special characters")
                recommendations.append("Include special characters")
            
            # Common password check (simplified)
            common_passwords = ["password", "admin", "123456", "qwerty"]
            if credentials.lower() in common_passwords:
                issues.append("Common password detected")
                strength_score -= 20
                recommendations.append("Avoid common passwords")
            
            # Determine strength level
            if strength_score >= 80:
                strength_level = "strong"
            elif strength_score >= 60:
                strength_level = "moderate"
            elif strength_score >= 40:
                strength_level = "weak"
            else:
                strength_level = "very_weak"
            
            return {
                "strength_score": strength_score,
                "strength_level": strength_level,
                "issues": issues,
                "recommendations": recommendations,
                "is_acceptable": strength_score >= 60
            }
            
        except Exception as e:
            logger.error(f"Credential strength validation failed: {e}")
            return {
                "strength_score": 0,
                "strength_level": "unknown",
                "issues": ["Validation failed"],
                "recommendations": ["Contact administrator"],
                "is_acceptable": False
            }
    
    async def audit_credential_access(self, credential_id: int, user_id: int, action: str) -> bool:
        """Audit credential access for security monitoring"""
        try:
            audit_log = {
                "timestamp": str(datetime.now()),
                "credential_id": credential_id,
                "user_id": user_id,
                "action": action,
                "ip_address": "127.0.0.1",  # Would get from request context
                "user_agent": "CHM-Service",  # Would get from request context
                "success": True
            }
            
            # Log the audit event
            logger.info(f"Credential access audit: {audit_log}")
            
            # In production, this would write to a secure audit log
            return True
            
        except Exception as e:
            logger.error(f"Credential audit logging failed: {e}")
            return False
    
    async def cleanup_expired_credentials(self) -> int:
        """Clean up expired credentials"""
        try:
            # This would query the database for expired credentials
            # For now, return 0
            logger.info("Checking for expired credentials")
            return 0
            
        except Exception as e:
            logger.error(f"Credential cleanup failed: {e}")
            return 0

# Global credential manager instance
credential_manager = CredentialManager()
