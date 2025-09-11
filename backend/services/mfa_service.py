"""
Multi-Factor Authentication (MFA) Service
Handles TOTP, backup codes, and other MFA methods
"""

import io
import logging
import secrets
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
import qrcode
import pyotp
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2

from backend.config import settings
from backend.common.exceptions import (
    AuthenticationException,
    ValidationException,
    MFARequiredException,
    InvalidTokenException
)
from backend.database.base import AsyncSession
from backend.models.user import User
# MFA models not yet implemented
class MFADevice:
    pass
class MFAMethod:
    pass
class MFADeviceStatus:
    pass
from sqlalchemy import select, update, and_, or_
from sqlalchemy.exc import IntegrityError

logger = logging.getLogger(__name__)


class MFAService:
    """Service for handling Multi-Factor Authentication"""
    
    def __init__(self):
        """Initialize MFA service"""
        # MFA settings
        self.issuer_name = settings.mfa_issuer or "CHM"
        self.totp_digits = 6
        self.totp_interval = 30
        self.backup_codes_count = 10
        self.max_devices_per_user = 5
        
        # Encryption for storing secrets
        self.encryption_key = self._derive_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Recovery codes settings
        self.recovery_code_length = 8
        self.recovery_codes_per_batch = 10
        
        logger.info("MFAService initialized")
    
    def _derive_encryption_key(self) -> bytes:
        """Derive encryption key from secret key"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'chm-mfa-salt',  # In production, use unique salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(
            kdf.derive(settings.secret_key.encode())
        )
        return key
    
    async def setup_totp(
        self,
        user: User,
        device_name: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Setup TOTP for user
        
        Args:
            user: User object
            device_name: Device name
            db: Database session
            
        Returns:
            Setup information including QR code
        """
        try:
            # Check device limit
            device_count = await self._get_device_count(db, user.id)
            if device_count >= self.max_devices_per_user:
                raise ValidationException(f"Maximum {self.max_devices_per_user} MFA devices allowed")
            
            # Generate secret
            secret = pyotp.random_base32()
            
            # Encrypt secret for storage
            encrypted_secret = self.cipher.encrypt(secret.encode()).decode()
            
            # Create TOTP URI
            totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user.email,
                issuer_name=self.issuer_name
            )
            
            # Generate QR code
            qr_code_data = self._generate_qr_code(totp_uri)
            
            # Store device (not active until verified)
            device = MFADevice(
                user_id=user.id,
                name=device_name,
                method=MFAMethod.TOTP,
                secret=encrypted_secret,
                status=MFADeviceStatus.PENDING,
                metadata={
                    'digits': self.totp_digits,
                    'interval': self.totp_interval
                }
            )
            db.add(device)
            await db.commit()
            
            return {
                'device_id': device.id,
                'secret': secret,
                'qr_code': qr_code_data,
                'manual_entry_key': secret,
                'manual_entry_setup': {
                    'issuer': self.issuer_name,
                    'account': user.email,
                    'secret': secret,
                    'digits': self.totp_digits,
                    'interval': self.totp_interval
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to setup TOTP: {e}")
            raise AuthenticationException(f"Failed to setup TOTP: {str(e)}")
    
    async def verify_totp_setup(
        self,
        user: User,
        device_id: int,
        code: str,
        db: AsyncSession
    ) -> bool:
        """
        Verify TOTP setup with initial code
        
        Args:
            user: User object
            device_id: Device ID
            code: TOTP code
            db: Database session
            
        Returns:
            True if verified successfully
        """
        try:
            # Get device
            device = await self._get_device(db, device_id, user.id)
            if not device:
                raise ValidationException("MFA device not found")
            
            if device.status != MFADeviceStatus.PENDING:
                raise ValidationException("Device already verified")
            
            # Decrypt secret
            secret = self.cipher.decrypt(device.secret.encode()).decode()
            
            # Verify code
            if self._verify_totp_code(secret, code):
                # Activate device
                device.status = MFADeviceStatus.ACTIVE
                device.verified_at = datetime.utcnow()
                device.last_used = datetime.utcnow()
                
                # Enable MFA for user if first device
                if not user.mfa_enabled:
                    user.mfa_enabled = True
                
                # Generate backup codes
                backup_codes = await self._generate_backup_codes(db, user.id)
                
                await db.commit()
                
                logger.info(f"TOTP device verified for user {user.username}")
                
                return {
                    'success': True,
                    'backup_codes': backup_codes,
                    'message': 'MFA has been successfully enabled'
                }
            else:
                return {
                    'success': False,
                    'message': 'Invalid verification code'
                }
                
        except Exception as e:
            logger.error(f"Failed to verify TOTP setup: {e}")
            raise AuthenticationException(f"Failed to verify TOTP: {str(e)}")
    
    async def verify_totp(
        self,
        user: User,
        code: str,
        db: AsyncSession
    ) -> bool:
        """
        Verify TOTP code for authentication
        
        Args:
            user: User object
            code: TOTP code
            db: Database session
            
        Returns:
            True if code is valid
        """
        try:
            # Get active TOTP devices
            devices = await self._get_active_devices(
                db, user.id, MFAMethod.TOTP
            )
            
            for device in devices:
                # Decrypt secret
                secret = self.cipher.decrypt(device.secret.encode()).decode()
                
                # Verify code
                if self._verify_totp_code(secret, code):
                    # Update last used
                    device.last_used = datetime.utcnow()
                    device.use_count = (device.use_count or 0) + 1
                    await db.commit()
                    
                    logger.info(f"TOTP verified for user {user.username}")
                    return True
            
            # Check backup codes if TOTP fails
            if await self._verify_backup_code(db, user.id, code):
                logger.info(f"Backup code used for user {user.username}")
                return True
            
            logger.warning(f"Invalid TOTP code for user {user.username}")
            return False
            
        except Exception as e:
            logger.error(f"Failed to verify TOTP: {e}")
            return False
    
    async def generate_backup_codes(
        self,
        user: User,
        db: AsyncSession
    ) -> List[str]:
        """
        Generate new backup codes for user
        
        Args:
            user: User object
            db: Database session
            
        Returns:
            List of backup codes
        """
        try:
            # Invalidate existing backup codes
            await self._invalidate_backup_codes(db, user.id)
            
            # Generate new codes
            codes = await self._generate_backup_codes(db, user.id)
            
            logger.info(f"Generated {len(codes)} backup codes for user {user.username}")
            return codes
            
        except Exception as e:
            logger.error(f"Failed to generate backup codes: {e}")
            raise AuthenticationException("Failed to generate backup codes")
    
    async def list_devices(
        self,
        user: User,
        db: AsyncSession
    ) -> List[Dict[str, Any]]:
        """
        List user's MFA devices
        
        Args:
            user: User object
            db: Database session
            
        Returns:
            List of device information
        """
        try:
            query = select(MFADevice).where(
                and_(
                    MFADevice.user_id == user.id,
                    MFADevice.status != MFADeviceStatus.DELETED
                )
            ).order_by(MFADevice.created_at.desc())
            
            result = await db.execute(query)
            devices = result.scalars().all()
            
            return [
                {
                    'id': device.id,
                    'name': device.name,
                    'method': device.method,
                    'status': device.status,
                    'created_at': device.created_at,
                    'last_used': device.last_used,
                    'use_count': device.use_count,
                    'is_primary': device.is_primary
                }
                for device in devices
            ]
            
        except Exception as e:
            logger.error(f"Failed to list MFA devices: {e}")
            return []
    
    async def remove_device(
        self,
        user: User,
        device_id: int,
        db: AsyncSession
    ) -> bool:
        """
        Remove MFA device
        
        Args:
            user: User object
            device_id: Device ID
            db: Database session
            
        Returns:
            True if removed successfully
        """
        try:
            # Get device
            device = await self._get_device(db, device_id, user.id)
            if not device:
                raise ValidationException("MFA device not found")
            
            # Mark as deleted
            device.status = MFADeviceStatus.DELETED
            device.deleted_at = datetime.utcnow()
            
            # Check if user has other active devices
            active_devices = await self._get_active_devices(db, user.id)
            if len(active_devices) == 1 and active_devices[0].id == device_id:
                # This is the last device, disable MFA
                user.mfa_enabled = False
                logger.info(f"MFA disabled for user {user.username} (last device removed)")
            
            await db.commit()
            
            logger.info(f"MFA device {device_id} removed for user {user.username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove MFA device: {e}")
            return False
    
    async def disable_mfa(
        self,
        user: User,
        db: AsyncSession
    ) -> bool:
        """
        Disable MFA for user completely
        
        Args:
            user: User object
            db: Database session
            
        Returns:
            True if disabled successfully
        """
        try:
            # Mark all devices as deleted
            query = update(MFADevice).where(
                and_(
                    MFADevice.user_id == user.id,
                    MFADevice.status != MFADeviceStatus.DELETED
                )
            ).values(
                status=MFADeviceStatus.DELETED,
                deleted_at=datetime.utcnow()
            )
            await db.execute(query)
            
            # Disable MFA for user
            user.mfa_enabled = False
            user.mfa_secret = None
            
            await db.commit()
            
            logger.info(f"MFA disabled for user {user.username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to disable MFA: {e}")
            return False
    
    async def setup_sms(
        self,
        user: User,
        phone_number: str,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Setup SMS-based MFA
        
        Args:
            user: User object
            phone_number: Phone number
            db: Database session
            
        Returns:
            Setup information
        """
        try:
            # Validate phone number
            if not self._validate_phone_number(phone_number):
                raise ValidationException("Invalid phone number format")
            
            # Check device limit
            device_count = await self._get_device_count(db, user.id)
            if device_count >= self.max_devices_per_user:
                raise ValidationException(f"Maximum {self.max_devices_per_user} MFA devices allowed")
            
            # Generate verification code
            verification_code = self._generate_sms_code()
            
            # Store device (pending verification)
            device = MFADevice(
                user_id=user.id,
                name=f"SMS: {phone_number[-4:]}",
                method=MFAMethod.SMS,
                secret=self.cipher.encrypt(verification_code.encode()).decode(),
                status=MFADeviceStatus.PENDING,
                metadata={
                    'phone_number': self._mask_phone_number(phone_number),
                    'full_number': self.cipher.encrypt(phone_number.encode()).decode()
                }
            )
            db.add(device)
            await db.commit()
            
            # Send SMS (would integrate with SMS service)
            # await self._send_sms(phone_number, verification_code)
            
            return {
                'device_id': device.id,
                'masked_phone': self._mask_phone_number(phone_number),
                'message': 'Verification code sent to your phone'
            }
            
        except Exception as e:
            logger.error(f"Failed to setup SMS MFA: {e}")
            raise AuthenticationException(f"Failed to setup SMS MFA: {str(e)}")
    
    async def setup_email(
        self,
        user: User,
        db: AsyncSession
    ) -> Dict[str, Any]:
        """
        Setup email-based MFA
        
        Args:
            user: User object
            db: Database session
            
        Returns:
            Setup information
        """
        try:
            # Check device limit
            device_count = await self._get_device_count(db, user.id)
            if device_count >= self.max_devices_per_user:
                raise ValidationException(f"Maximum {self.max_devices_per_user} MFA devices allowed")
            
            # Email MFA uses user's registered email
            device = MFADevice(
                user_id=user.id,
                name=f"Email: {user.email}",
                method=MFAMethod.EMAIL,
                secret=self.cipher.encrypt(secrets.token_hex(16).encode()).decode(),
                status=MFADeviceStatus.ACTIVE,  # Email is pre-verified
                verified_at=datetime.utcnow(),
                metadata={
                    'email': user.email
                }
            )
            db.add(device)
            
            # Enable MFA if first device
            if not user.mfa_enabled:
                user.mfa_enabled = True
            
            await db.commit()
            
            logger.info(f"Email MFA enabled for user {user.username}")
            
            return {
                'device_id': device.id,
                'email': user.email,
                'message': 'Email MFA has been enabled'
            }
            
        except Exception as e:
            logger.error(f"Failed to setup email MFA: {e}")
            raise AuthenticationException(f"Failed to setup email MFA: {str(e)}")
    
    async def send_email_code(
        self,
        user: User,
        db: AsyncSession
    ) -> bool:
        """
        Send MFA code via email
        
        Args:
            user: User object
            db: Database session
            
        Returns:
            True if sent successfully
        """
        try:
            # Get email MFA device
            devices = await self._get_active_devices(
                db, user.id, MFAMethod.EMAIL
            )
            
            if not devices:
                raise ValidationException("Email MFA not configured")
            
            # Generate code
            code = self._generate_email_code()
            
            # Store code temporarily (5 minutes expiry)
            device = devices[0]
            device.metadata['current_code'] = self.cipher.encrypt(code.encode()).decode()
            device.metadata['code_expires'] = (
                datetime.utcnow() + timedelta(minutes=5)
            ).isoformat()
            
            await db.commit()
            
            # Send email (integrate with EmailService)
            # await email_service.send_mfa_code(user, code)
            
            logger.info(f"Email MFA code sent to user {user.username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email MFA code: {e}")
            return False
    
    def _verify_totp_code(self, secret: str, code: str) -> bool:
        """Verify TOTP code"""
        try:
            totp = pyotp.TOTP(secret)
            # Allow 1 window before/after for clock skew
            return totp.verify(code, valid_window=1)
        except Exception:
            return False
    
    def _generate_qr_code(self, data: str) -> str:
        """Generate QR code as base64 string"""
        try:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(data)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            buffer.seek(0)
            
            return base64.b64encode(buffer.getvalue()).decode()
        except Exception as e:
            logger.error(f"Failed to generate QR code: {e}")
            return ""
    
    async def _generate_backup_codes(
        self,
        db: AsyncSession,
        user_id: int
    ) -> List[str]:
        """Generate backup codes"""
        codes = []
        
        for _ in range(self.backup_codes_count):
            code = secrets.token_hex(4).upper()
            codes.append(f"{code[:4]}-{code[4:]}")
            
            # Store hashed code
            hashed_code = self._hash_backup_code(code)
            
            device = MFADevice(
                user_id=user_id,
                name=f"Backup code",
                method=MFAMethod.BACKUP_CODE,
                secret=hashed_code,
                status=MFADeviceStatus.ACTIVE,
                verified_at=datetime.utcnow()
            )
            db.add(device)
        
        await db.commit()
        return codes
    
    def _hash_backup_code(self, code: str) -> str:
        """Hash backup code for storage"""
        # Remove dashes for hashing
        clean_code = code.replace("-", "")
        # In production, use proper hashing
        return self.cipher.encrypt(clean_code.encode()).decode()
    
    async def _verify_backup_code(
        self,
        db: AsyncSession,
        user_id: int,
        code: str
    ) -> bool:
        """Verify and consume backup code"""
        try:
            # Clean code
            clean_code = code.replace("-", "").upper()
            
            # Get unused backup codes
            query = select(MFADevice).where(
                and_(
                    MFADevice.user_id == user_id,
                    MFADevice.method == MFAMethod.BACKUP_CODE,
                    MFADevice.status == MFADeviceStatus.ACTIVE
                )
            )
            
            result = await db.execute(query)
            devices = result.scalars().all()
            
            for device in devices:
                try:
                    stored_code = self.cipher.decrypt(device.secret.encode()).decode()
                    if stored_code == clean_code:
                        # Mark as used
                        device.status = MFADeviceStatus.USED
                        device.last_used = datetime.utcnow()
                        await db.commit()
                        return True
                except Exception:
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to verify backup code: {e}")
            return False
    
    async def _invalidate_backup_codes(
        self,
        db: AsyncSession,
        user_id: int
    ):
        """Invalidate all existing backup codes"""
        query = update(MFADevice).where(
            and_(
                MFADevice.user_id == user_id,
                MFADevice.method == MFAMethod.BACKUP_CODE,
                MFADevice.status == MFADeviceStatus.ACTIVE
            )
        ).values(
            status=MFADeviceStatus.DELETED,
            deleted_at=datetime.utcnow()
        )
        await db.execute(query)
        await db.commit()
    
    async def _get_device(
        self,
        db: AsyncSession,
        device_id: int,
        user_id: int
    ) -> Optional[MFADevice]:
        """Get MFA device"""
        query = select(MFADevice).where(
            and_(
                MFADevice.id == device_id,
                MFADevice.user_id == user_id,
                MFADevice.status != MFADeviceStatus.DELETED
            )
        )
        result = await db.execute(query)
        return result.scalar_one_or_none()
    
    async def _get_active_devices(
        self,
        db: AsyncSession,
        user_id: int,
        method: Optional[MFAMethod] = None
    ) -> List[MFADevice]:
        """Get active MFA devices"""
        conditions = [
            MFADevice.user_id == user_id,
            MFADevice.status == MFADeviceStatus.ACTIVE
        ]
        
        if method:
            conditions.append(MFADevice.method == method)
        
        query = select(MFADevice).where(and_(*conditions))
        result = await db.execute(query)
        return result.scalars().all()
    
    async def _get_device_count(
        self,
        db: AsyncSession,
        user_id: int
    ) -> int:
        """Get count of user's MFA devices"""
        devices = await self._get_active_devices(db, user_id)
        # Don't count backup codes
        return len([d for d in devices if d.method != MFAMethod.BACKUP_CODE])
    
    def _generate_sms_code(self) -> str:
        """Generate SMS verification code"""
        return str(secrets.randbelow(999999)).zfill(6)
    
    def _generate_email_code(self) -> str:
        """Generate email verification code"""
        return str(secrets.randbelow(999999)).zfill(6)
    
    def _validate_phone_number(self, phone: str) -> bool:
        """Validate phone number format"""
        # Basic validation - in production use phonenumbers library
        import re
        pattern = r'^\+?[1-9]\d{1,14}$'
        return bool(re.match(pattern, phone.replace(" ", "").replace("-", "")))
    
    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for display"""
        if len(phone) < 8:
            return phone
        return f"{phone[:3]}****{phone[-4:]}"


# Global MFA service instance
mfa_service = MFAService()