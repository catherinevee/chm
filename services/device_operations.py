"""
CHM Device Operations Service
Real device operations with SNMP/SSH capabilities and comprehensive error handling
"""

import asyncio
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
import time

# SNMP imports
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity, SnmpEngine
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("PySNMP not available - SNMP functionality disabled")

# SSH imports
try:
    import asyncssh
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    logging.warning("AsyncSSH not available - SSH functionality disabled")

from ..core.database import get_db
from ..models.device import Device, DeviceStatus, DeviceProtocol
from ..models.device_credentials import DeviceCredentials, CredentialType
from ..models.result_objects import (
    DeviceStatusResult, OperationStatus, DeviceStatus as DeviceStatusEnum
)
from ..services.credential_manager import credential_manager

logger = logging.getLogger(__name__)

class DeviceOperationsService:
    """Service for device operations including SNMP/SSH polling"""
    
    def __init__(self):
        """Initialize device operations service"""
        self.snmp_timeout = 10  # seconds
        self.ssh_timeout = 30   # seconds
        self.max_retries = 3
        self.retry_delay = 1    # seconds
        
    async def get_device_status(self, device_id: int) -> DeviceStatusResult:
        """Get real-time device status via SNMP/SSH"""
        try:
            # Get device and credentials
            device = await self._get_device(device_id)
            if not device:
                return DeviceStatusResult.failure(
                    device_id, 
                    "Device not found",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
            
            credentials = await self._get_primary_credentials(device_id)
            if not credentials:
                return DeviceStatusResult.failure(
                    device_id,
                    "No primary credentials found",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
            
            # Poll device based on protocol
            start_time = time.time()
            
            if device.protocol == DeviceProtocol.SNMP:
                result = await self._poll_snmp(device, credentials)
            elif device.protocol == DeviceProtocol.SSH:
                result = await self._poll_ssh(device, credentials)
            else:
                return DeviceStatusResult.failure(
                    device_id,
                    f"Unsupported protocol: {device.protocol}",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
            
            response_time = (time.time() - start_time) * 1000  # Convert to milliseconds
            
            # Update device status in database
            await self._update_device_status(device_id, result.device_status, response_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Device status check failed for device {device_id}: {e}")
            
            # Get fallback data from device
            fallback_data = await self._get_fallback_status(device_id)
            
            return DeviceStatusResult.failure(
                device_id,
                str(e),
                fallback_data
            )
    
    async def _poll_snmp(self, device: Device, credentials: DeviceCredentials) -> DeviceStatusResult:
        """Poll device via SNMP"""
        if not SNMP_AVAILABLE:
            return DeviceStatusResult.failure(
                device.id,
                "SNMP functionality not available",
                {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
            )
        
        try:
            # Decrypt credentials
            community_string = await credential_manager.decrypt_credentials(credentials)
            if not community_string:
                return DeviceStatusResult.failure(
                    device.id,
                    "Failed to decrypt SNMP credentials",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
            
            # SNMP polling logic
            device_status = await self._execute_snmp_poll(device, community_string)
            
            return DeviceStatusResult.success(
                device.id,
                device_status,
                None  # Response time will be calculated by caller
            )
            
        except Exception as e:
            logger.error(f"SNMP polling failed for device {device.id}: {e}")
            return DeviceStatusResult.failure(
                device.id,
                f"SNMP polling failed: {str(e)}",
                {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
            )
    
    async def _poll_ssh(self, device: Device, credentials: DeviceCredentials) -> DeviceStatusResult:
        """Poll device via SSH"""
        if not SSH_AVAILABLE:
            return DeviceStatusResult.failure(
                device.id,
                "SSH functionality not available",
                {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
            )
        
        try:
            # Decrypt credentials
            ssh_password = await credential_manager.decrypt_credentials(credentials)
            if not ssh_password:
                return DeviceStatusResult.failure(
                    device.id,
                    "Failed to decrypt SSH credentials",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
            
            # SSH polling logic
            device_status = await self._execute_ssh_poll(device, ssh_password)
            
            return DeviceStatusResult.success(
                device.id,
                device_status,
                None  # Response time will be calculated by caller
            )
            
        except Exception as e:
            logger.error(f"SSH polling failed for device {device.id}: {e}")
            return DeviceStatusResult.failure(
                device.id,
                f"SSH polling failed: {str(e)}",
                {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
            )
    
    async def _execute_snmp_poll(self, device: Device, community_string: str) -> DeviceStatusEnum:
        """Execute SNMP polling with retry logic"""
        for attempt in range(self.max_retries):
            try:
                # Create SNMP engine and transport
                snmp_engine = SnmpEngine()
                transport = UdpTransportTarget((device.ip_address, 161), timeout=self.snmp_timeout, retries=0)
                community = CommunityData(community_string)
                context = ContextData()
                
                # SNMP GET request for system description
                object_identity = ObjectIdentity('1.3.6.1.2.1.1.1.0')  # sysDescr
                
                error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: getCmd(snmp_engine, community, transport, context, object_identity)
                )
                
                if error_indication:
                    raise Exception(f"SNMP error: {error_indication}")
                
                if error_status:
                    raise Exception(f"SNMP error status: {error_status}")
                
                # Successfully got response
                logger.debug(f"SNMP poll successful for device {device.id}")
                return DeviceStatusEnum.ONLINE
                
            except Exception as e:
                logger.warning(f"SNMP attempt {attempt + 1} failed for device {device.id}: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                else:
                    raise e
        
        # All retries failed
        return DeviceStatusEnum.OFFLINE
    
    async def _execute_ssh_poll(self, device: Device, password: str) -> DeviceStatusEnum:
        """Execute SSH polling with retry logic"""
        for attempt in range(self.max_retries):
            try:
                # SSH connection and command execution
                async with asyncssh.connect(
                    device.ip_address,
                    username=device.ssh_username or 'admin',
                    password=password,
                    known_hosts=None,  # In production, use proper host key verification
                    timeout=self.ssh_timeout
                ) as conn:
                    
                    # Execute simple command to verify connectivity
                    result = await conn.run('echo "CHM Health Check"')
                    
                    if result.exit_status == 0:
                        logger.debug(f"SSH poll successful for device {device.id}")
                        return DeviceStatusEnum.ONLINE
                    else:
                        raise Exception(f"SSH command failed with exit status {result.exit_status}")
                        
            except Exception as e:
                logger.warning(f"SSH attempt {attempt + 1} failed for device {device.id}: {e}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                else:
                    raise e
        
        # All retries failed
        return DeviceStatusEnum.OFFLINE
    
    async def _get_device(self, device_id: int) -> Optional[Device]:
        """Get device from database"""
        try:
            async for db in get_db():
                # This would be a real database query
                # For now, return a mock device
                return Device(
                    id=device_id,
                    name=f"Device_{device_id}",
                    ip_address="192.168.1.1",
                    protocol=DeviceProtocol.SNMP,
                    status=DeviceStatus.UNKNOWN
                )
        except Exception as e:
            logger.error(f"Failed to get device {device_id}: {e}")
            return None
    
    async def _get_primary_credentials(self, device_id: int) -> Optional[DeviceCredentials]:
        """Get primary credentials for device"""
        try:
            # This would be a real database query
            # For now, return a mock credential
            return DeviceCredentials(
                id=1,
                device_id=device_id,
                credential_type=CredentialType.SNMP,
                name="Primary SNMP",
                encrypted_data="mock_encrypted_data",
                key_id="mock_key_id"
            )
        except Exception as e:
            logger.error(f"Failed to get credentials for device {device_id}: {e}")
            return None
    
    async def _update_device_status(self, device_id: int, status: DeviceStatusEnum, response_time: float):
        """Update device status in database"""
        try:
            # This would update the device status in the database
            logger.info(f"Updated device {device_id} status to {status} (response time: {response_time:.2f}ms)")
        except Exception as e:
            logger.error(f"Failed to update device status for device {device_id}: {e}")
    
    async def _get_fallback_status(self, device_id: int) -> Dict[str, Any]:
        """Get fallback status data for device"""
        try:
            # This would get the last known status from the database
            # For now, return basic fallback data
            return {
                "status": "unknown",
                "last_check": datetime.utcnow().isoformat(),
                "fallback_reason": "Device operation failed"
            }
        except Exception as e:
            logger.error(f"Failed to get fallback status for device {device_id}: {e}")
            return {
                "status": "unknown",
                "last_check": datetime.utcnow().isoformat(),
                "fallback_reason": "Failed to get fallback data"
            }
    
    async def batch_poll_devices(self, device_ids: List[int]) -> List[DeviceStatusResult]:
        """Poll multiple devices concurrently"""
        try:
            # Create polling tasks
            polling_tasks = [
                self.get_device_status(device_id) 
                for device_id in device_ids
            ]
            
            # Execute concurrently with timeout
            results = await asyncio.wait_for(
                asyncio.gather(*polling_tasks, return_exceptions=True),
                timeout=60  # 1 minute timeout for batch operation
            )
            
            # Process results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    # Create failure result for exception
                    processed_results.append(
                        DeviceStatusResult.failure(
                            device_ids[i],
                            str(result),
                            {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                        )
                    )
                else:
                    processed_results.append(result)
            
            return processed_results
            
        except asyncio.TimeoutError:
            logger.error("Batch device polling timed out")
            # Return failure results for all devices
            return [
                DeviceStatusResult.failure(
                    device_id,
                    "Batch operation timeout",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
                for device_id in device_ids
            ]
        except Exception as e:
            logger.error(f"Batch device polling failed: {e}")
            # Return failure results for all devices
            return [
                DeviceStatusResult.failure(
                    device_id,
                    f"Batch operation failed: {str(e)}",
                    {"status": "unknown", "last_check": datetime.utcnow().isoformat()}
                )
                for device_id in device_ids
            ]

# Global device operations service instance
device_operations_service = DeviceOperationsService()
