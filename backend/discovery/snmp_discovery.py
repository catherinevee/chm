"""
SNMP Device Discovery and Auto-Addition Service
Discovers devices via SNMP polling and automatically adds them to inventory
"""

import asyncio
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
import logging
import uuid

from ..collector.protocols.snmp.session import SNMPSession, SNMPCredentials, SNMPResult
from ..collector.protocols.snmp.oids import StandardMIBs
from ..storage.database import db
from ..storage.models import Device

logger = logging.getLogger(__name__)

@dataclass
class DiscoveredDevice:
    """Information about a discovered device"""
    ip_address: str
    hostname: Optional[str] = None
    system_description: Optional[str] = None
    system_name: Optional[str] = None
    system_location: Optional[str] = None
    system_uptime: Optional[int] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    interface_count: Optional[int] = None
    snmp_credentials: Optional[Dict[str, Any]] = None
    discovery_timestamp: datetime = None

    def __post_init__(self):
        if self.discovery_timestamp is None:
            self.discovery_timestamp = datetime.now()

@dataclass
class DiscoveryResult:
    """Result of device discovery operation"""
    success: bool
    device: Optional[DiscoveredDevice] = None
    error: Optional[str] = None
    device_id: Optional[str] = None  # If added to inventory

class SNMPDeviceDiscovery:
    """SNMP-based device discovery and auto-addition service"""
    
    def __init__(self):
        self.default_communities = ["public", "private", "community"]
        self.default_snmpv3_users = []  # Can be configured
        
    def add_default_snmpv3_user(self, username: str, auth_protocol: str = "SHA", 
                                auth_password: str = "", priv_protocol: str = "AES128", 
                                priv_password: str = "", security_level: str = "authPriv"):
        """Add default SNMPv3 user for discovery attempts"""
        self.default_snmpv3_users.append({
            'username': username,
            'auth_protocol': auth_protocol,
            'auth_password': auth_password,
            'priv_protocol': priv_protocol,
            'priv_password': priv_password,
            'security_level': security_level
        })
    
    async def discover_device(self, ip_address: str, 
                            credentials: Optional[Dict[str, Any]] = None,
                            auto_add: bool = False) -> DiscoveryResult:
        """
        Discover a device via SNMP polling
        
        Args:
            ip_address: IP address of the device
            credentials: Specific SNMP credentials to use
            auto_add: Whether to automatically add device to inventory
            
        Returns:
            DiscoveryResult with device information
        """
        logger.info(f"Starting SNMP discovery for {ip_address}")
        
        if credentials:
            # Use provided credentials
            return await self._discover_with_credentials(ip_address, credentials, auto_add)
        else:
            # Try multiple credential combinations
            return await self._discover_with_multiple_credentials(ip_address, auto_add)
    
    async def _discover_with_credentials(self, ip_address: str, 
                                       credentials: Dict[str, Any], 
                                       auto_add: bool) -> DiscoveryResult:
        """Discover device with specific credentials"""
        try:
            # Create SNMP credentials
            if credentials.get('version') == '3':
                snmp_creds = SNMPCredentials(
                    version="3",
                    username=credentials['username'],
                    auth_protocol=credentials.get('auth_protocol', 'SHA'),
                    auth_password=credentials.get('auth_password', ''),
                    priv_protocol=credentials.get('priv_protocol', 'AES128'),
                    priv_password=credentials.get('priv_password', ''),
                    security_level=credentials.get('security_level', 'authPriv')
                )
            else:
                snmp_creds = SNMPCredentials(
                    version=credentials.get('version', '2c'),
                    community=credentials.get('community', 'public')
                )
            
            # Create session
            session = SNMPSession(
                host=ip_address,
                credentials=snmp_creds,
                timeout=credentials.get('timeout', 10),  # Increased from 5 to 10 seconds
                retries=credentials.get('retries', 3)    # Increased from 2 to 3 retries
            )
            
            # Test connection
            if not await session.connect():
                return DiscoveryResult(
                    success=False,
                    error=f"Failed to connect to {ip_address} with provided credentials"
                )
            
            # Gather device information
            device = await self._gather_device_info(session, ip_address, credentials)
            
            if auto_add and device:
                device_id = await self._add_device_to_inventory(device)
                return DiscoveryResult(success=True, device=device, device_id=device_id)
            
            return DiscoveryResult(success=True, device=device)
            
        except Exception as e:
            logger.error(f"Discovery failed for {ip_address}: {e}")
            return DiscoveryResult(success=False, error=str(e))
    
    async def _discover_with_multiple_credentials(self, ip_address: str, 
                                                auto_add: bool) -> DiscoveryResult:
        """Try multiple credential combinations to discover device"""
        logger.info(f"Attempting discovery with multiple credentials for {ip_address}")
        
        # Try SNMPv2c with common communities
        for community in self.default_communities:
            logger.debug(f"Trying SNMPv2c with community '{community}' for {ip_address}")
            
            credentials = {
                'version': '2c',
                'community': community,
                'timeout': 8,   # Increased from 3 to 8 seconds
                'retries': 2    # Increased from 1 to 2 retries
            }
            
            result = await self._discover_with_credentials(ip_address, credentials, False)
            if result.success:
                logger.info(f"Successfully discovered {ip_address} with SNMPv2c community '{community}'")
                if auto_add and result.device:
                    device_id = await self._add_device_to_inventory(result.device)
                    result.device_id = device_id
                return result
        
        # Try SNMPv3 with configured users
        for user_config in self.default_snmpv3_users:
            logger.debug(f"Trying SNMPv3 with user '{user_config['username']}' for {ip_address}")
            
            credentials = {
                'version': '3',
                'username': user_config['username'],
                'auth_protocol': user_config['auth_protocol'],
                'auth_password': user_config['auth_password'],
                'priv_protocol': user_config['priv_protocol'],
                'priv_password': user_config['priv_password'],
                'security_level': user_config['security_level'],
                'timeout': 5,
                'retries': 1
            }
            
            result = await self._discover_with_credentials(ip_address, credentials, False)
            if result.success:
                logger.info(f"Successfully discovered {ip_address} with SNMPv3 user '{user_config['username']}'")
                if auto_add and result.device:
                    device_id = await self._add_device_to_inventory(result.device)
                    result.device_id = device_id
                return result
        
        return DiscoveryResult(
            success=False,
            error=f"Failed to discover {ip_address} with any available credentials"
        )
    
    async def _gather_device_info(self, session: SNMPSession, ip_address: str, 
                                credentials: Dict[str, Any]) -> Optional[DiscoveredDevice]:
        """Gather comprehensive device information via SNMP"""
        device = DiscoveredDevice(ip_address=ip_address)
        device.snmp_credentials = credentials
        
        try:
            # System description
            sys_descr = await session.get_system_description()
            if sys_descr.success:
                device.system_description = sys_descr.value
                device.vendor = session.vendor
                device.device_type = session.device_type
                device.model = self._extract_model_from_description(sys_descr.value)
            
            # System name (hostname)
            sys_name = await session.get_system_name()
            if sys_name.success:
                device.system_name = sys_name.value
                device.hostname = sys_name.value
            
            # System location
            sys_location = await session.get_system_location()
            if sys_location.success:
                device.system_location = sys_location.value
            
            # System uptime
            sys_uptime = await session.get_system_uptime()
            if sys_uptime.success:
                device.system_uptime = sys_uptime.value
            
            # Interface count
            if_count = await session.get_interface_count()
            if if_count.success:
                device.interface_count = if_count.value
            
            # Try to get serial number from vendor-specific OIDs
            device.serial_number = await self._get_serial_number(session)
            
            logger.info(f"Successfully gathered info for {ip_address}: {device.vendor} {device.model}")
            return device
            
        except Exception as e:
            logger.error(f"Failed to gather device info for {ip_address}: {e}")
            return device  # Return partial info
    
    def _extract_model_from_description(self, description: str) -> str:
        """Extract device model from system description"""
        if not description:
            return "unknown"
            
        description_lower = description.lower()
        
        # Cisco patterns
        if 'cisco' in description_lower:
            # Look for common Cisco model patterns
            models = ['2960', '3560', '3750', '4500', '6500', '9300', 'isr4321', 'asr1000']
            for model in models:
                if model in description_lower:
                    return model.upper()
        
        # HP/Aruba patterns
        elif 'hp' in description_lower or 'aruba' in description_lower:
            if 'procurve' in description_lower:
                return 'ProCurve'
        
        # Juniper patterns
        elif 'juniper' in description_lower:
            if 'ex' in description_lower:
                return 'EX Series'
            elif 'mx' in description_lower:
                return 'MX Series'
        
        return "unknown"
    
    async def _get_serial_number(self, session: SNMPSession) -> Optional[str]:
        """Try to get device serial number from vendor-specific OIDs"""
        # This is a simplified implementation
        # In practice, you'd have vendor-specific OIDs for serial numbers
        
        # Cisco serial number OIDs (examples)
        cisco_serial_oids = [
            '1.3.6.1.2.1.47.1.1.1.1.11.1',  # entPhysicalSerialNum
            '1.3.6.1.4.1.9.3.6.3.0',        # chassisId
        ]
        
        if session.vendor and session.vendor.lower() == 'cisco':
            for oid in cisco_serial_oids:
                result = await session._get_single_oid(oid)
                if result.success and result.value:
                    return str(result.value)
        
        return "unknown"
    
    async def _add_device_to_inventory(self, device: DiscoveredDevice) -> str:
        """Add discovered device to inventory"""
        logger.info(f"Adding discovered device {device.ip_address} to inventory")
        
        try:
            # Check if device already exists
            existing_device = await db.fetch_one(
                "SELECT id FROM devices WHERE ip_address = :ip_address",
                {"ip_address": device.ip_address}
            )
            
            if existing_device:
                logger.info(f"Device {device.ip_address} already exists in inventory")
                return str(existing_device['id'])
            
            # Create new device record
            device_id = str(uuid.uuid4())
            device_data = {
                'id': device_id,
                'hostname': device.hostname or device.ip_address,
                'ip_address': device.ip_address,
                'device_type': self._normalize_device_type(device.device_type),
                'serial_number': device.serial_number,
                'model': device.model,
                'manufacturer': device.vendor,
                'location': device.system_location,
                'device_group': 'discovered',
                'asset_status': 'active',
                'poll_interval': 60,
                'created_at': datetime.now(),
                'updated_at': datetime.now()
            }
            
            # Insert device
            await db.execute(
                """
                INSERT INTO devices (
                    id, hostname, ip_address, device_type, serial_number, 
                    model, manufacturer, location, device_group, asset_status,
                    poll_interval, created_at, updated_at
                ) VALUES (
                    :id, :hostname, :ip_address, :device_type, :serial_number,
                    :model, :manufacturer, :location, :device_group, :asset_status,
                    :poll_interval, :created_at, :updated_at
                )
                """,
                device_data
            )
            
            # Add SNMP credentials
            if device.snmp_credentials:
                cred_id = str(uuid.uuid4())
                cred_data = {
                    'id': cred_id,
                    'device_id': device_id,
                    'protocol': 'snmp',
                    'version': device.snmp_credentials.get('version', '2c'),
                    'priority': 0,
                    'credentials': device.snmp_credentials,
                    'created_at': datetime.now()
                }
                
                await db.execute(
                    """
                    INSERT INTO device_credentials (
                        id, device_id, protocol, version, priority, credentials, created_at
                    ) VALUES (
                        :id, :device_id, :protocol, :version, :priority, :credentials, :created_at
                    )
                    """,
                    cred_data
                )
            
            logger.info(f"Successfully added device {device.ip_address} to inventory with ID {device_id}")
            return device_id
            
        except Exception as e:
            logger.error(f"Failed to add device {device.ip_address} to inventory: {e}")
            raise
    
    def _normalize_device_type(self, device_type: Optional[str]) -> str:
        """Normalize device type for database storage"""
        if not device_type:
            return 'other'
        
        device_type_lower = device_type.lower()
        
        if 'switch' in device_type_lower or any(model in device_type_lower for model in ['2960', '3560', '3750']):
            return 'switch'
        elif 'router' in device_type_lower or 'isr' in device_type_lower:
            return 'router'
        elif 'firewall' in device_type_lower or 'asa' in device_type_lower:
            return 'firewall'
        elif 'access point' in device_type_lower or 'ap' in device_type_lower:
            return 'access_point'
        else:
            return 'other'

# Global discovery service instance
snmp_discovery = SNMPDeviceDiscovery()
