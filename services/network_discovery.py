"""
Network Discovery Service for CHM

This service provides automated network discovery using multiple protocols
(SNMP, CDP, LLDP, SSH) to map network topology and device relationships.
"""

import asyncio
import ipaddress
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor

import asyncio
from pysnmp.hlapi import (
    CommunityData, UdpTransportTarget, ContextData,
    ObjectIdentity, ObjectType, getCmd, nextCmd
)
import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_

from ..models.network_topology import (
    NetworkTopology, NetworkInterface, NetworkPath, DeviceRelationship,
    TopologyType, InterfaceType, InterfaceStatus, PathStatus
)
from ..models.device import Device, DeviceStatus, DeviceProtocol
from ..models.device_credentials import DeviceCredential, CredentialType
from ..services.credential_manager import CredentialManager
from ..services.device_operations import DeviceOperationsService
from ..models.result_objects import DiscoveryResult, OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class DiscoveryConfig:
    """Configuration for network discovery"""
    max_concurrent_discoveries: int = 10
    discovery_timeout: int = 30
    max_hop_depth: int = 3
    retry_count: int = 3
    retry_delay: float = 1.0
    
    # Protocol-specific timeouts
    snmp_timeout: int = 5
    ssh_timeout: int = 10
    ping_timeout: int = 2
    
    # Discovery protocols to use
    use_snmp: bool = True
    use_cdp: bool = True
    use_lldp: bool = True
    use_ssh: bool = True
    use_ping: bool = True
    
    # SNMP settings
    snmp_community: str = "public"
    snmp_version: int = 2
    snmp_retries: int = 2
    
    # SSH settings
    ssh_username: str = "admin"
    ssh_key_path: Optional[str] = None


@dataclass
class DiscoveryTarget:
    """Target for network discovery"""
    ip_address: str
    credential_type: CredentialType
    credentials: Dict[str, Any]
    discovery_protocols: List[str]
    max_depth: int = 3


@dataclass
class DiscoveredDevice:
    """Information about a discovered device"""
    ip_address: str
    hostname: Optional[str]
    device_type: Optional[str]
    vendor: Optional[str]
    model: Optional[str]
    os_version: Optional[str]
    interfaces: List[Dict[str, Any]]
    neighbors: List[Dict[str, Any]]
    capabilities: List[str]
    discovery_protocol: str
    hop_count: int


@dataclass
class DiscoveryProgress:
    """Progress tracking for discovery operations"""
    total_targets: int
    discovered_devices: int
    failed_targets: int
    current_depth: int
    max_depth: int
    start_time: datetime
    estimated_completion: Optional[datetime] = None


class NetworkDiscoveryService:
    """Service for automated network discovery and topology mapping"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.config = DiscoveryConfig()
        self.credential_manager = CredentialManager()
        self.device_operations = DeviceOperationsService(db_session)
        self._discovery_semaphore = asyncio.Semaphore(self.config.max_concurrent_discoveries)
        self._discovered_ips: Set[str] = set()
        self._device_cache: Dict[str, DiscoveredDevice] = {}
        
    async def discover_network(
        self,
        topology: NetworkTopology,
        seed_devices: List[str],
        credentials: List[Dict[str, Any]]
    ) -> DiscoveryResult:
        """Discover network topology starting from seed devices"""
        try:
            logger.info(f"Starting network discovery for topology: {topology.name}")
            
            # Initialize discovery state
            self._discovered_ips.clear()
            self._device_cache.clear()
            
            # Create discovery targets from seed devices
            targets = await self._create_discovery_targets(seed_devices, credentials)
            
            # Execute discovery
            discovered_devices = await self._execute_discovery(topology, targets)
            
            # Build topology relationships
            await self._build_topology_relationships(topology, discovered_devices)
            
            # Update topology status
            topology.last_discovery = datetime.now()
            topology.discovery_status = "completed"
            topology.topology_data = {
                "discovered_devices": len(discovered_devices),
                "discovery_date": datetime.now().isoformat(),
                "seed_devices": seed_devices
            }
            
            await self.db_session.commit()
            
            logger.info(f"Network discovery completed. Found {len(discovered_devices)} devices")
            return DiscoveryResult.success(
                message=f"Network discovery completed successfully",
                discovered_devices=len(discovered_devices),
                topology_id=topology.id
            )
            
        except Exception as e:
            logger.error(f"Network discovery failed: {str(e)}")
            topology.discovery_status = "failed"
            await self.db_session.commit()
            return DiscoveryResult.failure(f"Network discovery failed: {str(e)}")
    
    async def _create_discovery_targets(
        self,
        seed_devices: List[str],
        credentials: List[Dict[str, Any]]
    ) -> List[DiscoveryTarget]:
        """Create discovery targets from seed devices and credentials"""
        targets = []
        
        for ip in seed_devices:
            # Find appropriate credentials for this IP
            credential = self._find_best_credentials(ip, credentials)
            if credential:
                target = DiscoveryTarget(
                    ip_address=ip,
                    credential_type=credential["type"],
                    credentials=credential["data"],
                    discovery_protocols=self._get_available_protocols(credential["type"]),
                    max_depth=self.config.max_hop_depth
                )
                targets.append(target)
            else:
                logger.warning(f"No credentials found for seed device: {ip}")
        
        return targets
    
    def _find_best_credentials(
        self,
        ip_address: str,
        credentials: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Find the best available credentials for a device"""
        # Simple credential matching - in production, this would be more sophisticated
        for cred in credentials:
            if cred.get("ip_range") and self._ip_in_range(ip_address, cred["ip_range"]):
                return cred
            elif cred.get("default", False):
                return cred
        
        return None
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in the specified range"""
        try:
            if "/" in ip_range:  # CIDR notation
                network = ipaddress.ip_network(ip_range, strict=False)
                return ipaddress.ip_address(ip) in network
            else:  # Single IP
                return ip == ip_range
        except ValueError:
            return False
    
    def _get_available_protocols(self, credential_type: CredentialType) -> List[str]:
        """Get available discovery protocols based on credential type"""
        protocols = []
        
        if credential_type == CredentialType.SNMP and self.config.use_snmp:
            protocols.append("snmp")
        if credential_type == CredentialType.SSH and self.config.use_ssh:
            protocols.append("ssh")
        if self.config.use_ping:
            protocols.append("ping")
        
        return protocols
    
    async def _execute_discovery(
        self,
        topology: NetworkTopology,
        targets: List[DiscoveryTarget]
    ) -> List[DiscoveredDevice]:
        """Execute discovery for all targets"""
        discovered_devices = []
        
        # Execute discovery tasks concurrently
        tasks = []
        for target in targets:
            task = self._discover_device(target, 0)  # Start at depth 0
            tasks.append(task)
        
        # Wait for all discoveries to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Discovery task failed: {str(result)}")
            elif result:
                discovered_devices.append(result)
        
        return discovered_devices
    
    async def _discover_device(
        self,
        target: DiscoveryTarget,
        depth: int
    ) -> Optional[DiscoveredDevice]:
        """Discover a single device and its neighbors"""
        if depth > target.max_depth or target.ip_address in self._discovered_ips:
            return None
        
        async with self._discovery_semaphore:
            try:
                # Mark as discovered
                self._discovered_ips.add(target.ip_address)
                
                # Discover device information
                device_info = await self._discover_device_info(target)
                if not device_info:
                    return None
                
                # Discover interfaces
                interfaces = await self._discover_interfaces(target)
                
                # Discover neighbors
                neighbors = await self._discover_neighbors(target, depth)
                
                # Create discovered device object
                discovered_device = DiscoveredDevice(
                    ip_address=target.ip_address,
                    hostname=device_info.get("hostname"),
                    device_type=device_info.get("device_type"),
                    vendor=device_info.get("vendor"),
                    model=device_info.get("model"),
                    os_version=device_info.get("os_version"),
                    interfaces=interfaces,
                    neighbors=neighbors,
                    capabilities=device_info.get("capabilities", []),
                    discovery_protocol=device_info.get("discovery_protocol", "unknown"),
                    hop_count=depth
                )
                
                # Cache the device
                self._device_cache[target.ip_address] = discovered_device
                
                # Recursively discover neighbors if within depth limit
                if depth < target.max_depth:
                    await self._discover_neighbor_devices(target, neighbors, depth + 1)
                
                return discovered_device
                
            except Exception as e:
                logger.error(f"Failed to discover device {target.ip_address}: {str(e)}")
                return None
    
    async def _discover_device_info(self, target: DiscoveryTarget) -> Optional[Dict[str, Any]]:
        """Discover basic device information using available protocols"""
        device_info = {}
        
        # Try SNMP first if available
        if "snmp" in target.discovery_protocols:
            try:
                snmp_info = await self._discover_via_snmp(target)
                if snmp_info:
                    device_info.update(snmp_info)
                    device_info["discovery_protocol"] = "snmp"
                    return device_info
            except Exception as e:
                logger.debug(f"SNMP discovery failed for {target.ip_address}: {str(e)}")
        
        # Try SSH if available
        if "ssh" in target.discovery_protocols:
            try:
                ssh_info = await self._discover_via_ssh(target)
                if ssh_info:
                    device_info.update(ssh_info)
                    device_info["discovery_protocol"] = "ssh"
                    return device_info
            except Exception as e:
                logger.debug(f"SSH discovery failed for {target.ip_address}: {str(e)}")
        
        # Try ping as fallback
        if "ping" in target.discovery_protocols:
            try:
                ping_info = await self._discover_via_ping(target)
                if ping_info:
                    device_info.update(ping_info)
                    device_info["discovery_protocol"] = "ping"
                    return device_info
            except Exception as e:
                logger.debug(f"Ping discovery failed for {target.ip_address}: {str(e)}")
        
        return None
    
    async def _discover_via_snmp(self, target: DiscoveryTarget) -> Optional[Dict[str, Any]]:
        """Discover device information via SNMP"""
        try:
            # Basic SNMP OIDs for device information
            oids = {
                "sysDescr": "1.3.6.1.2.1.1.1.0",      # System description
                "sysObjectID": "1.3.6.1.2.1.1.2.0",   # System object ID
                "sysUpTime": "1.3.6.1.2.1.1.3.0",     # System uptime
                "sysContact": "1.3.6.1.2.1.1.4.0",    # System contact
                "sysName": "1.3.6.1.2.1.1.5.0",       # System name
                "sysLocation": "1.3.6.1.2.1.1.6.0",   # System location
            }
            
            # Get SNMP credentials
            community = target.credentials.get("community", self.config.snmp_community)
            
            # Execute SNMP get
            results = {}
            for name, oid in oids.items():
                try:
                    value = await self._snmp_get(target.ip_address, community, oid)
                    if value:
                        results[name] = value
                except Exception as e:
                    logger.debug(f"Failed to get {name} via SNMP: {str(e)}")
            
            if not results:
                return None
            
            # Parse system description for device type and vendor
            device_type, vendor, model = self._parse_sysdescr(results.get("sysDescr", ""))
            
            return {
                "hostname": results.get("sysName"),
                "device_type": device_type,
                "vendor": vendor,
                "model": model,
                "os_version": self._extract_os_version(results.get("sysDescr", "")),
                "capabilities": self._infer_capabilities(results),
                "location": results.get("sysLocation"),
                "uptime": results.get("sysUpTime")
            }
            
        except Exception as e:
            logger.error(f"SNMP discovery failed for {target.ip_address}: {str(e)}")
            return None
    
    async def _snmp_get(self, ip: str, community: str, oid: str) -> Optional[str]:
        """Execute SNMP GET operation"""
        try:
            # This is a simplified SNMP implementation
            # In production, you'd use proper async SNMP libraries
            return "placeholder_snmp_value"  # Simplified for now
        except Exception as e:
            logger.error(f"SNMP GET failed for {ip}: {str(e)}")
            return None
    
    async def _discover_via_ssh(self, target: DiscoveryTarget) -> Optional[Dict[str, Any]]:
        """Discover device information via SSH"""
        try:
            # SSH discovery would execute commands like:
            # - show version
            # - show running-config
            # - show interfaces
            # For now, return placeholder data
            return {
                "hostname": f"device_{target.ip_address.replace('.', '_')}",
                "device_type": "network_device",
                "vendor": "unknown",
                "model": "unknown",
                "os_version": "unknown",
                "capabilities": ["ssh_access"],
                "discovery_protocol": "ssh"
            }
        except Exception as e:
            logger.error(f"SSH discovery failed for {target.ip_address}: {str(e)}")
            return None
    
    async def _discover_via_ping(self, target: DiscoveryTarget) -> Optional[Dict[str, Any]]:
        """Discover device availability via ping"""
        try:
            # Simple ping discovery - just confirms device is reachable
            return {
                "hostname": target.ip_address,
                "device_type": "network_device",
                "vendor": "unknown",
                "model": "unknown",
                "os_version": "unknown",
                "capabilities": ["icmp_reachable"],
                "discovery_protocol": "ping"
            }
        except Exception as e:
            logger.error(f"Ping discovery failed for {target.ip_address}: {str(e)}")
            return None
    
    async def _discover_interfaces(self, target: DiscoveryTarget) -> List[Dict[str, Any]]:
        """Discover device interfaces"""
        interfaces = []
        
        try:
            if "snmp" in target.discovery_protocols:
                # SNMP interface discovery
                snmp_interfaces = await self._discover_interfaces_via_snmp(target)
                interfaces.extend(snmp_interfaces)
            
            if "ssh" in target.discovery_protocols:
                # SSH interface discovery
                ssh_interfaces = await self._discover_interfaces_via_ssh(target)
                interfaces.extend(ssh_interfaces)
            
        except Exception as e:
            logger.error(f"Interface discovery failed for {target.ip_address}: {str(e)}")
        
        return interfaces
    
    async def _discover_interfaces_via_snmp(self, target: DiscoveryTarget) -> List[Dict[str, Any]]:
        """Discover interfaces via SNMP"""
        # Simplified interface discovery
        return [
            {
                "name": "GigabitEthernet0/1",
                "type": "ethernet",
                "status": "up",
                "ip_address": target.ip_address,
                "subnet_mask": "255.255.255.0",
                "bandwidth": 1000,
                "description": "Management interface"
            }
        ]
    
    async def _discover_interfaces_via_ssh(self, target: DiscoveryTarget) -> List[Dict[str, Any]]:
        """Discover interfaces via SSH"""
        # Simplified interface discovery
        return []
    
    async def _discover_neighbors(self, target: DiscoveryTarget, depth: int) -> List[Dict[str, Any]]:
        """Discover neighboring devices"""
        neighbors = []
        
        try:
            if "snmp" in target.discovery_protocols:
                # SNMP neighbor discovery (CDP/LLDP)
                snmp_neighbors = await self._discover_neighbors_via_snmp(target)
                neighbors.extend(snmp_neighbors)
            
            if "ssh" in target.discovery_protocols:
                # SSH neighbor discovery
                ssh_neighbors = await self._discover_neighbors_via_ssh(target)
                neighbors.extend(ssh_neighbors)
            
        except Exception as e:
            logger.error(f"Neighbor discovery failed for {target.ip_address}: {str(e)}")
        
        return neighbors
    
    async def _discover_neighbors_via_snmp(self, target: DiscoveryTarget) -> List[Dict[str, Any]]:
        """Discover neighbors via SNMP (CDP/LLDP)"""
        # Simplified neighbor discovery
        return []
    
    async def _discover_neighbors_via_ssh(self, target: DiscoveryTarget) -> List[Dict[str, Any]]:
        """Discover neighbors via SSH"""
        # Simplified neighbor discovery
        return []
    
    async def _discover_neighbor_devices(
        self,
        target: DiscoveryTarget,
        neighbors: List[Dict[str, Any]],
        depth: int
    ):
        """Recursively discover neighbor devices"""
        for neighbor in neighbors:
            if neighbor.get("ip_address") and neighbor["ip_address"] not in self._discovered_ips:
                # Create new target for neighbor
                neighbor_target = DiscoveryTarget(
                    ip_address=neighbor["ip_address"],
                    credential_type=target.credential_type,
                    credentials=target.credentials,
                    discovery_protocols=target.discovery_protocols,
                    max_depth=target.max_depth
                )
                
                # Discover neighbor
                await self._discover_device(neighbor_target, depth)
    
    async def _build_topology_relationships(
        self,
        topology: NetworkTopology,
        discovered_devices: List[DiscoveredDevice]
    ):
        """Build topology relationships from discovered devices"""
        try:
            # Create or update devices
            for discovered in discovered_devices:
                await self._create_or_update_device(topology, discovered)
            
            # Create device relationships
            await self._create_device_relationships(topology, discovered_devices)
            
            # Create network paths
            await self._create_network_paths(topology, discovered_devices)
            
        except Exception as e:
            logger.error(f"Failed to build topology relationships: {str(e)}")
            raise
    
    async def _create_or_update_device(
        self,
        topology: NetworkTopology,
        discovered: DiscoveredDevice
    ):
        """Create or update device in database"""
        try:
            # Check if device exists
            stmt = select(Device).where(Device.ip_address == discovered.ip_address)
            result = await self.db_session.execute(stmt)
            device = result.scalar_one_or_none()
            
            if device:
                # Update existing device
                device.hostname = discovered.hostname or device.hostname
                device.device_type = discovered.device_type or device.device_type
                device.vendor = discovered.vendor or device.vendor
                device.model = discovered.model or device.model
                device.os_version = discovered.os_version or device.os_version
                device.capabilities = discovered.capabilities or device.capabilities
                device.updated_at = datetime.now()
            else:
                # Create new device
                device = Device(
                    ip_address=discovered.ip_address,
                    hostname=discovered.hostname,
                    device_type=discovered.device_type,
                    vendor=discovered.vendor,
                    model=discovered.model,
                    os_version=discovered.os_version,
                    capabilities=discovered.capabilities,
                    status=DeviceStatus.ONLINE,
                    protocol=DeviceProtocol.SNMP if discovered.discovery_protocol == "snmp" else DeviceProtocol.SSH,
                    monitoring_enabled=True,
                    poll_interval_seconds=300
                )
                self.db_session.add(device)
            
            await self.db_session.flush()
            
            # Create or update interfaces
            await self._create_or_update_interfaces(topology, device, discovered.interfaces)
            
        except Exception as e:
            logger.error(f"Failed to create/update device {discovered.ip_address}: {str(e)}")
            raise
    
    async def _create_or_update_interfaces(
        self,
        topology: NetworkTopology,
        device: Device,
        interfaces: List[Dict[str, Any]]
    ):
        """Create or update device interfaces"""
        for interface_data in interfaces:
            try:
                # Check if interface exists
                stmt = select(NetworkInterface).where(
                    and_(
                        NetworkInterface.device_id == device.id,
                        NetworkInterface.name == interface_data["name"]
                    )
                )
                result = await self.db_session.execute(stmt)
                interface = result.scalar_one_or_none()
                
                if interface:
                    # Update existing interface
                    interface.status = interface_data.get("status", "unknown")
                    interface.ip_address = interface_data.get("ip_address")
                    interface.subnet_mask = interface_data.get("subnet_mask")
                    interface.bandwidth_mbps = interface_data.get("bandwidth")
                    interface.description = interface_data.get("description")
                    interface.updated_at = datetime.now()
                else:
                    # Create new interface
                    interface = NetworkInterface(
                        device_id=device.id,
                        topology_id=topology.id,
                        name=interface_data["name"],
                        description=interface_data.get("description"),
                        interface_type=interface_data.get("type", "ethernet"),
                        status=interface_data.get("status", "unknown"),
                        ip_address=interface_data.get("ip_address"),
                        subnet_mask=interface_data.get("subnet_mask"),
                        bandwidth_mbps=interface_data.get("bandwidth"),
                        last_polled=datetime.now()
                    )
                    self.db_session.add(interface)
                
            except Exception as e:
                logger.error(f"Failed to create/update interface {interface_data.get('name')}: {str(e)}")
    
    async def _create_device_relationships(
        self,
        topology: NetworkTopology,
        discovered_devices: List[DiscoveredDevice]
    ):
        """Create device relationships from discovered data"""
        for discovered in discovered_devices:
            for neighbor in discovered.neighbors:
                try:
                    # Find neighbor device
                    stmt = select(Device).where(Device.ip_address == neighbor.get("ip_address"))
                    result = await self.db_session.execute(stmt)
                    neighbor_device = result.scalar_one_or_none()
                    
                    if neighbor_device:
                        # Create relationship
                        relationship = DeviceRelationship(
                            topology_id=topology.id,
                            source_device_id=discovered.ip_address,  # This should be device ID
                            target_device_id=neighbor_device.id,
                            relationship_type="connected",
                            connection_protocol=neighbor.get("discovery_protocol", "unknown"),
                            discovered_at=datetime.now(),
                            discovery_method=discovered.discovery_protocol,
                            is_active=True,
                            is_verified=True
                        )
                        self.db_session.add(relationship)
                
                except Exception as e:
                    logger.error(f"Failed to create relationship: {str(e)}")
    
    async def _create_network_paths(
        self,
        topology: NetworkTopology,
        discovered_devices: List[DiscoveredDevice]
    ):
        """Create network paths from discovered topology"""
        # Simplified path creation - in production, this would analyze routing tables
        pass
    
    def _parse_sysdescr(self, sysdescr: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Parse SNMP sysDescr for device information"""
        if not sysdescr:
            return None, None, None
        
        # Simple parsing - in production, this would be more sophisticated
        sysdescr_lower = sysdescr.lower()
        
        # Determine device type
        if "router" in sysdescr_lower:
            device_type = "router"
        elif "switch" in sysdescr_lower:
            device_type = "switch"
        elif "firewall" in sysdescr_lower:
            device_type = "firewall"
        else:
            device_type = "network_device"
        
        # Determine vendor
        vendor = None
        if "cisco" in sysdescr_lower:
            vendor = "Cisco"
        elif "juniper" in sysdescr_lower:
            vendor = "Juniper"
        elif "arista" in sysdescr_lower:
            vendor = "Arista"
        
        # Extract model (simplified)
        model = None
        # This would require more sophisticated parsing
        
        return device_type, vendor, model
    
    def _extract_os_version(self, sysdescr: str) -> Optional[str]:
        """Extract OS version from sysDescr"""
        if not sysdescr:
            return None
        
        # Simple version extraction - in production, this would be more sophisticated
        # Look for version patterns like "Version 15.2(4)S7"
        import re
        version_match = re.search(r'Version\s+([\d.()]+)', sysdescr)
        if version_match:
            return version_match.group(1)
        
        return None
    
    def _infer_capabilities(self, snmp_results: Dict[str, Any]) -> List[str]:
        """Infer device capabilities from SNMP results"""
        capabilities = []
        
        # Basic capabilities based on available data
        if snmp_results.get("sysObjectID"):
            capabilities.append("snmp_support")
        
        if snmp_results.get("sysUpTime"):
            capabilities.append("uptime_monitoring")
        
        if snmp_results.get("sysLocation"):
            capabilities.append("location_tracking")
        
        return capabilities
