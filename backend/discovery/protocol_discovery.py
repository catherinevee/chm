"""
Enhanced Network Discovery Protocols
Implements CDP, LLDP, ARP, Ping, and Nmap discovery protocols
"""

import asyncio
import logging
import subprocess
import json
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import ipaddress
import socket
import struct

from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
from backend.storage.database import db
from backend.storage.models import (
    Device, DeviceType, DeviceStatus, NetworkDiscovery, 
    DeviceRelationship, NetworkInterface
)
from sqlalchemy import select, and_, or_

logger = logging.getLogger(__name__)

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)

@dataclass
class DiscoveredDevice:
    """Discovered device information"""
    ip_address: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os_info: Optional[str] = None
    open_ports: List[int] = None
    discovery_method: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class DeviceRelationshipInfo:
    """Device relationship information"""
    parent_device: str  # IP address
    child_device: str   # IP address
    relationship_type: str
    parent_interface: Optional[str] = None
    child_interface: Optional[str] = None
    discovery_protocol: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class EnhancedNetworkDiscovery:
    """Enhanced network discovery with multiple protocols"""
    
    # SNMP OIDs for various discovery protocols
    CDP_OIDS = {
        'cdp_cache_address': '1.3.6.1.4.1.9.9.23.1.2.1.1.4',
        'cdp_cache_device_id': '1.3.6.1.4.1.9.9.23.1.2.1.1.6',
        'cdp_cache_device_port': '1.3.6.1.4.1.9.9.23.1.2.1.1.7',
        'cdp_cache_platform': '1.3.6.1.4.1.9.9.23.1.2.1.1.8',
        'cdp_cache_capabilities': '1.3.6.1.4.1.9.9.23.1.2.1.1.9',
        'cdp_interface_enable': '1.3.6.1.4.1.9.9.23.1.1.1.1.2',
    }
    
    LLDP_OIDS = {
        'lldp_rem_chassis_id': '1.0.8802.1.1.2.1.4.1.1.5',
        'lldp_rem_port_id': '1.0.8802.1.1.2.1.4.1.1.7',
        'lldp_rem_port_desc': '1.0.8802.1.1.2.1.4.1.1.8',
        'lldp_rem_sys_name': '1.0.8802.1.1.2.1.4.1.1.9',
        'lldp_rem_sys_desc': '1.0.8802.1.1.2.1.4.1.1.10',
        'lldp_rem_sys_cap_supported': '1.0.8802.1.1.2.1.4.1.1.11',
        'lldp_rem_sys_cap_enabled': '1.0.8802.1.1.2.1.4.1.1.12',
    }
    
    ARP_OIDS = {
        'ip_net_to_media_if_index': '1.3.6.1.2.1.4.22.1.1',
        'ip_net_to_media_phys_address': '1.3.6.1.2.1.4.22.1.2',
        'ip_net_to_media_net_address': '1.3.6.1.2.1.4.22.1.3',
        'ip_net_to_media_type': '1.3.6.1.2.1.4.22.1.4',
    }
    
    def __init__(self):
        self.session_cache = {}
    
    async def discover_network(
        self, 
        network_cidr: str, 
        protocols: List[str], 
        discovery_name: Optional[str] = None
    ) -> NetworkDiscovery:
        """Discover network using specified protocols"""
        
        discovery = NetworkDiscovery(
            name=discovery_name or f"Discovery_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            network_cidr=network_cidr,
            protocol=",".join(protocols),
            status="running",
            start_time=datetime.utcnow()
        )
        
        await db.add(discovery)
        await db.commit()
        await db.refresh(discovery)
        
        try:
            discovered_devices = []
            discovered_relationships = []
            
            # Parse network CIDR
            network = ipaddress.ip_network(network_cidr, strict=False)
            
            # Discover devices using different protocols
            if "ping" in protocols:
                ping_devices = await self._discover_ping(network)
                discovered_devices.extend(ping_devices)
            
            if "arp" in protocols:
                arp_devices = await self._discover_arp(network)
                discovered_devices.extend(arp_devices)
            
            if "nmap" in protocols:
                nmap_devices = await self._discover_nmap(network)
                discovered_devices.extend(nmap_devices)
            
            if "snmp" in protocols:
                snmp_devices = await self._discover_snmp(network)
                discovered_devices.extend(snmp_devices)
            
            # Discover relationships using CDP/LLDP
            if "cdp" in protocols:
                cdp_relationships = await self._discover_cdp_relationships(discovered_devices)
                discovered_relationships.extend(cdp_relationships)
            
            if "lldp" in protocols:
                lldp_relationships = await self._discover_lldp_relationships(discovered_devices)
                discovered_relationships.extend(lldp_relationships)
            
            # Remove duplicates
            unique_devices = self._deduplicate_devices(discovered_devices)
            
            # Add devices to database
            devices_added = 0
            for device_info in unique_devices:
                try:
                    device = await self._add_discovered_device(device_info)
                    if device:
                        devices_added += 1
                except Exception as e:
                    logger.error(f"Failed to add device {device_info.ip_address}: {e}")
            
            # Add relationships
            relationships_added = 0
            for rel_info in discovered_relationships:
                try:
                    relationship = await self._add_device_relationship(rel_info)
                    if relationship:
                        relationships_added += 1
                except Exception as e:
                    logger.error(f"Failed to add relationship: {e}")
            
            # Update discovery status
            discovery.status = "completed"
            discovery.end_time = datetime.utcnow()
            discovery.devices_found = len(unique_devices)
            discovery.devices_added = devices_added
            
            await db.commit()
            
            logger.info(f"Discovery completed: {len(unique_devices)} devices found, {devices_added} added")
            
        except Exception as e:
            discovery.status = "failed"
            discovery.end_time = datetime.utcnow()
            discovery.error_message = str(e)
            await db.commit()
            logger.error(f"Discovery failed: {e}")
            raise
        
        return discovery
    
    async def _discover_ping(self, network: ipaddress.IPv4Network) -> List[DiscoveredDevice]:
        """Discover devices using ping sweep"""
        
        devices = []
        
        try:
            # Limit to reasonable network sizes
            if network.num_addresses > 1024:
                logger.warning(f"Network {network} too large for ping sweep, limiting to /22")
                network = ipaddress.ip_network(f"{network.network_address}/22", strict=False)
            
            # Create ping tasks
            ping_tasks = []
            for ip in network.hosts():
                ping_tasks.append(self._ping_host(str(ip)))
                
                # Limit concurrent pings
                if len(ping_tasks) >= 50:
                    results = await asyncio.gather(*ping_tasks, return_exceptions=True)
                    for result in results:
                        if isinstance(result, DiscoveredDevice):
                            devices.append(result)
                    ping_tasks = []
            
            # Process remaining tasks
            if ping_tasks:
                results = await asyncio.gather(*ping_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, DiscoveredDevice):
                        devices.append(result)
            
            logger.info(f"Ping discovery found {len(devices)} responsive hosts")
            
        except Exception as e:
            logger.error(f"Ping discovery failed: {e}")
        
        return devices
    
    async def _ping_host(self, ip_address: str) -> Optional[DiscoveredDevice]:
        """Ping a single host"""
        
        try:
            # Use system ping command
            cmd = ['ping', '-c', '1', '-W', '2', ip_address]
            
            # On Windows, use different parameters
            import platform
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', '2000', ip_address]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=5.0)
            
            if process.returncode == 0:
                # Try to resolve hostname
                hostname = None
                try:
                    hostname = socket.gethostbyaddr(ip_address)[0]
                except:
                    pass
                
                return DiscoveredDevice(
                    ip_address=ip_address,
                    hostname=hostname,
                    discovery_method="ping",
                    metadata={"ping_responsive": True}
                )
        
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            logger.debug(f"Ping failed for {ip_address}: {e}")
        
        # Return fallback ping data when ping fails
        fallback_data = FallbackData(
            data={
                'ip_address': ip_address,
                'status': 'unreachable',
                'response_time': 999.0,
                'packet_loss': 100.0
            },
            source="ping_fallback",
            confidence=0.0,
            metadata={"ip_address": ip_address, "error": str(e)}
        )
        
        return create_failure_result(
            error=f"Ping failed for {ip_address}",
            error_code="PING_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Ping failed",
                "Check network connectivity",
                "Verify firewall rules",
                "Consider alternative discovery methods"
            ]
        )
    
    async def _discover_arp(self, network: ipaddress.IPv4Network) -> List[DiscoveredDevice]:
        """Discover devices using ARP table queries"""
        
        devices = []
        
        try:
            # Get ARP table from system
            system_arp_devices = await self._get_system_arp_table()
            
            # Filter for network
            for device in system_arp_devices:
                try:
                    device_ip = ipaddress.ip_address(device.ip_address)
                    if device_ip in network:
                        devices.append(device)
                except:
                    continue
            
            # Query SNMP ARP tables from known devices
            snmp_arp_devices = await self._get_snmp_arp_tables(network)
            devices.extend(snmp_arp_devices)
            
            logger.info(f"ARP discovery found {len(devices)} devices")
            
        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
        
        return devices
    
    async def _get_system_arp_table(self) -> List[DiscoveredDevice]:
        """Get ARP table from local system"""
        
        devices = []
        
        try:
            # Use system ARP command
            import platform
            if platform.system().lower() == 'windows':
                cmd = ['arp', '-a']
            else:
                cmd = ['arp', '-a']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                devices = self._parse_arp_output(output)
            
        except Exception as e:
            logger.error(f"Failed to get system ARP table: {e}")
        
        return devices
    
    def _parse_arp_output(self, output: str) -> List[DiscoveredDevice]:
        """Parse ARP command output"""
        
        devices = []
        
        # Parse different ARP output formats
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Windows format: "  192.168.1.1          00-11-22-33-44-55     dynamic"
            windows_match = re.match(r'^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)', line)
            if windows_match:
                ip_addr, mac_addr, arp_type = windows_match.groups()
                devices.append(DiscoveredDevice(
                    ip_address=ip_addr,
                    mac_address=mac_addr.replace('-', ':'),
                    discovery_method="arp",
                    metadata={"arp_type": arp_type}
                ))
                continue
            
            # Linux format: "192.168.1.1 (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
            linux_match = re.match(r'^(\d+\.\d+\.\d+\.\d+).*at\s+([0-9a-fA-F:]{17})', line)
            if linux_match:
                ip_addr, mac_addr = linux_match.groups()
                devices.append(DiscoveredDevice(
                    ip_address=ip_addr,
                    mac_address=mac_addr,
                    discovery_method="arp",
                    metadata={"source": "system_arp"}
                ))
        
        return devices
    
    async def _get_snmp_arp_tables(self, network: ipaddress.IPv4Network) -> List[DiscoveredDevice]:
        """Get ARP tables from SNMP-enabled devices"""
        
        devices = []
        
        try:
            # Get existing devices that might have ARP tables
            existing_devices_query = select(Device).where(Device.current_state == DeviceStatus.ONLINE)
            result = await db.execute(existing_devices_query)
            existing_devices = result.scalars().all()
            
            for device in existing_devices:
                try:
                    device_arp = await self._query_snmp_arp_table(device)
                    # Filter for target network
                    for arp_device in device_arp:
                        try:
                            device_ip = ipaddress.ip_address(arp_device.ip_address)
                            if device_ip in network:
                                devices.append(arp_device)
                        except:
                            continue
                except Exception as e:
                    logger.debug(f"Failed to get ARP table from {device.hostname}: {e}")
            
        except Exception as e:
            logger.error(f"SNMP ARP discovery failed: {e}")
        
        return devices
    
    async def _query_snmp_arp_table(self, device: Device) -> List[DiscoveredDevice]:
        """Query ARP table from a device via SNMP"""
        
        devices = []
        
        try:
            session = await self._get_snmp_session(device)
            if not session:
                return devices
            
            # Walk ARP table
            arp_addresses = await session.walk_oid(self.ARP_OIDS['ip_net_to_media_net_address'])
            arp_mac_addresses = await session.walk_oid(self.ARP_OIDS['ip_net_to_media_phys_address'])
            
            if arp_addresses and arp_mac_addresses:
                for i, (addr_oid, ip_bytes) in enumerate(arp_addresses):
                    if i < len(arp_mac_addresses):
                        mac_oid, mac_bytes = arp_mac_addresses[i]
                        
                        # Convert IP bytes to string
                        if len(ip_bytes) >= 4:
                            ip_addr = '.'.join(str(b) for b in ip_bytes[-4:])
                            
                            # Convert MAC bytes to string
                            if len(mac_bytes) >= 6:
                                mac_addr = ':'.join(f'{b:02x}' for b in mac_bytes[-6:])
                                
                                devices.append(DiscoveredDevice(
                                    ip_address=ip_addr,
                                    mac_address=mac_addr,
                                    discovery_method="snmp_arp",
                                    metadata={
                                        "source_device": device.hostname,
                                        "source_ip": device.ip_address
                                    }
                                ))
            
        except Exception as e:
            logger.error(f"Failed to query ARP table from {device.hostname}: {e}")
        
        return devices
    
    async def _discover_nmap(self, network: ipaddress.IPv4Network) -> List[DiscoveredDevice]:
        """Discover devices using Nmap"""
        
        devices = []
        
        try:
            # Check if nmap is available
            try:
                process = await asyncio.create_subprocess_exec(
                    'nmap', '--version',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                if process.returncode != 0:
                    logger.warning("Nmap not available, skipping Nmap discovery")
                    return devices
            except FileNotFoundError:
                logger.warning("Nmap not found, skipping Nmap discovery")
                return devices
            
            # Limit network size for Nmap
            if network.num_addresses > 256:
                logger.warning(f"Network {network} too large for Nmap, limiting to /24")
                network = ipaddress.ip_network(f"{network.network_address}/24", strict=False)
            
            # Run Nmap scan
            cmd = [
                'nmap', '-sn', '-n', '--max-retries', '1', '--max-rtt-timeout', '2s',
                str(network)
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)
            
            if process.returncode == 0:
                output = stdout.decode()
                devices = self._parse_nmap_output(output)
            
            # Run detailed scan on responsive hosts
            if devices and len(devices) <= 20:  # Limit detailed scans
                detailed_devices = await self._nmap_detailed_scan([d.ip_address for d in devices])
                # Merge detailed information
                for detailed in detailed_devices:
                    for device in devices:
                        if device.ip_address == detailed.ip_address:
                            device.open_ports = detailed.open_ports
                            device.os_info = detailed.os_info
                            if detailed.metadata:
                                device.metadata = {**(device.metadata or {}), **detailed.metadata}
            
            logger.info(f"Nmap discovery found {len(devices)} devices")
            
        except asyncio.TimeoutError:
            logger.warning("Nmap scan timed out")
        except Exception as e:
            logger.error(f"Nmap discovery failed: {e}")
        
        return devices
    
    def _parse_nmap_output(self, output: str) -> List[DiscoveredDevice]:
        """Parse Nmap output"""
        
        devices = []
        
        # Parse Nmap output
        for line in output.split('\n'):
            line = line.strip()
            
            # Look for "Nmap scan report for" lines
            if line.startswith('Nmap scan report for'):
                # Extract IP address
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    ip_addr = ip_match.group(1)
                    
                    # Extract hostname if present
                    hostname = None
                    hostname_match = re.search(r'for (.+) \(', line)
                    if hostname_match:
                        hostname = hostname_match.group(1)
                    
                    devices.append(DiscoveredDevice(
                        ip_address=ip_addr,
                        hostname=hostname,
                        discovery_method="nmap",
                        metadata={"nmap_responsive": True}
                    ))
        
        return devices
    
    async def _nmap_detailed_scan(self, ip_addresses: List[str]) -> List[DiscoveredDevice]:
        """Perform detailed Nmap scan"""
        
        devices = []
        
        try:
            # Run detailed scan
            cmd = [
                'nmap', '-sV', '-O', '--max-retries', '1', '--max-rtt-timeout', '5s'
            ] + ip_addresses
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=600)
            
            if process.returncode == 0:
                output = stdout.decode()
                devices = self._parse_nmap_detailed_output(output)
            
        except Exception as e:
            logger.error(f"Detailed Nmap scan failed: {e}")
        
        return devices
    
    def _parse_nmap_detailed_output(self, output: str) -> List[DiscoveredDevice]:
        """Parse detailed Nmap output"""
        
        devices = []
        current_device = None
        
        for line in output.split('\n'):
            line = line.strip()
            
            # New device
            if line.startswith('Nmap scan report for'):
                if current_device:
                    devices.append(current_device)
                
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    current_device = DiscoveredDevice(
                        ip_address=ip_match.group(1),
                        discovery_method="nmap_detailed",
                        open_ports=[],
                        metadata={}
                    )
            
            # Open ports
            elif current_device and '/tcp' in line and 'open' in line:
                port_match = re.search(r'(\d+)/tcp', line)
                if port_match:
                    port = int(port_match.group(1))
                    current_device.open_ports.append(port)
                    
                    # Extract service information
                    service_match = re.search(r'open\s+(\w+)', line)
                    if service_match:
                        service = service_match.group(1)
                        current_device.metadata[f'port_{port}_service'] = service
            
            # OS detection
            elif current_device and line.startswith('Running:'):
                os_info = line.replace('Running:', '').strip()
                current_device.os_info = os_info
            
            # Device type detection
            elif current_device and line.startswith('Device type:'):
                device_type = line.replace('Device type:', '').strip()
                current_device.device_type = device_type
        
        # Add last device
        if current_device:
            devices.append(current_device)
        
        return devices
    
    async def _discover_snmp(self, network: ipaddress.IPv4Network) -> List[DiscoveredDevice]:
        """Discover devices using SNMP"""
        
        devices = []
        
        try:
            # Try SNMP on common IPs in the network
            snmp_tasks = []
            
            # Limit to reasonable number of IPs
            ip_list = list(network.hosts())
            if len(ip_list) > 100:
                # Sample common IPs: .1, .254, .10-20, etc.
                common_ips = []
                for ip in ip_list:
                    last_octet = int(str(ip).split('.')[-1])
                    if last_octet in [1, 2, 3, 4, 5, 10, 11, 12, 13, 14, 15, 20, 50, 100, 254]:
                        common_ips.append(str(ip))
                ip_list = common_ips[:50]  # Limit to 50 IPs
            else:
                ip_list = [str(ip) for ip in ip_list]
            
            for ip in ip_list:
                snmp_tasks.append(self._try_snmp_discovery(ip))
                
                # Process in batches
                if len(snmp_tasks) >= 20:
                    results = await asyncio.gather(*snmp_tasks, return_exceptions=True)
                    for result in results:
                        if isinstance(result, DiscoveredDevice):
                            devices.append(result)
                    snmp_tasks = []
            
            # Process remaining tasks
            if snmp_tasks:
                results = await asyncio.gather(*snmp_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, DiscoveredDevice):
                        devices.append(result)
            
            logger.info(f"SNMP discovery found {len(devices)} devices")
            
        except Exception as e:
            logger.error(f"SNMP discovery failed: {e}")
        
        return devices
    
    async def _try_snmp_discovery(self, ip_address: str) -> Optional[DiscoveredDevice]:
        """Try SNMP discovery on a single IP"""
        
        try:
            # Try common SNMP communities
            communities = ['public', 'private', 'community']
            
            for community in communities:
                try:
                    credentials = SNMPCredentials(version="2c", community=community)
                    session = SNMPSession(host=ip_address, credentials=credentials)
                    
                    if await session.connect():
                        # Get basic system information
                        sys_name = await session.get_single_oid('1.3.6.1.2.1.1.5.0')
                        sys_descr = await session.get_single_oid('1.3.6.1.2.1.1.1.0')
                        
                        if sys_name or sys_descr:
                            # Determine device type from description
                            device_type = self._determine_device_type(str(sys_descr) if sys_descr else "")
                            
                            return DiscoveredDevice(
                                ip_address=ip_address,
                                hostname=str(sys_name) if sys_name else None,
                                device_type=device_type,
                                discovery_method="snmp",
                                metadata={
                                    "snmp_community": community,
                                    "sys_descr": str(sys_descr) if sys_descr else None
                                }
                            )
                
                except Exception:
                    continue
            
        except Exception as e:
            logger.debug(f"SNMP discovery failed for {ip_address}: {e}")
        
        # Return fallback device data when SNMP discovery fails
        fallback_data = FallbackData(
            data=DiscoveredDevice(
                ip_address=ip_address,
                hostname=f"unknown-{ip_address.replace('.', '-')}",
                device_type="unknown",
                discovery_method="snmp_failed",
                metadata={"error": str(e)}
            ),
            source="snmp_discovery_fallback",
            confidence=0.0,
            metadata={"ip_address": ip_address, "error": str(e)}
        )
        
        return create_failure_result(
            error=f"SNMP discovery failed for {ip_address}",
            error_code="SNMP_DISCOVERY_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "SNMP discovery failed",
                "Check SNMP configuration",
                "Verify community strings",
                "Consider alternative discovery methods"
            ]
        )
    
    def _determine_device_type(self, sys_descr: str) -> str:
        """Determine device type from system description"""
        
        sys_descr_lower = sys_descr.lower()
        
        if any(keyword in sys_descr_lower for keyword in ['router', 'routing']):
            return 'router'
        elif any(keyword in sys_descr_lower for keyword in ['switch', 'switching']):
            return 'switch'
        elif any(keyword in sys_descr_lower for keyword in ['firewall', 'security']):
            return 'firewall'
        elif any(keyword in sys_descr_lower for keyword in ['server', 'linux', 'windows', 'unix']):
            return 'server'
        elif any(keyword in sys_descr_lower for keyword in ['printer', 'print']):
            return 'printer'
        elif any(keyword in sys_descr_lower for keyword in ['camera', 'surveillance']):
            return 'camera'
        else:
            return 'other'
    
    async def _discover_cdp_relationships(self, devices: List[DiscoveredDevice]) -> List[DeviceRelationshipInfo]:
        """Discover device relationships using CDP"""
        
        relationships = []
        
        try:
            for device_info in devices:
                if device_info.discovery_method in ['snmp', 'snmp_arp']:
                    try:
                        device_relationships = await self._query_cdp_neighbors(device_info.ip_address)
                        relationships.extend(device_relationships)
                    except Exception as e:
                        logger.debug(f"CDP query failed for {device_info.ip_address}: {e}")
            
            logger.info(f"CDP discovery found {len(relationships)} relationships")
            
        except Exception as e:
            logger.error(f"CDP relationship discovery failed: {e}")
        
        return relationships
    
    async def _query_cdp_neighbors(self, device_ip: str) -> List[DeviceRelationshipInfo]:
        """Query CDP neighbors from a device"""
        
        relationships = []
        
        try:
            # Create SNMP session
            credentials = SNMPCredentials(version="2c", community="public")
            session = SNMPSession(host=device_ip, credentials=credentials)
            
            if await session.connect():
                # Query CDP cache
                cdp_addresses = await session.walk_oid(self.CDP_OIDS['cdp_cache_address'])
                cdp_device_ids = await session.walk_oid(self.CDP_OIDS['cdp_cache_device_id'])
                cdp_device_ports = await session.walk_oid(self.CDP_OIDS['cdp_cache_device_port'])
                cdp_platforms = await session.walk_oid(self.CDP_OIDS['cdp_cache_platform'])
                
                if cdp_addresses and cdp_device_ids:
                    for i, (addr_oid, neighbor_ip_bytes) in enumerate(cdp_addresses):
                        if i < len(cdp_device_ids):
                            device_id_oid, device_id = cdp_device_ids[i]
                            
                            # Convert IP bytes to string
                            if len(neighbor_ip_bytes) >= 4:
                                neighbor_ip = '.'.join(str(b) for b in neighbor_ip_bytes[-4:])
                                
                                # Get interface information
                                local_interface = None
                                remote_interface = None
                                
                                if i < len(cdp_device_ports):
                                    remote_interface = str(cdp_device_ports[i][1])
                                
                                # Extract local interface from OID
                                oid_parts = addr_oid.split('.')
                                if len(oid_parts) > 2:
                                    local_if_index = oid_parts[-2]
                                    # TODO: Map interface index to interface name
                                
                                relationships.append(DeviceRelationshipInfo(
                                    parent_device=device_ip,
                                    child_device=neighbor_ip,
                                    relationship_type="cdp_neighbor",
                                    parent_interface=local_interface,
                                    child_interface=remote_interface,
                                    discovery_protocol="cdp",
                                    metadata={
                                        "neighbor_device_id": str(device_id),
                                        "platform": str(cdp_platforms[i][1]) if i < len(cdp_platforms) else None
                                    }
                                ))
            
        except Exception as e:
            logger.error(f"Failed to query CDP neighbors from {device_ip}: {e}")
        
        return relationships
    
    async def _discover_lldp_relationships(self, devices: List[DiscoveredDevice]) -> List[DeviceRelationshipInfo]:
        """Discover device relationships using LLDP"""
        
        relationships = []
        
        try:
            for device_info in devices:
                if device_info.discovery_method in ['snmp', 'snmp_arp']:
                    try:
                        device_relationships = await self._query_lldp_neighbors(device_info.ip_address)
                        relationships.extend(device_relationships)
                    except Exception as e:
                        logger.debug(f"LLDP query failed for {device_info.ip_address}: {e}")
            
            logger.info(f"LLDP discovery found {len(relationships)} relationships")
            
        except Exception as e:
            logger.error(f"LLDP relationship discovery failed: {e}")
        
        return relationships
    
    async def _query_lldp_neighbors(self, device_ip: str) -> List[DeviceRelationshipInfo]:
        """Query LLDP neighbors from a device"""
        
        relationships = []
        
        try:
            # Create SNMP session
            credentials = SNMPCredentials(version="2c", community="public")
            session = SNMPSession(host=device_ip, credentials=credentials)
            
            if await session.connect():
                # Query LLDP remote table
                lldp_chassis_ids = await session.walk_oid(self.LLDP_OIDS['lldp_rem_chassis_id'])
                lldp_sys_names = await session.walk_oid(self.LLDP_OIDS['lldp_rem_sys_name'])
                lldp_port_ids = await session.walk_oid(self.LLDP_OIDS['lldp_rem_port_id'])
                lldp_port_descs = await session.walk_oid(self.LLDP_OIDS['lldp_rem_port_desc'])
                
                if lldp_chassis_ids and lldp_sys_names:
                    for i, (chassis_oid, chassis_id) in enumerate(lldp_chassis_ids):
                        if i < len(lldp_sys_names):
                            sys_name_oid, sys_name = lldp_sys_names[i]
                            
                            # Extract interface information from OID
                            oid_parts = chassis_oid.split('.')
                            local_interface = None
                            if len(oid_parts) > 3:
                                local_if_index = oid_parts[-3]
                                # TODO: Map interface index to interface name
                            
                            remote_interface = None
                            if i < len(lldp_port_descs):
                                remote_interface = str(lldp_port_descs[i][1])
                            
                            relationships.append(DeviceRelationshipInfo(
                                parent_device=device_ip,
                                child_device=str(sys_name),  # LLDP uses system name, not IP
                                relationship_type="lldp_neighbor",
                                parent_interface=local_interface,
                                child_interface=remote_interface,
                                discovery_protocol="lldp",
                                metadata={
                                    "neighbor_chassis_id": str(chassis_id),
                                    "neighbor_sys_name": str(sys_name)
                                }
                            ))
            
        except Exception as e:
            logger.error(f"Failed to query LLDP neighbors from {device_ip}: {e}")
        
        return relationships
    
    def _deduplicate_devices(self, devices: List[DiscoveredDevice]) -> List[DiscoveredDevice]:
        """Remove duplicate devices based on IP address"""
        
        seen_ips = set()
        unique_devices = []
        
        for device in devices:
            if device.ip_address not in seen_ips:
                seen_ips.add(device.ip_address)
                unique_devices.append(device)
            else:
                # Merge information from duplicate
                for existing in unique_devices:
                    if existing.ip_address == device.ip_address:
                        # Merge hostname
                        if device.hostname and not existing.hostname:
                            existing.hostname = device.hostname
                        
                        # Merge MAC address
                        if device.mac_address and not existing.mac_address:
                            existing.mac_address = device.mac_address
                        
                        # Merge other fields
                        if device.vendor and not existing.vendor:
                            existing.vendor = device.vendor
                        
                        if device.device_type and not existing.device_type:
                            existing.device_type = device.device_type
                        
                        if device.os_info and not existing.os_info:
                            existing.os_info = device.os_info
                        
                        # Merge open ports
                        if device.open_ports:
                            if existing.open_ports:
                                existing.open_ports.extend(device.open_ports)
                                existing.open_ports = list(set(existing.open_ports))
                            else:
                                existing.open_ports = device.open_ports
                        
                        # Merge metadata
                        if device.metadata:
                            if existing.metadata:
                                existing.metadata.update(device.metadata)
                            else:
                                existing.metadata = device.metadata
                        
                        # Update discovery method to include both
                        if device.discovery_method != existing.discovery_method:
                            existing.discovery_method = f"{existing.discovery_method},{device.discovery_method}"
                        
                        break
        
        return unique_devices
    
    async def _add_discovered_device(self, device_info: DiscoveredDevice) -> Optional[Device]:
        """Add discovered device to database"""
        
        try:
            # Check if device already exists
            existing_query = select(Device).where(Device.ip_address == device_info.ip_address)
            result = await db.execute(existing_query)
            existing_device = result.scalar_one_or_none()
            
            if existing_device:
                # Update existing device with new information
                if device_info.hostname and not existing_device.hostname:
                    existing_device.hostname = device_info.hostname
                
                if device_info.device_type and not existing_device.device_type:
                    try:
                        existing_device.device_type = DeviceType(device_info.device_type)
                    except ValueError:
                        existing_device.device_type = DeviceType.OTHER
                
                existing_device.current_state = DeviceStatus.ONLINE
                existing_device.discovery_protocol = device_info.discovery_method
                existing_device.last_discovery = datetime.utcnow()
                existing_device.discovery_status = "discovered"
                
                await db.commit()
                return existing_device
            else:
                # Create new device
                device_type = DeviceType.OTHER
                if device_info.device_type:
                    try:
                        device_type = DeviceType(device_info.device_type)
                    except ValueError:
                        device_type = DeviceType.OTHER
                
                new_device = Device(
                    hostname=device_info.hostname or f"device-{device_info.ip_address}",
                    ip_address=device_info.ip_address,
                    device_type=device_type,
                    current_state=DeviceStatus.ONLINE,
                    discovery_protocol=device_info.discovery_method,
                    last_discovery=datetime.utcnow(),
                    discovery_status="discovered"
                )
                
                # Add additional information
                if device_info.os_info:
                    new_device.os_version = device_info.os_info[:255]  # Truncate if too long
                
                await db.add(new_device)
                await db.commit()
                await db.refresh(new_device)
                
                logger.info(f"Added new device: {device_info.ip_address} ({device_info.hostname})")
                return new_device
        
        except Exception as e:
            logger.error(f"Failed to add device {device_info.ip_address}: {e}")
            await db.rollback()
        
        return create_failure_result(
            error_code="DEVICE_ADDITION_FAILED",
            message=f"Failed to add device {device_info.ip_address}",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.ERROR,
                    message="Device addition failed",
                    details=f"Failed to add device {device_info.ip_address}: {str(e)}"
                )
            ),
            suggestions=["Check database connectivity", "Verify device data format", "Review error details"]
        )
    
    async def _add_device_relationship(self, rel_info: DeviceRelationshipInfo) -> Optional[DeviceRelationship]:
        """Add device relationship to database"""
        
        try:
            # Find parent and child devices
            parent_query = select(Device).where(Device.ip_address == rel_info.parent_device)
            parent_result = await db.execute(parent_query)
            parent_device = parent_result.scalar_one_or_none()
            
            # For LLDP, child_device might be a hostname
            if rel_info.discovery_protocol == "lldp":
                child_query = select(Device).where(
                    or_(Device.ip_address == rel_info.child_device, Device.hostname == rel_info.child_device)
                )
            else:
                child_query = select(Device).where(Device.ip_address == rel_info.child_device)
            
            child_result = await db.execute(child_query)
            child_device = child_result.scalar_one_or_none()
            
            if parent_device and child_device:
                # Check if relationship already exists
                existing_query = select(DeviceRelationship).where(
                    and_(
                        DeviceRelationship.parent_device_id == parent_device.id,
                        DeviceRelationship.child_device_id == child_device.id,
                        DeviceRelationship.relationship_type == rel_info.relationship_type
                    )
                )
                existing_result = await db.execute(existing_query)
                existing_rel = existing_result.scalar_one_or_none()
                
                if not existing_rel:
                    new_relationship = DeviceRelationship(
                        parent_device_id=parent_device.id,
                        child_device_id=child_device.id,
                        relationship_type=rel_info.relationship_type,
                        parent_interface=rel_info.parent_interface,
                        child_interface=rel_info.child_interface,
                        discovery_protocol=rel_info.discovery_protocol,
                        metadata=rel_info.metadata
                    )
                    
                    await db.add(new_relationship)
                    await db.commit()
                    await db.refresh(new_relationship)
                    
                    logger.info(f"Added relationship: {parent_device.hostname} -> {child_device.hostname}")
                    return new_relationship
        
        except Exception as e:
            logger.error(f"Failed to add relationship: {e}")
            await db.rollback()
        
        return create_failure_result(
            error_code="RELATIONSHIP_ADDITION_FAILED",
            message="Failed to add device relationship",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.ERROR,
                    message="Relationship addition failed",
                    details=f"Failed to add relationship: {str(e)}"
                )
            ),
            suggestions=["Check database connectivity", "Verify relationship data", "Review error details"]
        )
    
    async def _get_snmp_session(self, device: Device) -> Optional[SNMPSession]:
        """Get SNMP session for device"""
        
        try:
            # Use cached session if available
            if device.id in self.session_cache:
                return self.session_cache[device.id]
            
            # Create new session with default credentials
            credentials = SNMPCredentials(version="2c", community="public")
            session = SNMPSession(host=device.ip_address, credentials=credentials)
            
            if await session.connect():
                self.session_cache[device.id] = session
                return session
        
        except Exception as e:
            logger.error(f"Failed to create SNMP session for {device.hostname}: {e}")
        
        return create_failure_result(
            error_code="SNMP_SESSION_CREATION_FAILED",
            message=f"Failed to create SNMP session for {device.hostname}",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.ERROR,
                    message="SNMP session creation failed",
                    details=f"Failed to create SNMP session for {device.hostname}: {str(e)}"
                )
            ),
            suggestions=["Check SNMP credentials", "Verify network connectivity", "Review SNMP configuration"]
        )

# Global network discovery instance
enhanced_discovery = EnhancedNetworkDiscovery()
