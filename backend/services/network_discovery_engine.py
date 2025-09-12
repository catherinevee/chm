"""
Network Discovery Engine - Comprehensive network scanning and device discovery
"""

import asyncio
import logging
import ipaddress
import socket
import struct
import subprocess
import platform
from typing import Dict, Any, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from concurrent.futures import ThreadPoolExecutor
import json
import re

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_
import nmap
import ping3
from scapy.all import ARP, Ether, srp, ICMP, IP, sr1, TCP, UDP
from netaddr import IPNetwork, IPAddress

from backend.database.models import Device, DiscoveryJob, NetworkInterface
from backend.protocols.snmp_client import SNMPClient
from backend.protocols.ssh_client import AsyncSSHClient, DeviceSSHManager
from backend.services.device_service import DeviceService
from backend.common.exceptions import AppException

logger = logging.getLogger(__name__)


class NetworkDiscoveryEngine:
    """
    Comprehensive network discovery engine supporting multiple protocols
    """
    
    def __init__(self, db_session: AsyncSession):
        """
        Initialize discovery engine
        
        Args:
            db_session: Database session
        """
        self.db = db_session
        self.device_service = DeviceService(db_session)
        self.discovered_devices = []
        self.thread_pool = ThreadPoolExecutor(max_workers=20)
        
    async def discover_network(self,
                              ip_range: str,
                              protocols: List[str] = None,
                              credentials: Dict[str, Any] = None,
                              options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Discover devices in network range
        
        Args:
            ip_range: IP range to scan (CIDR notation)
            protocols: List of discovery protocols to use
            credentials: Authentication credentials
            options: Discovery options
            
        Returns:
            Discovery results dictionary
        """
        try:
            # Parse network range
            network = ipaddress.ip_network(ip_range, strict=False)
            total_hosts = network.num_addresses - 2  # Exclude network and broadcast
            
            logger.info(f"Starting discovery for {ip_range} ({total_hosts} hosts)")
            
            # Default protocols if not specified
            if not protocols:
                protocols = ['icmp', 'arp', 'snmp', 'ssh']
            
            # Default credentials if not provided
            if not credentials:
                credentials = {
                    'snmp_community': 'public',
                    'snmp_version': 'v2c',
                    'ssh_username': 'admin',
                    'ssh_password': None
                }
            
            # Discovery options
            options = options or {}
            parallel_scans = options.get('parallel_scans', 10)
            timeout = options.get('timeout', 5)
            
            # Phase 1: Host discovery
            active_hosts = await self._discover_active_hosts(
                network, protocols, timeout
            )
            
            logger.info(f"Found {len(active_hosts)} active hosts")
            
            # Phase 2: Device identification
            identified_devices = await self._identify_devices(
                active_hosts, protocols, credentials, parallel_scans
            )
            
            logger.info(f"Identified {len(identified_devices)} devices")
            
            # Phase 3: Detailed discovery
            detailed_devices = await self._detailed_discovery(
                identified_devices, credentials
            )
            
            # Phase 4: Store discovered devices
            stored_devices = await self._store_discovered_devices(detailed_devices)
            
            return {
                'success': True,
                'network': str(network),
                'total_hosts_scanned': total_hosts,
                'active_hosts_found': len(active_hosts),
                'devices_identified': len(identified_devices),
                'devices_stored': len(stored_devices),
                'devices': stored_devices,
                'timestamp': datetime.utcnow()
            }
            
        except Exception as e:
            logger.error(f"Discovery error: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.utcnow()
            }
    
    async def _discover_active_hosts(self,
                                    network: ipaddress.IPv4Network,
                                    protocols: List[str],
                                    timeout: int) -> List[str]:
        """
        Discover active hosts in network
        
        Args:
            network: Network to scan
            protocols: Discovery protocols
            timeout: Scan timeout
            
        Returns:
            List of active host IPs
        """
        active_hosts = set()
        
        # ICMP Ping Sweep
        if 'icmp' in protocols:
            icmp_hosts = await self._icmp_sweep(network, timeout)
            active_hosts.update(icmp_hosts)
            logger.info(f"ICMP sweep found {len(icmp_hosts)} hosts")
        
        # ARP Scan (for local network)
        if 'arp' in protocols and self._is_local_network(network):
            arp_hosts = await self._arp_scan(network)
            active_hosts.update(arp_hosts)
            logger.info(f"ARP scan found {len(arp_hosts)} hosts")
        
        # TCP SYN Scan on common ports
        if 'tcp' in protocols:
            tcp_hosts = await self._tcp_syn_scan(network, [22, 23, 80, 443, 161])
            active_hosts.update(tcp_hosts)
            logger.info(f"TCP scan found {len(tcp_hosts)} hosts")
        
        # UDP Scan for SNMP
        if 'snmp' in protocols:
            snmp_hosts = await self._udp_scan(network, [161])
            active_hosts.update(snmp_hosts)
            logger.info(f"UDP/SNMP scan found {len(snmp_hosts)} hosts")
        
        return list(active_hosts)
    
    async def _icmp_sweep(self,
                         network: ipaddress.IPv4Network,
                         timeout: int) -> List[str]:
        """
        Perform ICMP ping sweep
        
        Args:
            network: Network to sweep
            timeout: Ping timeout
            
        Returns:
            List of responding IPs
        """
        active_hosts = []
        
        # Use asyncio for parallel pinging
        tasks = []
        for ip in network.hosts():
            tasks.append(self._ping_host(str(ip), timeout))
        
        results = await asyncio.gather(*tasks)
        
        for ip, is_alive in zip(network.hosts(), results):
            if is_alive:
                active_hosts.append(str(ip))
        
        return active_hosts
    
    async def _ping_host(self, ip: str, timeout: int) -> bool:
        """
        Ping a single host
        
        Args:
            ip: IP address to ping
            timeout: Ping timeout
            
        Returns:
            True if host responds
        """
        try:
            # Use ping3 library for cross-platform ping
            response = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool,
                ping3.ping,
                ip,
                timeout
            )
            return response is not None
        except Exception as e:
            logger.debug(f"Exception, returning: {e}")
            return False
    
    async def _arp_scan(self, network: ipaddress.IPv4Network) -> List[str]:
        """
        Perform ARP scan on local network
        
        Args:
            network: Network to scan
            
        Returns:
            List of responding IPs
        """
        try:
            active_hosts = []
            
            # Create ARP request
            arp_request = ARP(pdst=str(network))
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request
            
            # Send and receive responses
            answered_list = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool,
                lambda: srp(arp_request_broadcast, timeout=2, verbose=False)[0]
            )
            
            for sent, received in answered_list:
                active_hosts.append(received.psrc)
            
            return active_hosts
            
        except Exception as e:
            logger.error(f"ARP scan error: {str(e)}")
            return []
    
    async def _tcp_syn_scan(self,
                           network: ipaddress.IPv4Network,
                           ports: List[int]) -> List[str]:
        """
        Perform TCP SYN scan
        
        Args:
            network: Network to scan
            ports: Ports to check
            
        Returns:
            List of hosts with open ports
        """
        active_hosts = set()
        
        # Use nmap for efficient scanning
        try:
            nm = nmap.PortScanner()
            
            # Scan in chunks to avoid overwhelming the network
            for ip in network.hosts():
                ip_str = str(ip)
                scan_result = await asyncio.get_event_loop().run_in_executor(
                    self.thread_pool,
                    nm.scan,
                    ip_str,
                    ','.join(map(str, ports)),
                    '-sS -T4'  # SYN scan, aggressive timing
                )
                
                if ip_str in nm.all_hosts():
                    if nm[ip_str].state() == 'up':
                        active_hosts.add(ip_str)
            
        except Exception as e:
            logger.error(f"TCP scan error: {str(e)}")
        
        return list(active_hosts)
    
    async def _udp_scan(self,
                       network: ipaddress.IPv4Network,
                       ports: List[int]) -> List[str]:
        """
        Perform UDP scan
        
        Args:
            network: Network to scan
            ports: UDP ports to check
            
        Returns:
            List of hosts with open UDP ports
        """
        active_hosts = set()
        
        for ip in network.hosts():
            for port in ports:
                if await self._check_udp_port(str(ip), port):
                    active_hosts.add(str(ip))
                    break
        
        return list(active_hosts)
    
    async def _check_udp_port(self, ip: str, port: int, timeout: int = 2) -> bool:
        """
        Check if UDP port is open
        
        Args:
            ip: Target IP
            port: UDP port
            timeout: Timeout in seconds
            
        Returns:
            True if port responds
        """
        try:
            # Create UDP packet
            udp_packet = IP(dst=ip) / UDP(dport=port)
            
            # Send packet and wait for response
            response = await asyncio.get_event_loop().run_in_executor(
                self.thread_pool,
                lambda: sr1(udp_packet, timeout=timeout, verbose=False)
            )
            
            return response is not None
            
        except Exception as e:
            logger.debug(f"Exception, returning: {e}")
            return False
    
    async def _identify_devices(self,
                               hosts: List[str],
                               protocols: List[str],
                               credentials: Dict[str, Any],
                               parallel_scans: int) -> List[Dict[str, Any]]:
        """
        Identify device types and basic information
        
        Args:
            hosts: List of host IPs
            protocols: Protocols to use
            credentials: Authentication credentials
            parallel_scans: Number of parallel scans
            
        Returns:
            List of identified devices
        """
        devices = []
        
        # Process hosts in batches
        for i in range(0, len(hosts), parallel_scans):
            batch = hosts[i:i + parallel_scans]
            tasks = []
            
            for host in batch:
                tasks.append(self._identify_single_device(
                    host, protocols, credentials
                ))
            
            batch_results = await asyncio.gather(*tasks)
            devices.extend([d for d in batch_results if d])
        
        return devices
    
    async def _identify_single_device(self,
                                     ip: str,
                                     protocols: List[str],
                                     credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Identify a single device
        
        Args:
            ip: Device IP address
            protocols: Protocols to try
            credentials: Authentication credentials
            
        Returns:
            Device information dictionary
        """
        device_info = {
            'ip_address': ip,
            'discovered_at': datetime.utcnow(),
            'discovery_methods': []
        }
        
        # Try SNMP identification
        if 'snmp' in protocols:
            snmp_info = await self._snmp_identify(ip, credentials)
            if snmp_info:
                device_info.update(snmp_info)
                device_info['discovery_methods'].append('snmp')
        
        # Try SSH identification
        if 'ssh' in protocols and not device_info.get('hostname'):
            ssh_info = await self._ssh_identify(ip, credentials)
            if ssh_info:
                device_info.update(ssh_info)
                device_info['discovery_methods'].append('ssh')
        
        # Try HTTP/HTTPS identification
        if 'http' in protocols:
            http_info = await self._http_identify(ip)
            if http_info:
                device_info.update(http_info)
                device_info['discovery_methods'].append('http')
        
        # Port fingerprinting for device type
        if not device_info.get('device_type'):
            device_info['device_type'] = await self._fingerprint_device(ip)
        
        return device_info if device_info.get('hostname') or device_info.get('device_type') else None
    
    async def _snmp_identify(self,
                            ip: str,
                            credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Identify device using SNMP
        
        Args:
            ip: Device IP
            credentials: SNMP credentials
            
        Returns:
            Device information from SNMP
        """
        try:
            client = SNMPClient(ip)
            community = credentials.get('snmp_community', 'public')
            
            # Test connectivity
            if not await client.test_connectivity(community):
                return None
            
            # Get system information
            sys_info = await client.get_system_info(community)
            
            # Determine device type from sysDescr
            device_type = self._determine_device_type(sys_info.get('description', ''))
            
            # Get interfaces for additional info
            interfaces = await client.get_interfaces(community)
            
            return {
                'hostname': sys_info.get('hostname'),
                'description': sys_info.get('description'),
                'location': sys_info.get('location'),
                'contact': sys_info.get('contact'),
                'uptime': sys_info.get('uptime'),
                'device_type': device_type,
                'interface_count': len(interfaces),
                'snmp_enabled': True,
                'snmp_version': credentials.get('snmp_version', 'v2c')
            }
            
        except Exception as e:
            logger.debug(f"SNMP identification failed for {ip}: {str(e)}")
            return None
        finally:
            if 'client' in locals():
                client.close()
    
    async def _ssh_identify(self,
                           ip: str,
                           credentials: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Identify device using SSH
        
        Args:
            ip: Device IP
            credentials: SSH credentials
            
        Returns:
            Device information from SSH
        """
        try:
            ssh_params = {
                'host': ip,
                'username': credentials.get('ssh_username', 'admin'),
                'password': credentials.get('ssh_password'),
                'timeout': 10
            }
            
            manager = DeviceSSHManager()
            device_info = await manager.get_device_info(ssh_params)
            
            if device_info:
                return {
                    'hostname': device_info.get('hostname'),
                    'vendor': device_info.get('vendor'),
                    'model': device_info.get('model'),
                    'version': device_info.get('version'),
                    'device_type': self._determine_device_type_from_vendor(
                        device_info.get('vendor', '')
                    ),
                    'ssh_enabled': True
                }
            
            return None
            
        except Exception as e:
            logger.debug(f"SSH identification failed for {ip}: {str(e)}")
            return None
    
    async def _http_identify(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Identify device using HTTP/HTTPS
        
        Args:
            ip: Device IP
            
        Returns:
            Device information from HTTP
        """
        try:
            import aiohttp
            
            device_info = {}
            
            # Try HTTPS first, then HTTP
            for protocol in ['https', 'http']:
                url = f"{protocol}://{ip}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=5),
                            ssl=False
                        ) as response:
                            # Check headers for device information
                            headers = response.headers
                            
                            if 'Server' in headers:
                                device_info['web_server'] = headers['Server']
                            
                            # Check for known device signatures
                            text = await response.text()
                            
                            # Check for router/switch web interfaces
                            if any(x in text.lower() for x in ['cisco', 'juniper', 'arista', 'mikrotik']):
                                device_info['has_web_interface'] = True
                                device_info['device_type'] = 'network_device'
                            
                            device_info[f'{protocol}_enabled'] = True
                            break
                            
                except Exception as e:
                    logger.debug(f"Exception in loop: {e}")
                    continue
            
            return device_info if device_info else None
            
        except Exception as e:
            logger.debug(f"HTTP identification failed for {ip}: {str(e)}")
            return None
    
    async def _fingerprint_device(self, ip: str) -> str:
        """
        Fingerprint device type based on open ports
        
        Args:
            ip: Device IP
            
        Returns:
            Detected device type
        """
        try:
            # Common port signatures
            port_signatures = {
                'router': [22, 23, 161, 443],
                'switch': [22, 23, 161],
                'firewall': [22, 443, 500, 4500],
                'server': [22, 80, 443, 3306, 5432],
                'printer': [9100, 515, 631],
                'camera': [554, 8000, 8080],
                'access_point': [22, 80, 443, 161],
                'load_balancer': [80, 443, 8080, 9000]
            }
            
            # Scan common ports
            open_ports = await self._scan_common_ports(ip)
            
            # Match against signatures
            best_match = 'unknown'
            best_score = 0
            
            for device_type, signature_ports in port_signatures.items():
                score = len(set(open_ports) & set(signature_ports))
                if score > best_score:
                    best_score = score
                    best_match = device_type
            
            return best_match
            
        except Exception as e:
            logger.debug(f"Device fingerprinting failed for {ip}: {str(e)}")
            return 'unknown'
    
    async def _scan_common_ports(self, ip: str) -> List[int]:
        """
        Scan common ports on device
        
        Args:
            ip: Device IP
            
        Returns:
            List of open ports
        """
        common_ports = [
            22, 23, 80, 443, 161, 162, 514, 515, 631,
            1433, 3306, 3389, 5432, 5900, 8080, 8443, 9100
        ]
        
        open_ports = []
        
        for port in common_ports:
            if await self._check_tcp_port(ip, port):
                open_ports.append(port)
        
        return open_ports
    
    async def _check_tcp_port(self, ip: str, port: int, timeout: float = 1) -> bool:
        """
        Check if TCP port is open
        
        Args:
            ip: Target IP
            port: TCP port
            timeout: Connection timeout
            
        Returns:
            True if port is open
        """
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            logger.debug(f"Exception, returning: {e}")
            return False
    
    async def _detailed_discovery(self,
                                 devices: List[Dict[str, Any]],
                                 credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Perform detailed discovery on identified devices
        
        Args:
            devices: List of identified devices
            credentials: Authentication credentials
            
        Returns:
            List of devices with detailed information
        """
        detailed_devices = []
        
        for device in devices:
            try:
                # Get additional details based on device type
                if device.get('snmp_enabled'):
                    details = await self._get_snmp_details(
                        device['ip_address'],
                        credentials
                    )
                    device.update(details)
                
                if device.get('ssh_enabled'):
                    details = await self._get_ssh_details(
                        device['ip_address'],
                        credentials
                    )
                    device.update(details)
                
                # Get neighbor information
                neighbors = await self._discover_neighbors(
                    device['ip_address'],
                    device.get('discovery_methods', []),
                    credentials
                )
                device['neighbors'] = neighbors
                
                detailed_devices.append(device)
                
            except Exception as e:
                logger.error(f"Detailed discovery error for {device['ip_address']}: {str(e)}")
                detailed_devices.append(device)
        
        return detailed_devices
    
    async def _get_snmp_details(self,
                               ip: str,
                               credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed SNMP information
        
        Args:
            ip: Device IP
            credentials: SNMP credentials
            
        Returns:
            Detailed device information
        """
        try:
            client = SNMPClient(ip)
            community = credentials.get('snmp_community', 'public')
            
            # Get interfaces with details
            interfaces = await client.get_interfaces(community)
            
            # Get CPU usage
            cpu = await client.get_cpu_usage(community)
            
            # Get memory usage
            memory = await client.get_memory_usage(community)
            
            # Get environment sensors
            sensors = await client.get_environment_sensors(community)
            
            return {
                'interfaces': interfaces,
                'cpu_usage': cpu,
                'memory_usage': memory,
                'environment_sensors': sensors,
                'metrics_available': True
            }
            
        except Exception as e:
            logger.debug(f"Failed to get SNMP details for {ip}: {str(e)}")
            return {}
        finally:
            if 'client' in locals():
                client.close()
    
    async def _get_ssh_details(self,
                              ip: str,
                              credentials: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get detailed SSH information
        
        Args:
            ip: Device IP
            credentials: SSH credentials
            
        Returns:
            Detailed device information
        """
        try:
            ssh_params = {
                'host': ip,
                'username': credentials.get('ssh_username', 'admin'),
                'password': credentials.get('ssh_password'),
                'timeout': 10
            }
            
            manager = DeviceSSHManager()
            
            # Get interfaces
            interfaces = await manager.get_interfaces(ssh_params)
            
            # Get configuration (if possible)
            try:
                config = await manager.get_configuration(ssh_params)
                has_config = bool(config)
            except Exception as e:

                logger.debug(f"Exception: {e}")
                has_config = False
            
            return {
                'ssh_interfaces': interfaces,
                'configuration_accessible': has_config,
                'management_accessible': True
            }
            
        except Exception as e:
            logger.debug(f"Failed to get SSH details for {ip}: {str(e)}")
            return {}
    
    async def _discover_neighbors(self,
                                 ip: str,
                                 discovery_methods: List[str],
                                 credentials: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Discover device neighbors using CDP/LLDP
        
        Args:
            ip: Device IP
            discovery_methods: Available discovery methods
            credentials: Authentication credentials
            
        Returns:
            List of neighbor devices
        """
        neighbors = []
        
        # Try SNMP-based neighbor discovery
        if 'snmp' in discovery_methods:
            try:
                client = SNMPClient(ip)
                community = credentials.get('snmp_community', 'public')
                
                # CDP neighbors (Cisco)
                cdp_oid = '1.3.6.1.4.1.9.9.23.1.2.1.1'
                cdp_neighbors = await client.walk(community, cdp_oid)
                
                for oid, value in cdp_neighbors:
                    if value:
                        neighbors.append({
                            'protocol': 'CDP',
                            'neighbor': str(value),
                            'discovered_via': ip
                        })
                
                # LLDP neighbors (standard)
                lldp_oid = '1.0.8802.1.1.2.1.4.1.1'
                lldp_neighbors = await client.walk(community, lldp_oid)
                
                for oid, value in lldp_neighbors:
                    if value:
                        neighbors.append({
                            'protocol': 'LLDP',
                            'neighbor': str(value),
                            'discovered_via': ip
                        })
                
            except Exception as e:
                logger.debug(f"Neighbor discovery failed for {ip}: {str(e)}")
        
        return neighbors
    
    async def _store_discovered_devices(self,
                                       devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Store discovered devices in database
        
        Args:
            devices: List of discovered devices
            
        Returns:
            List of stored device information
        """
        stored_devices = []
        
        for device_data in devices:
            try:
                # Prepare device data for storage
                device_dict = {
                    'hostname': device_data.get('hostname', device_data['ip_address']),
                    'ip_address': device_data['ip_address'],
                    'device_type': device_data.get('device_type', 'unknown'),
                    'manufacturer': device_data.get('vendor'),
                    'model': device_data.get('model'),
                    'location': device_data.get('location'),
                    'discovery_protocol': ','.join(device_data.get('discovery_methods', [])),
                    'snmp_community': device_data.get('snmp_community') if device_data.get('snmp_enabled') else None,
                    'snmp_version': device_data.get('snmp_version'),
                    'ssh_username': device_data.get('ssh_username') if device_data.get('ssh_enabled') else None
                }
                
                # Create or update device
                existing = await self.device_service._check_device_exists(
                    device_dict['ip_address'],
                    device_dict['hostname']
                )
                
                if existing:
                    # Update existing device
                    device = await self.device_service.update_device(
                        str(existing.id),
                        device_dict
                    )
                else:
                    # Create new device
                    device = await self.device_service.create_device(device_dict)
                
                # Store interfaces if available
                if device_data.get('interfaces'):
                    await self._store_interfaces(device.id, device_data['interfaces'])
                
                stored_devices.append({
                    'id': str(device.id),
                    'hostname': device.hostname,
                    'ip_address': device.ip_address,
                    'device_type': device.device_type,
                    'action': 'updated' if existing else 'created'
                })
                
            except Exception as e:
                logger.error(f"Failed to store device {device_data['ip_address']}: {str(e)}")
                stored_devices.append({
                    'ip_address': device_data['ip_address'],
                    'error': str(e),
                    'action': 'failed'
                })
        
        return stored_devices
    
    async def _store_interfaces(self,
                               device_id: UUID,
                               interfaces: List[Dict[str, Any]]):
        """
        Store device interfaces
        
        Args:
            device_id: Device UUID
            interfaces: List of interface data
        """
        try:
            for if_data in interfaces:
                interface = NetworkInterface(
                    device_id=device_id,
                    name=if_data.get('description', if_data.get('name', f"Interface{if_data.get('index', '')}")),
                    interface_type=if_data.get('type', 'unknown'),
                    speed=if_data.get('speed', 0),
                    admin_status=if_data.get('admin_status', 'unknown'),
                    operational_status=if_data.get('oper_status', 'unknown'),
                    last_change=datetime.utcnow()
                )
                
                self.db.add(interface)
            
            await self.db.commit()
            
        except Exception as e:
            logger.error(f"Failed to store interfaces for device {device_id}: {str(e)}")
            await self.db.rollback()
    
    def _determine_device_type(self, sys_descr: str) -> str:
        """
        Determine device type from SNMP sysDescr
        
        Args:
            sys_descr: System description string
            
        Returns:
            Device type
        """
        sys_descr_lower = sys_descr.lower()
        
        if any(x in sys_descr_lower for x in ['cisco ios', 'cisco nx-os', 'cisco asa']):
            if 'router' in sys_descr_lower or 'isr' in sys_descr_lower:
                return 'router'
            elif 'switch' in sys_descr_lower or 'catalyst' in sys_descr_lower:
                return 'switch'
            elif 'asa' in sys_descr_lower or 'firewall' in sys_descr_lower:
                return 'firewall'
        elif 'juniper' in sys_descr_lower:
            if 'srx' in sys_descr_lower:
                return 'firewall'
            elif 'mx' in sys_descr_lower:
                return 'router'
            elif 'ex' in sys_descr_lower:
                return 'switch'
        elif 'arista' in sys_descr_lower:
            return 'switch'
        elif 'linux' in sys_descr_lower or 'ubuntu' in sys_descr_lower:
            return 'server'
        elif 'windows' in sys_descr_lower:
            return 'server'
        elif 'printer' in sys_descr_lower:
            return 'printer'
        
        return 'unknown'
    
    def _determine_device_type_from_vendor(self, vendor: str) -> str:
        """
        Determine device type from vendor name
        
        Args:
            vendor: Vendor name
            
        Returns:
            Device type
        """
        vendor_lower = vendor.lower()
        
        vendor_map = {
            'cisco': 'network_device',
            'juniper': 'network_device',
            'arista': 'switch',
            'hp': 'switch',
            'dell': 'server',
            'vmware': 'virtual',
            'microsoft': 'server',
            'linux': 'server'
        }
        
        for key, device_type in vendor_map.items():
            if key in vendor_lower:
                return device_type
        
        return 'unknown'
    
    def _is_local_network(self, network: ipaddress.IPv4Network) -> bool:
        """
        Check if network is local (RFC1918)
        
        Args:
            network: Network to check
            
        Returns:
            True if network is local
        """
        private_networks = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16')
        ]
        
        for private_net in private_networks:
            if network.overlaps(private_net):
                return True
        
        return False