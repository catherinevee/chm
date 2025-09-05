"""
CHM Network Discovery Service
Comprehensive network discovery service with multiple discovery methods
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
import ipaddress
import socket
import subprocess
import json
import time

# SNMP imports for device identification
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("PySNMP not available - SNMP discovery disabled")

# SSH imports for device identification
try:
    import asyncssh
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    logging.warning("AsyncSSH not available - SSH discovery disabled")

from core.database import get_db
from models.device import Device, DeviceType, DeviceProtocol, DeviceStatus
from models.device_credentials import DeviceCredentials, CredentialType
from models.discovery_job import DiscoveryJob, DiscoveryType, DiscoveryStatus
from models.result_objects import DiscoveryResult, OperationStatus
from services.credential_manager import credential_manager

logger = logging.getLogger(__name__)

@dataclass
class DiscoveryConfig:
    """Configuration for network discovery"""
    default_community_strings: List[str] = None
    default_ssh_credentials: List[Tuple[str, str]] = None  # (username, password)
    ping_timeout: float = 1.0
    snmp_timeout: float = 2.0
    ssh_timeout: float = 5.0
    max_concurrent_scans: int = 50
    enable_ping_sweep: bool = True
    enable_snmp_discovery: bool = True
    enable_ssh_discovery: bool = True
    enable_arp_discovery: bool = True
    enable_cdp_discovery: bool = True
    enable_lldp_discovery: bool = True
    
    def __post_init__(self):
        if self.default_community_strings is None:
            self.default_community_strings = ["public", "private", "community"]
        if self.default_ssh_credentials is None:
            self.default_ssh_credentials = [
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", ""),
                ("root", "root"),
                ("cisco", "cisco"),
                ("user", "user")
            ]

@dataclass
class DiscoveredDevice:
    """Information about a discovered device"""
    ip_address: str
    hostname: Optional[str] = None
    device_type: Optional[DeviceType] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    mac_address: Optional[str] = None
    protocol: Optional[DeviceProtocol] = None
    community_string: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    discovery_method: str = "unknown"
    confidence_score: float = 0.0
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}

class NetworkDiscoveryService:
    """Service for comprehensive network device discovery"""
    
    def __init__(self, config: DiscoveryConfig = None):
        """Initialize network discovery service"""
        self.config = config or DiscoveryConfig()
        self.discovery_jobs: Dict[int, asyncio.Task] = {}
        
        # SNMP OIDs for device identification
        self.snmp_oids = {
            'system_description': '1.3.6.1.2.1.1.1.0',
            'system_object_id': '1.3.6.1.2.1.1.2.0',
            'system_uptime': '1.3.6.1.2.1.1.3.0',
            'system_contact': '1.3.6.1.2.1.1.4.0',
            'system_name': '1.3.6.1.2.1.1.5.0',
            'system_location': '1.3.6.1.2.1.1.6.0',
            'system_services': '1.3.6.1.2.1.1.7.0',
        }
        
        # Vendor OIDs for device identification
        self.vendor_oids = {
            'cisco': '1.3.6.1.4.1.9',
            'juniper': '1.3.6.1.4.1.2636',
            'hp': '1.3.6.1.4.1.11',
            'arista': '1.3.6.1.4.1.30065',
            'fortinet': '1.3.6.1.4.1.12356',
            'palo_alto': '1.3.6.1.4.1.25461',
            'f5': '1.3.6.1.4.1.3375',
            'brocade': '1.3.6.1.4.1.1991',
        }
    
    async def start_discovery_job(self, job_id: int, target_networks: List[str], 
                                 discovery_types: List[DiscoveryType]) -> DiscoveryResult:
        """Start a network discovery job"""
        try:
            # Get discovery job from database
            async for db in get_db():
                job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
                if not job:
                    return DiscoveryResult.failure(
                        job_id, "Discovery job not found", 
                        {"job_id": job_id}
                    )
                
                # Update job status
                job.status = DiscoveryStatus.RUNNING
                job.started_at = datetime.utcnow()
                job.updated_at = datetime.utcnow()
                db.commit()
                break
            
            # Start discovery task
            task = asyncio.create_task(self._run_discovery_job(job_id, target_networks, discovery_types))
            self.discovery_jobs[job_id] = task
            
            logger.info(f"Started discovery job {job_id} for networks: {target_networks}")
            
            return DiscoveryResult.success(
                job_id, 
                {"message": "Discovery job started", "networks": target_networks},
                None
            )
            
        except Exception as e:
            logger.error(f"Failed to start discovery job {job_id}: {e}")
            return DiscoveryResult.failure(
                job_id, f"Failed to start discovery job: {str(e)}", 
                {"error": str(e)}
            )
    
    async def _run_discovery_job(self, job_id: int, target_networks: List[str], 
                                discovery_types: List[DiscoveryType]):
        """Run the actual discovery job"""
        discovered_devices: List[DiscoveredDevice] = []
        
        try:
            # Parse target networks
            ip_ranges = []
            for network in target_networks:
                try:
                    ip_net = ipaddress.ip_network(network, strict=False)
                    ip_ranges.append(ip_net)
                except ValueError as e:
                    logger.warning(f"Invalid network range {network}: {e}")
            
            if not ip_ranges:
                raise ValueError("No valid network ranges provided")
            
            # Generate IP addresses to scan
            ip_addresses = []
            for ip_range in ip_ranges:
                ip_addresses.extend([str(ip) for ip in ip_range.hosts()])
            
            logger.info(f"Discovery job {job_id}: Scanning {len(ip_addresses)} IP addresses")
            
            # Update job progress
            await self._update_job_progress(job_id, len(ip_addresses), 0, 0)
            
            # Run discovery based on types
            if DiscoveryType.PING_SWEEP in discovery_types:
                discovered_devices.extend(await self._ping_sweep_discovery(ip_addresses))
            
            if DiscoveryType.SNMP_DISCOVERY in discovery_types:
                discovered_devices.extend(await self._snmp_discovery(ip_addresses))
            
            if DiscoveryType.SSH_DISCOVERY in discovery_types:
                discovered_devices.extend(await self._ssh_discovery(ip_addresses))
            
            if DiscoveryType.ARP_DISCOVERY in discovery_types:
                discovered_devices.extend(await self._arp_discovery(ip_ranges))
            
            # Remove duplicates and merge information
            unique_devices = self._merge_discovered_devices(discovered_devices)
            
            # Store discovered devices in database
            await self._store_discovered_devices(job_id, unique_devices)
            
            # Update job completion
            await self._update_job_completion(job_id, len(unique_devices))
            
            logger.info(f"Discovery job {job_id} completed: found {len(unique_devices)} devices")
            
        except Exception as e:
            logger.error(f"Discovery job {job_id} failed: {e}")
            await self._update_job_failure(job_id, str(e))
        finally:
            # Clean up job task
            if job_id in self.discovery_jobs:
                del self.discovery_jobs[job_id]
    
    async def _ping_sweep_discovery(self, ip_addresses: List[str]) -> List[DiscoveredDevice]:
        """Discover devices using ping sweep"""
        discovered_devices = []
        
        logger.info(f"Starting ping sweep for {len(ip_addresses)} addresses")
        
        # Create semaphore to limit concurrent pings
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
        async def ping_ip(ip: str) -> Optional[DiscoveredDevice]:
            async with semaphore:
                try:
                    # Use asyncio to run ping command
                    process = await asyncio.create_subprocess_exec(
                        'ping', '-c', '1', '-W', str(int(self.config.ping_timeout * 1000)), ip,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await process.communicate()
                    
                    if process.returncode == 0:
                        # Device is reachable
                        device = DiscoveredDevice(
                            ip_address=ip,
                            discovery_method="ping_sweep",
                            confidence_score=0.3
                        )
                        
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(ip)[0]
                            device.hostname = hostname
                            device.confidence_score += 0.2
                        except socket.herror:
                            pass
                        
                        return device
                    
                except Exception as e:
                    logger.debug(f"Ping failed for {ip}: {e}")
                
                return None
        
        # Execute ping sweep concurrently
        tasks = [ping_ip(ip) for ip in ip_addresses]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful results
        for result in results:
            if isinstance(result, DiscoveredDevice):
                discovered_devices.append(result)
        
        logger.info(f"Ping sweep completed: found {len(discovered_devices)} reachable devices")
        return discovered_devices
    
    async def _snmp_discovery(self, ip_addresses: List[str]) -> List[DiscoveredDevice]:
        """Discover devices using SNMP"""
        if not SNMP_AVAILABLE:
            logger.warning("SNMP discovery skipped - PySNMP not available")
            return []
        
        discovered_devices = []
        
        logger.info(f"Starting SNMP discovery for {len(ip_addresses)} addresses")
        
        # Create semaphore to limit concurrent SNMP requests
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
        async def snmp_discover_ip(ip: str) -> Optional[DiscoveredDevice]:
            async with semaphore:
                for community in self.config.default_community_strings:
                    try:
                        device_info = await self._snmp_get_device_info(ip, community)
                        if device_info:
                            device_info.community_string = community
                            device_info.discovery_method = "snmp"
                            device_info.confidence_score = 0.8
                            return device_info
                    except Exception as e:
                        logger.debug(f"SNMP discovery failed for {ip} with community {community}: {e}")
                
                return None
        
        # Execute SNMP discovery concurrently
        tasks = [snmp_discover_ip(ip) for ip in ip_addresses]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful results
        for result in results:
            if isinstance(result, DiscoveredDevice):
                discovered_devices.append(result)
        
        logger.info(f"SNMP discovery completed: found {len(discovered_devices)} SNMP-enabled devices")
        return discovered_devices
    
    async def _snmp_get_device_info(self, ip: str, community: str) -> Optional[DiscoveredDevice]:
        """Get device information via SNMP"""
        try:
            # Create SNMP engine and transport
            snmp_engine = SnmpEngine()
            transport = UdpTransportTarget(
                (ip, 161), 
                timeout=self.config.snmp_timeout, 
                retries=0
            )
            community_data = CommunityData(community)
            context = ContextData()
            
            device = DiscoveredDevice(ip_address=ip)
            
            # Get system description
            object_identity = ObjectIdentity(self.snmp_oids['system_description'])
            
            error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: getCmd(snmp_engine, community_data, transport, context, object_identity)
            )
            
            if not error_indication and not error_status:
                system_desc = str(var_binds[0][1])
                device.additional_info['system_description'] = system_desc
                
                # Parse vendor and model from system description
                vendor, model = self._parse_system_description(system_desc)
                if vendor:
                    device.vendor = vendor
                if model:
                    device.model = model
                
                # Determine device type based on vendor/model
                device.device_type = self._determine_device_type(vendor, model)
                
                # Get system name (hostname)
                object_identity = ObjectIdentity(self.snmp_oids['system_name'])
                error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: getCmd(snmp_engine, community_data, transport, context, object_identity)
                )
                
                if not error_indication and not error_status:
                    device.hostname = str(var_binds[0][1])
                
                return device
            
        except Exception as e:
            logger.debug(f"SNMP device info failed for {ip}: {e}")
        
        return None
    
    def _parse_system_description(self, system_desc: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse vendor and model from system description"""
        system_desc_lower = system_desc.lower()
        
        # Common vendor patterns
        vendor_patterns = {
            'cisco': ['cisco systems', 'cisco'],
            'juniper': ['juniper networks', 'juniper'],
            'hp': ['hewlett packard', 'hp', 'hpe'],
            'arista': ['arista networks', 'arista'],
            'fortinet': ['fortinet', 'fortigate'],
            'palo alto': ['palo alto networks', 'palo alto'],
            'f5': ['f5 networks', 'f5'],
            'brocade': ['brocade communications', 'brocade'],
        }
        
        vendor = None
        model = None
        
        for vendor_name, patterns in vendor_patterns.items():
            for pattern in patterns:
                if pattern in system_desc_lower:
                    vendor = vendor_name.title()
                    break
            if vendor:
                break
        
        # Try to extract model (simplified)
        if vendor:
            # Look for common model patterns
            words = system_desc.split()
            for i, word in enumerate(words):
                if word.lower() in ['ios', 'nx-os', 'junos', 'eos']:
                    if i > 0:
                        model = words[i-1]
                    break
        
        return vendor, model
    
    def _determine_device_type(self, vendor: Optional[str], model: Optional[str]) -> DeviceType:
        """Determine device type based on vendor and model"""
        if not vendor:
            return DeviceType.UNKNOWN
        
        vendor_lower = vendor.lower()
        model_lower = model.lower() if model else ""
        
        # Router patterns
        if any(pattern in vendor_lower for pattern in ['cisco', 'juniper', 'arista']):
            if any(pattern in model_lower for pattern in ['router', 'isr', 'asr', 'mx', 'ex']):
                return DeviceType.ROUTER
        
        # Switch patterns
        if any(pattern in vendor_lower for pattern in ['cisco', 'hp', 'arista', 'brocade']):
            if any(pattern in model_lower for pattern in ['switch', 'catalyst', 'procurve', 'eos']):
                return DeviceType.SWITCH
        
        # Firewall patterns
        if any(pattern in vendor_lower for pattern in ['fortinet', 'palo alto', 'cisco']):
            if any(pattern in model_lower for pattern in ['firewall', 'asa', 'fortigate', 'pa-']):
                return DeviceType.FIREWALL
        
        # Server patterns
        if any(pattern in vendor_lower for pattern in ['hp', 'dell', 'ibm', 'cisco']):
            if any(pattern in model_lower for pattern in ['server', 'blade', 'ucs']):
                return DeviceType.SERVER
        
        # Default based on vendor
        if vendor_lower in ['cisco', 'juniper', 'arista']:
            return DeviceType.ROUTER
        elif vendor_lower in ['hp', 'brocade']:
            return DeviceType.SWITCH
        elif vendor_lower in ['fortinet', 'palo alto']:
            return DeviceType.FIREWALL
        
        return DeviceType.UNKNOWN
    
    async def _ssh_discovery(self, ip_addresses: List[str]) -> List[DiscoveredDevice]:
        """Discover devices using SSH"""
        if not SSH_AVAILABLE:
            logger.warning("SSH discovery skipped - AsyncSSH not available")
            return []
        
        discovered_devices = []
        
        logger.info(f"Starting SSH discovery for {len(ip_addresses)} addresses")
        
        # Create semaphore to limit concurrent SSH connections
        semaphore = asyncio.Semaphore(self.config.max_concurrent_scans)
        
        async def ssh_discover_ip(ip: str) -> Optional[DiscoveredDevice]:
            async with semaphore:
                for username, password in self.config.default_ssh_credentials:
                    try:
                        device_info = await self._ssh_get_device_info(ip, username, password)
                        if device_info:
                            device_info.ssh_username = username
                            device_info.ssh_password = password
                            device_info.discovery_method = "ssh"
                            device_info.confidence_score = 0.9
                            return device_info
                    except Exception as e:
                        logger.debug(f"SSH discovery failed for {ip} with {username}: {e}")
                
                return None
        
        # Execute SSH discovery concurrently
        tasks = [ssh_discover_ip(ip) for ip in ip_addresses]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Collect successful results
        for result in results:
            if isinstance(result, DiscoveredDevice):
                discovered_devices.append(result)
        
        logger.info(f"SSH discovery completed: found {len(discovered_devices)} SSH-enabled devices")
        return discovered_devices
    
    async def _ssh_get_device_info(self, ip: str, username: str, password: str) -> Optional[DiscoveredDevice]:
        """Get device information via SSH"""
        try:
            async with asyncssh.connect(
                ip,
                username=username,
                password=password,
                known_hosts=None,  # In production, use proper host key verification
                timeout=self.config.ssh_timeout
            ) as conn:
                
                device = DiscoveredDevice(ip_address=ip)
                
                # Get hostname
                result = await conn.run('hostname')
                if result.exit_status == 0:
                    device.hostname = result.stdout.strip()
                
                # Get system information
                result = await conn.run('uname -a')
                if result.exit_status == 0:
                    uname_output = result.stdout.strip()
                    device.additional_info['uname'] = uname_output
                    
                    # Parse vendor and model from uname
                    vendor, model = self._parse_uname_output(uname_output)
                    if vendor:
                        device.vendor = vendor
                    if model:
                        device.model = model
                    
                    device.device_type = self._determine_device_type(vendor, model)
                
                # Get network interfaces
                result = await conn.run('ip addr show')
                if result.exit_status == 0:
                    device.additional_info['interfaces'] = result.stdout.strip()
                
                return device
                
        except Exception as e:
            logger.debug(f"SSH device info failed for {ip}: {e}")
        
        return None
    
    def _parse_uname_output(self, uname_output: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse vendor and model from uname output"""
        uname_lower = uname_output.lower()
        
        vendor = None
        model = None
        
        # Common patterns in uname output
        if 'cisco' in uname_lower:
            vendor = 'Cisco'
        elif 'juniper' in uname_lower:
            vendor = 'Juniper'
        elif 'linux' in uname_lower:
            vendor = 'Linux'
        
        return vendor, model
    
    async def _arp_discovery(self, ip_ranges: List[ipaddress.IPv4Network]) -> List[DiscoveredDevice]:
        """Discover devices using ARP table"""
        discovered_devices = []
        
        logger.info(f"Starting ARP discovery for {len(ip_ranges)} network ranges")
        
        try:
            # Get ARP table
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                arp_output = result.stdout
                
                for line in arp_output.split('\n'):
                    if '(' in line and ')' in line:
                        # Parse ARP entry: hostname (ip) at mac [type]
                        try:
                            parts = line.split()
                            if len(parts) >= 4:
                                ip_part = parts[1]  # (ip)
                                ip = ip_part.strip('()')
                                mac = parts[3]
                                
                                # Check if IP is in our target ranges
                                ip_obj = ipaddress.ip_address(ip)
                                if any(ip_obj in ip_range for ip_range in ip_ranges):
                                    device = DiscoveredDevice(
                                        ip_address=ip,
                                        mac_address=mac,
                                        discovery_method="arp",
                                        confidence_score=0.7
                                    )
                                    
                                    # Try to get hostname
                                    if parts[0] != '?':
                                        device.hostname = parts[0]
                                        device.confidence_score += 0.1
                                    
                                    discovered_devices.append(device)
                                    
                        except (ValueError, IndexError) as e:
                            logger.debug(f"Failed to parse ARP entry: {line}")
                            continue
            
        except Exception as e:
            logger.warning(f"ARP discovery failed: {e}")
        
        logger.info(f"ARP discovery completed: found {len(discovered_devices)} devices")
        return discovered_devices
    
    def _merge_discovered_devices(self, devices: List[DiscoveredDevice]) -> List[DiscoveredDevice]:
        """Merge information from multiple discovery methods for the same device"""
        device_map: Dict[str, DiscoveredDevice] = {}
        
        for device in devices:
            ip = device.ip_address
            
            if ip in device_map:
                # Merge information
                existing = device_map[ip]
                
                # Use highest confidence information
                if device.confidence_score > existing.confidence_score:
                    device_map[ip] = device
                else:
                    # Merge additional information
                    existing.additional_info.update(device.additional_info)
                    existing.discovery_method += f",{device.discovery_method}"
                    
                    # Use more specific information if available
                    if not existing.hostname and device.hostname:
                        existing.hostname = device.hostname
                    if not existing.vendor and device.vendor:
                        existing.vendor = device.vendor
                    if not existing.model and device.model:
                        existing.model = device.model
                    if not existing.mac_address and device.mac_address:
                        existing.mac_address = device.mac_address
            else:
                device_map[ip] = device
        
        return list(device_map.values())
    
    async def _store_discovered_devices(self, job_id: int, devices: List[DiscoveredDevice]):
        """Store discovered devices in database"""
        try:
            async for db in get_db():
                for device in devices:
                    # Check if device already exists
                    existing_device = db.query(Device).filter(
                        Device.ip_address == device.ip_address
                    ).first()
                    
                    if existing_device:
                        # Update existing device with new information
                        if device.hostname and not existing_device.hostname:
                            existing_device.hostname = device.hostname
                        if device.vendor and not existing_device.vendor:
                            existing_device.vendor = device.vendor
                        if device.model and not existing_device.model:
                            existing_device.model = device.model
                        if device.mac_address and not existing_device.mac_address:
                            existing_device.mac_address = device.mac_address
                        
                        existing_device.updated_at = datetime.utcnow()
                    else:
                        # Create new device
                        new_device = Device(
                            name=device.hostname or f"Device_{device.ip_address}",
                            ip_address=device.ip_address,
                            hostname=device.hostname,
                            device_type=device.device_type or DeviceType.UNKNOWN,
                            vendor=device.vendor,
                            model=device.model,
                            mac_address=device.mac_address,
                            protocol=device.protocol or DeviceProtocol.SNMP,
                            status=DeviceStatus.UNKNOWN,
                            is_monitored=False,  # Not monitored by default
                            created_at=datetime.utcnow(),
                            updated_at=datetime.utcnow()
                        )
                        db.add(new_device)
                        
                        # Store discovery information
                        if device.community_string:
                            credentials = DeviceCredentials(
                                device_id=new_device.id,
                                credential_type=CredentialType.SNMP,
                                name="Discovered SNMP",
                                encrypted_data=device.community_string,  # In production, encrypt this
                                key_id="discovery",
                                is_primary=True,
                                created_at=datetime.utcnow()
                            )
                            db.add(credentials)
                        
                        if device.ssh_username and device.ssh_password:
                            credentials = DeviceCredentials(
                                device_id=new_device.id,
                                credential_type=CredentialType.SSH,
                                name="Discovered SSH",
                                encrypted_data=device.ssh_password,  # In production, encrypt this
                                key_id="discovery",
                                is_primary=True,
                                created_at=datetime.utcnow()
                            )
                            db.add(credentials)
                
                db.commit()
                break
                
        except Exception as e:
            logger.error(f"Failed to store discovered devices for job {job_id}: {e}")
    
    async def _update_job_progress(self, job_id: int, total_targets: int, completed_targets: int, failed_targets: int):
        """Update discovery job progress"""
        try:
            async for db in get_db():
                job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
                if job:
                    job.total_targets = total_targets
                    job.completed_targets = completed_targets
                    job.failed_targets = failed_targets
                    job.progress_percentage = (completed_targets / total_targets * 100) if total_targets > 0 else 0
                    job.updated_at = datetime.utcnow()
                    db.commit()
                break
                
        except Exception as e:
            logger.error(f"Failed to update job progress for job {job_id}: {e}")
    
    async def _update_job_completion(self, job_id: int, devices_found: int):
        """Update discovery job completion"""
        try:
            async for db in get_db():
                job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
                if job:
                    job.status = DiscoveryStatus.COMPLETED
                    job.completed_at = datetime.utcnow()
                    job.updated_at = datetime.utcnow()
                    job.results = {"devices_found": devices_found}
                    db.commit()
                break
                
        except Exception as e:
            logger.error(f"Failed to update job completion for job {job_id}: {e}")
    
    async def _update_job_failure(self, job_id: int, error_message: str):
        """Update discovery job failure"""
        try:
            async for db in get_db():
                job = db.query(DiscoveryJob).filter(DiscoveryJob.id == job_id).first()
                if job:
                    job.status = DiscoveryStatus.FAILED
                    job.completed_at = datetime.utcnow()
                    job.updated_at = datetime.utcnow()
                    job.results = {"error": error_message}
                    db.commit()
                break
                
        except Exception as e:
            logger.error(f"Failed to update job failure for job {job_id}: {e}")
    
    async def get_discovery_status(self) -> Dict[str, Any]:
        """Get current discovery service status"""
        return {
            "active_jobs": len(self.discovery_jobs),
            "job_ids": list(self.discovery_jobs.keys()),
            "config": {
                "max_concurrent_scans": self.config.max_concurrent_scans,
                "ping_timeout": self.config.ping_timeout,
                "snmp_timeout": self.config.snmp_timeout,
                "ssh_timeout": self.config.ssh_timeout,
                "enable_ping_sweep": self.config.enable_ping_sweep,
                "enable_snmp_discovery": self.config.enable_snmp_discovery,
                "enable_ssh_discovery": self.config.enable_ssh_discovery,
                "enable_arp_discovery": self.config.enable_arp_discovery
            }
        }

# Global network discovery service instance
network_discovery_service = NetworkDiscoveryService()
