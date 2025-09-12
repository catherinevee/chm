"""
Network Discovery Service
Automatically discovers network devices using various scanning techniques
Enhanced with comprehensive SNMP monitoring capabilities
"""

import asyncio
import ipaddress
import nmap
import socket
import struct
from typing import List, Dict, Optional, Set, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import asyncssh
from pysnmp.hlapi import *

# Import enhanced SNMP monitoring
from backend.collector.protocols.snmp.monitor import snmp_monitor
from backend.collector.protocols.snmp.oids import OIDManager, StandardMIBs

import json
from pathlib import Path

from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
    ObjectIdentity, ObjectType, getCmd, nextCmd
)

from ..storage.models import Device, DeviceCredential, DeviceType, DeviceState
from ..collector.protocols.snmp import monitor as snmp_monitor
from ..common.exceptions import DiscoveryException, DeviceUnreachableException
from ..common.result_objects import DiscoveryResult, DeviceInfo, FallbackData, HealthStatus

logger = logging.getLogger(__name__)

class DiscoveryResult:
    """Structured result object for discovery operations"""
    
    def __init__(self, success: bool = False, data: Any = None, error: str = None, 
                 error_code: str = None, fallback_data: FallbackData = None, 
                 health_status: HealthStatus = None, suggestions: List[str] = None):
        self.success = success
        self.data = data
        self.error = error
        self.error_code = error_code
        self.fallback_data = fallback_data or FallbackData()
        self.health_status = health_status or HealthStatus()
        self.suggestions = suggestions or []
        self.timestamp = datetime.utcnow()
        self.attempts = 0
        self.recovery_attempts = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'error_code': self.error_code,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'health_status': self.health_status.to_dict() if self.health_status else None,
            'suggestions': self.suggestions,
            'timestamp': self.timestamp.isoformat(),
            'attempts': self.attempts,
            'recovery_attempts': self.recovery_attempts
        }

class FallbackData:
    """Fallback data when primary operations fail"""
    
    def __init__(self, data: Any = None, source: str = None, timestamp: datetime = None, 
                 validity_period: timedelta = None, confidence: float = 0.0):
        self.data = data
        self.source = source
        self.timestamp = timestamp or datetime.utcnow()
        self.validity_period = validity_period or timedelta(hours=1)
        self.confidence = confidence
        self.is_stale = False
    
    def is_valid(self) -> bool:
        return datetime.utcnow() - self.timestamp < self.validity_period
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'data': self.data,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'validity_period_seconds': self.validity_period.total_seconds(),
            'confidence': self.confidence,
            'is_stale': self.is_stale
        }

class HealthStatus:
    """Health status information for services and operations"""
    
    def __init__(self, status: str = "unknown", details: Dict[str, Any] = None, 
                 last_check: datetime = None, degradation_reason: str = None):
        self.status = status  # healthy, degraded, down, unknown
        self.details = details or {}
        self.last_check = last_check or datetime.utcnow()
        self.degradation_reason = degradation_reason
        self.capabilities = []
        self.fallback_available = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'details': self.details,
            'last_check': self.last_check.isoformat(),
            'degradation_reason': self.degradation_reason,
            'capabilities': self.capabilities,
            'fallback_available': self.fallback_available
        }

class DeviceInfo:
    """Enhanced device information with fallback capabilities"""
    
    def __init__(self, ip_address: str, hostname: str = None, device_type: str = None,
                 vendor: str = None, model: str = None, capabilities: List[str] = None):
        self.ip_address = ip_address
        self.hostname = hostname or f"unknown-{ip_address.replace('.', '-')}"
        self.device_type = device_type or "unknown"
        self.vendor = vendor or "unknown"
        self.model = model or "unknown"
        self.capabilities = capabilities or []
        self.discovery_methods = []
        self.fallback_data = {}
        self.health_indicators = {}
        self.last_seen = datetime.utcnow()
        self.discovery_confidence = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'vendor': self.vendor,
            'model': self.model,
            'capabilities': self.capabilities,
            'discovery_methods': self.discovery_methods,
            'fallback_data': self.fallback_data,
            'health_indicators': self.health_indicators,
            'last_seen': self.last_seen.isoformat(),
            'discovery_confidence': self.discovery_confidence
        }

@dataclass
class DiscoveredDevice:
    ip_address: str
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    snmp_community: Optional[str] = None
    snmp_version: Optional[str] = None
    ssh_enabled: bool = False
    telnet_enabled: bool = False
    http_enabled: bool = False
    https_enabled: bool = False
    mac_address: Optional[str] = None
    discovery_time: datetime = None
    # Enhanced SNMP information
    snmp_system_info: Optional[Dict[str, Any]] = None
    snmp_interface_count: Optional[int] = None
    snmp_cpu_utilization: Optional[float] = None
    snmp_memory_info: Optional[Dict[str, Any]] = None
    snmp_temperature: Optional[float] = None
    snmp_vendor_metrics: Optional[Dict[str, Any]] = None

class NetworkDiscoveryService:
    def __init__(self):
        self.common_snmp_communities = ['public', 'private', 'community', 'cisco', 'admin']
        self.common_ports = [22, 23, 80, 443, 161, 162]
        self.nm = nmap.PortScanner()
        self.oid_manager = OIDManager()
        
    async def discover_network(self, network_cidr: str, scan_type: str = "comprehensive", protocol: str = "snmp") -> List[DiscoveredDevice]:
        """
        Discover devices in a network range with multiple discovery protocols
        
        Args:
            network_cidr: Network CIDR (e.g., "192.168.1.0/24")
            scan_type: "quick", "standard", or "comprehensive"
            protocol: "snmp", "cdp", "lldp", "arp", "ping", or "nmap"
        
        Returns:
            List of discovered devices with comprehensive data
        """
        logger.info(f"Starting {protocol} network discovery for {network_cidr}")
        
        # Parse network range
        network = ipaddress.ip_network(network_cidr, strict=False)
        ip_list = [str(ip) for ip in network.hosts()]
        
        # Choose discovery method based on protocol
        if protocol == "cdp":
            return await self._cdp_discovery(ip_list)
        elif protocol == "lldp":
            return await self._lldp_discovery(ip_list)
        elif protocol == "arp":
            return await self._arp_discovery(network_cidr)
        elif protocol == "ping":
            return await self._ping_discovery(ip_list)
        elif protocol == "nmap":
            return await self._nmap_discovery(network_cidr)
        else:  # Default to SNMP
            if scan_type == "quick":
                return await self._quick_scan(ip_list)
            elif scan_type == "standard":
                return await self._standard_scan(ip_list)
            else:
                return await self._comprehensive_scan(ip_list)
    
    async def _quick_scan(self, ip_list: List[str]) -> List[DiscoveredDevice]:
        """Quick ping-based scan with basic SNMP detection"""
        devices = []
        
        async def ping_and_snmp_host(ip: str) -> Optional[DiscoveredDevice]:
            try:
                # Quick ping test
                proc = await asyncio.create_subprocess_exec(
                    'ping', '-c', '1', '-W', '1', ip,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                
                if proc.returncode == 0:
                    device = DiscoveredDevice(
                        ip_address=ip,
                        discovery_time=datetime.now()
                    )
                    
                    # Basic SNMP detection
                    snmp_info = await self._detect_snmp(ip)
                    if snmp_info:
                        device.snmp_community = snmp_info['community']
                        device.snmp_version = snmp_info['version']
                        device.vendor = snmp_info.get('vendor')
                        device.model = snmp_info.get('model')
                        device.hostname = snmp_info.get('hostname')
                        
                        # Get basic system information
                        device.snmp_system_info = await self._get_basic_snmp_info(ip, snmp_info)
                    
                    return device
            except Exception as e:
                logger.debug(f"Quick scan failed for {ip}: {e}")
                # Create fallback device info with basic connectivity
                fallback_device = DeviceInfo(
                    ip_address=ip,
                    hostname=f"unknown-{ip.replace('.', '-')}",
                    device_type="unknown",
                    vendor="unknown",
                    model="unknown",
                    capabilities=["basic_connectivity"],
                    discovery_methods=["ping"],
                    discovery_confidence=0.1
                )
                
                # Create fallback data
                fallback_data = FallbackData(
                    data=fallback_device,
                    source="ping_only",
                    confidence=0.1,
                    metadata={"error": str(e), "method": "ping"}
                )
                
                # Return partial success with fallback data
                return create_partial_success_result(
                    data=fallback_device,
                    fallback_data=fallback_data,
                    health_status=HealthStatus(
                        status=HealthLevel.DEGRADED,
                        degradation_reason="Discovery failed, using fallback data",
                        fallback_available=True
                    ),
                    suggestions=[
                        "Device responds to ping but detailed discovery failed",
                        "Check if SNMP is enabled on the device",
                        "Verify network connectivity and firewall rules",
                        "Try manual device configuration if needed"
                    ]
                )
        
        # Concurrent scan
        tasks = [ping_and_snmp_host(ip) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredDevice):
                devices.append(result)
        
        return devices
    
    async def _standard_scan(self, ip_list: List[str]) -> List[DiscoveredDevice]:
        """Standard scan with port detection and enhanced SNMP monitoring"""
        devices = await self._quick_scan(ip_list)
        
        # Enhanced scan for discovered devices
        enhanced_devices = []
        for device in devices:
            enhanced_device = await self._enhance_device_info(device)
            if enhanced_device:
                enhanced_devices.append(enhanced_device)
        
        return enhanced_devices
    
    async def _comprehensive_scan(self, ip_list: List[str]) -> List[DiscoveredDevice]:
        """Comprehensive scan with all detection methods and full SNMP monitoring"""
        devices = await self._standard_scan(ip_list)
        
        # Additional comprehensive checks with full SNMP monitoring
        for device in devices:
            await self._perform_comprehensive_checks(device)
        
        return devices
    
    async def _enhance_device_info(self, device: DiscoveredDevice) -> Optional[DiscoveredDevice]:
        """Enhance device information with port scanning and comprehensive SNMP"""
        try:
            # Port scan
            open_ports = await self._scan_ports(device.ip_address)
            device.ssh_enabled = 22 in open_ports
            device.telnet_enabled = 23 in open_ports
            device.http_enabled = 80 in open_ports
            device.https_enabled = 443 in open_ports
            
            # Enhanced SNMP detection and monitoring
            if device.snmp_community:
                await self._enhance_snmp_monitoring(device)
            
            # MAC address detection
            device.mac_address = await self._get_mac_address(device.ip_address)
            
            return device
            
        except Exception as e:
            logger.error(f"Error enhancing device info for {device.ip_address}: {e}")
            return device
    
    async def _enhance_snmp_monitoring(self, device: DiscoveredDevice):
        """Enhance device with comprehensive SNMP monitoring data"""
        try:
            # Create SNMP credentials
            credentials = {
                'host': device.ip_address,
                'community': device.snmp_community,
                'version': device.snmp_version or '2c',
                'port': 161,
                'timeout': 10,  # Increased from 3 to 10 seconds
                'retries': 3    # Increased from 2 to 3 retries
            }
            
            # Get comprehensive SNMP metrics
            monitoring_result = await snmp_monitor.monitor_essential_metrics(
                f"discovery_{device.ip_address}", credentials
            )
            
            if 'error' not in monitoring_result:
                essential_metrics = monitoring_result.get('essential_metrics', {})
                
                # Extract key metrics
                device.snmp_cpu_utilization = essential_metrics.get('cpu_utilization')
                device.snmp_memory_info = essential_metrics.get('memory')
                device.snmp_interface_count = essential_metrics.get('interface_count')
                
                # Get interface performance data
                interface_performance = await snmp_monitor.monitor_interface_performance(
                    f"discovery_{device.ip_address}", credentials
                )
                
                if 'interface_performance' in interface_performance:
                    device.snmp_vendor_metrics = {
                        'interface_performance': interface_performance['interface_performance']
                    }
                
                # Get network performance data
                network_performance = await snmp_monitor.monitor_network_performance(
                    f"discovery_{device.ip_address}", credentials
                )
                
                if 'network_performance' in network_performance:
                    if device.snmp_vendor_metrics is None:
                        device.snmp_vendor_metrics = {}
                    device.snmp_vendor_metrics['network_performance'] = network_performance['network_performance']
                
                # Get temperature if available
                if device.vendor and device.vendor.lower() == 'cisco':
                    temp_result = await self._get_temperature(device.ip_address, credentials)
                    if temp_result:
                        device.snmp_temperature = temp_result
            
        except Exception as e:
            logger.debug(f"Enhanced SNMP monitoring failed for {device.ip_address}: {e}")
    
    async def _get_basic_snmp_info(self, ip: str, snmp_info: Dict) -> Dict[str, Any]:
        """Get basic SNMP system information"""
        try:
            credentials = {
                'host': ip,
                'community': snmp_info['community'],
                'version': snmp_info['version'],
                'port': 161,
                'timeout': 8,   # Increased from 2 to 8 seconds
                'retries': 2    # Increased from 1 to 2 retries
            }
            
            # Get system uptime
            uptime_result = await self._get_snmp_value(
                ip, credentials, StandardMIBs.SYSTEM['sysUpTime'].oid
            )
            
            # Get system location
            location_result = await self._get_snmp_value(
                ip, credentials, StandardMIBs.SYSTEM['sysLocation'].oid
            )
            
            # Get interface count
            if_count_result = await self._get_snmp_value(
                ip, credentials, StandardMIBs.INTERFACE['ifNumber'].oid
            )
            
            return {
                'uptime': uptime_result,
                'location': location_result,
                'interface_count': if_count_result
            }
            
        except Exception as e:
            logger.debug(f"Basic SNMP info failed for {ip}: {e}")
            return {}
    
    async def _get_temperature(self, ip: str, credentials: Dict) -> Optional[float]:
        """Get device temperature"""
        try:
            # Try Cisco temperature OIDs
            cisco_temp_oids = [
                '1.3.6.1.4.1.9.9.13.1.3.1.3.1',  # ciscoEnvMonTemperatureValue
                '1.3.6.1.4.1.9.9.91.1.1.1.1.4.1'  # entSensorValue
            ]
            
            for oid in cisco_temp_oids:
                result = await self._get_snmp_value(ip, credentials, oid)
                if result is not None:
                    return float(result)
            
            # Return default temperature with fallback indicator
            fallback_data = FallbackData(
                data=25.0,  # Default room temperature
                source="default_value",
                confidence=0.1,
                metadata={"reason": "SNMP temperature OIDs not available", "ip": ip}
            )
            
            return create_partial_success_result(
                data=25.0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="Temperature monitoring not available",
                    fallback_available=True
                ),
                suggestions=[
                    "Device may not support temperature monitoring",
                    "Check if temperature sensors are enabled",
                    "Verify SNMP MIB support for temperature OIDs",
                    "Consider manual temperature monitoring"
                ]
            )
            
        except Exception as e:
            logger.debug(f"Temperature check failed for {ip}: {e}")
            # Return fallback temperature with error context
            fallback_data = FallbackData(
                data=25.0,  # Default room temperature
                source="error_fallback",
                confidence=0.05,
                metadata={"error": str(e), "ip": ip, "method": "snmp_temperature"}
            )
            
            return create_failure_result(
                error=f"Temperature check failed for {ip}: {e}",
                error_code="TEMPERATURE_CHECK_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Check SNMP connectivity and community strings",
                    "Verify device supports temperature monitoring",
                    "Check SNMP timeout and retry settings",
                    "Consider alternative monitoring methods"
                ]
            )
    
    async def _get_snmp_value(self, ip: str, credentials: Dict, oid: str) -> Optional[Any]:
        """Get a single SNMP value"""
        try:
            # Determine SNMP version
            mp_model = 1 if credentials['version'] == '1' else 0
            
            # Create SNMP engine and data
            snmp_engine = SnmpEngine()
            community_data = CommunityData(credentials['community'], mpModel=mp_model)
            transport_target = UdpTransportTarget((ip, credentials['port']), 
                                                timeout=credentials['timeout'], 
                                                retries=credentials['retries'])
            context_data = ContextData()
            
            # Create object identity
            object_identity = ObjectIdentity(oid)
            
            # Execute SNMP GET
            iterator = getCmd(snmp_engine, community_data, transport_target, 
                            context_data, ObjectType(object_identity))
            
            error_indication, error_status, error_index, var_binds = next(iterator)
            
            if error_indication or error_status:
                # Return fallback data for SNMP errors
                fallback_data = FallbackData(
                    data="unknown",
                    source="snmp_error",
                    confidence=0.0,
                    metadata={
                        "error_indication": str(error_indication),
                        "error_status": str(error_status),
                        "oid": oid,
                        "ip": ip
                    }
                )
                
                return create_failure_result(
                    error=f"SNMP GET failed for {oid} on {ip}",
                    error_code="SNMP_GET_FAILED",
                    fallback_data=fallback_data,
                    suggestions=[
                        "Check SNMP community string and version",
                        "Verify OID exists on the device",
                        "Check SNMP access control lists",
                        "Verify device SNMP configuration"
                    ]
                )
            
            # Extract value
            for var_bind in var_binds:
                oid_name, oid_value = var_bind
                return self._convert_snmp_value(oid_value)
            
            # Return fallback for empty response
            fallback_data = FallbackData(
                data="no_data",
                source="empty_response",
                confidence=0.0,
                metadata={"oid": oid, "ip": ip, "var_binds_count": len(var_binds)}
            )
            
            return create_failure_result(
                error=f"SNMP GET returned no data for {oid} on {ip}",
                error_code="SNMP_NO_DATA",
                fallback_data=fallback_data,
                suggestions=[
                    "Verify OID is supported by the device",
                    "Check SNMP MIB support",
                    "Verify device SNMP configuration",
                    "Try alternative OIDs if available"
                ]
            )
            
        except Exception as e:
            logger.debug(f"SNMP GET failed for {oid}: {e}")
            # Return fallback data for exceptions
            fallback_data = FallbackData(
                data="exception_error",
                source="exception",
                confidence=0.0,
                metadata={"error": str(e), "oid": oid, "ip": ip}
            )
            
            return create_failure_result(
                error=f"SNMP GET exception for {oid} on {ip}: {e}",
                error_code="SNMP_EXCEPTION",
                fallback_data=fallback_data,
                suggestions=[
                    "Check network connectivity to device",
                    "Verify SNMP port is accessible",
                    "Check firewall rules for SNMP",
                    "Verify SNMP service is running"
                ]
            )
    
    def _convert_snmp_value(self, snmp_value) -> Any:
        """Convert SNMP value to Python type"""
        from pysnmp.proto.rfc1902 import Integer32, OctetString, Counter32, Gauge32, TimeTicks
        
        if isinstance(snmp_value, Integer32):
            return int(snmp_value)
        elif isinstance(snmp_value, Counter32):
            return int(snmp_value)
        elif isinstance(snmp_value, Gauge32):
            return int(snmp_value)
        elif isinstance(snmp_value, TimeTicks):
            return int(snmp_value)
        elif isinstance(snmp_value, OctetString):
            return str(snmp_value)
        else:
            return str(snmp_value)
    
    async def _scan_ports(self, ip: str) -> Set[int]:
        """Scan for open ports"""
        open_ports = set()
        
        async def check_port(port: int) -> Optional[int]:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=1.0
                )
                writer.close()
                await writer.wait_closed()
                return port
            except Exception as e:
                # Port check failed - return a sentinel value instead of None
                logger.debug(f"Port {port} check failed on {ip}: {e}")
                return -1  # Use -1 to indicate port check failure
        
        tasks = [check_port(port) for port in self.common_ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, int) and result > 0:  # Only add valid port numbers
                open_ports.add(result)
        
        return open_ports
    
    async def _detect_snmp(self, ip: str) -> Optional[Dict]:
        """Detect SNMP configuration with enhanced capabilities"""
        for community in self.common_snmp_communities:
            for version in ['2c', '1']:
                try:
                    # Try to get system description
                    iterator = getCmd(
                        SnmpEngine(),
                        CommunityData(community, mpModel=1 if version == '1' else 0),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
                    )
                    
                    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
                    
                    if errorIndication or errorStatus:
                        continue
                    
                    sys_descr = str(varBinds[0][1])
                    
                    # Try to get hostname
                    hostname_iterator = getCmd(
                        SnmpEngine(),
                        CommunityData(community, mpModel=1 if version == '1' else 0),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))  # sysName
                    )
                    
                    hostname_error, hostname_status, hostname_index, hostname_binds = next(hostname_iterator)
                    hostname = str(hostname_binds[0][1]) if not hostname_error and not hostname_status else None
                    
                    # Determine vendor and model from sysDescr
                    vendor, model = self._parse_sys_descr(sys_descr)
                    
                    return {
                        'community': community,
                        'version': version,
                        'vendor': vendor,
                        'model': model,
                        'hostname': hostname
                    }
                    
                except Exception as e:
                    logger.debug(f"SNMP detection failed for {ip} with community {community}: {e}")
                    continue
        
        # Return fallback SNMP configuration when detection fails
        fallback_data = FallbackData(
            data={
                'community': 'public',
                'version': '2c',
                'vendor': 'unknown',
                'model': 'unknown',
                'hostname': None
            },
            source="fallback_defaults",
            confidence=0.1,
            metadata={"ip": ip, "reason": "SNMP detection failed for all communities"}
        )
        
        return create_partial_success_result(
            data=fallback_data.data,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="SNMP detection failed, using default configuration",
                fallback_available=True
            ),
            suggestions=[
                "SNMP may not be enabled on this device",
                "Check if SNMP community strings are configured",
                "Verify SNMP is enabled on the device",
                "Try manual SNMP configuration",
                "Consider alternative discovery methods"
            ]
        )
    
    def _parse_sys_descr(self, sys_descr: str) -> tuple:
        """Parse system description to extract vendor and model"""
        sys_descr_lower = sys_descr.lower()
        
        if 'cisco' in sys_descr_lower:
            vendor = 'Cisco'
            # Extract model from common patterns
            if '2960' in sys_descr:
                model = '2960'
            elif '3560' in sys_descr:
                model = '3560'
            elif '4500' in sys_descr:
                model = '4500'
            elif '3850' in sys_descr:
                model = '3850'
            elif '9300' in sys_descr:
                model = '9300'
            else:
                model = 'Unknown'
        elif 'juniper' in sys_descr_lower:
            vendor = 'Juniper'
            model = 'Unknown'
        elif 'arista' in sys_descr_lower:
            vendor = 'Arista'
            model = 'Unknown'
        elif 'hp' in sys_descr_lower or 'hewlett-packard' in sys_descr_lower:
            vendor = 'HP'
            model = 'Unknown'
        elif 'brocade' in sys_descr_lower:
            vendor = 'Brocade'
            model = 'Unknown'
        elif 'extreme' in sys_descr_lower:
            vendor = 'Extreme'
            model = 'Unknown'
        else:
            vendor = 'Unknown'
            model = 'Unknown'
        
        return vendor, model
    
    async def _get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address using ARP"""
        try:
            # This is a simplified version - in production you'd use proper ARP scanning
            proc = await asyncio.create_subprocess_exec(
                'arp', '-n', ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await proc.communicate()
            
            if proc.returncode == 0:
                lines = stdout.decode().split('\n')
                for line in lines:
                    if ip in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[2]
        except Exception as e:
            logger.debug(f"Failed to get MAC address for {ip}: {e}")
        
        # Return fallback MAC address data when lookup fails
        fallback_data = FallbackData(
            data="00:00:00:00:00:00",  # Default MAC address
            source="mac_lookup_fallback",
            confidence=0.0,
            metadata={"ip": ip, "error": str(e)}
        )
        
        return create_failure_result(
            error=f"Failed to get MAC address for {ip}",
            error_code="MAC_LOOKUP_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "MAC address lookup failed",
                "Check ARP table manually",
                "Verify network connectivity",
                "Consider alternative discovery methods"
            ]
        )
    
    async def _perform_comprehensive_checks(self, device: DiscoveredDevice):
        """Perform comprehensive device checks with full SNMP monitoring"""
        # SSH connection test
        if device.ssh_enabled:
            await self._test_ssh_connection(device)
        
        # HTTP/HTTPS service detection
        if device.http_enabled or device.https_enabled:
            await self._detect_web_services(device)
        
        # Full SNMP monitoring if SNMP is available
        if device.snmp_community:
            await self._perform_full_snmp_monitoring(device)
    
    async def _perform_full_snmp_monitoring(self, device: DiscoveredDevice):
        """Perform full SNMP monitoring for comprehensive discovery"""
        try:
            credentials = {
                'host': device.ip_address,
                'community': device.snmp_community,
                'version': device.snmp_version or '2c',
                'port': 161,
                'timeout': 12,  # Increased from 5 to 12 seconds for device polling
                'retries': 4    # Increased from 3 to 4 retries
            }
            
            # Get comprehensive monitoring data
            monitoring_result = await snmp_monitor.monitor_device(
                f"comprehensive_{device.ip_address}", credentials
            )
            
            if 'error' not in monitoring_result:
                # Update device with comprehensive SNMP data
                metrics = monitoring_result.get('metrics', {})
                
                # Update system information
                if 'system' in metrics:
                    system_info = metrics['system']
                    device.snmp_system_info = {
                        'uptime': system_info.get('uptime'),
                        'name': system_info.get('name'),
                        'location': system_info.get('location')
                    }
                
                # Update performance metrics
                if 'performance' in metrics:
                    perf_info = metrics['performance']
                    device.snmp_cpu_utilization = perf_info.get('cpu_utilization')
                    device.snmp_memory_info = {
                        'used': perf_info.get('memory_used'),
                        'free': perf_info.get('memory_free')
                    }
                    device.snmp_temperature = perf_info.get('temperature')
                
                # Update interface information
                if 'interfaces' in metrics:
                    interface_info = metrics['interfaces']
                    device.snmp_interface_count = interface_info.get('count')
                
                # Update vendor-specific metrics
                if 'vendor_specific' in metrics:
                    device.snmp_vendor_metrics = metrics['vendor_specific']
                
                # Add alerts if any
                alerts = monitoring_result.get('alerts', [])
                if alerts:
                    if device.snmp_vendor_metrics is None:
                        device.snmp_vendor_metrics = {}
                    device.snmp_vendor_metrics['alerts'] = alerts
                
        except Exception as e:
            logger.debug(f"Full SNMP monitoring failed for {device.ip_address}: {e}")
    
    async def _test_ssh_connection(self, device: DiscoveredDevice):
        """Test SSH connection and gather basic info"""
        try:
            import asyncssh
            import asyncio
            
            # Test SSH connectivity
            try:
                async with asyncssh.connect(
                    device.ip_address,
                    username='admin',  # Default username, should be configurable
                    password='',  # Should be from encrypted credentials
                    known_hosts=None,
                    connect_timeout=5
                ) as conn:
                    # Execute basic commands to gather device info
                    result = await conn.run('uname -a', check=False)
                    if result.returncode == 0:
                        device.os_info = result.stdout.strip()
                        logger.info(f"SSH connection successful to {device.ip_address}")
                        
                        # Try to get more device information
                        try:
                            # Get hostname
                            hostname_result = await conn.run('hostname', check=False)
                            if hostname_result.returncode == 0:
                                device.hostname = hostname_result.stdout.strip()
                            
                            # Get system info
                            system_result = await conn.run('cat /etc/os-release', check=False)
                            if system_result.returncode == 0:
                                device.system_info = system_result.stdout.strip()
                                
                        except Exception as cmd_error:
                            logger.debug(f"SSH command execution failed for {device.ip_address}: {cmd_error}")
                            
            except asyncssh.PermissionDenied:
                logger.debug(f"SSH permission denied for {device.ip_address}")
            except asyncssh.ConnectionLost:
                logger.debug(f"SSH connection lost for {device.ip_address}")
            except Exception as ssh_error:
                logger.debug(f"SSH connection failed for {device.ip_address}: {ssh_error}")
                
        except ImportError:
            logger.warning("asyncssh not available for SSH testing")
        except Exception as e:
            logger.debug(f"SSH test failed for {device.ip_address}: {e}")
    
    async def _detect_web_services(self, device: DiscoveredDevice):
        """Detect web-based management interfaces"""
        try:
            # Test for common web management interfaces
            async with aiohttp.ClientSession() as session:
                for protocol in ['http', 'https']:
                    if (protocol == 'http' and device.http_enabled) or (protocol == 'https' and device.https_enabled):
                        url = f"{protocol}://{device.ip_address}"
                        try:
                            async with session.get(url, timeout=2) as response:
                                if response.status == 200:
                                    logger.info(f"Web interface detected at {url}")
                        except asyncio.TimeoutError:
                            logger.debug(f"Web interface timeout for {url}")
                        except aiohttp.ClientError as e:
                            logger.debug(f"Web interface connection error for {url}: {e}")
                        except Exception as e:
                            logger.debug(f"Web interface detection error for {url}: {e}")
        except Exception as e:
            logger.debug(f"Web service detection failed for {device.ip_address}: {e}")
    
    # ===== NEW DISCOVERY PROTOCOLS =====
    
    async def _cdp_discovery(self, ip_list: List[str]) -> List[DiscoveredDevice]:
        """Discover devices using Cisco Discovery Protocol (CDP)"""
        logger.info("Starting CDP discovery")
        devices = []
        
        # CDP uses SNMP to query CDP neighbor tables
        cdp_neighbor_oid = "1.3.6.1.4.1.9.9.23.1.2.1.1"  # cdpCacheTable
        
        for ip in ip_list:
            try:
                # First check if device responds to ping
                if not await self._ping_host(ip):
                    continue
                
                # Try to get SNMP access
                snmp_info = await self._detect_snmp(ip)
                if not snmp_info:
                    continue
                
                device = DiscoveredDevice(
                    ip_address=ip,
                    hostname=snmp_info.get('hostname'),
                    vendor=snmp_info.get('vendor'),
                    model=snmp_info.get('model'),
                    snmp_community=snmp_info['community'],
                    snmp_version=snmp_info['version'],
                    discovery_time=datetime.now()
                )
                
                # Get CDP neighbors
                cdp_neighbors = await self._get_cdp_neighbors(ip, snmp_info)
                if cdp_neighbors:
                    if device.snmp_vendor_metrics is None:
                        device.snmp_vendor_metrics = {}
                    device.snmp_vendor_metrics['cdp_neighbors'] = cdp_neighbors
                    device.device_type = "router" if "router" in snmp_info.get('model', '').lower() else "switch"
                
                devices.append(device)
                logger.info(f"CDP discovery found device: {ip} ({device.hostname})")
                
            except Exception as e:
                logger.debug(f"CDP discovery failed for {ip}: {e}")
        
        return devices
    
    async def _lldp_discovery(self, ip_list: List[str]) -> List[DiscoveredDevice]:
        """Discover devices using Link Layer Discovery Protocol (LLDP)"""
        logger.info("Starting LLDP discovery")
        devices = []
        
        # LLDP MIB OIDs
        lldp_neighbor_oid = "1.0.8802.1.1.2.1.4.1.1"  # lldpRemTable
        
        for ip in ip_list:
            try:
                # First check if device responds to ping
                if not await self._ping_host(ip):
                    continue
                
                # Try to get SNMP access
                snmp_info = await self._detect_snmp(ip)
                if not snmp_info:
                    continue
                
                device = DiscoveredDevice(
                    ip_address=ip,
                    hostname=snmp_info.get('hostname'),
                    vendor=snmp_info.get('vendor'),
                    model=snmp_info.get('model'),
                    snmp_community=snmp_info['community'],
                    snmp_version=snmp_info['version'],
                    discovery_time=datetime.now()
                )
                
                # Get LLDP neighbors
                lldp_neighbors = await self._get_lldp_neighbors(ip, snmp_info)
                if lldp_neighbors:
                    if device.snmp_vendor_metrics is None:
                        device.snmp_vendor_metrics = {}
                    device.snmp_vendor_metrics['lldp_neighbors'] = lldp_neighbors
                    device.device_type = "switch"  # LLDP is commonly on switches
                
                devices.append(device)
                logger.info(f"LLDP discovery found device: {ip} ({device.hostname})")
                
            except Exception as e:
                logger.debug(f"LLDP discovery failed for {ip}: {e}")
        
        return devices
    
    async def _arp_discovery(self, network_cidr: str) -> List[DiscoveredDevice]:
        """Discover devices using ARP table scanning"""
        logger.info(f"Starting ARP discovery for {network_cidr}")
        devices = []
        
        try:
            # Get local ARP table
            arp_entries = await self._get_arp_table()
            
            # Filter entries for the target network
            network = ipaddress.ip_network(network_cidr, strict=False)
            
            for arp_entry in arp_entries:
                try:
                    ip_addr = ipaddress.ip_address(arp_entry['ip'])
                    if ip_addr in network:
                        device = DiscoveredDevice(
                            ip_address=str(ip_addr),
                            mac_address=arp_entry['mac'],
                            discovery_time=datetime.now()
                        )
                        
                        # Try to get hostname via reverse DNS
                        try:
                            hostname = socket.gethostbyaddr(str(ip_addr))[0]
                            device.hostname = hostname
                        except Exception as e:
                            logger.debug(f"Could not resolve hostname for {ip_addr}: {e}")
                        
                        # Try to determine device type from MAC OUI
                        device.vendor = self._get_vendor_from_mac(arp_entry['mac'])
                        device.device_type = self._guess_device_type_from_vendor(device.vendor)
                        
                        devices.append(device)
                        logger.info(f"ARP discovery found device: {ip_addr} ({arp_entry['mac']})")
                
                except Exception as e:
                    logger.debug(f"Error processing ARP entry {arp_entry}: {e}")
        
        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
        
        return devices
    
    async def _ping_discovery(self, ip_list: List[str]) -> List[DiscoveredDevice]:
        """Discover devices using ping sweep"""
        logger.info("Starting ping discovery")
        devices = []
        
        async def ping_and_discover(ip: str) -> Optional[DiscoveredDevice]:
            try:
                if await self._ping_host(ip):
                    device = DiscoveredDevice(
                        ip_address=ip,
                        discovery_time=datetime.now()
                    )
                    
                    # Try to get hostname via reverse DNS
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        device.hostname = hostname
                    except Exception as e:
                        logger.debug(f"Could not resolve hostname for {ip}: {e}")
                    
                    # Try basic port scan to determine device type
                    open_ports = await self._scan_ports(ip)
                    device.ssh_enabled = 22 in open_ports
                    device.telnet_enabled = 23 in open_ports
                    device.http_enabled = 80 in open_ports
                    device.https_enabled = 443 in open_ports
                    
                    # Guess device type from open ports
                    if 161 in open_ports:  # SNMP
                        device.device_type = "network_device"
                    elif 80 in open_ports or 443 in open_ports:
                        device.device_type = "server"
                    elif 22 in open_ports:
                        device.device_type = "server"
                    else:
                        device.device_type = "unknown"
                    
                    return device
            except Exception as e:
                logger.debug(f"Ping discovery failed for {ip}: {e}")
                
                # Return fallback device data when ping discovery fails
                fallback_data = FallbackData(
                    data=DiscoveredDevice(
                        ip_address=ip,
                        discovery_time=datetime.now(),
                        hostname=f"unknown-{ip.replace('.', '-')}",
                        device_type="unknown",
                        vendor="unknown",
                        model="unknown",
                        discovery_methods=["ping_failed"]
                    ),
                    source="ping_discovery_fallback",
                    confidence=0.0,
                    metadata={"ip": ip, "error": str(e)}
                )
                
                return create_failure_result(
                    error=f"Ping discovery failed for {ip}",
                    error_code="PING_DISCOVERY_FAILED",
                    fallback_data=fallback_data,
                    suggestions=[
                        "Ping discovery failed",
                        "Check network connectivity",
                        "Verify firewall rules",
                        "Consider alternative discovery methods"
                    ]
                )
        
        # Concurrent ping scan
        tasks = [ping_and_discover(ip) for ip in ip_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, DiscoveredDevice):
                devices.append(result)
                logger.info(f"Ping discovery found device: {result.ip_address} ({result.hostname})")
        
        return devices
    
    async def _nmap_discovery(self, network_cidr: str) -> List[DiscoveredDevice]:
        """Discover devices using Nmap network scanning"""
        logger.info(f"Starting Nmap discovery for {network_cidr}")
        devices = []
        
        try:
            # Use ThreadPoolExecutor for nmap (it's synchronous)
            with ThreadPoolExecutor(max_workers=1) as executor:
                loop = asyncio.get_event_loop()
                
                # Run nmap scan in thread
                scan_result = await loop.run_in_executor(
                    executor,
                    self._run_nmap_scan,
                    network_cidr
                )
                
                if scan_result:
                    for ip, host_info in scan_result['scan'].items():
                        try:
                            device = DiscoveredDevice(
                                ip_address=ip,
                                discovery_time=datetime.now()
                            )
                            
                            # Extract host information
                            if 'hostnames' in host_info and host_info['hostnames']:
                                device.hostname = host_info['hostnames'][0].get('name', '')
                            
                            # Extract port information
                            if 'tcp' in host_info:
                                tcp_ports = host_info['tcp']
                                open_ports = [port for port, info in tcp_ports.items() if info['state'] == 'open']
                                
                                device.ssh_enabled = 22 in open_ports
                                device.telnet_enabled = 23 in open_ports
                                device.http_enabled = 80 in open_ports
                                device.https_enabled = 443 in open_ports
                            
                            # Extract OS information if available
                            if 'osmatch' in host_info and host_info['osmatch']:
                                os_match = host_info['osmatch'][0]
                                device.vendor = self._extract_vendor_from_os(os_match.get('name', ''))
                                device.device_type = self._guess_device_type_from_os(os_match.get('name', ''))
                            
                            # Extract MAC address if available
                            if 'addresses' in host_info:
                                addresses = host_info['addresses']
                                if 'mac' in addresses:
                                    device.mac_address = addresses['mac']
                                    if not device.vendor:
                                        device.vendor = self._get_vendor_from_mac(device.mac_address)
                            
                            devices.append(device)
                            logger.info(f"Nmap discovery found device: {ip} ({device.hostname})")
                            
                        except Exception as e:
                            logger.debug(f"Error processing Nmap result for {ip}: {e}")
        
        except Exception as e:
            logger.error(f"Nmap discovery failed: {e}")
        
        return devices
    
    # ===== HELPER METHODS FOR NEW PROTOCOLS =====
    
    def _run_nmap_scan(self, network_cidr: str) -> Dict:
        """Run nmap scan (synchronous method for thread execution)"""
        try:
            # Basic nmap scan with OS detection
            result = self.nm.scan(hosts=network_cidr, arguments='-sS -O -sV --version-intensity 0')
            return result
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            
            # Return fallback nmap scan data when scan fails
            fallback_data = FallbackData(
                data={"scan": {}, "nmap": {"scanstats": {"timestr": "0s"}}},
                source="nmap_scan_fallback",
                confidence=0.0,
                metadata={"network_cidr": network_cidr, "error": str(e)}
            )
            
            return create_failure_result(
                error=f"Nmap scan failed for {network_cidr}",
                error_code="NMAP_SCAN_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Nmap scan failed",
                    "Check nmap installation",
                    "Verify network permissions",
                    "Consider alternative discovery methods"
                ]
            ).data  # Return the fallback data directly for this synchronous method
    
    async def _ping_host(self, ip: str) -> bool:
        """Simple ping test"""
        try:
            proc = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception as e:
            logger.debug(f"Ping failed for {ip}: {e}")
            return False
    
    async def _get_cdp_neighbors(self, ip: str, snmp_info: Dict) -> List[Dict]:
        """Get CDP neighbor information via SNMP"""
        neighbors = []
        try:
            credentials = {
                'host': ip,
                'community': snmp_info['community'],
                'version': snmp_info['version'],
                'port': 161,
                'timeout': 3,
                'retries': 2
            }
            
            # CDP neighbor table OIDs
            cdp_cache_address = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"  # cdpCacheAddress
            cdp_cache_device_id = "1.3.6.1.4.1.9.9.23.1.2.1.1.6"  # cdpCacheDeviceId
            cdp_cache_platform = "1.3.6.1.4.1.9.9.23.1.2.1.1.8"  # cdpCachePlatform
            
            # Walk the CDP table (simplified - in production you'd walk the full table)
            device_id = await self._get_snmp_value(ip, credentials, cdp_cache_device_id + ".0")
            if device_id:
                neighbor = {
                    'device_id': str(device_id),
                    'protocol': 'CDP'
                }
                neighbors.append(neighbor)
        
        except Exception as e:
            logger.debug(f"Failed to get CDP neighbors for {ip}: {e}")
        
        return neighbors
    
    async def _get_lldp_neighbors(self, ip: str, snmp_info: Dict) -> List[Dict]:
        """Get LLDP neighbor information via SNMP"""
        neighbors = []
        try:
            credentials = {
                'host': ip,
                'community': snmp_info['community'],
                'version': snmp_info['version'],
                'port': 161,
                'timeout': 3,
                'retries': 2
            }
            
            # LLDP neighbor table OIDs
            lldp_rem_sys_name = "1.0.8802.1.1.2.1.4.1.1.9"  # lldpRemSysName
            
            # Try to get LLDP system name (simplified)
            sys_name = await self._get_snmp_value(ip, credentials, lldp_rem_sys_name + ".0.0.0")
            if sys_name:
                neighbor = {
                    'system_name': str(sys_name),
                    'protocol': 'LLDP'
                }
                neighbors.append(neighbor)
        
        except Exception as e:
            logger.debug(f"Failed to get LLDP neighbors for {ip}: {e}")
        
        return neighbors
    
    async def _get_arp_table(self) -> List[Dict]:
        """Get system ARP table"""
        arp_entries = []
        try:
            proc = await asyncio.create_subprocess_exec(
                'arp', '-a',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL
            )
            stdout, _ = await proc.communicate()
            
            if proc.returncode == 0:
                lines = stdout.decode().split('\n')
                for line in lines:
                    if '(' in line and ')' in line:
                        # Parse line like: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0
                        parts = line.split()
                        if len(parts) >= 4:
                            ip_part = parts[1].strip('()')
                            mac_part = parts[3]
                            
                            try:
                                ipaddress.ip_address(ip_part)  # Validate IP
                                arp_entries.append({
                                    'ip': ip_part,
                                    'mac': mac_part
                                })
                            except Exception as e:
                                logger.debug(f"Failed to parse ARP entry: {e}")
                                continue
        
        except Exception as e:
            logger.debug(f"Failed to get ARP table: {e}")
        
        return arp_entries
    
    def _get_vendor_from_mac(self, mac_address: str) -> str:
        """Get vendor from MAC address OUI (simplified)"""
        if not mac_address:
            return "Unknown"
        
        # Simple OUI mapping (in production, use a comprehensive OUI database)
        oui_map = {
            '00:1b:21': 'Cisco',
            '00:1c:0e': 'Cisco',
            '00:1d:71': 'Cisco',
            '00:50:56': 'VMware',
            '00:0c:29': 'VMware',
            '08:00:27': 'Oracle VirtualBox',
            '00:15:5d': 'Microsoft',
            '00:1c:42': 'Parallels',
        }
        
        oui = mac_address[:8].lower()
        return oui_map.get(oui, "Unknown")
    
    def _guess_device_type_from_vendor(self, vendor: str) -> str:
        """Guess device type from vendor"""
        if not vendor or vendor == "Unknown":
            return "unknown"
        
        vendor_lower = vendor.lower()
        if vendor_lower in ['cisco', 'juniper', 'arista', 'brocade']:
            return "network_device"
        elif vendor_lower in ['vmware', 'microsoft', 'oracle']:
            return "server"
        else:
            return "unknown"
    
    def _extract_vendor_from_os(self, os_name: str) -> str:
        """Extract vendor from OS name"""
        os_lower = os_name.lower()
        if 'cisco' in os_lower:
            return 'Cisco'
        elif 'juniper' in os_lower or 'junos' in os_lower:
            return 'Juniper'
        elif 'linux' in os_lower:
            return 'Linux'
        elif 'windows' in os_lower:
            return 'Microsoft'
        else:
            return 'Unknown'
    
    def _guess_device_type_from_os(self, os_name: str) -> str:
        """Guess device type from OS name"""
        os_lower = os_name.lower()
        if any(keyword in os_lower for keyword in ['router', 'switch', 'firewall', 'cisco', 'juniper']):
            return 'network_device'
        elif any(keyword in os_lower for keyword in ['server', 'windows server', 'linux']):
            return 'server'
        elif any(keyword in os_lower for keyword in ['printer', 'print']):
            return 'printer'
        else:
            return 'unknown'

# Global discovery service instance
discovery_service = NetworkDiscoveryService()
