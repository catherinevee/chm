"""
SNMP Session Management
Provides comprehensive SNMP monitoring capabilities for network devices
"""

import asyncio
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging
try:
    # Try new pysnmp 7.x imports
    from pysnmp.hlapi.v3arch.asyncio import *
    from pysnmp.hlapi.v3arch import *
except ImportError:
    # Fallback to older pysnmp imports
    from pysnmp.hlapi import *
    
from pysnmp.proto.rfc1902 import Integer32, OctetString, Counter32, Gauge32, TimeTicks

from .oids import OIDManager, OIDDefinition, OIDCategory, StandardMIBs, CiscoOIDs, JuniperOIDs, AristaOIDs

logger = logging.getLogger(__name__)

@dataclass
class SNMPCredentials:
    """SNMP credentials for different versions"""
    version: str = "2c"  # 1, 2c, 3
    community: Optional[str] = "public"  # For v1/v2c
    username: Optional[str] = None  # For v3
    auth_protocol: Optional[str] = None  # MD5, SHA
    auth_password: Optional[str] = None
    priv_protocol: Optional[str] = None  # DES, AES128, AES192, AES256
    priv_password: Optional[str] = None
    security_level: str = "noAuthNoPriv"  # noAuthNoPriv, authNoPriv, authPriv

@dataclass
class SNMPResult:
    """Result of SNMP operation"""
    success: bool
    value: Optional[Any] = None
    oid: Optional[str] = None
    name: Optional[str] = None
    error: Optional[str] = None
    timestamp: datetime = None

@dataclass
class DeviceMetrics:
    """Comprehensive device metrics"""
    # System metrics
    system_uptime: Optional[int] = None
    system_description: Optional[str] = None
    system_name: Optional[str] = None
    system_location: Optional[str] = None
    
    # Performance metrics
    cpu_utilization: Optional[float] = None
    memory_used: Optional[int] = None
    memory_free: Optional[int] = None
    memory_total: Optional[int] = None
    temperature: Optional[float] = None
    
    # Interface metrics
    interface_count: Optional[int] = None
    interface_stats: Dict[str, Dict[str, Any]] = None
    
    # Traffic metrics
    ip_in_receives: Optional[int] = None
    ip_in_delivers: Optional[int] = None
    ip_out_requests: Optional[int] = None
    ip_in_errors: Optional[int] = None
    ip_out_discards: Optional[int] = None
    
    # TCP/UDP metrics
    tcp_active_opens: Optional[int] = None
    tcp_passive_opens: Optional[int] = None
    tcp_curr_estab: Optional[int] = None
    tcp_in_segs: Optional[int] = None
    tcp_out_segs: Optional[int] = None
    tcp_retrans_segs: Optional[int] = None
    tcp_in_errs: Optional[int] = None
    
    # Error metrics
    interface_errors: Dict[str, Dict[str, int]] = None
    
    # Vendor-specific metrics
    vendor_metrics: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.interface_stats is None:
            self.interface_stats = {}
        if self.interface_errors is None:
            self.interface_errors = {}
        if self.vendor_metrics is None:
            self.vendor_metrics = {}

class SNMPSession:
    """Enhanced SNMP session with comprehensive monitoring capabilities including SNMPv3"""
    
    def __init__(self, host: str, credentials: Optional[SNMPCredentials] = None, 
                 port: int = 161, timeout: int = 3, retries: int = 3):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.vendor = None
        self.device_type = None
        
        # Handle credentials
        if credentials is None:
            credentials = SNMPCredentials()
        self.credentials = credentials
        
        # Initialize OID manager
        self.oid_manager = OIDManager()
        
        # Validate SNMPv3 credentials
        if self.credentials.version == "3":
            self._validate_snmpv3_credentials()
    
    def _validate_snmpv3_credentials(self):
        """Validate SNMPv3 credentials"""
        if not self.credentials.username:
            raise ValueError("Username is required for SNMPv3")
        
        if self.credentials.security_level in ["authNoPriv", "authPriv"]:
            if not self.credentials.auth_protocol or not self.credentials.auth_password:
                raise ValueError("Authentication protocol and password required for authNoPriv/authPriv")
        
        if self.credentials.security_level == "authPriv":
            if not self.credentials.priv_protocol or not self.credentials.priv_password:
                raise ValueError("Privacy protocol and password required for authPriv")
    
    def _get_auth_protocol(self, protocol: str):
        """Get authentication protocol object"""
        if protocol.upper() == "MD5":
            return "usmHMACMD5AuthProtocol"
        elif protocol.upper() == "SHA":
            return "usmHMACSHAAuthProtocol"
        else:
            raise ValueError(f"Unsupported authentication protocol: {protocol}")
    
    def _get_priv_protocol(self, protocol: str):
        """Get privacy protocol object"""
        if protocol.upper() == "DES":
            return "usmDESPrivProtocol"
        elif protocol.upper() == "AES128":
            return "usmAesCfb128Protocol"
        elif protocol.upper() == "AES192":
            return "usmAesCfb192Protocol"
        elif protocol.upper() == "AES256":
            return "usmAesCfb256Protocol"
        else:
            raise ValueError(f"Unsupported privacy protocol: {protocol}")
    
    def _create_security_data(self):
        """Create appropriate security data based on SNMP version"""
        if self.credentials.version == "3":
            # SNMPv3 User-based Security Model
            if self.credentials.security_level == "noAuthNoPriv":
                return UsmUserData(self.credentials.username)
            elif self.credentials.security_level == "authNoPriv":
                return UsmUserData(
                    self.credentials.username,
                    authKey=self.credentials.auth_password
                )
            elif self.credentials.security_level == "authPriv":
                return UsmUserData(
                    self.credentials.username,
                    authKey=self.credentials.auth_password,
                    privKey=self.credentials.priv_password
                )
        else:
            # SNMPv1/v2c Community-based Security Model
            mp_model = 1 if self.credentials.version == "1" else 0
            return CommunityData(self.credentials.community or "public", mpModel=mp_model)
        
        raise ValueError(f"Unsupported SNMP version: {self.credentials.version}")
        
    async def connect(self) -> bool:
        """Test SNMP connectivity"""
        try:
            # Try to get system description
            result = await self.get_system_description()
            if result.success:
                # Determine vendor from system description
                self.vendor = self._determine_vendor(result.value)
                self.device_type = self._determine_device_type(result.value)
                logger.info(f"SNMP connection established to {self.host} (Vendor: {self.vendor}, Type: {self.device_type})")
                return True
            return False
        except Exception as e:
            logger.error(f"SNMP connection failed to {self.host}: {e}")
            return False
    
    async def get_system_description(self) -> SNMPResult:
        """Get system description"""
        return await self._get_single_oid(StandardMIBs.SYSTEM['sysDescr'].oid)
    
    async def get_system_uptime(self) -> SNMPResult:
        """Get system uptime"""
        return await self._get_single_oid(StandardMIBs.SYSTEM['sysUpTime'].oid)
    
    async def get_system_name(self) -> SNMPResult:
        """Get system name"""
        return await self._get_single_oid(StandardMIBs.SYSTEM['sysName'].oid)
    
    async def get_system_location(self) -> SNMPResult:
        """Get system location"""
        return await self._get_single_oid(StandardMIBs.SYSTEM['sysLocation'].oid)
    
    async def get_cpu_usage(self) -> SNMPResult:
        """Get CPU usage (vendor-specific)"""
        if not self.vendor:
            return SNMPResult(success=False, error="Vendor not determined")
        
        # Get vendor-specific CPU OIDs
        vendor_oids = self.oid_manager.get_vendor_oids(self.vendor, self.device_type)
        cpu_oids = vendor_oids.get('cpu', [])
        
        if not cpu_oids:
            return SNMPResult(success=False, error="No CPU OIDs available for this vendor")
        
        # Try each CPU OID until one works
        for cpu_oid in cpu_oids:
            result = await self._get_single_oid(cpu_oid.oid)
            if result.success:
                return result
        
        return SNMPResult(success=False, error="Failed to get CPU usage from all available OIDs")
    
    async def get_memory_usage(self) -> Dict[str, Any]:
        """Get memory usage information"""
        if not self.vendor:
            return {"error": "Vendor not determined"}
        
        vendor_oids = self.oid_manager.get_vendor_oids(self.vendor, self.device_type)
        memory_oids = vendor_oids.get('memory', [])
        
        memory_info = {}
        for memory_oid in memory_oids:
            result = await self._get_single_oid(memory_oid.oid)
            if result.success:
                memory_info[memory_oid.name] = {
                    'value': result.value,
                    'unit': memory_oid.unit,
                    'description': memory_oid.description
                }
        
        return memory_info
    
    async def get_temperature(self) -> SNMPResult:
        """Get device temperature"""
        if not self.vendor:
            return SNMPResult(success=False, error="Vendor not determined")
        
        vendor_oids = self.oid_manager.get_vendor_oids(self.vendor, self.device_type)
        temp_oids = vendor_oids.get('temperature', [])
        
        if not temp_oids:
            return SNMPResult(success=False, error="No temperature OIDs available for this vendor")
        
        # Try each temperature OID until one works
        for temp_oid in temp_oids:
            result = await self._get_single_oid(temp_oid.oid)
            if result.success:
                return result
        
        return SNMPResult(success=False, error="Failed to get temperature from all available OIDs")
    
    async def get_interface_count(self) -> SNMPResult:
        """Get number of interfaces"""
        return await self._get_single_oid(StandardMIBs.INTERFACE['ifNumber'].oid)
    
    async def get_interface_table(self) -> Dict[str, Dict[str, Any]]:
        """Get complete interface table"""
        interfaces = {}
        
        # Get interface indices first
        indices = await self._walk_oid(StandardMIBs.INTERFACE['ifIndex'].oid)
        if not indices.success:
            return interfaces
        
        # For each interface, get all relevant information
        for index in indices.value:
            interface_info = await self._get_interface_info(index)
            if interface_info:
                interfaces[index] = interface_info
        
        return interfaces
    
    async def get_interface_stats(self) -> Dict[str, Dict[str, int]]:
        """Get interface statistics (traffic, errors, discards)"""
        stats = {}
        
        # Get interface indices
        indices = await self._walk_oid(StandardMIBs.INTERFACE['ifIndex'].oid)
        if not indices.success:
            return stats
        
        # Get traffic statistics for each interface
        for index in indices.value:
            interface_stats = {}
            
            # Traffic counters
            in_octets = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifInOctets'].oid}.{index}")
            if in_octets.success:
                interface_stats['in_octets'] = in_octets.value
            
            out_octets = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifOutOctets'].oid}.{index}")
            if out_octets.success:
                interface_stats['out_octets'] = out_octets.value
            
            # Error counters
            in_errors = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifInErrors'].oid}.{index}")
            if in_errors.success:
                interface_stats['in_errors'] = in_errors.value
            
            out_errors = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifOutErrors'].oid}.{index}")
            if out_errors.success:
                interface_stats['out_errors'] = out_errors.value
            
            # Discard counters
            in_discards = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifInDiscards'].oid}.{index}")
            if in_discards.success:
                interface_stats['in_discards'] = in_discards.value
            
            out_discards = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifOutDiscards'].oid}.{index}")
            if out_discards.success:
                interface_stats['out_discards'] = out_discards.value
            
            if interface_stats:
                stats[index] = interface_stats
        
        return stats
    
    async def get_ip_statistics(self) -> Dict[str, int]:
        """Get IP layer statistics"""
        ip_stats = {}
        
        ip_oids = [
            'ipInReceives', 'ipInDelivers', 'ipOutRequests',
            'ipInErrors', 'ipOutDiscards', 'ipInHdrErrors',
            'ipInAddrErrors', 'ipInUnknownProtos', 'ipInDiscards'
        ]
        
        for oid_name in ip_oids:
            if oid_name in StandardMIBs.IP:
                result = await self._get_single_oid(StandardMIBs.IP[oid_name].oid)
                if result.success:
                    ip_stats[oid_name] = result.value
        
        return ip_stats
    
    async def get_tcp_statistics(self) -> Dict[str, int]:
        """Get TCP layer statistics"""
        tcp_stats = {}
        
        tcp_oids = [
            'tcpActiveOpens', 'tcpPassiveOpens', 'tcpCurrEstab',
            'tcpInSegs', 'tcpOutSegs', 'tcpRetransSegs', 'tcpInErrs'
        ]
        
        for oid_name in tcp_oids:
            if oid_name in StandardMIBs.TCP:
                result = await self._get_single_oid(StandardMIBs.TCP[oid_name].oid)
                if result.success:
                    tcp_stats[oid_name] = result.value
        
        return tcp_stats
    
    async def get_comprehensive_metrics(self) -> DeviceMetrics:
        """Get comprehensive device metrics"""
        metrics = DeviceMetrics()
        
        # System information
        sys_uptime = await self.get_system_uptime()
        if sys_uptime.success:
            metrics.system_uptime = sys_uptime.value
        
        sys_name = await self.get_system_name()
        if sys_name.success:
            metrics.system_name = sys_name.value
        
        sys_location = await self.get_system_location()
        if sys_location.success:
            metrics.system_location = sys_location.value
        
        # Performance metrics
        cpu_result = await self.get_cpu_usage()
        if cpu_result.success:
            metrics.cpu_utilization = cpu_result.value
        
        memory_info = await self.get_memory_usage()
        if memory_info and 'error' not in memory_info:
            metrics.vendor_metrics['memory'] = memory_info
        
        temp_result = await self.get_temperature()
        if temp_result.success:
            metrics.temperature = temp_result.value
        
        # Interface metrics
        if_count = await self.get_interface_count()
        if if_count.success:
            metrics.interface_count = if_count.value
        
        interface_stats = await self.get_interface_stats()
        if interface_stats:
            metrics.interface_stats = interface_stats
        
        # IP statistics
        ip_stats = await self.get_ip_statistics()
        if ip_stats:
            metrics.ip_in_receives = ip_stats.get('ipInReceives')
            metrics.ip_in_delivers = ip_stats.get('ipInDelivers')
            metrics.ip_out_requests = ip_stats.get('ipOutRequests')
            metrics.ip_in_errors = ip_stats.get('ipInErrors')
            metrics.ip_out_discards = ip_stats.get('ipOutDiscards')
        
        # TCP statistics
        tcp_stats = await self.get_tcp_statistics()
        if tcp_stats:
            metrics.tcp_active_opens = tcp_stats.get('tcpActiveOpens')
            metrics.tcp_passive_opens = tcp_stats.get('tcpPassiveOpens')
            metrics.tcp_curr_estab = tcp_stats.get('tcpCurrEstab')
            metrics.tcp_in_segs = tcp_stats.get('tcpInSegs')
            metrics.tcp_out_segs = tcp_stats.get('tcpOutSegs')
            metrics.tcp_retrans_segs = tcp_stats.get('tcpRetransSegs')
            metrics.tcp_in_errs = tcp_stats.get('tcpInErrs')
        
        # Vendor-specific metrics
        if self.vendor:
            vendor_metrics = await self._get_vendor_specific_metrics()
            if vendor_metrics:
                metrics.vendor_metrics.update(vendor_metrics)
        
        return metrics
    
    async def _get_vendor_specific_metrics(self) -> Dict[str, Any]:
        """Get vendor-specific metrics"""
        vendor_metrics = {}
        
        if self.vendor.lower() == 'cisco':
            # Cisco-specific metrics
            if self.device_type in ['3560', '4500']:
                # PoE metrics
                poe_oids = CiscoOIDs.POE
                for name, oid_def in poe_oids.items():
                    result = await self._get_single_oid(oid_def.oid)
                    if result.success:
                        vendor_metrics[f'poe_{name}'] = result.value
            
            if self.device_type in ['2960', '3560']:
                # Stack metrics
                stack_oids = CiscoOIDs.STACK
                for name, oid_def in stack_oids.items():
                    result = await self._get_single_oid(oid_def.oid)
                    if result.success:
                        vendor_metrics[f'stack_{name}'] = result.value
            
            if self.device_type == '4500':
                # Supervisor metrics
                supervisor_oids = CiscoOIDs.SUPERVISOR
                for name, oid_def in supervisor_oids.items():
                    result = await self._get_single_oid(oid_def.oid)
                    if result.success:
                        vendor_metrics[f'supervisor_{name}'] = result.value
        
        return vendor_metrics
    
    async def _get_interface_info(self, index: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific interface"""
        interface_info = {}
        
        # Interface description
        desc_result = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifDescr'].oid}.{index}")
        if desc_result.success:
            interface_info['description'] = desc_result.value
        
        # Interface type
        type_result = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifType'].oid}.{index}")
        if type_result.success:
            interface_info['type'] = type_result.value
        
        # Interface speed
        speed_result = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifSpeed'].oid}.{index}")
        if speed_result.success:
            interface_info['speed'] = speed_result.value
        
        # Administrative status
        admin_result = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifAdminStatus'].oid}.{index}")
        if admin_result.success:
            interface_info['admin_status'] = admin_result.value
        
        # Operational status
        oper_result = await self._get_single_oid(f"{StandardMIBs.INTERFACE['ifOperStatus'].oid}.{index}")
        if oper_result.success:
            interface_info['oper_status'] = oper_result.value
        
        return interface_info if interface_info else None
    
    async def _get_single_oid(self, oid: str) -> SNMPResult:
        """Get a single OID value"""
        try:
            # Create SNMP engine and data
            snmp_engine = SnmpEngine()
            security_data = self._create_security_data()
            transport_target = UdpTransportTarget((self.host, self.port), 
                                                timeout=self.timeout, 
                                                retries=self.retries)
            context_data = ContextData()
            
            # Create object identity
            object_identity = ObjectIdentity(oid)
            
            # Execute SNMP GET
            iterator = getCmd(snmp_engine, security_data, transport_target, 
                            context_data, ObjectType(object_identity))
            
            error_indication, error_status, error_index, var_binds = next(iterator)
            
            if error_indication:
                return SNMPResult(success=False, error=str(error_indication), oid=oid)
            
            if error_status:
                return SNMPResult(success=False, 
                                error=f"{error_status.prettyPrint()} at {var_binds[int(error_index) - 1][0] if error_index else '?'}", 
                                oid=oid)
            
            # Extract value
            for var_bind in var_binds:
                oid_name, oid_value = var_bind
                return SNMPResult(success=True, 
                                value=self._convert_snmp_value(oid_value), 
                                oid=str(oid_name), 
                                name=str(oid_name), 
                                timestamp=datetime.now())
            
            return SNMPResult(success=False, error="No data returned", oid=oid)
            
        except Exception as e:
            logger.error(f"SNMP GET failed for {oid}: {e}")
            return SNMPResult(success=False, error=str(e), oid=oid)
    
    async def _walk_oid(self, base_oid: str) -> SNMPResult:
        """Walk an OID tree"""
        try:
            # Create SNMP engine and data
            snmp_engine = SnmpEngine()
            security_data = self._create_security_data()
            transport_target = UdpTransportTarget((self.host, self.port), 
                                                timeout=self.timeout, 
                                                retries=self.retries)
            context_data = ContextData()
            
            # Create object identity
            object_identity = ObjectIdentity(base_oid)
            
            # Execute SNMP WALK
            iterator = nextCmd(snmp_engine, security_data, transport_target, 
                             context_data, ObjectType(object_identity), 
                             lexicographicMode=False, maxRows=100)
            
            values = []
            for error_indication, error_status, error_index, var_binds in iterator:
                if error_indication:
                    return SNMPResult(success=False, error=str(error_indication), oid=base_oid)
                
                if error_status:
                    return SNMPResult(success=False, 
                                    error=f"{error_status.prettyPrint()} at {var_binds[int(error_index) - 1][0] if error_index else '?'}", 
                                    oid=base_oid)
                
                for var_bind in var_binds:
                    oid_name, oid_value = var_bind
                    values.append(self._convert_snmp_value(oid_value))
            
            return SNMPResult(success=True, value=values, oid=base_oid, timestamp=datetime.now())
            
        except Exception as e:
            logger.error(f"SNMP WALK failed for {base_oid}: {e}")
            return SNMPResult(success=False, error=str(e), oid=base_oid)
    
    def _convert_snmp_value(self, snmp_value) -> Any:
        """Convert SNMP value to Python type"""
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
    
    def _determine_vendor(self, sys_descr: str) -> str:
        """Determine vendor from system description"""
        sys_descr_lower = sys_descr.lower()
        
        if 'cisco' in sys_descr_lower:
            return 'Cisco'
        elif 'juniper' in sys_descr_lower:
            return 'Juniper'
        elif 'arista' in sys_descr_lower:
            return 'Arista'
        elif 'hp' in sys_descr_lower or 'hewlett-packard' in sys_descr_lower:
            return 'HP'
        elif 'brocade' in sys_descr_lower:
            return 'Brocade'
        elif 'extreme' in sys_descr_lower:
            return 'Extreme'
        else:
            return 'Unknown'
    
    def _determine_device_type(self, sys_descr: str) -> str:
        """Determine device type from system description"""
        sys_descr_lower = sys_descr.lower()
        
        if '2960' in sys_descr:
            return '2960'
        elif '3560' in sys_descr:
            return '3560'
        elif '4500' in sys_descr:
            return '4500'
        elif '3850' in sys_descr:
            return '3850'
        elif '9300' in sys_descr:
            return '9300'
        else:
            return 'Unknown'

class SNMPManager:
    """Manages multiple SNMP sessions"""
    
    def __init__(self):
        self.sessions: Dict[str, SNMPSession] = {}
    
    async def get_session(self, device_id: str, credentials: Dict[str, Any]) -> Optional[SNMPSession]:
        """Get or create SNMP session for a device"""
        if device_id in self.sessions:
            return self.sessions[device_id]
        
        # Create SNMP credentials object
        snmp_creds = SNMPCredentials(
            version=credentials.get('version', '2c'),
            community=credentials.get('community', 'public'),
            username=credentials.get('username'),
            auth_protocol=credentials.get('auth_protocol'),
            auth_password=credentials.get('auth_password'),
            priv_protocol=credentials.get('priv_protocol'),
            priv_password=credentials.get('priv_password'),
            security_level=credentials.get('security_level', 'noAuthNoPriv')
        )
        
        # Create new session
        session = SNMPSession(
            host=credentials['host'],
            credentials=snmp_creds,
            port=credentials.get('port', 161),
            timeout=credentials.get('timeout', 3),
            retries=credentials.get('retries', 3)
        )
        
        # Test connection
        if await session.connect():
            self.sessions[device_id] = session
            return session
        
        # Return fallback session data when SNMP connection fails
        fallback_data = FallbackData(
            data=None,
            source="session_fallback",
            confidence=0.0,
            metadata={"reason": "SNMP session creation failed", "device_id": device_id}
        )
        
        return create_failure_result(
            error="SNMP session creation failed",
            error_code="SNMP_SESSION_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Check network connectivity to the device",
                "Verify SNMP is enabled on the device",
                "Check SNMP community string and version",
                "Verify SNMP port is accessible",
                "Check firewall rules for SNMP",
                "Verify SNMP user credentials for SNMPv3"
            ]
        )
    
    async def close_session(self, device_id: str):
        """Close SNMP session for a device"""
        if device_id in self.sessions:
            del self.sessions[device_id]
    
    async def close_all_sessions(self):
        """Close all SNMP sessions"""
        self.sessions.clear()

# Global SNMP manager instance
snmp_manager = SNMPManager()
