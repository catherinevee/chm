"""
SNMP Client - Comprehensive SNMP v1/v2c/v3 implementation for device monitoring
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
from pysnmp.hlapi.asyncio import (
    SnmpEngine,
    CommunityData,
    UsmUserData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
    bulkCmd,
    setCmd,
    usmHMACMD5AuthProtocol,
    usmHMACSHAAuthProtocol,
    usmDESPrivProtocol,
    usmAesCfb128Protocol,
    usmNoAuthProtocol,
    usmNoPrivProtocol
)
from pysnmp.proto.rfc1902 import Integer, OctetString, ObjectName
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pyasn1.type import univ

logger = logging.getLogger(__name__)

class SNMPClient:
    """
    Comprehensive SNMP client supporting v1, v2c, and v3 protocols
    """
    
    # Standard SNMP OIDs
    OIDS = {
        # System Information
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
        'sysServices': '1.3.6.1.2.1.1.7.0',
        
        # Interface Information
        'ifNumber': '1.3.6.1.2.1.2.1.0',
        'ifTable': '1.3.6.1.2.1.2.2',
        'ifIndex': '1.3.6.1.2.1.2.2.1.1',
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',
        'ifType': '1.3.6.1.2.1.2.2.1.3',
        'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
        'ifPhysAddress': '1.3.6.1.2.1.2.2.1.6',
        'ifAdminStatus': '1.3.6.1.2.1.2.2.1.7',
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
        'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
        'ifOutOctets': '1.3.6.1.2.1.2.2.1.16',
        'ifInErrors': '1.3.6.1.2.1.2.2.1.14',
        'ifOutErrors': '1.3.6.1.2.1.2.2.1.20',
        
        # CPU and Memory (Cisco)
        'cpmCPUTotal5min': '1.3.6.1.4.1.9.9.109.1.1.1.1.5',
        'cpmCPUTotal1min': '1.3.6.1.4.1.9.9.109.1.1.1.1.3',
        'ciscoMemoryPoolUsed': '1.3.6.1.4.1.9.9.48.1.1.1.5',
        'ciscoMemoryPoolFree': '1.3.6.1.4.1.9.9.48.1.1.1.6',
        
        # Host Resources MIB
        'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
        'hrStorageTable': '1.3.6.1.2.1.25.2.3',
        'hrStorageDescr': '1.3.6.1.2.1.25.2.3.1.3',
        'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
        'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
        
        # Environmental (Entity Sensor MIB)
        'entPhySensorValue': '1.3.6.1.2.1.99.1.1.1.4',
        'entPhySensorType': '1.3.6.1.2.1.99.1.1.1.1',
        
        # IP MIB
        'ipForwarding': '1.3.6.1.2.1.4.1.0',
        'ipInReceives': '1.3.6.1.2.1.4.3.0',
        'ipInDelivers': '1.3.6.1.2.1.4.9.0',
        'ipOutRequests': '1.3.6.1.2.1.4.10.0',
    }
    
    def __init__(self, 
                 host: str,
                 port: int = 161,
                 timeout: int = 5,
                 retries: int = 3):
        """
        Initialize SNMP client
        
        Args:
            host: Target device IP address
            port: SNMP port (default: 161)
            timeout: Request timeout in seconds
            retries: Number of retry attempts
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.engine = SnmpEngine()
        self.transport = UdpTransportTarget((host, port), timeout=timeout, retries=retries)
        
    async def get_v2c(self, 
                      community: str,
                      oids: List[str]) -> Dict[str, Any]:
        """
        Perform SNMP GET operation using v2c
        
        Args:
            community: SNMP community string
            oids: List of OIDs to retrieve
            
        Returns:
            Dictionary of OID: value pairs
        """
        try:
            results = {}
            auth_data = CommunityData(community, mpModel=1)  # v2c
            
            for oid in oids:
                error_indication, error_status, error_index, var_binds = await getCmd(
                    self.engine,
                    auth_data,
                    self.transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                
                if error_indication:
                    logger.error(f"SNMP error: {error_indication}")
                    results[oid] = None
                elif error_status:
                    logger.error(f"SNMP error at {error_index}: {error_status}")
                    results[oid] = None
                else:
                    for var_bind in var_binds:
                        oid_str = str(var_bind[0])
                        value = self._convert_value(var_bind[1])
                        results[oid_str] = value
                        
            return results
            
        except Exception as e:
            logger.error(f"SNMP v2c GET error: {str(e)}")
            raise
    
    async def get_v3(self,
                     username: str,
                     auth_key: Optional[str] = None,
                     priv_key: Optional[str] = None,
                     auth_protocol: str = 'SHA',
                     priv_protocol: str = 'AES',
                     oids: List[str] = None) -> Dict[str, Any]:
        """
        Perform SNMP GET operation using v3
        
        Args:
            username: SNMPv3 username
            auth_key: Authentication key
            priv_key: Privacy/encryption key
            auth_protocol: Authentication protocol (MD5, SHA)
            priv_protocol: Privacy protocol (DES, AES)
            oids: List of OIDs to retrieve
            
        Returns:
            Dictionary of OID: value pairs
        """
        try:
            results = {}
            
            # Setup authentication
            auth_proto = usmHMACSHAAuthProtocol if auth_protocol == 'SHA' else usmHMACMD5AuthProtocol
            priv_proto = usmAesCfb128Protocol if priv_protocol == 'AES' else usmDESPrivProtocol
            
            if auth_key and priv_key:
                # authPriv
                user_data = UsmUserData(username, auth_key, priv_key,
                                       authProtocol=auth_proto,
                                       privProtocol=priv_proto)
            elif auth_key:
                # authNoPriv
                user_data = UsmUserData(username, auth_key,
                                       authProtocol=auth_proto)
            else:
                # noAuthNoPriv
                user_data = UsmUserData(username)
            
            for oid in oids:
                error_indication, error_status, error_index, var_binds = await getCmd(
                    self.engine,
                    user_data,
                    self.transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(oid))
                )
                
                if error_indication:
                    logger.error(f"SNMPv3 error: {error_indication}")
                    results[oid] = None
                elif error_status:
                    logger.error(f"SNMPv3 error at {error_index}: {error_status}")
                    results[oid] = None
                else:
                    for var_bind in var_binds:
                        oid_str = str(var_bind[0])
                        value = self._convert_value(var_bind[1])
                        results[oid_str] = value
                        
            return results
            
        except Exception as e:
            logger.error(f"SNMPv3 GET error: {str(e)}")
            raise
    
    async def walk(self,
                   community: str,
                   base_oid: str,
                   version: str = 'v2c',
                   max_rows: int = 1000) -> List[Tuple[str, Any]]:
        """
        Perform SNMP WALK operation
        
        Args:
            community: SNMP community string
            base_oid: Base OID to walk from
            version: SNMP version
            max_rows: Maximum number of rows to retrieve
            
        Returns:
            List of (OID, value) tuples
        """
        try:
            results = []
            auth_data = CommunityData(community, mpModel=1 if version == 'v2c' else 0)
            
            rows_retrieved = 0
            async for error_indication, error_status, error_index, var_binds in nextCmd(
                self.engine,
                auth_data,
                self.transport,
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False
            ):
                if error_indication:
                    logger.error(f"SNMP WALK error: {error_indication}")
                    break
                elif error_status:
                    logger.error(f"SNMP WALK error at {error_index}: {error_status}")
                    break
                else:
                    for var_bind in var_binds:
                        oid_str = str(var_bind[0])
                        value = self._convert_value(var_bind[1])
                        results.append((oid_str, value))
                        rows_retrieved += 1
                        
                        if rows_retrieved >= max_rows:
                            break
                
                if rows_retrieved >= max_rows:
                    break
                    
            return results
            
        except Exception as e:
            logger.error(f"SNMP WALK error: {str(e)}")
            raise
    
    async def bulk_get(self,
                       community: str,
                       oids: List[str],
                       non_repeaters: int = 0,
                       max_repetitions: int = 25) -> Dict[str, Any]:
        """
        Perform SNMP BULK GET operation (v2c/v3 only)
        
        Args:
            community: SNMP community string
            oids: List of OIDs to retrieve
            non_repeaters: Number of non-repeating OIDs
            max_repetitions: Maximum repetitions for repeating OIDs
            
        Returns:
            Dictionary of OID: value pairs
        """
        try:
            results = {}
            auth_data = CommunityData(community, mpModel=1)  # v2c
            
            error_indication, error_status, error_index, var_binds = await bulkCmd(
                self.engine,
                auth_data,
                self.transport,
                ContextData(),
                non_repeaters,
                max_repetitions,
                *[ObjectType(ObjectIdentity(oid)) for oid in oids]
            )
            
            if error_indication:
                logger.error(f"SNMP BULK GET error: {error_indication}")
            elif error_status:
                logger.error(f"SNMP BULK GET error at {error_index}: {error_status}")
            else:
                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    value = self._convert_value(var_bind[1])
                    results[oid_str] = value
                    
            return results
            
        except Exception as e:
            logger.error(f"SNMP BULK GET error: {str(e)}")
            raise
    
    async def get_system_info(self, community: str) -> Dict[str, Any]:
        """
        Get basic system information
        
        Args:
            community: SNMP community string
            
        Returns:
            Dictionary with system information
        """
        oids = [
            self.OIDS['sysDescr'],
            self.OIDS['sysName'],
            self.OIDS['sysLocation'],
            self.OIDS['sysContact'],
            self.OIDS['sysUpTime']
        ]
        
        data = await self.get_v2c(community, oids)
        
        return {
            'description': data.get(self.OIDS['sysDescr']),
            'hostname': data.get(self.OIDS['sysName']),
            'location': data.get(self.OIDS['sysLocation']),
            'contact': data.get(self.OIDS['sysContact']),
            'uptime': self._parse_uptime(data.get(self.OIDS['sysUpTime']))
        }
    
    async def get_interfaces(self, community: str) -> List[Dict[str, Any]]:
        """
        Get network interface information
        
        Args:
            community: SNMP community string
            
        Returns:
            List of interface dictionaries
        """
        interfaces = []
        
        # Walk interface table
        if_indices = await self.walk(community, self.OIDS['ifIndex'])
        
        for oid, index in if_indices:
            if_data = {}
            if_data['index'] = index
            
            # Get interface details
            oids = {
                'description': f"{self.OIDS['ifDescr']}.{index}",
                'type': f"{self.OIDS['ifType']}.{index}",
                'speed': f"{self.OIDS['ifSpeed']}.{index}",
                'admin_status': f"{self.OIDS['ifAdminStatus']}.{index}",
                'oper_status': f"{self.OIDS['ifOperStatus']}.{index}",
                'in_octets': f"{self.OIDS['ifInOctets']}.{index}",
                'out_octets': f"{self.OIDS['ifOutOctets']}.{index}",
                'in_errors': f"{self.OIDS['ifInErrors']}.{index}",
                'out_errors': f"{self.OIDS['ifOutErrors']}.{index}"
            }
            
            details = await self.get_v2c(community, list(oids.values()))
            
            if_data['description'] = details.get(oids['description'])
            if_data['type'] = self._get_interface_type(details.get(oids['type']))
            if_data['speed'] = details.get(oids['speed'])
            if_data['admin_status'] = 'up' if details.get(oids['admin_status']) == 1 else 'down'
            if_data['oper_status'] = 'up' if details.get(oids['oper_status']) == 1 else 'down'
            if_data['in_octets'] = details.get(oids['in_octets'], 0)
            if_data['out_octets'] = details.get(oids['out_octets'], 0)
            if_data['in_errors'] = details.get(oids['in_errors'], 0)
            if_data['out_errors'] = details.get(oids['out_errors'], 0)
            
            interfaces.append(if_data)
            
        return interfaces
    
    async def get_cpu_usage(self, community: str, vendor: str = 'cisco') -> Dict[str, float]:
        """
        Get CPU usage information
        
        Args:
            community: SNMP community string
            vendor: Device vendor (cisco, juniper, etc.)
            
        Returns:
            Dictionary with CPU usage percentages
        """
        cpu_data = {}
        
        if vendor.lower() == 'cisco':
            oids = [
                self.OIDS['cpmCPUTotal1min'],
                self.OIDS['cpmCPUTotal5min']
            ]
            data = await self.get_v2c(community, oids)
            cpu_data['1min'] = data.get(self.OIDS['cpmCPUTotal1min'], 0)
            cpu_data['5min'] = data.get(self.OIDS['cpmCPUTotal5min'], 0)
            
        elif vendor.lower() in ['generic', 'linux']:
            # Use HOST-RESOURCES-MIB
            processors = await self.walk(community, self.OIDS['hrProcessorLoad'])
            if processors:
                cpu_values = [value for _, value in processors if value]
                if cpu_values:
                    cpu_data['average'] = sum(cpu_values) / len(cpu_values)
                    cpu_data['max'] = max(cpu_values)
                    cpu_data['processors'] = len(cpu_values)
        
        return cpu_data
    
    async def get_memory_usage(self, community: str, vendor: str = 'cisco') -> Dict[str, Any]:
        """
        Get memory usage information
        
        Args:
            community: SNMP community string
            vendor: Device vendor
            
        Returns:
            Dictionary with memory usage information
        """
        memory_data = {}
        
        if vendor.lower() == 'cisco':
            # Cisco specific memory OIDs
            used_oid = f"{self.OIDS['ciscoMemoryPoolUsed']}.1"
            free_oid = f"{self.OIDS['ciscoMemoryPoolFree']}.1"
            
            data = await self.get_v2c(community, [used_oid, free_oid])
            used = data.get(used_oid, 0)
            free = data.get(free_oid, 0)
            total = used + free
            
            memory_data = {
                'used': used,
                'free': free,
                'total': total,
                'percent_used': (used / total * 100) if total > 0 else 0
            }
            
        elif vendor.lower() in ['generic', 'linux']:
            # Use HOST-RESOURCES-MIB
            storage = await self.walk(community, self.OIDS['hrStorageTable'])
            # Parse storage table for memory information
            # Implementation would parse the table structure
            
        return memory_data
    
    async def get_environment_sensors(self, community: str) -> List[Dict[str, Any]]:
        """
        Get environmental sensor readings (temperature, voltage, fans)
        
        Args:
            community: SNMP community string
            
        Returns:
            List of sensor readings
        """
        sensors = []
        
        # Walk entity sensor table
        sensor_values = await self.walk(community, self.OIDS['entPhySensorValue'])
        sensor_types = await self.walk(community, self.OIDS['entPhySensorType'])
        
        type_map = {
            1: 'other',
            2: 'unknown',
            3: 'voltsAC',
            4: 'voltsDC',
            5: 'amperes',
            6: 'watts',
            7: 'hertz',
            8: 'celsius',
            9: 'percentRH',
            10: 'rpm',
            11: 'cmm',
            12: 'truthvalue'
        }
        
        for (value_oid, value), (type_oid, sensor_type) in zip(sensor_values, sensor_types):
            if value and sensor_type:
                sensor_data = {
                    'oid': value_oid,
                    'type': type_map.get(sensor_type, 'unknown'),
                    'value': value,
                    'timestamp': datetime.utcnow()
                }
                sensors.append(sensor_data)
                
        return sensors
    
    def _convert_value(self, value: Any) -> Any:
        """
        Convert SNMP value to Python type
        
        Args:
            value: Raw SNMP value
            
        Returns:
            Converted Python value
        """
        if isinstance(value, Integer):
            return int(value)
        elif isinstance(value, OctetString):
            try:
                return value.prettyPrint()
            except:
                return str(value)
        elif isinstance(value, ObjectName):
            return str(value)
        elif isinstance(value, univ.Null):
            return None
        else:
            return str(value)
    
    def _parse_uptime(self, timeticks: Optional[int]) -> Dict[str, int]:
        """
        Parse SNMP TimeTicks to human-readable format
        
        Args:
            timeticks: SNMP TimeTicks value (hundredths of a second)
            
        Returns:
            Dictionary with days, hours, minutes, seconds
        """
        if not timeticks:
            return {'days': 0, 'hours': 0, 'minutes': 0, 'seconds': 0}
            
        total_seconds = timeticks / 100  # Convert from hundredths
        
        days = int(total_seconds // 86400)
        hours = int((total_seconds % 86400) // 3600)
        minutes = int((total_seconds % 3600) // 60)
        seconds = int(total_seconds % 60)
        
        return {
            'days': days,
            'hours': hours,
            'minutes': minutes,
            'seconds': seconds,
            'total_seconds': int(total_seconds)
        }
    
    def _get_interface_type(self, if_type: Optional[int]) -> str:
        """
        Convert interface type number to string
        
        Args:
            if_type: Interface type number
            
        Returns:
            Interface type string
        """
        if_types = {
            1: 'other',
            6: 'ethernetCsmacd',
            23: 'ppp',
            24: 'softwareLoopback',
            32: 'frameRelay',
            53: 'propVirtual',
            117: 'gigabitEthernet',
            131: 'tunnel',
            135: 'l2vlan',
            136: 'l3ipvlan',
            161: 'ieee8023adLag'
        }
        
        return if_types.get(if_type, f'unknown({if_type})')
    
    async def test_connectivity(self, community: str, version: str = 'v2c') -> bool:
        """
        Test SNMP connectivity to device
        
        Args:
            community: SNMP community string
            version: SNMP version
            
        Returns:
            True if connectivity successful, False otherwise
        """
        try:
            # Try to get sysDescr
            result = await self.get_v2c(community, [self.OIDS['sysDescr']])
            return result.get(self.OIDS['sysDescr']) is not None
        except Exception as e:
            logger.error(f"SNMP connectivity test failed: {str(e)}")
            return False
    
    def close(self):
        """Close SNMP engine"""
        if hasattr(self, 'engine'):
            self.engine.transportDispatcher.closeDispatcher()


class SNMPPoller:
    """
    High-level SNMP polling coordinator
    """
    
    def __init__(self):
        self.clients = {}
        
    async def poll_device(self, 
                         device_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Poll a device for all metrics
        
        Args:
            device_config: Device configuration including credentials
            
        Returns:
            Dictionary of collected metrics
        """
        try:
            host = device_config['ip_address']
            community = device_config.get('snmp_community', 'public')
            version = device_config.get('snmp_version', 'v2c')
            vendor = device_config.get('vendor', 'generic')
            
            # Create or get client
            if host not in self.clients:
                self.clients[host] = SNMPClient(host)
            
            client = self.clients[host]
            
            # Test connectivity first
            if not await client.test_connectivity(community, version):
                logger.error(f"SNMP connectivity failed for {host}")
                return {'error': 'SNMP connectivity failed'}
            
            # Collect all metrics
            metrics = {
                'timestamp': datetime.utcnow(),
                'device': host,
                'system': await client.get_system_info(community),
                'interfaces': await client.get_interfaces(community),
                'cpu': await client.get_cpu_usage(community, vendor),
                'memory': await client.get_memory_usage(community, vendor),
                'sensors': await client.get_environment_sensors(community)
            }
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error polling device {host}: {str(e)}")
            return {'error': str(e)}
    
    async def poll_multiple_devices(self,
                                   devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Poll multiple devices concurrently
        
        Args:
            devices: List of device configurations
            
        Returns:
            List of metric dictionaries
        """
        tasks = [self.poll_device(device) for device in devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results = []
        for device, result in zip(devices, results):
            if isinstance(result, Exception):
                processed_results.append({
                    'device': device['ip_address'],
                    'error': str(result)
                })
            else:
                processed_results.append(result)
                
        return processed_results
    
    def cleanup(self):
        """Clean up all SNMP clients"""
        for client in self.clients.values():
            client.close()
        self.clients.clear()