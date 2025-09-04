"""
SNMP Handler for device monitoring
"""

from typing import Dict, Any, Optional, List
import asyncio
import logging
from pysnmp.hlapi import *
from pysnmp.smi import builder, view
from pysnmp.entity.rfc3413.oneliner import cmdgen
import concurrent.futures

from backend.common.exceptions import SNMPConnectionException
from backend.common.utils import retry, circuit_breaker
from backend.monitoring.connection_pool import snmp_pool
from backend.monitoring.mib_manager import mib_manager

logger = logging.getLogger(__name__)

class SNMPHandler:
    """Handles SNMP operations for device monitoring"""
    
    def __init__(self, max_workers: int = 10):
        """Initialize SNMP handler with thread pool executor"""
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
    
    # Common OIDs
    OID_SYSTEM = {
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysObjectID': '1.3.6.1.2.1.1.2.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0',
        'sysServices': '1.3.6.1.2.1.1.7.0'
    }
    
    OID_INTERFACES = {
        'ifNumber': '1.3.6.1.2.1.2.1.0',
        'ifTable': '1.3.6.1.2.1.2.2',
        'ifIndex': '1.3.6.1.2.1.2.2.1.1',
        'ifDescr': '1.3.6.1.2.1.2.2.1.2',
        'ifType': '1.3.6.1.2.1.2.2.1.3',
        'ifSpeed': '1.3.6.1.2.1.2.2.1.5',
        'ifOperStatus': '1.3.6.1.2.1.2.2.1.8',
        'ifInOctets': '1.3.6.1.2.1.2.2.1.10',
        'ifOutOctets': '1.3.6.1.2.1.2.2.1.16'
    }
    
    OID_HOST_RESOURCES = {
        'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
        'hrStorageDescr': '1.3.6.1.2.1.25.2.3.1.3',
        'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
        'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
        'hrMemorySize': '1.3.6.1.2.1.25.2.2.0'
    }
    
    def __init__(self):
        # Use the global SNMP pool's executor
        self.executor = snmp_pool.executor
    
    @retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(SNMPConnectionException,))
    @circuit_breaker(failure_threshold=5, recovery_timeout=60)
    async def get_device_info(
        self,
        ip_address: str,
        community: str = 'public',
        version: str = '2c',
        port: int = 161,
        timeout: int = 5,
        retries: int = 3
    ) -> Dict[str, Any]:
        """Get basic device information via SNMP"""
        try:
            # Run SNMP operations in thread pool
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                self._get_device_info_sync,
                ip_address,
                community,
                version,
                port,
                timeout,
                retries
            )
            return result
            
        except Exception as e:
            logger.error(f"Failed to get device info from {ip_address}: {e}")
            raise SNMPConnectionException(
                ip_address=ip_address,
                community=community,
                error_details=str(e)
            )
    
    def _get_device_info_sync(
        self,
        ip_address: str,
        community: str,
        version: str,
        port: int,
        timeout: int,
        retries: int
    ) -> Dict[str, Any]:
        """Synchronous SNMP get operation"""
        device_info = {}
        
        # Prepare SNMP parameters
        if version == '3':
            # SNMPv3 parameters (simplified - would need full user credentials)
            auth_data = UsmUserData('usr-md5-none', 'authkey1')
        else:
            # SNMPv1/v2c parameters
            auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        
        transport_target = UdpTransportTarget((ip_address, port), timeout=timeout, retries=retries)
        
        # Get system information
        for oid_name, oid_value in self.OID_SYSTEM.items():
            try:
                # Get engine from pool
                engine = snmp_pool.get_or_create_engine(ip_address, community, version)
                
                error_indication, error_status, error_index, var_binds = next(
                    getCmd(
                        engine,
                        auth_data,
                        transport_target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid_value))
                    )
                )
                
                if error_indication:
                    logger.warning(f"SNMP error for {oid_name}: {error_indication}")
                elif error_status:
                    logger.warning(f"SNMP error for {oid_name}: {error_status.prettyPrint()}")
                else:
                    for var_bind in var_binds:
                        device_info[oid_name] = str(var_bind[1])
                        
            except Exception as e:
                logger.debug(f"Failed to get {oid_name}: {e}")
        
        # Determine vendor from sysDescr or sysObjectID
        if 'sysDescr' in device_info:
            sys_descr = device_info['sysDescr'].lower()
            if 'cisco' in sys_descr:
                device_info['vendor'] = 'Cisco'
            elif 'juniper' in sys_descr:
                device_info['vendor'] = 'Juniper'
            elif 'arista' in sys_descr:
                device_info['vendor'] = 'Arista'
            elif 'hp' in sys_descr or 'hewlett' in sys_descr:
                device_info['vendor'] = 'HP'
            else:
                device_info['vendor'] = 'Unknown'
        
        return device_info
    
    async def get_interface_statistics(
        self,
        ip_address: str,
        community: str = 'public',
        version: str = '2c',
        port: int = 161
    ) -> List[Dict[str, Any]]:
        """Get interface statistics via SNMP"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                self._get_interface_statistics_sync,
                ip_address,
                community,
                version,
                port
            )
            return result
            
        except Exception as e:
            logger.error(f"Failed to get interface statistics from {ip_address}: {e}")
            return []
    
    def _get_interface_statistics_sync(
        self,
        ip_address: str,
        community: str,
        version: str,
        port: int
    ) -> List[Dict[str, Any]]:
        """Synchronous SNMP walk for interface statistics"""
        interfaces = []
        
        # Prepare SNMP parameters
        auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        transport_target = UdpTransportTarget((ip_address, port))
        
        # Walk interface table
        try:
            for (error_indication,
                 error_status,
                 error_index,
                 var_binds) in nextCmd(
                    SnmpEngine(),
                    auth_data,
                    transport_target,
                    ContextData(),
                    ObjectType(ObjectIdentity(self.OID_INTERFACES['ifDescr'])),
                    ObjectType(ObjectIdentity(self.OID_INTERFACES['ifOperStatus'])),
                    ObjectType(ObjectIdentity(self.OID_INTERFACES['ifSpeed'])),
                    ObjectType(ObjectIdentity(self.OID_INTERFACES['ifInOctets'])),
                    ObjectType(ObjectIdentity(self.OID_INTERFACES['ifOutOctets'])),
                    lexicographicMode=False
                ):
                
                if error_indication:
                    logger.warning(f"SNMP walk error: {error_indication}")
                    break
                elif error_status:
                    logger.warning(f"SNMP walk error: {error_status.prettyPrint()}")
                    break
                else:
                    interface = {}
                    for var_bind in var_binds:
                        oid = str(var_bind[0])
                        value = var_bind[1]
                        
                        if self.OID_INTERFACES['ifDescr'] in oid:
                            interface['description'] = str(value)
                        elif self.OID_INTERFACES['ifOperStatus'] in oid:
                            interface['status'] = 'up' if int(value) == 1 else 'down'
                        elif self.OID_INTERFACES['ifSpeed'] in oid:
                            interface['speed'] = int(value)
                        elif self.OID_INTERFACES['ifInOctets'] in oid:
                            interface['in_octets'] = int(value)
                        elif self.OID_INTERFACES['ifOutOctets'] in oid:
                            interface['out_octets'] = int(value)
                    
                    if interface:
                        interfaces.append(interface)
                        
        except Exception as e:
            logger.error(f"Interface walk failed: {e}")
        
        return interfaces
    
    async def get_vendor_specific_metrics(
        self,
        ip_address: str,
        vendor: str,
        community: str = 'public',
        version: str = '2c'
    ) -> Dict[str, Any]:
        """Get vendor-specific metrics via SNMP"""
        try:
            loop = asyncio.get_event_loop()
            
            if vendor.lower() == 'cisco':
                result = await loop.run_in_executor(
                    self.executor,
                    self._get_cisco_metrics_sync,
                    ip_address,
                    community,
                    version
                )
            elif vendor.lower() == 'juniper':
                result = await loop.run_in_executor(
                    self.executor,
                    self._get_juniper_metrics_sync,
                    ip_address,
                    community,
                    version
                )
            elif vendor.lower() == 'arista':
                result = await loop.run_in_executor(
                    self.executor,
                    self._get_arista_metrics_sync,
                    ip_address,
                    community,
                    version
                )
            else:
                # Default to generic metrics
                result = {
                    'cpu_usage': await self.get_cpu_usage(ip_address, community, version),
                    'memory': await self.get_memory_usage(ip_address, community, version)
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to get vendor-specific metrics: {e}")
            return {}
    
    def _get_cisco_metrics_sync(
        self,
        ip_address: str,
        community: str,
        version: str
    ) -> Dict[str, Any]:
        """Get Cisco-specific metrics using validated OIDs"""
        metrics = {}
        auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        transport_target = UdpTransportTarget((ip_address, 161))
        engine = snmp_pool.get_or_create_engine(ip_address, community, version)
        
        # Get validated Cisco OIDs from MIB manager
        cisco_oids = mib_manager.get_vendor_oids('cisco')
        
        # CPU metrics - try multiple OIDs for compatibility
        cpu_oids = [
            ('cpu_5sec_rev', cisco_oids.get('cpmCPUTotal5secRev')),
            ('cpu_1min_rev', cisco_oids.get('cpmCPUTotal1minRev')),
            ('cpu_5min_rev', cisco_oids.get('cpmCPUTotal5minRev')),
        ]
        
        for name, oid in cpu_oids:
            if not oid:
                continue
                
            try:
                error_indication, error_status, error_index, var_binds = next(
                    getCmd(
                        engine,
                        auth_data,
                        transport_target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid))
                    )
                )
                
                if not error_indication and not error_status:
                    for var_bind in var_binds:
                        value = int(var_bind[1])
                        metrics[name] = value
                        logger.debug(f"Cisco {name}: {value}% for {ip_address}")
                        break  # Use first successful CPU reading
            except Exception as e:
                logger.debug(f"Failed to get Cisco {name} from {ip_address}: {e}")
        
        # Memory metrics - walk the memory pool table
        memory_pool_used_oid = cisco_oids.get('ciscoMemoryPoolUsed')
        memory_pool_free_oid = cisco_oids.get('ciscoMemoryPoolFree')
        memory_pool_name_oid = cisco_oids.get('ciscoMemoryPoolName')
        
        if memory_pool_used_oid and memory_pool_free_oid:
            try:
                # Walk memory pools to find processor memory
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    engine, auth_data, transport_target, ContextData(),
                    ObjectType(ObjectIdentity(memory_pool_name_oid)),
                    ObjectType(ObjectIdentity(memory_pool_used_oid)),
                    ObjectType(ObjectIdentity(memory_pool_free_oid)),
                    lexicographicMode=False, maxRows=10
                ):
                    if error_indication or error_status:
                        break
                    
                    pool_name = str(var_binds[0][1]).lower()
                    used_bytes = int(var_binds[1][1]) if var_binds[1][1] else 0
                    free_bytes = int(var_binds[2][1]) if var_binds[2][1] else 0
                    
                    # Focus on processor memory pool
                    if 'processor' in pool_name or 'system' in pool_name:
                        total_bytes = used_bytes + free_bytes
                        if total_bytes > 0:
                            usage_percent = (used_bytes / total_bytes) * 100
                            metrics['memory_usage_percent'] = usage_percent
                            metrics['memory_used_bytes'] = used_bytes
                            metrics['memory_total_bytes'] = total_bytes
                            logger.debug(f"Cisco memory usage: {usage_percent:.1f}% for {ip_address}")
                            break
                            
            except Exception as e:
                logger.debug(f"Failed to get Cisco memory info from {ip_address}: {e}")
        
        # Temperature monitoring
        temp_value_oid = cisco_oids.get('ciscoEnvMonTemperatureValue')
        temp_state_oid = cisco_oids.get('ciscoEnvMonTemperatureState')
        
        if temp_value_oid and temp_state_oid:
            try:
                temperatures = []
                for (error_indication, error_status, error_index, var_binds) in nextCmd(
                    engine, auth_data, transport_target, ContextData(),
                    ObjectType(ObjectIdentity(temp_value_oid)),
                    ObjectType(ObjectIdentity(temp_state_oid)),
                    lexicographicMode=False, maxRows=5
                ):
                    if error_indication or error_status:
                        break
                    
                    temp_value = int(var_binds[0][1]) if var_binds[0][1] else 0
                    temp_state = int(var_binds[1][1]) if var_binds[1][1] else 0
                    
                    # State: 1=normal, 2=warning, 3=critical, 4=shutdown, 5=notPresent, 6=notFunctioning
                    if temp_value > 0 and temp_state in [1, 2, 3]:
                        temperatures.append(temp_value)
                
                if temperatures:
                    metrics['temperature_celsius'] = sum(temperatures) / len(temperatures)
                    
            except Exception as e:
                logger.debug(f"Failed to get Cisco temperature from {ip_address}: {e}")
        
        return metrics
    
    def _get_juniper_metrics_sync(
        self,
        ip_address: str,
        community: str,
        version: str
    ) -> Dict[str, Any]:
        """Get Juniper-specific metrics"""
        metrics = {}
        auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        transport_target = UdpTransportTarget((ip_address, 161))
        
        # Juniper OIDs
        juniper_oids = {
            'cpu_usage': '1.3.6.1.4.1.2636.3.1.13.1.8',
            'mem_buffer_util': '1.3.6.1.4.1.2636.3.1.13.1.11',
            'temp_celsius': '1.3.6.1.4.1.2636.3.1.13.1.7'
        }
        
        for name, oid in juniper_oids.items():
            try:
                for (error_indication,
                     error_status,
                     error_index,
                     var_binds) in nextCmd(
                        SnmpEngine(),
                        auth_data,
                        transport_target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid)),
                        lexicographicMode=False
                    ):
                    
                    if error_indication or error_status:
                        break
                    
                    for var_bind in var_binds:
                        if name not in metrics:
                            metrics[name] = []
                        metrics[name].append(int(var_bind[1]))
            except (ValueError, TypeError) as e:
                logger.debug(f"Error parsing SNMP metric {name}: {e}")
            except Exception as e:
                logger.debug(f"Unexpected error parsing SNMP metric {name}: {e}")
        
        # Average values if multiple
        for key in metrics:
            if isinstance(metrics[key], list) and metrics[key]:
                metrics[key] = sum(metrics[key]) / len(metrics[key])
        
        return metrics
    
    def _get_arista_metrics_sync(
        self,
        ip_address: str,
        community: str,
        version: str
    ) -> Dict[str, Any]:
        """Get Arista-specific metrics"""
        metrics = {}
        auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        transport_target = UdpTransportTarget((ip_address, 161))
        
        # Arista uses similar OIDs to standard but with extensions
        arista_oids = {
            'cpu_util': '1.3.6.1.4.1.30065.3.1.1.0',
            'mem_total': '1.3.6.1.4.1.30065.3.2.1.0',
            'mem_free': '1.3.6.1.4.1.30065.3.2.2.0'
        }
        
        for name, oid in arista_oids.items():
            try:
                error_indication, error_status, error_index, var_binds = next(
                    getCmd(
                        SnmpEngine(),
                        auth_data,
                        transport_target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid))
                    )
                )
                
                if not error_indication and not error_status:
                    for var_bind in var_binds:
                        metrics[name] = int(var_bind[1])
            except:
                pass
        
        # Fallback to standard OIDs if Arista-specific fail
        if not metrics:
            metrics['cpu_usage'] = self._get_cpu_usage_sync(ip_address, community, version)
            metrics['memory'] = self._get_memory_usage_sync(ip_address, community, version)
        
        return metrics
    
    async def get_cpu_usage(
        self,
        ip_address: str,
        community: str = 'public',
        version: str = '2c'
    ) -> float:
        """Get CPU usage percentage via SNMP"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                self._get_cpu_usage_sync,
                ip_address,
                community,
                version
            )
            return result
            
        except Exception as e:
            logger.error(f"Failed to get CPU usage from {ip_address}: {e}")
            return 0.0
    
    def _get_cpu_usage_sync(
        self,
        ip_address: str,
        community: str,
        version: str
    ) -> float:
        """Get CPU usage via SNMP"""
        auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        transport_target = UdpTransportTarget((ip_address, 161))
        
        cpu_loads = []
        
        # Try to get processor load
        for (error_indication,
             error_status,
             error_index,
             var_binds) in nextCmd(
                SnmpEngine(),
                auth_data,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(self.OID_HOST_RESOURCES['hrProcessorLoad'])),
                lexicographicMode=False
            ):
            
            if error_indication or error_status:
                break
                
            for var_bind in var_binds:
                try:
                    cpu_loads.append(int(var_bind[1]))
                except:
                    pass
        
        if cpu_loads:
            return sum(cpu_loads) / len(cpu_loads)
        
        return 0.0
    
    async def get_memory_usage(
        self,
        ip_address: str,
        community: str = 'public',
        version: str = '2c'
    ) -> Dict[str, Any]:
        """Get memory usage via SNMP"""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                self.executor,
                self._get_memory_usage_sync,
                ip_address,
                community,
                version
            )
            return result
            
        except Exception as e:
            logger.error(f"Failed to get memory usage from {ip_address}: {e}")
            return {'total': 0, 'used': 0, 'free': 0, 'percent': 0}
    
    def _get_memory_usage_sync(
        self,
        ip_address: str,
        community: str,
        version: str
    ) -> Dict[str, Any]:
        """Get memory usage via SNMP"""
        auth_data = CommunityData(community, mpModel=0 if version == '1' else 1)
        transport_target = UdpTransportTarget((ip_address, 161))
        
        memory_info = {'total': 0, 'used': 0, 'free': 0, 'percent': 0}
        
        # Get storage information
        storage_data = []
        
        for (error_indication,
             error_status,
             error_index,
             var_binds) in nextCmd(
                SnmpEngine(),
                auth_data,
                transport_target,
                ContextData(),
                ObjectType(ObjectIdentity(self.OID_HOST_RESOURCES['hrStorageDescr'])),
                ObjectType(ObjectIdentity(self.OID_HOST_RESOURCES['hrStorageSize'])),
                ObjectType(ObjectIdentity(self.OID_HOST_RESOURCES['hrStorageUsed'])),
                lexicographicMode=False
            ):
            
            if error_indication or error_status:
                break
            
            storage_entry = {}
            for var_bind in var_binds:
                oid = str(var_bind[0])
                value = var_bind[1]
                
                if self.OID_HOST_RESOURCES['hrStorageDescr'] in oid:
                    storage_entry['description'] = str(value)
                elif self.OID_HOST_RESOURCES['hrStorageSize'] in oid:
                    storage_entry['size'] = int(value) if value else 0
                elif self.OID_HOST_RESOURCES['hrStorageUsed'] in oid:
                    storage_entry['used'] = int(value) if value else 0
            
            # Look for RAM/Memory entries
            if storage_entry.get('description', '').lower() in ['ram', 'physical memory', 'real memory']:
                memory_info['total'] = storage_entry.get('size', 0) * 1024  # Convert to bytes
                memory_info['used'] = storage_entry.get('used', 0) * 1024
                memory_info['free'] = memory_info['total'] - memory_info['used']
                if memory_info['total'] > 0:
                    memory_info['percent'] = (memory_info['used'] / memory_info['total']) * 100
                break
        
        return memory_info
    
    async def test_connection(
        self,
        ip_address: str,
        community: str = 'public',
        version: str = '2c',
        port: int = 161
    ) -> bool:
        """Test SNMP connectivity"""
        try:
            # Try to get sysName
            info = await self.get_device_info(ip_address, community, version, port, timeout=3, retries=1)
            return bool(info)
        except:
            return False
    
    def __del__(self):
        """Cleanup executor on deletion"""
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=False)