"""
OID library for different device types
Contains all SNMP OIDs organized by vendor and purpose
Includes standard MIBs and vendor-specific OIDs for comprehensive monitoring
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional

class OIDCategory(Enum):
    SYSTEM = "system"
    CPU = "cpu"
    MEMORY = "memory"
    INTERFACE = "interface"
    TEMPERATURE = "temperature"
    POWER = "power"
    POE = "poe"
    STACK = "stack"
    SUPERVISOR = "supervisor"
    DISK = "disk"
    PROCESS = "process"
    BUFFER = "buffer"
    QUEUE = "queue"
    ERROR = "error"
    TRAFFIC = "traffic"

@dataclass
class OIDDefinition:
    oid: str
    name: str
    category: OIDCategory
    description: str
    unit: Optional[str] = None
    multiplier: float = 1.0  # For unit conversion
    is_counter: bool = False  # For counter vs gauge values
    
class StandardMIBs:
    """Standard MIBs (RFC 1213, RFC 2863, etc.) - Essential for all devices"""
    
    # System Group (RFC 1213)
    SYSTEM = {
        'sysDescr': OIDDefinition(
            '1.3.6.1.2.1.1.1.0',
            'sysDescr',
            OIDCategory.SYSTEM,
            'System description'
        ),
        'sysObjectID': OIDDefinition(
            '1.3.6.1.2.1.1.2.0',
            'sysObjectID',
            OIDCategory.SYSTEM,
            'System object identifier'
        ),
        'sysUpTime': OIDDefinition(
            '1.3.6.1.2.1.1.3.0',
            'sysUpTime',
            OIDCategory.SYSTEM,
            'System uptime',
            'timeticks'
        ),
        'sysContact': OIDDefinition(
            '1.3.6.1.2.1.1.4.0',
            'sysContact',
            OIDCategory.SYSTEM,
            'System contact information'
        ),
        'sysName': OIDDefinition(
            '1.3.6.1.2.1.1.5.0',
            'sysName',
            OIDCategory.SYSTEM,
            'System name'
        ),
        'sysLocation': OIDDefinition(
            '1.3.6.1.2.1.1.6.0',
            'sysLocation',
            OIDCategory.SYSTEM,
            'System location'
        ),
        'sysServices': OIDDefinition(
            '1.3.6.1.2.1.1.7.0',
            'sysServices',
            OIDCategory.SYSTEM,
            'System services'
        ),
    }
    
    # Interface Group (RFC 1213, RFC 2863)
    INTERFACE = {
        'ifNumber': OIDDefinition(
            '1.3.6.1.2.1.2.1.0',
            'ifNumber',
            OIDCategory.INTERFACE,
            'Number of interfaces'
        ),
        'ifTable': OIDDefinition(
            '1.3.6.1.2.1.2.2.1',
            'ifTable',
            OIDCategory.INTERFACE,
            'Interface table'
        ),
        # Interface entry OIDs (for individual interfaces)
        'ifIndex': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.1',
            'ifIndex',
            OIDCategory.INTERFACE,
            'Interface index'
        ),
        'ifDescr': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.2',
            'ifDescr',
            OIDCategory.INTERFACE,
            'Interface description'
        ),
        'ifType': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.3',
            'ifType',
            OIDCategory.INTERFACE,
            'Interface type'
        ),
        'ifMtu': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.4',
            'ifMtu',
            OIDCategory.INTERFACE,
            'Interface MTU'
        ),
        'ifSpeed': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.5',
            'ifSpeed',
            OIDCategory.INTERFACE,
            'Interface speed',
            'bps'
        ),
        'ifPhysAddress': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.6',
            'ifPhysAddress',
            OIDCategory.INTERFACE,
            'Interface physical address'
        ),
        'ifAdminStatus': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.7',
            'ifAdminStatus',
            OIDCategory.INTERFACE,
            'Interface administrative status'
        ),
        'ifOperStatus': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.8',
            'ifOperStatus',
            OIDCategory.INTERFACE,
            'Interface operational status'
        ),
        'ifLastChange': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.9',
            'ifLastChange',
            OIDCategory.INTERFACE,
            'Interface last change time'
        ),
        'ifInOctets': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.10',
            'ifInOctets',
            OIDCategory.TRAFFIC,
            'Incoming octets',
            'octets',
            1.0,
            True
        ),
        'ifInUcastPkts': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.11',
            'ifInUcastPkts',
            OIDCategory.TRAFFIC,
            'Incoming unicast packets',
            'packets',
            1.0,
            True
        ),
        'ifInNUcastPkts': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.12',
            'ifInNUcastPkts',
            OIDCategory.TRAFFIC,
            'Incoming non-unicast packets',
            'packets',
            1.0,
            True
        ),
        'ifInDiscards': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.13',
            'ifInDiscards',
            OIDCategory.ERROR,
            'Incoming discards',
            'packets',
            1.0,
            True
        ),
        'ifInErrors': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.14',
            'ifInErrors',
            OIDCategory.ERROR,
            'Incoming errors',
            'packets',
            1.0,
            True
        ),
        'ifInUnknownProtos': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.15',
            'ifInUnknownProtos',
            OIDCategory.ERROR,
            'Incoming unknown protocols',
            'packets',
            1.0,
            True
        ),
        'ifOutOctets': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.16',
            'ifOutOctets',
            OIDCategory.TRAFFIC,
            'Outgoing octets',
            'octets',
            1.0,
            True
        ),
        'ifOutUcastPkts': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.17',
            'ifOutUcastPkts',
            OIDCategory.TRAFFIC,
            'Outgoing unicast packets',
            'packets',
            1.0,
            True
        ),
        'ifOutNUcastPkts': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.18',
            'ifOutNUcastPkts',
            OIDCategory.TRAFFIC,
            'Outgoing non-unicast packets',
            'packets',
            1.0,
            True
        ),
        'ifOutDiscards': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.19',
            'ifOutDiscards',
            OIDCategory.ERROR,
            'Outgoing discards',
            'packets',
            1.0,
            True
        ),
        'ifOutErrors': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.20',
            'ifOutErrors',
            OIDCategory.ERROR,
            'Outgoing errors',
            'packets',
            1.0,
            True
        ),
        'ifOutQLen': OIDDefinition(
            '1.3.6.1.2.1.2.2.1.21',
            'ifOutQLen',
            OIDCategory.QUEUE,
            'Output queue length',
            'packets'
        ),
    }
    
    # IP Group (RFC 1213)
    IP = {
        'ipForwarding': OIDDefinition(
            '1.3.6.1.2.1.4.1.0',
            'ipForwarding',
            OIDCategory.SYSTEM,
            'IP forwarding enabled'
        ),
        'ipDefaultTTL': OIDDefinition(
            '1.3.6.1.2.1.4.2.0',
            'ipDefaultTTL',
            OIDCategory.SYSTEM,
            'Default IP TTL'
        ),
        'ipInReceives': OIDDefinition(
            '1.3.6.1.2.1.4.3.0',
            'ipInReceives',
            OIDCategory.TRAFFIC,
            'IP packets received',
            'packets',
            1.0,
            True
        ),
        'ipInHdrErrors': OIDDefinition(
            '1.3.6.1.2.1.4.4.0',
            'ipInHdrErrors',
            OIDCategory.ERROR,
            'IP header errors',
            'packets',
            1.0,
            True
        ),
        'ipInAddrErrors': OIDDefinition(
            '1.3.6.1.2.1.4.5.0',
            'ipInAddrErrors',
            OIDCategory.ERROR,
            'IP address errors',
            'packets',
            1.0,
            True
        ),
        'ipForwDatagrams': OIDDefinition(
            '1.3.6.1.2.1.4.6.0',
            'ipForwDatagrams',
            OIDCategory.TRAFFIC,
            'IP datagrams forwarded',
            'packets',
            1.0,
            True
        ),
        'ipInUnknownProtos': OIDDefinition(
            '1.3.6.1.2.1.4.7.0',
            'ipInUnknownProtos',
            OIDCategory.ERROR,
            'IP unknown protocols',
            'packets',
            1.0,
            True
        ),
        'ipInDiscards': OIDDefinition(
            '1.3.6.1.2.1.4.8.0',
            'ipInDiscards',
            OIDCategory.ERROR,
            'IP input discards',
            'packets',
            1.0,
            True
        ),
        'ipInDelivers': OIDDefinition(
            '1.3.6.1.2.1.4.9.0',
            'ipInDelivers',
            OIDCategory.TRAFFIC,
            'IP input delivers',
            'packets',
            1.0,
            True
        ),
        'ipOutRequests': OIDDefinition(
            '1.3.6.1.2.1.4.10.0',
            'ipOutRequests',
            OIDCategory.TRAFFIC,
            'IP output requests',
            'packets',
            1.0,
            True
        ),
        'ipOutDiscards': OIDDefinition(
            '1.3.6.1.2.1.4.11.0',
            'ipOutDiscards',
            OIDCategory.ERROR,
            'IP output discards',
            'packets',
            1.0,
            True
        ),
        'ipOutNoRoutes': OIDDefinition(
            '1.3.6.1.2.1.4.12.0',
            'ipOutNoRoutes',
            OIDCategory.ERROR,
            'IP output no routes',
            'packets',
            1.0,
            True
        ),
        'ipReasmTimeout': OIDDefinition(
            '1.3.6.1.2.1.4.13.0',
            'ipReasmTimeout',
            OIDCategory.SYSTEM,
            'IP reassembly timeout'
        ),
        'ipReasmReqds': OIDDefinition(
            '1.3.6.1.2.1.4.14.0',
            'ipReasmReqds',
            OIDCategory.TRAFFIC,
            'IP reassembly requests',
            'packets',
            1.0,
            True
        ),
        'ipReasmOKs': OIDDefinition(
            '1.3.6.1.2.1.4.15.0',
            'ipReasmOKs',
            OIDCategory.TRAFFIC,
            'IP reassembly OKs',
            'packets',
            1.0,
            True
        ),
        'ipReasmFails': OIDDefinition(
            '1.3.6.1.2.1.4.16.0',
            'ipReasmFails',
            OIDCategory.ERROR,
            'IP reassembly failures',
            'packets',
            1.0,
            True
        ),
        'ipFragOKs': OIDDefinition(
            '1.3.6.1.2.1.4.17.0',
            'ipFragOKs',
            OIDCategory.TRAFFIC,
            'IP fragmentation OKs',
            'packets',
            1.0,
            True
        ),
        'ipFragFails': OIDDefinition(
            '1.3.6.1.2.1.4.18.0',
            'ipFragFails',
            OIDCategory.ERROR,
            'IP fragmentation failures',
            'packets',
            1.0,
            True
        ),
        'ipFragCreates': OIDDefinition(
            '1.3.6.1.2.1.4.19.0',
            'ipFragCreates',
            OIDCategory.TRAFFIC,
            'IP fragmentation creates',
            'packets',
            1.0,
            True
        ),
    }
    
    # TCP Group (RFC 1213)
    TCP = {
        'tcpRtoAlgorithm': OIDDefinition(
            '1.3.6.1.2.1.6.1.0',
            'tcpRtoAlgorithm',
            OIDCategory.SYSTEM,
            'TCP retransmission timeout algorithm'
        ),
        'tcpRtoMin': OIDDefinition(
            '1.3.6.1.2.1.6.2.0',
            'tcpRtoMin',
            OIDCategory.SYSTEM,
            'TCP minimum retransmission timeout',
            'milliseconds'
        ),
        'tcpRtoMax': OIDDefinition(
            '1.3.6.1.2.1.6.3.0',
            'tcpRtoMax',
            OIDCategory.SYSTEM,
            'TCP maximum retransmission timeout',
            'milliseconds'
        ),
        'tcpMaxConn': OIDDefinition(
            '1.3.6.1.2.1.6.4.0',
            'tcpMaxConn',
            OIDCategory.SYSTEM,
            'TCP maximum connections'
        ),
        'tcpActiveOpens': OIDDefinition(
            '1.3.6.1.2.1.6.5.0',
            'tcpActiveOpens',
            OIDCategory.TRAFFIC,
            'TCP active opens',
            'connections',
            1.0,
            True
        ),
        'tcpPassiveOpens': OIDDefinition(
            '1.3.6.1.2.1.6.6.0',
            'tcpPassiveOpens',
            OIDCategory.TRAFFIC,
            'TCP passive opens',
            'connections',
            1.0,
            True
        ),
        'tcpAttemptFails': OIDDefinition(
            '1.3.6.1.2.1.6.7.0',
            'tcpAttemptFails',
            OIDCategory.ERROR,
            'TCP attempt failures',
            'connections',
            1.0,
            True
        ),
        'tcpEstabResets': OIDDefinition(
            '1.3.6.1.2.1.6.8.0',
            'tcpEstabResets',
            OIDCategory.ERROR,
            'TCP established resets',
            'connections',
            1.0,
            True
        ),
        'tcpCurrEstab': OIDDefinition(
            '1.3.6.1.2.1.6.9.0',
            'tcpCurrEstab',
            OIDCategory.SYSTEM,
            'TCP current established connections'
        ),
        'tcpInSegs': OIDDefinition(
            '1.3.6.1.2.1.6.10.0',
            'tcpInSegs',
            OIDCategory.TRAFFIC,
            'TCP input segments',
            'segments',
            1.0,
            True
        ),
        'tcpOutSegs': OIDDefinition(
            '1.3.6.1.2.1.6.11.0',
            'tcpOutSegs',
            OIDCategory.TRAFFIC,
            'TCP output segments',
            'segments',
            1.0,
            True
        ),
        'tcpRetransSegs': OIDDefinition(
            '1.3.6.1.2.1.6.12.0',
            'tcpRetransSegs',
            OIDCategory.ERROR,
            'TCP retransmitted segments',
            'segments',
            1.0,
            True
        ),
        'tcpInErrs': OIDDefinition(
            '1.3.6.1.2.1.6.14.0',
            'tcpInErrs',
            OIDCategory.ERROR,
            'TCP input errors',
            'segments',
            1.0,
            True
        ),
        'tcpOutRsts': OIDDefinition(
            '1.3.6.1.2.1.6.15.0',
            'tcpOutRsts',
            OIDCategory.ERROR,
            'TCP output resets',
            'segments',
            1.0,
            True
        ),
    }
    
    # UDP Group (RFC 1213)
    UDP = {
        'udpInDatagrams': OIDDefinition(
            '1.3.6.1.2.1.7.1.0',
            'udpInDatagrams',
            OIDCategory.TRAFFIC,
            'UDP input datagrams',
            'datagrams',
            1.0,
            True
        ),
        'udpNoPorts': OIDDefinition(
            '1.3.6.1.2.1.7.2.0',
            'udpNoPorts',
            OIDCategory.ERROR,
            'UDP no ports',
            'datagrams',
            1.0,
            True
        ),
        'udpInErrors': OIDDefinition(
            '1.3.6.1.2.1.7.3.0',
            'udpInErrors',
            OIDCategory.ERROR,
            'UDP input errors',
            'datagrams',
            1.0,
            True
        ),
        'udpOutDatagrams': OIDDefinition(
            '1.3.6.1.2.1.7.4.0',
            'udpOutDatagrams',
            OIDCategory.TRAFFIC,
            'UDP output datagrams',
            'datagrams',
            1.0,
            True
        ),
    }

class CiscoOIDs:
    """Cisco-specific OIDs organized by category"""
    
    # System OIDs
    SYSTEM = {
        'sysDescr': OIDDefinition(
            '1.3.6.1.2.1.1.1.0',
            'sysDescr',
            OIDCategory.SYSTEM,
            'System description'
        ),
        'sysUpTime': OIDDefinition(
            '1.3.6.1.2.1.1.3.0',
            'sysUpTime',
            OIDCategory.SYSTEM,
            'System uptime',
            'timeticks'
        ),
        'sysName': OIDDefinition(
            '1.3.6.1.2.1.1.5.0',
            'sysName',
            OIDCategory.SYSTEM,
            'System name'
        ),
        'sysLocation': OIDDefinition(
            '1.3.6.1.2.1.1.6.0',
            'sysLocation',
            OIDCategory.SYSTEM,
            'System location'
        ),
    }
    
    # CPU OIDs (try in order)
    CPU = [
        OIDDefinition(
            '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1',
            'cpmCPUTotal5secRev',
            OIDCategory.CPU,
            'CPU utilization for 5 seconds',
            '%'
        ),
        OIDDefinition(
            '1.3.6.1.4.1.9.2.1.57.0',
            'avgBusy5',
            OIDCategory.CPU,
            'Average CPU busy percentage (5 sec)',
            '%'
        ),
        OIDDefinition(
            '1.3.6.1.4.1.9.9.109.1.1.1.1.8.1',
            'cpmCPUTotal1minRev',
            OIDCategory.CPU,
            'CPU utilization for 1 minute',
            '%'
        ),
        OIDDefinition(
            '1.3.6.1.4.1.9.9.109.1.1.1.1.9.1',
            'cpmCPUTotal5minRev',
            OIDCategory.CPU,
            'CPU utilization for 5 minutes',
            '%'
        ),
    ]
    
    # Memory OIDs
    MEMORY = {
        'processor_pool_free': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.6.1',
            'ciscoMemoryPoolFree',
            OIDCategory.MEMORY,
            'Processor memory pool free',
            'bytes'
        ),
        'processor_pool_used': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.5.1',
            'ciscoMemoryPoolUsed',
            OIDCategory.MEMORY,
            'Processor memory pool used',
            'bytes'
        ),
        'io_pool_free': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.6.2',
            'ciscoMemoryPoolFree.2',
            OIDCategory.MEMORY,
            'I/O memory pool free',
            'bytes'
        ),
        'io_pool_used': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.5.2',
            'ciscoMemoryPoolUsed.2',
            OIDCategory.MEMORY,
            'I/O memory pool used',
            'bytes'
        ),
        'packet_pool_free': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.6.3',
            'ciscoMemoryPoolFree.3',
            OIDCategory.MEMORY,
            'Packet memory pool free',
            'bytes'
        ),
        'packet_pool_used': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.5.3',
            'ciscoMemoryPoolUsed.3',
            OIDCategory.MEMORY,
            'Packet memory pool used',
            'bytes'
        ),
    }
    
    # Temperature OIDs
    TEMPERATURE = [
        OIDDefinition(
            '1.3.6.1.4.1.9.9.13.1.3.1.3.1',
            'ciscoEnvMonTemperatureValue',
            OIDCategory.TEMPERATURE,
            'Temperature sensor value',
            '°C'
        ),
        OIDDefinition(
            '1.3.6.1.4.1.9.9.91.1.1.1.1.4.1',
            'entSensorValue',
            OIDCategory.TEMPERATURE,
            'Entity sensor value (newer devices)',
            '°C'
        ),
    ]
    
    # Buffer OIDs
    BUFFER = {
        'buffer_small_free': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.1.1',
            'ciscoBufferPoolFree',
            OIDCategory.BUFFER,
            'Small buffer pool free',
            'buffers'
        ),
        'buffer_small_used': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.1.2',
            'ciscoBufferPoolUsed',
            OIDCategory.BUFFER,
            'Small buffer pool used',
            'buffers'
        ),
        'buffer_middle_free': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.2.1',
            'ciscoBufferPoolFree.2',
            OIDCategory.BUFFER,
            'Middle buffer pool free',
            'buffers'
        ),
        'buffer_middle_used': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.2.2',
            'ciscoBufferPoolUsed.2',
            OIDCategory.BUFFER,
            'Middle buffer pool used',
            'buffers'
        ),
        'buffer_big_free': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.3.1',
            'ciscoBufferPoolFree.3',
            OIDCategory.BUFFER,
            'Big buffer pool free',
            'buffers'
        ),
        'buffer_big_used': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.3.2',
            'ciscoBufferPoolUsed.3',
            OIDCategory.BUFFER,
            'Big buffer pool used',
            'buffers'
        ),
        'buffer_huge_free': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.4.1',
            'ciscoBufferPoolFree.4',
            OIDCategory.BUFFER,
            'Huge buffer pool free',
            'buffers'
        ),
        'buffer_huge_used': OIDDefinition(
            '1.3.6.1.4.1.9.2.2.1.1.4.2',
            'ciscoBufferPoolUsed.4',
            OIDCategory.BUFFER,
            'Huge buffer pool used',
            'buffers'
        ),
    }
    
    # Process OIDs
    PROCESS = {
        'process_cpu': OIDDefinition(
            '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1',
            'cpmCPUTotal5secRev',
            OIDCategory.PROCESS,
            'Process CPU utilization',
            '%'
        ),
        'process_memory': OIDDefinition(
            '1.3.6.1.4.1.9.9.48.1.1.1.5.1',
            'ciscoMemoryPoolUsed',
            OIDCategory.PROCESS,
            'Process memory usage',
            'bytes'
        ),
    }
    
    # PoE OIDs for 3560/4500
    POE = {
        'total_power': OIDDefinition(
            '1.3.6.1.4.1.9.9.68.1.5.1.1.2.1',
            'cpeExtPsePortPwrMax',
            OIDCategory.POE,
            'Maximum PoE power available',
            'milliwatts',
            0.001  # Convert to watts
        ),
        'used_power': OIDDefinition(
            '1.3.6.1.4.1.9.9.68.1.5.1.1.3.1',
            'cpeExtPsePortPwrAllocated',
            OIDCategory.POE,
            'PoE power allocated',
            'milliwatts',
            0.001
        ),
        'remaining_power': OIDDefinition(
            '1.3.6.1.4.1.9.9.68.1.5.1.1.4.1',
            'cpeExtPsePortPwrRemaining',
            OIDCategory.POE,
            'PoE power remaining',
            'milliwatts',
            0.001
        ),
    }
    
    # Stack OIDs for 2960S/X, 3560-X
    STACK = {
        'stack_members': OIDDefinition(
            '1.3.6.1.4.1.9.9.500.1.2.1.1.1',
            'cswSwitchNumCurrent',
            OIDCategory.STACK,
            'Current number of stack members'
        ),
        'stack_state': OIDDefinition(
            '1.3.6.1.4.1.9.9.500.1.2.1.1.6',
            'cswSwitchState',
            OIDCategory.STACK,
            'Stack member state'
        ),
        'stack_role': OIDDefinition(
            '1.3.6.1.4.1.9.9.500.1.2.1.1.3',
            'cswSwitchRole',
            OIDCategory.STACK,
            'Stack member role'
        ),
    }
    
    # 4500 Supervisor OIDs
    SUPERVISOR = {
        'module_status': OIDDefinition(
            '1.3.6.1.4.1.9.9.117.1.2.1.1.2',
            'cModuleStatus',
            OIDCategory.SUPERVISOR,
            'Module operational status'
        ),
        'redundancy_state': OIDDefinition(
            '1.3.6.1.4.1.9.9.176.1.1.2.0',
            'cRFStatusPeerUnitState',
            OIDCategory.SUPERVISOR,
            'Redundancy peer state'
        ),
        'active_supervisor': OIDDefinition(
            '1.3.6.1.4.1.9.9.176.1.1.1.0',
            'cRFStatusUnitState',
            OIDCategory.SUPERVISOR,
            'Active supervisor state'
        ),
    }
    
    @classmethod
    def get_oids_for_device_type(cls, device_type: str) -> Dict[str, List[OIDDefinition]]:
        """Return relevant OIDs based on device type"""
        
        base_oids = {
            'system': list(cls.SYSTEM.values()),
            'cpu': cls.CPU,
            'memory': list(cls.MEMORY.values()),
            'temperature': cls.TEMPERATURE,
            'buffer': list(cls.BUFFER.values()),
            'process': list(cls.PROCESS.values()),
        }
        
        if device_type == "2960":
            # 2960 doesn't support PoE on most models
            base_oids['stack'] = list(cls.STACK.values())
            
        elif device_type == "3560":
            # 3560 supports PoE and stacking
            base_oids['poe'] = list(cls.POE.values())
            base_oids['stack'] = list(cls.STACK.values())
            
        elif device_type == "4500":
            # 4500 supports PoE and supervisor redundancy
            base_oids['poe'] = list(cls.POE.values())
            base_oids['supervisor'] = list(cls.SUPERVISOR.values())
            
        return base_oids

class JuniperOIDs:
    """Juniper-specific OIDs"""
    
    # System OIDs
    SYSTEM = {
        'sysDescr': OIDDefinition(
            '1.3.6.1.2.1.1.1.0',
            'sysDescr',
            OIDCategory.SYSTEM,
            'System description'
        ),
        'sysUpTime': OIDDefinition(
            '1.3.6.1.2.1.1.3.0',
            'sysUpTime',
            OIDCategory.SYSTEM,
            'System uptime',
            'timeticks'
        ),
    }
    
    # CPU OIDs
    CPU = [
        OIDDefinition(
            '1.3.6.1.4.1.2636.1.1.1.2.1.0',
            'jnxOperatingCPU',
            OIDCategory.CPU,
            'CPU utilization',
            '%'
        ),
    ]
    
    # Memory OIDs
    MEMORY = {
        'memory_used': OIDDefinition(
            '1.3.6.1.4.1.2636.1.1.1.2.2.1.0',
            'jnxOperatingMemory',
            OIDCategory.MEMORY,
            'Memory usage',
            'bytes'
        ),
        'memory_free': OIDDefinition(
            '1.3.6.1.4.1.2636.1.1.1.2.3.1.0',
            'jnxOperatingBuffer',
            OIDCategory.MEMORY,
            'Memory free',
            'bytes'
        ),
    }
    
    # Temperature OIDs
    TEMPERATURE = [
        OIDDefinition(
            '1.3.6.1.4.1.2636.1.1.1.2.4.1.0',
            'jnxOperatingTemp',
            OIDCategory.TEMPERATURE,
            'Temperature',
            '°C'
        ),
    ]

class AristaOIDs:
    """Arista-specific OIDs"""
    
    # System OIDs
    SYSTEM = {
        'sysDescr': OIDDefinition(
            '1.3.6.1.2.1.1.1.0',
            'sysDescr',
            OIDCategory.SYSTEM,
            'System description'
        ),
        'sysUpTime': OIDDefinition(
            '1.3.6.1.2.1.1.3.0',
            'sysUpTime',
            OIDCategory.SYSTEM,
            'System uptime',
            'timeticks'
        ),
    }
    
    # CPU OIDs
    CPU = [
        OIDDefinition(
            '1.3.6.1.4.1.30065.1.1.1.1.1.0',
            'aristaCpuUtilization',
            OIDCategory.CPU,
            'CPU utilization',
            '%'
        ),
    ]
    
    # Memory OIDs
    MEMORY = {
        'memory_used': OIDDefinition(
            '1.3.6.1.4.1.30065.1.1.1.2.1.0',
            'aristaMemoryUsed',
            OIDCategory.MEMORY,
            'Memory used',
            'bytes'
        ),
        'memory_free': OIDDefinition(
            '1.3.6.1.4.1.30065.1.1.1.2.2.0',
            'aristaMemoryFree',
            OIDCategory.MEMORY,
            'Memory free',
            'bytes'
        ),
    }

class OIDManager:
    """Manages OID collections for different vendors and device types"""
    
    @staticmethod
    def get_standard_oids() -> Dict[str, Dict[str, OIDDefinition]]:
        """Get all standard MIB OIDs"""
        return {
            'system': StandardMIBs.SYSTEM,
            'interface': StandardMIBs.INTERFACE,
            'ip': StandardMIBs.IP,
            'tcp': StandardMIBs.TCP,
            'udp': StandardMIBs.UDP,
        }
    
    @staticmethod
    def get_vendor_oids(vendor: str, device_type: str = None) -> Dict[str, List[OIDDefinition]]:
        """Get vendor-specific OIDs"""
        if vendor.lower() == 'cisco':
            return CiscoOIDs.get_oids_for_device_type(device_type or 'unknown')
        elif vendor.lower() == 'juniper':
            return {
                'system': list(JuniperOIDs.SYSTEM.values()),
                'cpu': JuniperOIDs.CPU,
                'memory': list(JuniperOIDs.MEMORY.values()),
                'temperature': JuniperOIDs.TEMPERATURE,
            }
        elif vendor.lower() == 'arista':
            return {
                'system': list(AristaOIDs.SYSTEM.values()),
                'cpu': AristaOIDs.CPU,
                'memory': list(AristaOIDs.MEMORY.values()),
            }
        else:
            # Return standard OIDs for unknown vendors
            return {
                'system': list(StandardMIBs.SYSTEM.values()),
                'interface': list(StandardMIBs.INTERFACE.values()),
            }
    
    @staticmethod
    def get_all_oids_for_device(vendor: str, device_type: str = None) -> Dict[str, List[OIDDefinition]]:
        """Get all relevant OIDs for a device (standard + vendor-specific)"""
        standard_oids = OIDManager.get_standard_oids()
        vendor_oids = OIDManager.get_vendor_oids(vendor, device_type)
        
        # Combine standard and vendor-specific OIDs
        all_oids = {}
        
        # Add standard OIDs
        for category, oids in standard_oids.items():
            if isinstance(oids, dict):
                all_oids[category] = list(oids.values())
            else:
                all_oids[category] = oids
        
        # Add vendor-specific OIDs (vendor OIDs take precedence)
        for category, oids in vendor_oids.items():
            all_oids[category] = oids
        
        return all_oids
    
    @staticmethod
    def get_essential_monitoring_oids() -> List[OIDDefinition]:
        """Get essential OIDs for basic device monitoring"""
        essential_oids = []
        
        # System information
        essential_oids.extend([
            StandardMIBs.SYSTEM['sysDescr'],
            StandardMIBs.SYSTEM['sysUpTime'],
            StandardMIBs.SYSTEM['sysName'],
        ])
        
        # Interface statistics (for traffic monitoring)
        essential_oids.extend([
            StandardMIBs.INTERFACE['ifInOctets'],
            StandardMIBs.INTERFACE['ifOutOctets'],
            StandardMIBs.INTERFACE['ifInErrors'],
            StandardMIBs.INTERFACE['ifOutErrors'],
            StandardMIBs.INTERFACE['ifInDiscards'],
            StandardMIBs.INTERFACE['ifOutDiscards'],
        ])
        
        # IP statistics
        essential_oids.extend([
            StandardMIBs.IP['ipInReceives'],
            StandardMIBs.IP['ipInDelivers'],
            StandardMIBs.IP['ipOutRequests'],
            StandardMIBs.IP['ipInErrors'],
            StandardMIBs.IP['ipOutDiscards'],
        ])
        
        return essential_oids
