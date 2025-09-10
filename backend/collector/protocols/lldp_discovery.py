"""
CHM LLDP Discovery Module
Link Layer Discovery Protocol implementation for network device discovery
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import struct
import socket

logger = logging.getLogger(__name__)

@dataclass
class LLDPDevice:
    """LLDP discovered device information"""
    chassis_id: str
    port_id: str
    system_name: str
    system_description: str
    port_description: str
    system_capabilities: List[str]
    management_addresses: List[str]
    protocol_version: str = "LLDP"
    discovered_at: datetime = None
    ttl: int = 120

class LLDPDiscovery:
    """Link Layer Discovery Protocol discovery implementation"""
    
    def __init__(self):
        self.lldp_multicast = "01:80:c2:00:00:0e"  # LLDP multicast MAC
        self.lldp_ethertype = 0x88cc  # LLDP ethertype
        self.timeout = 30  # seconds
        self.discovered_devices: Dict[str, LLDPDevice] = {}
        
    async def discover_devices(self, interface: str = None) -> List[LLDPDevice]:
        """
        Discover devices using LLDP protocol
        
        Args:
            interface: Network interface to listen on (optional)
            
        Returns:
            List of discovered LLDP devices
        """
        logger.info(f"Starting LLDP discovery on interface: {interface or 'all'}")
        
        try:
            # Create raw socket for LLDP discovery
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(self.timeout)
            
            discovered_devices = []
            start_time = datetime.now()
            
            while (datetime.now() - start_time).seconds < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    device = await self._parse_lldp_frame(data, addr)
                    if device:
                        discovered_devices.append(device)
                        logger.info(f"LLDP discovered device: {device.system_name} at {device.chassis_id}")
                        
                except socket.timeout:
                    break
                except Exception as e:
                    logger.warning(f"Error receiving LLDP frame: {e}")
                    continue
            
            sock.close()
            
            logger.info(f"LLDP discovery completed. Found {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"LLDP discovery failed: {e}")
            return []
    
    async def _parse_lldp_frame(self, data: bytes, addr: tuple) -> Optional[LLDPDevice]:
        """
        Parse LLDP frame and extract device information
        
        Args:
            data: Raw LLDP frame data
            addr: Source address tuple
            
        Returns:
            LLDPDevice object or None if parsing fails
        """
        try:
            # LLDP frame structure
            # Ethernet header (14 bytes) + LLDP payload
            
            if len(data) < 14:
                return None
                
            # Parse Ethernet header
            dst_mac = data[0:6]
            src_mac = data[6:12]
            ethertype = struct.unpack('>H', data[12:14])[0]
            
            # Check if this is an LLDP frame
            if ethertype != self.lldp_ethertype:
                return None
                
            # Parse LLDP payload
            lldp_data = data[14:]
            device_info = {}
            
            offset = 0
            while offset < len(lldp_data) - 1:
                if offset + 2 > len(lldp_data):
                    break
                    
                tlv_type = (lldp_data[offset] >> 1) & 0x7F
                tlv_length = ((lldp_data[offset] & 0x01) << 8) | lldp_data[offset + 1]
                
                if offset + 2 + tlv_length > len(lldp_data):
                    break
                    
                tlv_value = lldp_data[offset + 2:offset + 2 + tlv_length]
                
                # Parse TLV based on type
                if tlv_type == 1:  # Chassis ID
                    device_info['chassis_id'] = self._parse_chassis_id_tlv(tlv_value)
                elif tlv_type == 2:  # Port ID
                    device_info['port_id'] = self._parse_port_id_tlv(tlv_value)
                elif tlv_type == 3:  # Time To Live
                    device_info['ttl'] = struct.unpack('>H', tlv_value)[0]
                elif tlv_type == 4:  # Port Description
                    device_info['port_description'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 5:  # System Name
                    device_info['system_name'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 6:  # System Description
                    device_info['system_description'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 7:  # System Capabilities
                    device_info['system_capabilities'] = self._parse_capabilities_tlv(tlv_value)
                elif tlv_type == 8:  # Management Address
                    device_info['management_addresses'] = self._parse_management_address_tlv(tlv_value)
                
                offset += 2 + tlv_length
                
                # End of LLDPDU TLV (type 0)
                if tlv_type == 0:
                    break
            
            # Create LLDPDevice object
            if 'chassis_id' in device_info and 'port_id' in device_info:
                device = LLDPDevice(
                    chassis_id=device_info.get('chassis_id', ''),
                    port_id=device_info.get('port_id', ''),
                    system_name=device_info.get('system_name', 'Unknown'),
                    system_description=device_info.get('system_description', ''),
                    port_description=device_info.get('port_description', ''),
                    system_capabilities=device_info.get('system_capabilities', []),
                    management_addresses=device_info.get('management_addresses', []),
                    protocol_version="LLDP",
                    discovered_at=datetime.now(),
                    ttl=device_info.get('ttl', 120)
                )
                return device
                
        except Exception as e:
            logger.warning(f"Failed to parse LLDP frame: {e}")
            
        return None
    
    def _parse_chassis_id_tlv(self, data: bytes) -> str:
        """Parse chassis ID TLV from LLDP packet"""
        try:
            if len(data) < 1:
                return ""
            subtype = data[0]
            if subtype == 4:  # MAC address
                if len(data) >= 7:
                    mac = ":".join([f"{b:02x}" for b in data[1:7]])
                    return mac
            elif subtype == 5:  # Network address
                if len(data) >= 5:
                    # Parse IP address
                    addr_type = data[1]
                    if addr_type == 1 and len(data) >= 7:  # IPv4
                        ip = socket.inet_ntoa(data[3:7])
                        return ip
            elif subtype == 7:  # Local
                return data[1:].decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Failed to parse chassis ID TLV: {e}")
        return ""
    
    def _parse_port_id_tlv(self, data: bytes) -> str:
        """Parse port ID TLV from LLDP packet"""
        try:
            if len(data) < 1:
                return ""
            subtype = data[0]
            if subtype == 3:  # MAC address
                if len(data) >= 7:
                    mac = ":".join([f"{b:02x}" for b in data[1:7]])
                    return mac
            elif subtype == 4:  # Network address
                if len(data) >= 5:
                    addr_type = data[1]
                    if addr_type == 1 and len(data) >= 7:  # IPv4
                        ip = socket.inet_ntoa(data[3:7])
                        return ip
            elif subtype == 7:  # Local
                return data[1:].decode('utf-8', errors='ignore')
        except Exception as e:
            logger.warning(f"Failed to parse port ID TLV: {e}")
        return ""
    
    def _parse_capabilities_tlv(self, data: bytes) -> List[str]:
        """Parse system capabilities TLV from LLDP packet"""
        capabilities = []
        try:
            if len(data) >= 4:
                caps = struct.unpack('>H', data[2:4])[0]
                capability_map = {
                    0x01: "Other",
                    0x02: "Repeater",
                    0x04: "Bridge",
                    0x08: "WLAN Access Point",
                    0x10: "Router",
                    0x20: "Telephone",
                    0x40: "DOCSIS Cable Device",
                    0x80: "Station Only"
                }
                
                for bit, name in capability_map.items():
                    if caps & bit:
                        capabilities.append(name)
        except Exception as e:
            logger.warning(f"Failed to parse capabilities TLV: {e}")
        return capabilities
    
    def _parse_management_address_tlv(self, data: bytes) -> List[str]:
        """Parse management address TLV from LLDP packet"""
        addresses = []
        try:
            if len(data) >= 5:
                addr_length = data[0]
                addr_subtype = data[1]
                
                if addr_subtype == 1 and len(data) >= 7:  # IPv4
                    ip = socket.inet_ntoa(data[3:7])
                    addresses.append(ip)
                elif addr_subtype == 2 and len(data) >= 19:  # IPv6
                    ipv6 = socket.inet_ntop(socket.AF_INET6, data[3:19])
                    addresses.append(ipv6)
        except Exception as e:
            logger.warning(f"Failed to parse management address TLV: {e}")
        return addresses
    
    async def get_device_neighbors(self, device_ip: str, community: str = "public") -> List[LLDPDevice]:
        """
        Get LLDP neighbors from a specific device via SNMP
        
        Args:
            device_ip: IP address of the device to query
            community: SNMP community string
            
        Returns:
            List of LLDP neighbor devices
        """
        logger.info(f"Getting LLDP neighbors from device: {device_ip}")
        
        try:
            # LLDP OIDs for neighbor information
            lldp_oids = {
                'lldpRemChassisId': '1.0.8802.1.1.2.1.4.1.1.5',
                'lldpRemPortId': '1.0.8802.1.1.2.1.4.1.1.7',
                'lldpRemSysName': '1.0.8802.1.1.2.1.4.1.1.9',
                'lldpRemSysDesc': '1.0.8802.1.1.2.1.4.1.1.10',
                'lldpRemPortDesc': '1.0.8802.1.1.2.1.4.1.1.8',
                'lldpRemSysCapEnabled': '1.0.8802.1.1.2.1.4.1.1.12'
            }
            
            # This would integrate with the existing SNMP service
            # For now, return empty list as placeholder
            logger.info(f"LLDP neighbor discovery via SNMP not yet implemented for {device_ip}")
            return []
            
        except Exception as e:
            logger.error(f"Failed to get LLDP neighbors from {device_ip}: {e}")
            return []
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get LLDP discovery statistics"""
        return {
            "total_discovered": len(self.discovered_devices),
            "devices": list(self.discovered_devices.keys()),
            "protocol": "LLDP",
            "multicast_mac": self.lldp_multicast,
            "ethertype": f"0x{self.lldp_ethertype:04x}"
        }

# Global LLDP discovery instance
lldp_discovery = LLDPDiscovery()
