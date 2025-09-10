"""
CHM CDP Discovery Module
Cisco Discovery Protocol implementation for network device discovery
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
class CDPDevice:
    """CDP discovered device information"""
    device_id: str
    device_name: str
    platform: str
    capabilities: List[str]
    interface: str
    port_id: str
    software_version: str
    ip_address: Optional[str] = None
    protocol_version: str = "CDPv2"
    discovered_at: datetime = None

class CDPDiscovery:
    """Cisco Discovery Protocol discovery implementation"""
    
    def __init__(self):
        self.cdp_multicast = "224.0.1.40"  # CDP multicast address
        self.cdp_port = 2000
        self.timeout = 10  # seconds
        self.discovered_devices: Dict[str, CDPDevice] = {}
        
    async def discover_devices(self, interface: str = None) -> List[CDPDevice]:
        """
        Discover devices using CDP protocol
        
        Args:
            interface: Network interface to listen on (optional)
            
        Returns:
            List of discovered CDP devices
        """
        logger.info(f"Starting CDP discovery on interface: {interface or 'all'}")
        
        try:
            # Create socket for CDP discovery
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            
            # Bind to CDP port
            sock.bind(('', self.cdp_port))
            
            # Join multicast group
            mreq = struct.pack("4sl", socket.inet_aton(self.cdp_multicast), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            
            discovered_devices = []
            start_time = datetime.now()
            
            while (datetime.now() - start_time).seconds < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    device = await self._parse_cdp_packet(data, addr[0])
                    if device:
                        discovered_devices.append(device)
                        logger.info(f"CDP discovered device: {device.device_name} at {addr[0]}")
                        
                except socket.timeout:
                    break
                except Exception as e:
                    logger.warning(f"Error receiving CDP packet: {e}")
                    continue
            
            sock.close()
            
            logger.info(f"CDP discovery completed. Found {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"CDP discovery failed: {e}")
            return []
    
    async def _parse_cdp_packet(self, data: bytes, source_ip: str) -> Optional[CDPDevice]:
        """
        Parse CDP packet and extract device information
        
        Args:
            data: Raw CDP packet data
            source_ip: Source IP address of the packet
            
        Returns:
            CDPDevice object or None if parsing fails
        """
        try:
            # CDP packet structure (simplified)
            # Version (1 byte) + TTL (1 byte) + Checksum (2 bytes) + TLVs
            
            if len(data) < 4:
                return None
                
            version = data[0]
            ttl = data[1]
            checksum = struct.unpack('>H', data[2:4])[0]
            
            # Parse TLVs (Type-Length-Value)
            offset = 4
            device_info = {}
            
            while offset < len(data) - 1:
                if offset + 4 > len(data):
                    break
                    
                tlv_type = struct.unpack('>H', data[offset:offset+2])[0]
                tlv_length = struct.unpack('>H', data[offset+2:offset+4])[0]
                
                if offset + tlv_length > len(data):
                    break
                    
                tlv_value = data[offset+4:offset+tlv_length]
                
                # Parse TLV based on type
                if tlv_type == 1:  # Device ID
                    device_info['device_id'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 2:  # Address
                    device_info['addresses'] = self._parse_address_tlv(tlv_value)
                elif tlv_type == 3:  # Port ID
                    device_info['port_id'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 4:  # Capabilities
                    device_info['capabilities'] = self._parse_capabilities_tlv(tlv_value)
                elif tlv_type == 5:  # Software Version
                    device_info['software_version'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 6:  # Platform
                    device_info['platform'] = tlv_value.decode('utf-8', errors='ignore')
                elif tlv_type == 7:  # IP Prefix
                    device_info['ip_prefix'] = tlv_value.decode('utf-8', errors='ignore')
                
                offset += tlv_length
            
            # Create CDPDevice object
            if 'device_id' in device_info:
                device = CDPDevice(
                    device_id=device_info.get('device_id', ''),
                    device_name=device_info.get('device_id', 'Unknown'),
                    platform=device_info.get('platform', 'Unknown'),
                    capabilities=device_info.get('capabilities', []),
                    interface='CDP',
                    port_id=device_info.get('port_id', ''),
                    software_version=device_info.get('software_version', ''),
                    ip_address=source_ip,
                    protocol_version=f"CDPv{version}",
                    discovered_at=datetime.now()
                )
                return device
                
        except Exception as e:
            logger.warning(f"Failed to parse CDP packet: {e}")
            
        return None
    
    def _parse_address_tlv(self, data: bytes) -> List[str]:
        """Parse address TLV from CDP packet"""
        addresses = []
        try:
            # Simplified address parsing
            # In real implementation, this would parse the full address structure
            offset = 0
            while offset < len(data) - 1:
                if offset + 2 > len(data):
                    break
                addr_length = struct.unpack('>H', data[offset:offset+2])[0]
                if offset + addr_length > len(data):
                    break
                addr_data = data[offset+2:offset+addr_length]
                # Parse IP address (simplified)
                if len(addr_data) >= 4:
                    ip = socket.inet_ntoa(addr_data[:4])
                    addresses.append(ip)
                offset += addr_length
        except Exception as e:
            logger.warning(f"Failed to parse address TLV: {e}")
        return addresses
    
    def _parse_capabilities_tlv(self, data: bytes) -> List[str]:
        """Parse capabilities TLV from CDP packet"""
        capabilities = []
        try:
            if len(data) >= 4:
                caps = struct.unpack('>I', data[:4])[0]
                capability_map = {
                    0x01: "Router",
                    0x02: "Transparent Bridge",
                    0x04: "Source Route Bridge",
                    0x08: "Switch",
                    0x10: "Host",
                    0x20: "IGMP",
                    0x40: "Repeater"
                }
                
                for bit, name in capability_map.items():
                    if caps & bit:
                        capabilities.append(name)
        except Exception as e:
            logger.warning(f"Failed to parse capabilities TLV: {e}")
        return capabilities
    
    async def get_device_neighbors(self, device_ip: str, community: str = "public") -> List[CDPDevice]:
        """
        Get CDP neighbors from a specific device via SNMP
        
        Args:
            device_ip: IP address of the device to query
            community: SNMP community string
            
        Returns:
            List of CDP neighbor devices
        """
        logger.info(f"Getting CDP neighbors from device: {device_ip}")
        
        try:
            # CDP OIDs for neighbor information
            cdp_oids = {
                'cdpCacheDeviceId': '1.3.6.1.4.1.9.9.23.1.2.1.1.6',
                'cdpCacheDevicePort': '1.3.6.1.4.1.9.9.23.1.2.1.1.7',
                'cdpCachePlatform': '1.3.6.1.4.1.9.9.23.1.2.1.1.8',
                'cdpCacheVersion': '1.3.6.1.4.1.9.9.23.1.2.1.1.5',
                'cdpCacheCapabilities': '1.3.6.1.4.1.9.9.23.1.2.1.1.4'
            }
            
            # This would integrate with the existing SNMP service
            # For now, return empty list as placeholder
            logger.info(f"CDP neighbor discovery via SNMP not yet implemented for {device_ip}")
            return []
            
        except Exception as e:
            logger.error(f"Failed to get CDP neighbors from {device_ip}: {e}")
            return []
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get CDP discovery statistics"""
        return {
            "total_discovered": len(self.discovered_devices),
            "devices": list(self.discovered_devices.keys()),
            "protocol": "CDP",
            "multicast_address": self.cdp_multicast,
            "port": self.cdp_port
        }

# Global CDP discovery instance
cdp_discovery = CDPDiscovery()
