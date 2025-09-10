"""
CHM ARP Discovery Module
ARP table parsing for network device discovery
"""

import asyncio
import logging
import subprocess
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
import socket

logger = logging.getLogger(__name__)

@dataclass
class ARPDevice:
    """ARP discovered device information"""
    ip_address: str
    mac_address: str
    interface: str
    device_type: str = "Unknown"
    vendor: Optional[str] = None
    discovered_at: datetime = None

class ARPDiscovery:
    """ARP table discovery implementation"""
    
    def __init__(self):
        self.discovered_devices: Dict[str, ARPDevice] = {}
        self.vendor_oui_map = self._load_vendor_oui_map()
        
    async def discover_devices(self, network_range: str = None) -> List[ARPDevice]:
        """
        Discover devices using ARP table
        
        Args:
            network_range: Network range to scan (optional)
            
        Returns:
            List of discovered ARP devices
        """
        logger.info(f"Starting ARP discovery for range: {network_range or 'all'}")
        
        try:
            arp_table = await self._get_arp_table()
            discovered_devices = []
            
            for entry in arp_table:
                device = ARPDevice(
                    ip_address=entry['ip'],
                    mac_address=entry['mac'],
                    interface=entry['interface'],
                    vendor=self._get_vendor_from_mac(entry['mac']),
                    discovered_at=datetime.now()
                )
                discovered_devices.append(device)
                self.discovered_devices[entry['ip']] = device
                
            logger.info(f"ARP discovery completed. Found {len(discovered_devices)} devices")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
            return []
    
    async def _get_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table from system"""
        try:
            # Try different methods based on OS
            import platform
            system = platform.system().lower()
            
            if system == "windows":
                return await self._get_windows_arp_table()
            elif system in ["linux", "darwin"]:
                return await self._get_unix_arp_table()
            else:
                logger.warning(f"Unsupported OS for ARP discovery: {system}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to get ARP table: {e}")
            return []
    
    async def _get_windows_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table on Windows"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"ARP command failed: {result.stderr}")
                return []
            
            arp_entries = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                # Parse Windows ARP output format
                # Example: "  192.168.1.1           00-11-22-33-44-55     dynamic"
                match = re.match(r'\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})\s+(\w+)', line, re.IGNORECASE)
                if match:
                    ip, mac, interface = match.groups()
                    arp_entries.append({
                        'ip': ip,
                        'mac': mac.replace('-', ':'),
                        'interface': interface
                    })
            
            return arp_entries
            
        except Exception as e:
            logger.error(f"Failed to get Windows ARP table: {e}")
            return []
    
    async def _get_unix_arp_table(self) -> List[Dict[str, str]]:
        """Get ARP table on Unix-like systems"""
        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"ARP command failed: {result.stderr}")
                return []
            
            arp_entries = []
            lines = result.stdout.split('\n')
            
            for line in lines:
                # Parse Unix ARP output format
                # Example: "hostname (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0"
                match = re.match(r'.*\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})\s+\[(\w+)\]\s+on\s+(\w+)', line, re.IGNORECASE)
                if match:
                    ip, mac, device_type, interface = match.groups()
                    arp_entries.append({
                        'ip': ip,
                        'mac': mac,
                        'interface': interface,
                        'type': device_type
                    })
            
            return arp_entries
            
        except Exception as e:
            logger.error(f"Failed to get Unix ARP table: {e}")
            return []
    
    def _get_vendor_from_mac(self, mac_address: str) -> Optional[str]:
        """Get vendor from MAC address OUI"""
        try:
            # Extract OUI (first 3 bytes) from MAC address
            mac_clean = mac_address.replace(':', '').replace('-', '').upper()
            if len(mac_clean) >= 6:
                oui = mac_clean[:6]
                return self.vendor_oui_map.get(oui, "Unknown")
        except Exception as e:
            logger.warning(f"Failed to get vendor for MAC {mac_address}: {e}")
        return None
    
    def _load_vendor_oui_map(self) -> Dict[str, str]:
        """Load vendor OUI mapping"""
        # Common vendor OUIs (simplified list)
        return {
            "000C29": "VMware",
            "001B21": "Intel",
            "001CC0": "Cisco",
            "001D7E": "Cisco",
            "001E13": "Cisco",
            "001FCA": "Cisco",
            "0021A0": "Cisco",
            "0022BD": "Cisco",
            "0023EB": "Cisco",
            "0024C4": "Cisco",
            "0025B3": "Cisco",
            "0026F2": "Cisco",
            "0027EB": "Cisco",
            "0028F8": "Cisco",
            "002A6A": "Cisco",
            "002B67": "Cisco",
            "002C54": "Cisco",
            "002D76": "Cisco",
            "002E4A": "Cisco",
            "002F35": "Cisco",
            "0030F2": "Cisco",
            "0031A0": "Cisco",
            "0032A0": "Cisco",
            "0033A0": "Cisco",
            "0034A0": "Cisco",
            "0035A0": "Cisco",
            "0036A0": "Cisco",
            "0037A0": "Cisco",
            "0038A0": "Cisco",
            "0039A0": "Cisco",
            "003AA0": "Cisco",
            "003BA0": "Cisco",
            "003CA0": "Cisco",
            "003DA0": "Cisco",
            "003EA0": "Cisco",
            "003FA0": "Cisco",
            "0040A0": "Cisco",
            "0041A0": "Cisco",
            "0042A0": "Cisco",
            "0043A0": "Cisco",
            "0044A0": "Cisco",
            "0045A0": "Cisco",
            "0046A0": "Cisco",
            "0047A0": "Cisco",
            "0048A0": "Cisco",
            "0049A0": "Cisco",
            "004AA0": "Cisco",
            "004BA0": "Cisco",
            "004CA0": "Cisco",
            "004DA0": "Cisco",
            "004EA0": "Cisco",
            "004FA0": "Cisco",
            "0050A0": "Cisco",
            "0051A0": "Cisco",
            "0052A0": "Cisco",
            "0053A0": "Cisco",
            "0054A0": "Cisco",
            "0055A0": "Cisco",
            "0056A0": "Cisco",
            "0057A0": "Cisco",
            "0058A0": "Cisco",
            "0059A0": "Cisco",
            "005AA0": "Cisco",
            "005BA0": "Cisco",
            "005CA0": "Cisco",
            "005DA0": "Cisco",
            "005EA0": "Cisco",
            "005FA0": "Cisco",
            "0060A0": "Cisco",
            "0061A0": "Cisco",
            "0062A0": "Cisco",
            "0063A0": "Cisco",
            "0064A0": "Cisco",
            "0065A0": "Cisco",
            "0066A0": "Cisco",
            "0067A0": "Cisco",
            "0068A0": "Cisco",
            "0069A0": "Cisco",
            "006AA0": "Cisco",
            "006BA0": "Cisco",
            "006CA0": "Cisco",
            "006DA0": "Cisco",
            "006EA0": "Cisco",
            "006FA0": "Cisco",
            "0070A0": "Cisco",
            "0071A0": "Cisco",
            "0072A0": "Cisco",
            "0073A0": "Cisco",
            "0074A0": "Cisco",
            "0075A0": "Cisco",
            "0076A0": "Cisco",
            "0077A0": "Cisco",
            "0078A0": "Cisco",
            "0079A0": "Cisco",
            "007AA0": "Cisco",
            "007BA0": "Cisco",
            "007CA0": "Cisco",
            "007DA0": "Cisco",
            "007EA0": "Cisco",
            "007FA0": "Cisco",
            "0080A0": "Cisco",
            "0081A0": "Cisco",
            "0082A0": "Cisco",
            "0083A0": "Cisco",
            "0084A0": "Cisco",
            "0085A0": "Cisco",
            "0086A0": "Cisco",
            "0087A0": "Cisco",
            "0088A0": "Cisco",
            "0089A0": "Cisco",
            "008AA0": "Cisco",
            "008BA0": "Cisco",
            "008CA0": "Cisco",
            "008DA0": "Cisco",
            "008EA0": "Cisco",
            "008FA0": "Cisco",
            "0090A0": "Cisco",
            "0091A0": "Cisco",
            "0092A0": "Cisco",
            "0093A0": "Cisco",
            "0094A0": "Cisco",
            "0095A0": "Cisco",
            "0096A0": "Cisco",
            "0097A0": "Cisco",
            "0098A0": "Cisco",
            "0099A0": "Cisco",
            "009AA0": "Cisco",
            "009BA0": "Cisco",
            "009CA0": "Cisco",
            "009DA0": "Cisco",
            "009EA0": "Cisco",
            "009FA0": "Cisco",
            "00A0A0": "Cisco",
            "00A1A0": "Cisco",
            "00A2A0": "Cisco",
            "00A3A0": "Cisco",
            "00A4A0": "Cisco",
            "00A5A0": "Cisco",
            "00A6A0": "Cisco",
            "00A7A0": "Cisco",
            "00A8A0": "Cisco",
            "00A9A0": "Cisco",
            "00AAA0": "Cisco",
            "00ABA0": "Cisco",
            "00ACA0": "Cisco",
            "00ADA0": "Cisco",
            "00AEA0": "Cisco",
            "00AFA0": "Cisco",
            "00B0A0": "Cisco",
            "00B1A0": "Cisco",
            "00B2A0": "Cisco",
            "00B3A0": "Cisco",
            "00B4A0": "Cisco",
            "00B5A0": "Cisco",
            "00B6A0": "Cisco",
            "00B7A0": "Cisco",
            "00B8A0": "Cisco",
            "00B9A0": "Cisco",
            "00BAA0": "Cisco",
            "00BBA0": "Cisco",
            "00BCA0": "Cisco",
            "00BDA0": "Cisco",
            "00BEA0": "Cisco",
            "00BFA0": "Cisco",
            "00C0A0": "Cisco",
            "00C1A0": "Cisco",
            "00C2A0": "Cisco",
            "00C3A0": "Cisco",
            "00C4A0": "Cisco",
            "00C5A0": "Cisco",
            "00C6A0": "Cisco",
            "00C7A0": "Cisco",
            "00C8A0": "Cisco",
            "00C9A0": "Cisco",
            "00CAA0": "Cisco",
            "00CBA0": "Cisco",
            "00CCA0": "Cisco",
            "00CDA0": "Cisco",
            "00CEA0": "Cisco",
            "00CFA0": "Cisco",
            "00D0A0": "Cisco",
            "00D1A0": "Cisco",
            "00D2A0": "Cisco",
            "00D3A0": "Cisco",
            "00D4A0": "Cisco",
            "00D5A0": "Cisco",
            "00D6A0": "Cisco",
            "00D7A0": "Cisco",
            "00D8A0": "Cisco",
            "00D9A0": "Cisco",
            "00DAA0": "Cisco",
            "00DBA0": "Cisco",
            "00DCA0": "Cisco",
            "00DDA0": "Cisco",
            "00DEA0": "Cisco",
            "00DFA0": "Cisco",
            "00E0A0": "Cisco",
            "00E1A0": "Cisco",
            "00E2A0": "Cisco",
            "00E3A0": "Cisco",
            "00E4A0": "Cisco",
            "00E5A0": "Cisco",
            "00E6A0": "Cisco",
            "00E7A0": "Cisco",
            "00E8A0": "Cisco",
            "00E9A0": "Cisco",
            "00EAA0": "Cisco",
            "00EBA0": "Cisco",
            "00ECA0": "Cisco",
            "00EDA0": "Cisco",
            "00EEA0": "Cisco",
            "00EFA0": "Cisco",
            "00F0A0": "Cisco",
            "00F1A0": "Cisco",
            "00F2A0": "Cisco",
            "00F3A0": "Cisco",
            "00F4A0": "Cisco",
            "00F5A0": "Cisco",
            "00F6A0": "Cisco",
            "00F7A0": "Cisco",
            "00F8A0": "Cisco",
            "00F9A0": "Cisco",
            "00FAA0": "Cisco",
            "00FBA0": "Cisco",
            "00FCA0": "Cisco",
            "00FDA0": "Cisco",
            "00FEA0": "Cisco",
            "00FFA0": "Cisco"
        }
    
    async def ping_sweep(self, network_range: str) -> List[str]:
        """
        Perform ping sweep to populate ARP table
        
        Args:
            network_range: Network range to ping (e.g., "192.168.1.0/24")
            
        Returns:
            List of responsive IP addresses
        """
        logger.info(f"Starting ping sweep for range: {network_range}")
        
        try:
            import ipaddress
            network = ipaddress.ip_network(network_range, strict=False)
            responsive_ips = []
            
            # Limit to reasonable number of hosts
            hosts = list(network.hosts())[:254]  # Limit to 254 hosts
            
            # Ping hosts concurrently
            tasks = [self._ping_host(str(host)) for host in hosts]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                if result is True:  # Host is responsive
                    responsive_ips.append(str(hosts[i]))
            
            logger.info(f"Ping sweep completed. {len(responsive_ips)} hosts responsive")
            return responsive_ips
            
        except Exception as e:
            logger.error(f"Ping sweep failed: {e}")
            return []
    
    async def _ping_host(self, ip: str) -> bool:
        """Ping a single host"""
        try:
            # Use asyncio subprocess for ping
            process = await asyncio.create_subprocess_exec(
                'ping', '-c', '1', '-W', '1', ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await process.wait()
            return process.returncode == 0
        except Exception:
            return False
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get ARP discovery statistics"""
        return {
            "total_discovered": len(self.discovered_devices),
            "devices": list(self.discovered_devices.keys()),
            "protocol": "ARP",
            "vendor_count": len(set(device.vendor for device in self.discovered_devices.values() if device.vendor))
        }

# Global ARP discovery instance
arp_discovery = ARPDiscovery()
