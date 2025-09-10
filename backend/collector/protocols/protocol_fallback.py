"""
CHM Protocol Fallback System
Intelligent protocol selection and fallback for device discovery and monitoring
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from .cdp_discovery import cdp_discovery, CDPDevice
from .lldp_discovery import lldp_discovery, LLDPDevice
from .arp_discovery import arp_discovery, ARPDevice

logger = logging.getLogger(__name__)

class ProtocolType(Enum):
    """Supported protocol types"""
    CDP = "cdp"
    LLDP = "lldp"
    ARP = "arp"
    SNMP = "snmp"
    SSH = "ssh"
    REST = "rest"
    ICMP = "icmp"

@dataclass
class DiscoveryResult:
    """Unified discovery result"""
    protocol: str
    device_info: Dict[str, Any]
    confidence: float
    discovered_at: datetime
    source: str

class ProtocolFallback:
    """Protocol fallback and selection system"""
    
    def __init__(self):
        self.protocol_priority = [
            ProtocolType.CDP,
            ProtocolType.LLDP,
            ProtocolType.ARP,
            ProtocolType.SNMP,
            ProtocolType.SSH,
            ProtocolType.REST,
            ProtocolType.ICMP
        ]
        
        self.protocol_weights = {
            ProtocolType.CDP: 0.9,
            ProtocolType.LLDP: 0.9,
            ProtocolType.ARP: 0.7,
            ProtocolType.SNMP: 0.8,
            ProtocolType.SSH: 0.6,
            ProtocolType.REST: 0.5,
            ProtocolType.ICMP: 0.3
        }
        
        self.discovery_results: Dict[str, List[DiscoveryResult]] = {}
        
    async def discover_network(self, network_range: str, protocols: List[str] = None) -> List[DiscoveryResult]:
        """
        Discover network devices using multiple protocols with fallback
        
        Args:
            network_range: Network range to discover
            protocols: List of protocols to use (optional)
            
        Returns:
            List of discovery results from all protocols
        """
        logger.info(f"Starting multi-protocol discovery for range: {network_range}")
        
        if protocols is None:
            protocols = [p.value for p in self.protocol_priority]
        
        all_results = []
        
        # Run discovery protocols concurrently
        discovery_tasks = []
        
        if "cdp" in protocols:
            discovery_tasks.append(self._run_cdp_discovery(network_range))
        
        if "lldp" in protocols:
            discovery_tasks.append(self._run_lldp_discovery(network_range))
        
        if "arp" in protocols:
            discovery_tasks.append(self._run_arp_discovery(network_range))
        
        # Wait for all discovery tasks to complete
        if discovery_tasks:
            results = await asyncio.gather(*discovery_tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_results.extend(result)
                elif isinstance(result, Exception):
                    logger.warning(f"Discovery task failed: {result}")
        
        # Deduplicate and merge results
        merged_results = self._merge_discovery_results(all_results)
        
        logger.info(f"Multi-protocol discovery completed. Found {len(merged_results)} unique devices")
        return merged_results
    
    async def _run_cdp_discovery(self, network_range: str) -> List[DiscoveryResult]:
        """Run CDP discovery"""
        try:
            logger.info("Starting CDP discovery")
            cdp_devices = await cdp_discovery.discover_devices()
            
            results = []
            for device in cdp_devices:
                result = DiscoveryResult(
                    protocol="cdp",
                    device_info={
                        "device_id": device.device_id,
                        "device_name": device.device_name,
                        "platform": device.platform,
                        "capabilities": device.capabilities,
                        "interface": device.interface,
                        "port_id": device.port_id,
                        "software_version": device.software_version,
                        "ip_address": device.ip_address,
                        "protocol_version": device.protocol_version
                    },
                    confidence=self.protocol_weights[ProtocolType.CDP],
                    discovered_at=device.discovered_at or datetime.now(),
                    source="cdp_discovery"
                )
                results.append(result)
            
            logger.info(f"CDP discovery found {len(results)} devices")
            return results
            
        except Exception as e:
            logger.error(f"CDP discovery failed: {e}")
            return []
    
    async def _run_lldp_discovery(self, network_range: str) -> List[DiscoveryResult]:
        """Run LLDP discovery"""
        try:
            logger.info("Starting LLDP discovery")
            lldp_devices = await lldp_discovery.discover_devices()
            
            results = []
            for device in lldp_devices:
                result = DiscoveryResult(
                    protocol="lldp",
                    device_info={
                        "chassis_id": device.chassis_id,
                        "port_id": device.port_id,
                        "system_name": device.system_name,
                        "system_description": device.system_description,
                        "port_description": device.port_description,
                        "system_capabilities": device.system_capabilities,
                        "management_addresses": device.management_addresses,
                        "protocol_version": device.protocol_version,
                        "ttl": device.ttl
                    },
                    confidence=self.protocol_weights[ProtocolType.LLDP],
                    discovered_at=device.discovered_at or datetime.now(),
                    source="lldp_discovery"
                )
                results.append(result)
            
            logger.info(f"LLDP discovery found {len(results)} devices")
            return results
            
        except Exception as e:
            logger.error(f"LLDP discovery failed: {e}")
            return []
    
    async def _run_arp_discovery(self, network_range: str) -> List[DiscoveryResult]:
        """Run ARP discovery"""
        try:
            logger.info("Starting ARP discovery")
            
            # First do a ping sweep to populate ARP table
            responsive_ips = await arp_discovery.ping_sweep(network_range)
            
            # Then get ARP table
            arp_devices = await arp_discovery.discover_devices(network_range)
            
            results = []
            for device in arp_devices:
                result = DiscoveryResult(
                    protocol="arp",
                    device_info={
                        "ip_address": device.ip_address,
                        "mac_address": device.mac_address,
                        "interface": device.interface,
                        "device_type": device.device_type,
                        "vendor": device.vendor
                    },
                    confidence=self.protocol_weights[ProtocolType.ARP],
                    discovered_at=device.discovered_at or datetime.now(),
                    source="arp_discovery"
                )
                results.append(result)
            
            logger.info(f"ARP discovery found {len(results)} devices")
            return results
            
        except Exception as e:
            logger.error(f"ARP discovery failed: {e}")
            return []
    
    def _merge_discovery_results(self, results: List[DiscoveryResult]) -> List[DiscoveryResult]:
        """
        Merge and deduplicate discovery results from multiple protocols
        
        Args:
            results: List of discovery results from all protocols
            
        Returns:
            Merged and deduplicated results
        """
        logger.info(f"Merging {len(results)} discovery results")
        
        # Group results by device identifier
        device_groups = {}
        
        for result in results:
            device_id = self._get_device_identifier(result)
            
            if device_id not in device_groups:
                device_groups[device_id] = []
            
            device_groups[device_id].append(result)
        
        # Merge results for each device
        merged_results = []
        
        for device_id, device_results in device_groups.items():
            if len(device_results) == 1:
                # Single result, use as-is
                merged_results.append(device_results[0])
            else:
                # Multiple results, merge them
                merged_result = self._merge_device_results(device_results)
                merged_results.append(merged_result)
        
        logger.info(f"Merged into {len(merged_results)} unique devices")
        return merged_results
    
    def _get_device_identifier(self, result: DiscoveryResult) -> str:
        """Get unique device identifier from discovery result"""
        device_info = result.device_info
        
        # Try different identifier strategies based on protocol
        if result.protocol == "cdp":
            return device_info.get("device_id", "") or device_info.get("ip_address", "")
        elif result.protocol == "lldp":
            return device_info.get("chassis_id", "") or device_info.get("system_name", "")
        elif result.protocol == "arp":
            return device_info.get("ip_address", "") or device_info.get("mac_address", "")
        else:
            # Fallback to IP address or MAC address
            return device_info.get("ip_address", "") or device_info.get("mac_address", "")
    
    def _merge_device_results(self, results: List[DiscoveryResult]) -> DiscoveryResult:
        """
        Merge multiple discovery results for the same device
        
        Args:
            results: List of discovery results for the same device
            
        Returns:
            Merged discovery result
        """
        # Sort by confidence (highest first)
        results.sort(key=lambda x: x.confidence, reverse=True)
        
        # Use the highest confidence result as base
        base_result = results[0]
        merged_info = base_result.device_info.copy()
        
        # Merge information from other results
        for result in results[1:]:
            for key, value in result.device_info.items():
                if key not in merged_info or not merged_info[key]:
                    merged_info[key] = value
                elif isinstance(value, list) and isinstance(merged_info[key], list):
                    # Merge lists
                    merged_info[key] = list(set(merged_info[key] + value))
        
        # Calculate combined confidence
        total_confidence = sum(r.confidence for r in results)
        avg_confidence = total_confidence / len(results)
        
        # Create merged result
        merged_result = DiscoveryResult(
            protocol="multi",
            device_info=merged_info,
            confidence=min(avg_confidence * 1.2, 1.0),  # Boost confidence for multiple sources
            discovered_at=base_result.discovered_at,
            source="protocol_fallback"
        )
        
        return merged_result
    
    async def get_best_protocol_for_device(self, device_info: Dict[str, Any]) -> ProtocolType:
        """
        Determine the best protocol for monitoring a specific device
        
        Args:
            device_info: Device information from discovery
            
        Returns:
            Best protocol type for the device
        """
        # Analyze device capabilities and characteristics
        capabilities = device_info.get("capabilities", [])
        device_type = device_info.get("device_type", "")
        vendor = device_info.get("vendor", "")
        
        # Protocol selection logic
        if "Router" in capabilities or "Switch" in capabilities:
            if vendor and "cisco" in vendor.lower():
                return ProtocolType.CDP
            else:
                return ProtocolType.LLDP
        elif device_type == "network_device":
            return ProtocolType.SNMP
        elif device_type == "server":
            return ProtocolType.SSH
        elif device_type == "web_service":
            return ProtocolType.REST
        else:
            return ProtocolType.ICMP
    
    def get_discovery_statistics(self) -> Dict[str, Any]:
        """Get protocol fallback statistics"""
        total_devices = len(self.discovery_results)
        protocol_counts = {}
        
        for device_id, results in self.discovery_results.items():
            for result in results:
                protocol = result.protocol
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1
        
        return {
            "total_devices": total_devices,
            "protocol_counts": protocol_counts,
            "protocol_priority": [p.value for p in self.protocol_priority],
            "protocol_weights": {p.value: w for p, w in self.protocol_weights.items()}
        }

# Global protocol fallback instance
protocol_fallback = ProtocolFallback()
