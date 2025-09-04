"""
Device Classification Service for CHM

This service provides intelligent device categorization and capability detection
using multiple discovery methods and machine learning techniques.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict
import json

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import joinedload

from ..models.device import Device, DeviceStatus, DeviceProtocol
from ..models.network_topology import NetworkInterface, InterfaceType, InterfaceStatus
from ..models.metric import Metric, MetricType, MetricCategory
from ..models.device_credentials import DeviceCredential, CredentialType
from ..services.credential_manager import CredentialManager
from ..services.device_operations import DeviceOperationsService
from ..models.result_objects import OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class DeviceCapability:
    """Device capability information"""
    name: str
    description: str
    category: str
    confidence: float  # 0.0 - 1.0
    detection_method: str
    parameters: Dict[str, Any]
    is_enabled: bool = True
    last_verified: Optional[datetime] = None


@dataclass
class DeviceClassification:
    """Device classification result"""
    device_id: int
    primary_type: str
    secondary_types: List[str]
    vendor: str
    model: str
    os_family: str
    os_version: str
    capabilities: List[DeviceCapability]
    classification_confidence: float
    classification_method: str
    last_updated: datetime
    metadata: Dict[str, Any]


@dataclass
class ClassificationRule:
    """Rule for device classification"""
    name: str
    description: str
    priority: int
    conditions: List[Dict[str, Any]]
    classification: Dict[str, Any]
    confidence_boost: float
    is_active: bool = True


class DeviceClassificationService:
    """Service for intelligent device classification and capability detection"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.credential_manager = CredentialManager()
        self.device_operations = DeviceOperationsService(db_session)
        self._classification_cache: Dict[int, DeviceClassification] = {}
        self._capability_patterns: Dict[str, List[re.Pattern]] = {}
        self._vendor_patterns: Dict[str, List[re.Pattern]] = {}
        self._os_patterns: Dict[str, List[re.Pattern]] = {}
        self._classification_rules: List[ClassificationRule] = []
        
        # Initialize patterns and rules
        self._initialize_patterns()
        self._initialize_classification_rules()
    
    async def classify_device(
        self,
        device_id: int,
        force_refresh: bool = False
    ) -> Optional[DeviceClassification]:
        """Classify a device and detect its capabilities"""
        try:
            # Check cache first
            if not force_refresh and device_id in self._classification_cache:
                cached = self._classification_cache[device_id]
                if (datetime.now() - cached.last_updated).days < 7:  # Cache for 7 days
                    return cached
            
            # Get device information
            device = await self._get_device(device_id)
            if not device:
                logger.error(f"Device {device_id} not found")
                return None
            
            # Perform classification
            classification = await self._perform_device_classification(device)
            
            # Cache the result
            self._classification_cache[device_id] = classification
            
            # Update device with classification results
            await self._update_device_classification(device, classification)
            
            return classification
            
        except Exception as e:
            logger.error(f"Device classification failed for device {device_id}: {str(e)}")
            return None
    
    async def classify_multiple_devices(
        self,
        device_ids: List[int],
        max_concurrent: int = 5
    ) -> Dict[int, Optional[DeviceClassification]]:
        """Classify multiple devices concurrently"""
        results = {}
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def classify_single(device_id: int):
            async with semaphore:
                try:
                    classification = await self.classify_device(device_id)
                    return device_id, classification
                except Exception as e:
                    logger.error(f"Failed to classify device {device_id}: {str(e)}")
                    return device_id, None
        
        # Execute classifications concurrently
        tasks = [classify_single(device_id) for device_id in device_ids]
        completed = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in completed:
            if isinstance(result, Exception):
                logger.error(f"Classification task failed: {str(result)}")
            elif result:
                device_id, classification = result
                results[device_id] = classification
        
        return results
    
    async def detect_device_capabilities(
        self,
        device_id: int,
        refresh_existing: bool = False
    ) -> List[DeviceCapability]:
        """Detect device capabilities using multiple methods"""
        try:
            device = await self._get_device(device_id)
            if not device:
                return []
            
            # Get existing capabilities if not refreshing
            existing_capabilities = {}
            if not refresh_existing:
                existing_capabilities = {
                    cap.name: cap for cap in device.capabilities or []
                }
            
            # Detect capabilities using various methods
            detected_capabilities = []
            
            # SNMP-based capability detection
            if device.protocol == DeviceProtocol.SNMP:
                snmp_capabilities = await self._detect_capabilities_via_snmp(device)
                detected_capabilities.extend(snmp_capabilities)
            
            # SSH-based capability detection
            if device.protocol == DeviceProtocol.SSH:
                ssh_capabilities = await self._detect_capabilities_via_ssh(device)
                detected_capabilities.extend(ssh_capabilities)
            
            # Interface-based capability detection
            interface_capabilities = await self._detect_capabilities_via_interfaces(device)
            detected_capabilities.extend(interface_capabilities)
            
            # Metric-based capability detection
            metric_capabilities = await self._detect_capabilities_via_metrics(device)
            detected_capabilities.extend(metric_capabilities)
            
            # Merge with existing capabilities
            merged_capabilities = self._merge_capabilities(
                existing_capabilities, detected_capabilities
            )
            
            return list(merged_capabilities.values())
            
        except Exception as e:
            logger.error(f"Capability detection failed for device {device_id}: {str(e)}")
            return []
    
    async def get_device_recommendations(
        self,
        device_id: int
    ) -> List[Dict[str, Any]]:
        """Get recommendations for device optimization based on classification"""
        try:
            classification = await self.classify_device(device_id)
            if not classification:
                return []
            
            recommendations = []
            
            # Performance recommendations
            perf_recs = await self._get_performance_recommendations(device_id, classification)
            recommendations.extend(perf_recs)
            
            # Security recommendations
            security_recs = await self._get_security_recommendations(device_id, classification)
            recommendations.extend(security_recs)
            
            # Monitoring recommendations
            monitoring_recs = await self._get_monitoring_recommendations(device_id, classification)
            recommendations.extend(monitoring_recs)
            
            # Upgrade recommendations
            upgrade_recs = await self._get_upgrade_recommendations(device_id, classification)
            recommendations.extend(upgrade_recs)
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to get device recommendations: {str(e)}")
            return []
    
    async def _perform_device_classification(self, device: Device) -> DeviceClassification:
        """Perform comprehensive device classification"""
        try:
            # Initialize classification data
            classification_data = {
                "primary_type": "unknown",
                "secondary_types": [],
                "vendor": "unknown",
                "model": "unknown",
                "os_family": "unknown",
                "os_version": "unknown",
                "capabilities": [],
                "classification_confidence": 0.0,
                "classification_method": "unknown"
            }
            
            # Try SNMP classification first
            if device.protocol == DeviceProtocol.SNMP:
                snmp_class = await self._classify_via_snmp(device)
                if snmp_class and snmp_class["confidence"] > 0.5:
                    classification_data.update(snmp_class)
                    classification_data["classification_method"] = "snmp"
            
            # Try SSH classification if SNMP didn't work well
            if (device.protocol == DeviceProtocol.SSH and 
                classification_data["classification_confidence"] < 0.7):
                ssh_class = await self._classify_via_ssh(device)
                if ssh_class and ssh_class["confidence"] > classification_data["classification_confidence"]:
                    classification_data.update(ssh_class)
                    classification_data["classification_method"] = "ssh"
            
            # Apply classification rules
            rule_class = await self._apply_classification_rules(device, classification_data)
            if rule_class and rule_class["confidence"] > classification_data["classification_confidence"]:
                classification_data.update(rule_class)
                classification_data["classification_method"] = "rules"
            
            # Detect capabilities
            capabilities = await self.detect_device_capabilities(device.id)
            classification_data["capabilities"] = capabilities
            
            # Calculate final confidence
            final_confidence = self._calculate_final_confidence(classification_data, capabilities)
            classification_data["classification_confidence"] = final_confidence
            
            # Create classification result
            return DeviceClassification(
                device_id=device.id,
                primary_type=classification_data["primary_type"],
                secondary_types=classification_data["secondary_types"],
                vendor=classification_data["vendor"],
                model=classification_data["model"],
                os_family=classification_data["os_family"],
                os_version=classification_data["os_version"],
                capabilities=capabilities,
                classification_confidence=final_confidence,
                classification_method=classification_data["classification_method"],
                last_updated=datetime.now(),
                metadata={
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "protocol": device.protocol.value if device.protocol else None
                }
            )
            
        except Exception as e:
            logger.error(f"Device classification failed: {str(e)}")
            # Return basic classification
            return DeviceClassification(
                device_id=device.id,
                primary_type="unknown",
                secondary_types=[],
                vendor="unknown",
                model="unknown",
                os_family="unknown",
                os_version="unknown",
                capabilities=[],
                classification_confidence=0.0,
                classification_method="error",
                last_updated=datetime.now(),
                metadata={"error": str(e)}
            )
    
    async def _classify_via_snmp(self, device: Device) -> Optional[Dict[str, Any]]:
        """Classify device using SNMP"""
        try:
            # This is a simplified SNMP classification
            # In production, you'd query actual SNMP OIDs
            
            # Simulate SNMP queries
            snmp_data = {
                "sysDescr": "Cisco IOS Software, C3560 Software (C3560-IPBASEK9-M), Version 12.2(53)SEY2, RELEASE SOFTWARE (fc1)",
                "sysObjectID": "1.3.6.1.4.1.9.1.516",
                "sysVendor": "Cisco Systems, Inc.",
                "sysModel": "WS-C3560-24PS-S"
            }
            
            # Parse system description
            classification = self._parse_snmp_sysdescr(snmp_data["sysDescr"])
            
            # Add vendor and model from specific OIDs
            if snmp_data.get("sysVendor"):
                classification["vendor"] = snmp_data["sysVendor"]
            
            if snmp_data.get("sysModel"):
                classification["model"] = snmp_data["sysModel"]
            
            # Set confidence based on data quality
            confidence = 0.8 if classification["primary_type"] != "unknown" else 0.3
            classification["confidence"] = confidence
            
            return classification
            
        except Exception as e:
            logger.error(f"SNMP classification failed: {str(e)}")
            return None
    
    async def _classify_via_ssh(self, device: Device) -> Optional[Dict[str, Any]]:
        """Classify device using SSH"""
        try:
            # This is a simplified SSH classification
            # In production, you'd execute actual commands
            
            # Simulate SSH command execution
            ssh_data = {
                "show version": "Cisco IOS XE Software, Version 16.09.04",
                "show inventory": "NAME: \"Chassis\", DESCR: \"Cisco ISR4331/K9\"",
                "show running-config": "hostname Router-01"
            }
            
            # Parse SSH output
            classification = self._parse_ssh_output(ssh_data)
            
            # Set confidence
            confidence = 0.7 if classification["primary_type"] != "unknown" else 0.2
            classification["confidence"] = confidence
            
            return classification
            
        except Exception as e:
            logger.error(f"SSH classification failed: {str(e)}")
            return None
    
    async def _apply_classification_rules(
        self,
        device: Device,
        current_classification: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Apply classification rules to improve classification"""
        try:
            best_rule_match = None
            best_confidence = current_classification.get("confidence", 0.0)
            
            for rule in self._classification_rules:
                if not rule.is_active:
                    continue
                
                # Check if rule conditions are met
                if self._evaluate_rule_conditions(device, rule.conditions):
                    # Apply rule classification
                    rule_classification = rule.classification.copy()
                    rule_classification["confidence"] = min(1.0, best_confidence + rule.confidence_boost)
                    
                    if rule_classification["confidence"] > best_confidence:
                        best_rule_match = rule_classification
                        best_confidence = rule_classification["confidence"]
            
            return best_rule_match
            
        except Exception as e:
            logger.error(f"Rule-based classification failed: {str(e)}")
            return None
    
    def _evaluate_rule_conditions(self, device: Device, conditions: List[Dict[str, Any]]) -> bool:
        """Evaluate if device meets rule conditions"""
        try:
            for condition in conditions:
                condition_type = condition.get("type")
                
                if condition_type == "hostname_pattern":
                    pattern = condition.get("pattern", "")
                    if not re.search(pattern, device.hostname or "", re.IGNORECASE):
                        return False
                
                elif condition_type == "ip_range":
                    ip_range = condition.get("range", "")
                    if not self._ip_in_range(device.ip_address, ip_range):
                        return False
                
                elif condition_type == "protocol":
                    expected_protocol = condition.get("protocol", "")
                    if device.protocol and device.protocol.value != expected_protocol:
                        return False
                
                elif condition_type == "capability":
                    required_capability = condition.get("capability", "")
                    if not device.capabilities or required_capability not in device.capabilities:
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Rule condition evaluation failed: {str(e)}")
            return False
    
    async def _detect_capabilities_via_snmp(self, device: Device) -> List[DeviceCapability]:
        """Detect device capabilities via SNMP"""
        capabilities = []
        
        try:
            # This is a simplified capability detection
            # In production, you'd query specific SNMP OIDs for capabilities
            
            # Common SNMP-based capabilities
            snmp_capabilities = [
                DeviceCapability(
                    name="snmp_v1",
                    description="SNMP version 1 support",
                    category="management",
                    confidence=0.9,
                    detection_method="snmp",
                    parameters={"version": "v1"}
                ),
                DeviceCapability(
                    name="snmp_v2c",
                    description="SNMP version 2c support",
                    category="management",
                    confidence=0.9,
                    detection_method="snmp",
                    parameters={"version": "v2c"}
                ),
                DeviceCapability(
                    name="interface_monitoring",
                    description="Interface status and statistics monitoring",
                    category="monitoring",
                    confidence=0.8,
                    detection_method="snmp",
                    parameters={"oids": ["ifOperStatus", "ifInOctets", "ifOutOctets"]}
                )
            ]
            
            capabilities.extend(snmp_capabilities)
            
        except Exception as e:
            logger.error(f"SNMP capability detection failed: {str(e)}")
        
        return capabilities
    
    async def _detect_capabilities_via_ssh(self, device: Device) -> List[DeviceCapability]:
        """Detect device capabilities via SSH"""
        capabilities = []
        
        try:
            # This is a simplified capability detection
            # In production, you'd execute actual commands
            
            # Common SSH-based capabilities
            ssh_capabilities = [
                DeviceCapability(
                    name="ssh_access",
                    description="SSH remote access",
                    category="access",
                    confidence=0.9,
                    detection_method="ssh",
                    parameters={"protocol": "ssh"}
                ),
                DeviceCapability(
                    name="command_execution",
                    description="Remote command execution",
                    category="management",
                    confidence=0.8,
                    detection_method="ssh",
                    parameters={"commands": ["show", "configure"]}
                )
            ]
            
            capabilities.extend(ssh_capabilities)
            
        except Exception as e:
            logger.error(f"SSH capability detection failed: {str(e)}")
        
        return capabilities
    
    async def _detect_capabilities_via_interfaces(self, device: Device) -> List[DeviceCapability]:
        """Detect device capabilities via interface analysis"""
        capabilities = []
        
        try:
            # Get device interfaces
            stmt = select(NetworkInterface).where(NetworkInterface.device_id == device.id)
            result = await self.db_session.execute(stmt)
            interfaces = result.scalars().all()
            
            if not interfaces:
                return capabilities
            
            # Analyze interface types and capabilities
            interface_types = set()
            total_bandwidth = 0
            has_wireless = False
            has_fiber = False
            
            for interface in interfaces:
                interface_types.add(interface.interface_type)
                total_bandwidth += interface.bandwidth_mbps or 0
                
                if interface.interface_type == "wireless":
                    has_wireless = True
                elif interface.interface_type == "fiber":
                    has_fiber = True
            
            # Interface-based capabilities
            if len(interfaces) > 1:
                capabilities.append(DeviceCapability(
                    name="multi_interface",
                    description=f"Multiple interfaces ({len(interfaces)})",
                    category="connectivity",
                    confidence=0.9,
                    detection_method="interface_analysis",
                    parameters={"interface_count": len(interfaces)}
                ))
            
            if total_bandwidth > 10000:  # 10 Gbps total
                capabilities.append(DeviceCapability(
                    name="high_bandwidth",
                    description=f"High bandwidth capacity ({total_bandwidth} Mbps)",
                    category="performance",
                    confidence=0.8,
                    detection_method="interface_analysis",
                    parameters={"total_bandwidth": total_bandwidth}
                ))
            
            if has_wireless:
                capabilities.append(DeviceCapability(
                    name="wireless_support",
                    description="Wireless interface support",
                    category="connectivity",
                    confidence=0.9,
                    detection_method="interface_analysis",
                    parameters={"wireless_interfaces": True}
                ))
            
            if has_fiber:
                capabilities.append(DeviceCapability(
                    name="fiber_support",
                    description="Fiber optic interface support",
                    category="connectivity",
                    confidence=0.9,
                    detection_method="interface_analysis",
                    parameters={"fiber_interfaces": True}
                ))
            
        except Exception as e:
            logger.error(f"Interface capability detection failed: {str(e)}")
        
        return capabilities
    
    async def _detect_capabilities_via_metrics(self, device: Device) -> List[DeviceCapability]:
        """Detect device capabilities via metric analysis"""
        capabilities = []
        
        try:
            # Get recent metrics for the device
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            stmt = select(Metric).where(
                and_(
                    Metric.device_id == device.id,
                    Metric.timestamp >= cutoff_time
                )
            ).order_by(Metric.timestamp.desc()).limit(100)
            
            result = await self.db_session.execute(stmt)
            metrics = result.scalars().all()
            
            if not metrics:
                return capabilities
            
            # Analyze metrics for capabilities
            metric_names = set()
            metric_categories = set()
            
            for metric in metrics:
                metric_names.add(metric.metric_name)
                metric_categories.add(metric.category.value if metric.category else "unknown")
            
            # Metric-based capabilities
            if "cpu_usage" in metric_names:
                capabilities.append(DeviceCapability(
                    name="cpu_monitoring",
                    description="CPU usage monitoring",
                    category="monitoring",
                    confidence=0.8,
                    detection_method="metric_analysis",
                    parameters={"metrics": ["cpu_usage"]}
                ))
            
            if "memory_usage" in metric_names:
                capabilities.append(DeviceCapability(
                    name="memory_monitoring",
                    description="Memory usage monitoring",
                    category="monitoring",
                    confidence=0.8,
                    detection_method="metric_analysis",
                    parameters={"metrics": ["memory_usage"]}
                ))
            
            if "network_traffic" in metric_names:
                capabilities.append(DeviceCapability(
                    name="traffic_monitoring",
                    description="Network traffic monitoring",
                    category="monitoring",
                    confidence=0.8,
                    detection_method="metric_analysis",
                    parameters={"metrics": ["network_traffic"]}
                ))
            
            # Category-based capabilities
            if "performance" in metric_categories:
                capabilities.append(DeviceCapability(
                    name="performance_monitoring",
                    description="Performance metrics collection",
                    category="monitoring",
                    confidence=0.7,
                    detection_method="metric_analysis",
                    parameters={"categories": ["performance"]}
                ))
            
        except Exception as e:
            logger.error(f"Metric capability detection failed: {str(e)}")
        
        return capabilities
    
    def _merge_capabilities(
        self,
        existing: Dict[str, DeviceCapability],
        detected: List[DeviceCapability]
    ) -> Dict[str, DeviceCapability]:
        """Merge existing and newly detected capabilities"""
        merged = existing.copy()
        
        for capability in detected:
            if capability.name in merged:
                # Update existing capability if new one has higher confidence
                if capability.confidence > merged[capability.name].confidence:
                    merged[capability.name] = capability
            else:
                # Add new capability
                merged[capability.name] = capability
        
        return merged
    
    def _calculate_final_confidence(
        self,
        classification_data: Dict[str, Any],
        capabilities: List[DeviceCapability]
    ) -> float:
        """Calculate final classification confidence"""
        base_confidence = classification_data.get("confidence", 0.0)
        
        # Boost confidence based on capability count
        capability_boost = min(0.2, len(capabilities) * 0.02)
        
        # Boost confidence based on data completeness
        completeness_boost = 0.0
        if classification_data.get("vendor") != "unknown":
            completeness_boost += 0.1
        if classification_data.get("model") != "unknown":
            completeness_boost += 0.1
        if classification_data.get("os_family") != "unknown":
            completeness_boost += 0.1
        
        final_confidence = min(1.0, base_confidence + capability_boost + completeness_boost)
        return final_confidence
    
    def _parse_snmp_sysdescr(self, sysdescr: str) -> Dict[str, Any]:
        """Parse SNMP sysDescr for device information"""
        classification = {
            "primary_type": "unknown",
            "secondary_types": [],
            "vendor": "unknown",
            "model": "unknown",
            "os_family": "unknown",
            "os_version": "unknown"
        }
        
        if not sysdescr:
            return classification
        
        sysdescr_lower = sysdescr.lower()
        
        # Determine device type
        if "router" in sysdescr_lower:
            classification["primary_type"] = "router"
        elif "switch" in sysdescr_lower:
            classification["primary_type"] = "switch"
        elif "firewall" in sysdescr_lower:
            classification["primary_type"] = "firewall"
        elif "server" in sysdescr_lower:
            classification["primary_type"] = "server"
        elif "access point" in sysdescr_lower or "ap" in sysdescr_lower:
            classification["primary_type"] = "access_point"
        
        # Determine vendor
        if "cisco" in sysdescr_lower:
            classification["vendor"] = "Cisco"
        elif "juniper" in sysdescr_lower:
            classification["vendor"] = "Juniper"
        elif "arista" in sysdescr_lower:
            classification["vendor"] = "Arista"
        elif "hp" in sysdescr_lower or "hewlett-packard" in sysdescr_lower:
            classification["vendor"] = "HP"
        elif "dell" in sysdescr_lower:
            classification["vendor"] = "Dell"
        
        # Determine OS family
        if "ios" in sysdescr_lower:
            classification["os_family"] = "Cisco IOS"
        elif "ios xe" in sysdescr_lower:
            classification["os_family"] = "Cisco IOS XE"
        elif "nx-os" in sysdescr_lower:
            classification["os_family"] = "Cisco NX-OS"
        elif "junos" in sysdescr_lower:
            classification["os_family"] = "Juniper JUNOS"
        elif "eos" in sysdescr_lower:
            classification["os_family"] = "Arista EOS"
        
        # Extract OS version
        version_match = re.search(r'version\s+([\d.()]+)', sysdescr_lower)
        if version_match:
            classification["os_version"] = version_match.group(1)
        
        return classification
    
    def _parse_ssh_output(self, ssh_data: Dict[str, str]) -> Dict[str, Any]:
        """Parse SSH command output for device information"""
        classification = {
            "primary_type": "unknown",
            "secondary_types": [],
            "vendor": "unknown",
            "model": "unknown",
            "os_family": "unknown",
            "os_version": "unknown"
        }
        
        # Parse show version output
        if "show version" in ssh_data:
            version_output = ssh_data["show version"].lower()
            
            # Determine vendor
            if "cisco" in version_output:
                classification["vendor"] = "Cisco"
            elif "juniper" in version_output:
                classification["vendor"] = "Juniper"
            elif "arista" in version_output:
                classification["vendor"] = "Arista"
            
            # Determine OS family
            if "ios xe" in version_output:
                classification["os_family"] = "Cisco IOS XE"
            elif "ios" in version_output:
                classification["os_family"] = "Cisco IOS"
            elif "junos" in version_output:
                classification["os_family"] = "Juniper JUNOS"
            
            # Extract version
            version_match = re.search(r'version\s+([\d.]+)', version_output)
            if version_match:
                classification["os_version"] = version_match.group(1)
        
        # Parse show inventory output
        if "show inventory" in ssh_data:
            inventory_output = ssh_data["show inventory"].lower()
            
            # Determine device type
            if "router" in inventory_output:
                classification["primary_type"] = "router"
            elif "switch" in inventory_output:
                classification["primary_type"] = "switch"
            elif "firewall" in inventory_output:
                classification["primary_type"] = "firewall"
            
            # Extract model
            model_match = re.search(r'descr.*?([a-z0-9-]+)', inventory_output, re.IGNORECASE)
            if model_match:
                classification["model"] = model_match.group(1)
        
        return classification
    
    def _ip_in_range(self, ip: str, ip_range: str) -> bool:
        """Check if IP is in the specified range"""
        try:
            if "/" in ip_range:  # CIDR notation
                import ipaddress
                network = ipaddress.ip_network(ip_range, strict=False)
                return ipaddress.ip_address(ip) in network
            else:  # Single IP
                return ip == ip_range
        except ValueError:
            return False
    
    async def _get_device(self, device_id: int) -> Optional[Device]:
        """Get device by ID"""
        try:
            stmt = select(Device).where(Device.id == device_id)
            result = await self.db_session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Failed to get device {device_id}: {str(e)}")
            return None
    
    async def _update_device_classification(
        self,
        device: Device,
        classification: DeviceClassification
    ):
        """Update device with classification results"""
        try:
            # Update device fields
            if classification.vendor != "unknown":
                device.vendor = classification.vendor
            
            if classification.model != "unknown":
                device.model = classification.model
            
            if classification.os_version != "unknown":
                device.os_version = classification.os_version
            
            # Update capabilities
            capability_names = [cap.name for cap in classification.capabilities]
            device.capabilities = capability_names
            
            # Update device type if we have a good classification
            if classification.classification_confidence > 0.7:
                device.device_type = classification.primary_type
            
            device.updated_at = datetime.now()
            
            await self.db_session.commit()
            
        except Exception as e:
            logger.error(f"Failed to update device classification: {str(e)}")
    
    async def _get_performance_recommendations(
        self,
        device_id: int,
        classification: DeviceClassification
    ) -> List[Dict[str, Any]]:
        """Get performance optimization recommendations"""
        recommendations = []
        
        try:
            # Get recent performance metrics
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            stmt = select(Metric).where(
                and_(
                    Metric.device_id == device_id,
                    Metric.category == MetricCategory.PERFORMANCE,
                    Metric.timestamp >= cutoff_time
                )
            ).order_by(Metric.timestamp.desc()).limit(50)
            
            result = await self.db_session.execute(stmt)
            metrics = result.scalars().all()
            
            # Analyze performance issues
            high_cpu_metrics = [m for m in metrics if m.metric_name == "cpu_usage" and m.value > 80]
            high_memory_metrics = [m for m in metrics if m.metric_name == "memory_usage" and m.value > 80]
            
            if high_cpu_metrics:
                recommendations.append({
                    "type": "performance",
                    "priority": "high",
                    "title": "High CPU Usage Detected",
                    "description": f"CPU usage exceeded 80% {len(high_cpu_metrics)} times in the last 24 hours",
                    "recommendation": "Investigate high CPU processes and consider load balancing or hardware upgrade",
                    "affected_metrics": ["cpu_usage"]
                })
            
            if high_memory_metrics:
                recommendations.append({
                    "type": "performance",
                    "priority": "medium",
                    "title": "High Memory Usage Detected",
                    "description": f"Memory usage exceeded 80% {len(high_memory_metrics)} times in the last 24 hours",
                    "recommendation": "Monitor memory usage trends and consider memory upgrade if persistent",
                    "affected_metrics": ["memory_usage"]
                })
            
        except Exception as e:
            logger.error(f"Failed to get performance recommendations: {str(e)}")
        
        return recommendations
    
    async def _get_security_recommendations(
        self,
        device_id: int,
        classification: DeviceClassification
    ) -> List[Dict[str, Any]]:
        """Get security recommendations"""
        recommendations = []
        
        try:
            # Security recommendations based on device type and capabilities
            if classification.primary_type == "router":
                recommendations.append({
                    "type": "security",
                    "priority": "medium",
                    "title": "Router Security Hardening",
                    "description": "Router detected - ensure security best practices are implemented",
                    "recommendation": "Enable access control lists, disable unnecessary services, and implement logging",
                    "affected_components": ["routing", "access_control"]
                })
            
            if classification.primary_type == "switch":
                recommendations.append({
                    "type": "security",
                    "priority": "medium",
                    "title": "Switch Security Configuration",
                    "description": "Switch detected - implement layer 2 security measures",
                    "recommendation": "Enable port security, implement VLAN segmentation, and monitor for MAC address changes",
                    "affected_components": ["switching", "vlan_management"]
                })
            
            # Check for security capabilities
            security_capabilities = [cap for cap in classification.capabilities if "security" in cap.category.lower()]
            if not security_capabilities:
                recommendations.append({
                    "type": "security",
                    "priority": "low",
                    "title": "Security Monitoring",
                    "description": "No security monitoring capabilities detected",
                    "recommendation": "Consider implementing security monitoring and logging capabilities",
                    "affected_components": ["monitoring", "logging"]
                })
            
        except Exception as e:
            logger.error(f"Failed to get security recommendations: {str(e)}")
        
        return recommendations
    
    async def _get_monitoring_recommendations(
        self,
        device_id: int,
        classification: DeviceClassification
    ) -> List[Dict[str, Any]]:
        """Get monitoring recommendations"""
        recommendations = []
        
        try:
            # Check monitoring coverage
            monitoring_capabilities = [cap for cap in classification.capabilities if "monitoring" in cap.category.lower()]
            
            if len(monitoring_capabilities) < 3:
                recommendations.append({
                    "type": "monitoring",
                    "priority": "medium",
                    "title": "Expand Monitoring Coverage",
                    "description": f"Limited monitoring capabilities detected ({len(monitoring_capabilities)})",
                    "recommendation": "Implement additional monitoring for performance, availability, and security metrics",
                    "affected_components": ["monitoring", "metrics_collection"]
                })
            
            # Check for specific monitoring gaps
            metric_names = [cap.name for cap in monitoring_capabilities]
            
            if "cpu_monitoring" not in metric_names:
                recommendations.append({
                    "type": "monitoring",
                    "priority": "high",
                    "title": "CPU Monitoring Missing",
                    "description": "CPU usage monitoring not available",
                    "recommendation": "Implement CPU monitoring to track device performance",
                    "affected_components": ["performance_monitoring"]
                })
            
            if "memory_monitoring" not in metric_names:
                recommendations.append({
                    "type": "monitoring",
                    "priority": "high",
                    "title": "Memory Monitoring Missing",
                    "description": "Memory usage monitoring not available",
                    "recommendation": "Implement memory monitoring to track resource utilization",
                    "affected_components": ["resource_monitoring"]
                })
            
        except Exception as e:
            logger.error(f"Failed to get monitoring recommendations: {str(e)}")
        
        return recommendations
    
    async def _get_upgrade_recommendations(
        self,
        device_id: int,
        classification: DeviceClassification
    ) -> List[Dict[str, Any]]:
        """Get upgrade recommendations"""
        recommendations = []
        
        try:
            # Check OS version for upgrade recommendations
            if classification.os_version != "unknown":
                # This is a simplified version check
                # In production, you'd have a database of current versions and security advisories
                
                if "ios" in classification.os_family.lower():
                    recommendations.append({
                        "type": "upgrade",
                        "priority": "low",
                        "title": "IOS Version Review",
                        "description": f"Current IOS version: {classification.os_version}",
                        "recommendation": "Review for security patches and feature updates",
                        "affected_components": ["operating_system", "security"]
                    })
            
            # Check device age and capabilities for hardware upgrade recommendations
            if classification.primary_type in ["router", "switch"]:
                # This would require additional device metadata (manufacture date, etc.)
                recommendations.append({
                    "type": "upgrade",
                    "priority": "low",
                    "title": "Hardware Lifecycle Review",
                    "description": "Network infrastructure device detected",
                    "recommendation": "Review hardware lifecycle and plan for future upgrades",
                    "affected_components": ["hardware", "infrastructure"]
                })
            
        except Exception as e:
            logger.error(f"Failed to get upgrade recommendations: {str(e)}")
        
        return recommendations
    
    def _initialize_patterns(self):
        """Initialize regex patterns for device classification"""
        # Vendor patterns
        self._vendor_patterns = {
            "cisco": [
                re.compile(r"cisco", re.IGNORECASE),
                re.compile(r"ios", re.IGNORECASE),
                re.compile(r"cat[0-9]+", re.IGNORECASE)
            ],
            "juniper": [
                re.compile(r"juniper", re.IGNORECASE),
                re.compile(r"junos", re.IGNORECASE)
            ],
            "arista": [
                re.compile(r"arista", re.IGNORECASE),
                re.compile(r"eos", re.IGNORECASE)
            ]
        }
        
        # OS patterns
        self._os_patterns = {
            "ios": [
                re.compile(r"ios\s+software", re.IGNORECASE),
                re.compile(r"cisco\s+ios", re.IGNORECASE)
            ],
            "ios_xe": [
                re.compile(r"ios\s+xe", re.IGNORECASE),
                re.compile(r"xe\s+software", re.IGNORECASE)
            ],
            "junos": [
                re.compile(r"junos", re.IGNORECASE),
                re.compile(r"juniper\s+os", re.IGNORECASE)
            ]
        }
    
    def _initialize_classification_rules(self):
        """Initialize classification rules"""
        self._classification_rules = [
            ClassificationRule(
                name="Cisco Router Pattern",
                description="Identify Cisco routers by hostname pattern",
                priority=1,
                conditions=[
                    {"type": "hostname_pattern", "pattern": r"router-.*"},
                    {"type": "protocol", "protocol": "snmp"}
                ],
                classification={
                    "primary_type": "router",
                    "vendor": "Cisco",
                    "os_family": "Cisco IOS",
                    "confidence": 0.8
                },
                confidence_boost=0.1
            ),
            ClassificationRule(
                name="Cisco Switch Pattern",
                description="Identify Cisco switches by hostname pattern",
                priority=1,
                conditions=[
                    {"type": "hostname_pattern", "pattern": r"switch-.*"},
                    {"type": "protocol", "protocol": "snmp"}
                ],
                classification={
                    "primary_type": "switch",
                    "vendor": "Cisco",
                    "os_family": "Cisco IOS",
                    "confidence": 0.8
                },
                confidence_boost=0.1
            ),
            ClassificationRule(
                name="Network Infrastructure",
                description="Identify network infrastructure devices by IP range",
                priority=2,
                conditions=[
                    {"type": "ip_range", "range": "10.0.0.0/8"}
                ],
                classification={
                    "primary_type": "network_device",
                    "confidence": 0.6
                },
                confidence_boost=0.05
            )
        ]
