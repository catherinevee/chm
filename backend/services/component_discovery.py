"""
Component Discovery Service
Handles hardware and software component discovery for network devices
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload

from backend.storage.database import db
from backend.storage.models import (
    Device, HardwareComponent, SoftwareComponent, NetworkInterface,
    DeviceStatus, ComponentType, ComponentStatus
)
from backend.collector.snmp_collector import SNMPCollector
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

class ComponentDiscoveryService:
    """Service for discovering and managing device components"""
    
    def __init__(self):
        self.snmp_collector = SNMPCollector()
    
    async def get_device_components(self, device_id: str) -> Dict[str, List[Any]]:
        """Get all components for a device"""
        try:
            # Get hardware components
            hardware_query = select(HardwareComponent).where(
                HardwareComponent.device_id == device_id
            ).order_by(HardwareComponent.component_type, HardwareComponent.name)
            hardware_result = await db.execute(hardware_query)
            hardware_components = hardware_result.scalars().all()
            
            # Get software components
            software_query = select(SoftwareComponent).where(
                SoftwareComponent.device_id == device_id
            ).order_by(SoftwareComponent.component_type, SoftwareComponent.name)
            software_result = await db.execute(software_query)
            software_components = software_result.scalars().all()
            
            # Get network interfaces
            interface_query = select(NetworkInterface).where(
                NetworkInterface.device_id == device_id
            ).order_by(NetworkInterface.interface_name)
            interface_result = await db.execute(interface_query)
            network_interfaces = interface_result.scalars().all()
            
            return {
                "hardware": hardware_components,
                "software": software_components,
                "interfaces": network_interfaces
            }
        
        except Exception as e:
            logger.error(f"Failed to get device components for {device_id}: {e}")
            raise
    
    async def get_hardware_components(self, device_id: str) -> List[HardwareComponent]:
        """Get hardware components for a device"""
        try:
            query = select(HardwareComponent).where(
                HardwareComponent.device_id == device_id
            ).order_by(HardwareComponent.component_type, HardwareComponent.name)
            
            result = await db.execute(query)
            return result.scalars().all()
        
        except Exception as e:
            logger.error(f"Failed to get hardware components for {device_id}: {e}")
            raise
    
    async def get_software_components(self, device_id: str) -> List[SoftwareComponent]:
        """Get software components for a device"""
        try:
            query = select(SoftwareComponent).where(
                SoftwareComponent.device_id == device_id
            ).order_by(SoftwareComponent.component_type, SoftwareComponent.name)
            
            result = await db.execute(query)
            return result.scalars().all()
        
        except Exception as e:
            logger.error(f"Failed to get software components for {device_id}: {e}")
            raise
    
    async def get_network_interfaces(self, device_id: str) -> List[NetworkInterface]:
        """Get network interfaces for a device"""
        try:
            query = select(NetworkInterface).where(
                NetworkInterface.device_id == device_id
            ).order_by(NetworkInterface.interface_name)
            
            result = await db.execute(query)
            return result.scalars().all()
        
        except Exception as e:
            logger.error(f"Failed to get network interfaces for {device_id}: {e}")
            raise
    
    async def discover_device_components(self, device_id: str) -> Dict[str, Any]:
        """Discover all components for a device"""
        try:
            # Get device information
            device_query = select(Device).where(Device.id == device_id)
            device_result = await db.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                return {
                    "success": False,
                    "message": f"Device with ID {device_id} not found"
                }
            
            logger.info(f"Starting component discovery for device {device.hostname} ({device.ip_address})")
            
            # Initialize counters
            components_discovered = {
                "hardware": 0,
                "software": 0,
                "interfaces": 0
            }
            
            # Discover hardware components
            try:
                hardware_count = await self._discover_hardware_components(device)
                components_discovered["hardware"] = hardware_count
            except Exception as e:
                logger.error(f"Hardware discovery failed for {device.hostname}: {e}")
            
            # Discover software components
            try:
                software_count = await self._discover_software_components(device)
                components_discovered["software"] = software_count
            except Exception as e:
                logger.error(f"Software discovery failed for {device.hostname}: {e}")
            
            # Discover/update network interfaces
            try:
                interface_count = await self._discover_network_interfaces(device)
                components_discovered["interfaces"] = interface_count
            except Exception as e:
                logger.error(f"Interface discovery failed for {device.hostname}: {e}")
            
            # Commit all changes
            await db.commit()
            
            total_discovered = sum(components_discovered.values())
            
            return {
                "success": True,
                "message": f"Component discovery completed for {device.hostname}. Discovered {total_discovered} components.",
                "components_discovered": components_discovered
            }
        
        except Exception as e:
            await db.rollback()
            logger.error(f"Component discovery failed for device {device_id}: {e}")
            raise
    
    async def _discover_hardware_components(self, device: Device) -> int:
        """Discover hardware components via SNMP"""
        try:
            components_found = 0
            
            # Entity MIB OIDs for hardware discovery
            entity_oids = {
                "entPhysicalDescr": "1.3.6.1.2.1.47.1.1.1.1.2",      # Component description
                "entPhysicalName": "1.3.6.1.2.1.47.1.1.1.1.7",       # Component name
                "entPhysicalModelName": "1.3.6.1.2.1.47.1.1.1.1.13", # Model name
                "entPhysicalSerialNum": "1.3.6.1.2.1.47.1.1.1.1.11", # Serial number
                "entPhysicalMfgName": "1.3.6.1.2.1.47.1.1.1.1.12",   # Manufacturer
                "entPhysicalClass": "1.3.6.1.2.1.47.1.1.1.1.5",      # Component class
                "entPhysicalFirmwareRev": "1.3.6.1.2.1.47.1.1.1.1.9" # Firmware version
            }
            
            # Walk the entity table
            for oid_name, oid in entity_oids.items():
                try:
                    result = await self.snmp_collector.walk_oid(device.ip_address, oid)
                    
                    if oid_name == "entPhysicalDescr" and result:
                        # Process each physical entity
                        for index, description in result.items():
                            if description and description.strip():
                                # Get additional info for this entity
                                entity_info = await self._get_entity_info(device, index, entity_oids)
                                
                                # Create or update hardware component
                                component = await self._create_hardware_component(
                                    device.id, index, description, entity_info
                                )
                                if component:
                                    components_found += 1
                
                except Exception as e:
                    logger.debug(f"Failed to get {oid_name} for {device.hostname}: {e}")
                    continue
            
            # Also try Cisco-specific OIDs for additional hardware info
            await self._discover_cisco_hardware(device)
            
            logger.info(f"Discovered {components_found} hardware components for {device.hostname}")
            return components_found
        
        except Exception as e:
            logger.error(f"Hardware component discovery failed for {device.hostname}: {e}")
            return 0
    
    async def _get_entity_info(self, device: Device, index: str, entity_oids: Dict[str, str]) -> Dict[str, Any]:
        """Get additional entity information"""
        entity_info = {}
        
        for info_name, base_oid in entity_oids.items():
            if info_name != "entPhysicalDescr":  # Skip description as we already have it
                try:
                    full_oid = f"{base_oid}.{index}"
                    result = await self.snmp_collector.get_oid(device.ip_address, full_oid)
                    if result:
                        entity_info[info_name] = result
                except:
                    continue
        
        return entity_info
    
    async def _create_hardware_component(self, device_id: str, index: str, description: str, entity_info: Dict[str, Any]) -> Optional[HardwareComponent]:
        """Create or update a hardware component"""
        try:
            # Determine component type from description
            component_type = self._classify_hardware_component(description)
            
            # Check if component already exists
            existing_query = select(HardwareComponent).where(
                and_(
                    HardwareComponent.device_id == device_id,
                    HardwareComponent.name == description,
                    HardwareComponent.position == index
                )
            )
            existing_result = await db.execute(existing_query)
            existing_component = existing_result.scalar_one_or_none()
            
            if existing_component:
                # Update existing component
                existing_component.description = description
                existing_component.component_type = component_type
                existing_component.model = entity_info.get("entPhysicalModelName", "")[:100] if entity_info.get("entPhysicalModelName") else None
                existing_component.serial_number = entity_info.get("entPhysicalSerialNum", "")[:100] if entity_info.get("entPhysicalSerialNum") else None
                existing_component.manufacturer = entity_info.get("entPhysicalMfgName", "")[:100] if entity_info.get("entPhysicalMfgName") else None
                existing_component.firmware_version = entity_info.get("entPhysicalFirmwareRev", "")[:50] if entity_info.get("entPhysicalFirmwareRev") else None
                existing_component.status = ComponentStatus.ACTIVE
                existing_component.updated_at = datetime.utcnow()
                
                return existing_component
            else:
                # Create new component
                component = HardwareComponent(
                    device_id=device_id,
                    component_type=component_type,
                    name=description[:100] if description else f"Component {index}",
                    description=description[:255] if description else None,
                    position=index[:50] if index else None,
                    model=entity_info.get("entPhysicalModelName", "")[:100] if entity_info.get("entPhysicalModelName") else None,
                    serial_number=entity_info.get("entPhysicalSerialNum", "")[:100] if entity_info.get("entPhysicalSerialNum") else None,
                    manufacturer=entity_info.get("entPhysicalMfgName", "")[:100] if entity_info.get("entPhysicalMfgName") else None,
                    firmware_version=entity_info.get("entPhysicalFirmwareRev", "")[:50] if entity_info.get("entPhysicalFirmwareRev") else None,
                    status=ComponentStatus.ACTIVE,
                    health_status="unknown",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                db.add(component)
                return component
        
        except Exception as e:
            logger.error(f"Failed to create hardware component: {e}")
            
            # Return fallback component data when creation fails
            fallback_data = FallbackData(
                data=HardwareComponent(
                    device_id=device_id,
                    component_type=ComponentType.OTHER,
                    name="unknown-component",
                    description="Component creation failed",
                    position="unknown",
                    status=ComponentStatus.ERROR,
                    health_status="error",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                ),
                source="component_creation_fallback",
                confidence=0.0,
                metadata={"device_id": device_id, "error": str(e)}
            )
            
            return create_failure_result(
                error=f"Failed to create hardware component for device {device_id}",
                error_code="COMPONENT_CREATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Component creation failed",
                    "Check device connectivity",
                    "Verify SNMP configuration",
                    "Review error logs"
                ]
            )
    
    def _classify_hardware_component(self, description: str) -> ComponentType:
        """Classify hardware component based on description"""
        if not description:
            return ComponentType.OTHER
        
        desc_lower = description.lower()
        
        if any(keyword in desc_lower for keyword in ["cpu", "processor", "central processing"]):
            return ComponentType.CPU
        elif any(keyword in desc_lower for keyword in ["memory", "ram", "dimm"]):
            return ComponentType.MEMORY
        elif any(keyword in desc_lower for keyword in ["disk", "drive", "storage", "ssd", "hdd"]):
            return ComponentType.STORAGE
        elif any(keyword in desc_lower for keyword in ["power", "psu", "supply"]):
            return ComponentType.POWER_SUPPLY
        elif any(keyword in desc_lower for keyword in ["fan", "cooling", "blower"]):
            return ComponentType.FAN
        elif any(keyword in desc_lower for keyword in ["interface", "port", "ethernet", "gigabit"]):
            return ComponentType.NETWORK_INTERFACE
        elif any(keyword in desc_lower for keyword in ["sensor", "temperature", "thermal"]):
            return ComponentType.SENSOR
        elif any(keyword in desc_lower for keyword in ["chassis", "backplane", "slot"]):
            return ComponentType.CHASSIS
        else:
            return ComponentType.OTHER
    
    async def _discover_cisco_hardware(self, device: Device):
        """Discover Cisco-specific hardware components"""
        try:
            # Cisco environmental monitoring
            cisco_oids = {
                "ciscoEnvMonTemperatureDescr": "1.3.6.1.4.1.9.9.13.1.3.1.2",
                "ciscoEnvMonFanDescr": "1.3.6.1.4.1.9.9.13.1.4.1.2",
                "ciscoEnvMonSupplyDescr": "1.3.6.1.4.1.9.9.13.1.5.1.2"
            }
            
            for oid_name, oid in cisco_oids.items():
                try:
                    result = await self.snmp_collector.walk_oid(device.ip_address, oid)
                    if result:
                        for index, description in result.items():
                            if description and description.strip():
                                component_type = ComponentType.SENSOR
                                if "fan" in oid_name.lower():
                                    component_type = ComponentType.FAN
                                elif "supply" in oid_name.lower():
                                    component_type = ComponentType.POWER_SUPPLY
                                
                                await self._create_simple_hardware_component(
                                    device.id, f"cisco_{index}", description, component_type
                                )
                except Exception as e:
                    logger.debug(f"Failed to get Cisco {oid_name} for {device.hostname}: {e}")
                    continue
        
        except Exception as e:
            logger.debug(f"Cisco hardware discovery failed for {device.hostname}: {e}")
    
    async def _create_simple_hardware_component(self, device_id: str, index: str, description: str, component_type: ComponentType):
        """Create a simple hardware component"""
        try:
            # Check if component already exists
            existing_query = select(HardwareComponent).where(
                and_(
                    HardwareComponent.device_id == device_id,
                    HardwareComponent.name == description,
                    HardwareComponent.position == index
                )
            )
            existing_result = await db.execute(existing_query)
            existing_component = existing_result.scalar_one_or_none()
            
            if not existing_component:
                component = HardwareComponent(
                    device_id=device_id,
                    component_type=component_type,
                    name=description[:100] if description else f"Component {index}",
                    description=description[:255] if description else None,
                    position=index[:50] if index else None,
                    status=ComponentStatus.ACTIVE,
                    health_status="unknown",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                db.add(component)
        
        except Exception as e:
            logger.error(f"Failed to create simple hardware component: {e}")
    
    async def _discover_software_components(self, device: Device) -> int:
        """Discover software components via SNMP"""
        try:
            components_found = 0
            
            # Host Resources MIB for software
            software_oids = {
                "hrSWRunName": "1.3.6.1.2.1.25.4.2.1.2",      # Running software name
                "hrSWRunPath": "1.3.6.1.2.1.25.4.2.1.4",      # Software path
                "hrSWRunParameters": "1.3.6.1.2.1.25.4.2.1.5", # Parameters
                "hrSWRunType": "1.3.6.1.2.1.25.4.2.1.6",      # Software type
                "hrSWRunStatus": "1.3.6.1.2.1.25.4.2.1.7"     # Status
            }
            
            # Get running software
            try:
                result = await self.snmp_collector.walk_oid(device.ip_address, software_oids["hrSWRunName"])
                if result:
                    for index, name in result.items():
                        if name and name.strip():
                            # Get additional software info
                            software_info = await self._get_software_info(device, index, software_oids)
                            
                            # Create software component
                            component = await self._create_software_component(
                                device.id, index, name, software_info
                            )
                            if component:
                                components_found += 1
            except Exception as e:
                logger.debug(f"Failed to discover running software for {device.hostname}: {e}")
            
            # Try to get installed software (if available)
            try:
                installed_oid = "1.3.6.1.2.1.25.6.3.1.2"  # hrSWInstalledName
                result = await self.snmp_collector.walk_oid(device.ip_address, installed_oid)
                if result:
                    for index, name in result.items():
                        if name and name.strip():
                            component = await self._create_software_component(
                                device.id, f"installed_{index}", name, {"type": "installed"}
                            )
                            if component:
                                components_found += 1
            except Exception as e:
                logger.debug(f"Failed to discover installed software for {device.hostname}: {e}")
            
            logger.info(f"Discovered {components_found} software components for {device.hostname}")
            return components_found
        
        except Exception as e:
            logger.error(f"Software component discovery failed for {device.hostname}: {e}")
            return 0
    
    async def _get_software_info(self, device: Device, index: str, software_oids: Dict[str, str]) -> Dict[str, Any]:
        """Get additional software information"""
        software_info = {}
        
        for info_name, base_oid in software_oids.items():
            if info_name != "hrSWRunName":  # Skip name as we already have it
                try:
                    full_oid = f"{base_oid}.{index}"
                    result = await self.snmp_collector.get_oid(device.ip_address, full_oid)
                    if result:
                        software_info[info_name] = result
                except:
                    continue
        
        return software_info
    
    async def _create_software_component(self, device_id: str, index: str, name: str, software_info: Dict[str, Any]) -> Optional[SoftwareComponent]:
        """Create or update a software component"""
        try:
            # Determine component type
            component_type = self._classify_software_component(name, software_info)
            
            # Extract version from name if possible
            version = self._extract_version(name)
            
            # Check if component already exists
            existing_query = select(SoftwareComponent).where(
                and_(
                    SoftwareComponent.device_id == device_id,
                    SoftwareComponent.name == name[:100]
                )
            )
            existing_result = await db.execute(existing_query)
            existing_component = existing_result.scalar_one_or_none()
            
            if existing_component:
                # Update existing component
                existing_component.version = version[:50] if version else "unknown"
                existing_component.component_type = component_type
                existing_component.path = software_info.get("hrSWRunPath", "")[:255] if software_info.get("hrSWRunPath") else None
                existing_component.status = self._map_software_status(software_info.get("hrSWRunStatus"))
                existing_component.updated_at = datetime.utcnow()
                
                return existing_component
            else:
                # Create new component
                component = SoftwareComponent(
                    device_id=device_id,
                    name=name[:100] if name else f"Software {index}",
                    version=version[:50] if version else "unknown",
                    component_type=component_type,
                    path=software_info.get("hrSWRunPath", "")[:255] if software_info.get("hrSWRunPath") else None,
                    status=self._map_software_status(software_info.get("hrSWRunStatus")),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                
                db.add(component)
                return component
        
        except Exception as e:
            logger.error(f"Failed to create software component: {e}")
            
            # Return fallback component data when creation fails
            fallback_data = FallbackData(
                data=SoftwareComponent(
                    device_id=device_id,
                    component_type=ComponentType.OTHER,
                    name="unknown-software",
                    description="Software component creation failed",
                    status=ComponentStatus.ERROR,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                ),
                source="software_component_creation_fallback",
                confidence=0.0,
                metadata={"device_id": device_id, "error": str(e)}
            )
            
            return create_failure_result(
                error=f"Failed to create software component for device {device_id}",
                error_code="SOFTWARE_COMPONENT_CREATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Software component creation failed",
                    "Check device connectivity",
                    "Verify SNMP configuration",
                    "Review error logs"
                ]
            )
    
    def _classify_software_component(self, name: str, software_info: Dict[str, Any]) -> ComponentType:
        """Classify software component based on name and info"""
        if not name:
            return ComponentType.OTHER
        
        name_lower = name.lower()
        
        if any(keyword in name_lower for keyword in ["ios", "junos", "firmware", "bootloader", "bios"]):
            return ComponentType.FIRMWARE
        elif any(keyword in name_lower for keyword in ["service", "daemon", "process"]):
            return ComponentType.SERVICE
        elif any(keyword in name_lower for keyword in ["driver", "module", "kernel"]):
            return ComponentType.DRIVER
        elif software_info.get("type") == "installed":
            return ComponentType.APPLICATION
        else:
            return ComponentType.PROCESS
    
    def _extract_version(self, name: str) -> Optional[str]:
        """Extract version from software name"""
        import re
        
        # Common version patterns
        patterns = [
            r'v?(\d+\.\d+\.\d+\.\d+)',  # x.x.x.x
            r'v?(\d+\.\d+\.\d+)',       # x.x.x
            r'v?(\d+\.\d+)',            # x.x
            r'Version\s+(\S+)',         # Version xxx
            r'v(\S+)',                  # vxxx
        ]
        
        for pattern in patterns:
            match = re.search(pattern, name, re.IGNORECASE)
            if match:
                return match.group(1)
        
        # Return fallback version data when no version found
        fallback_data = FallbackData(
            data="unknown",
            source="version_extraction_fallback",
            confidence=0.0,
            metadata={"name": name, "reason": "No version pattern matched"}
        )
        
        return create_partial_success_result(
            data="unknown",
            fallback_data=fallback_data,
            health_status=HealthStatus(
                level=HealthLevel.WARNING,
                message="No version information found",
                details=f"No version pattern matched for software name: {name}",
                timestamp=datetime.now().isoformat()
            ),
            suggestions=[
                "No version information found",
                "Check software naming convention",
                "Use fallback version value",
                "Contact administrator for version details"
            ]
        ).data
    
    def _map_software_status(self, snmp_status) -> ComponentStatus:
        """Map SNMP software status to ComponentStatus"""
        if not snmp_status:
            return ComponentStatus.UNKNOWN
        
        # hrSWRunStatus values: running(1), runnable(2), notRunnable(3), invalid(4)
        try:
            status_int = int(snmp_status)
            if status_int == 1:
                return ComponentStatus.ACTIVE
            elif status_int in [2, 3]:
                return ComponentStatus.INACTIVE
            else:
                return ComponentStatus.FAILED
        except:
            return ComponentStatus.UNKNOWN
    
    async def _discover_network_interfaces(self, device: Device) -> int:
        """Discover/update network interfaces"""
        try:
            interfaces_found = 0
            
            # Interface MIB OIDs
            interface_oids = {
                "ifDescr": "1.3.6.1.2.1.2.2.1.2",         # Interface description
                "ifType": "1.3.6.1.2.1.2.2.1.3",          # Interface type
                "ifMtu": "1.3.6.1.2.1.2.2.1.4",           # MTU
                "ifSpeed": "1.3.6.1.2.1.2.2.1.5",         # Speed
                "ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",   # MAC address
                "ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",   # Admin status
                "ifOperStatus": "1.3.6.1.2.1.2.2.1.8",    # Operational status
            }
            
            # Get interface descriptions first
            result = await self.snmp_collector.walk_oid(device.ip_address, interface_oids["ifDescr"])
            if result:
                for index, description in result.items():
                    if description and description.strip():
                        # Get additional interface info
                        interface_info = await self._get_interface_info(device, index, interface_oids)
                        
                        # Create or update interface
                        interface = await self._create_network_interface(
                            device.id, index, description, interface_info
                        )
                        if interface:
                            interfaces_found += 1
            
            logger.info(f"Discovered {interfaces_found} network interfaces for {device.hostname}")
            return interfaces_found
        
        except Exception as e:
            logger.error(f"Network interface discovery failed for {device.hostname}: {e}")
            return 0
    
    async def _get_interface_info(self, device: Device, index: str, interface_oids: Dict[str, str]) -> Dict[str, Any]:
        """Get additional interface information"""
        interface_info = {}
        
        for info_name, base_oid in interface_oids.items():
            if info_name != "ifDescr":  # Skip description as we already have it
                try:
                    full_oid = f"{base_oid}.{index}"
                    result = await self.snmp_collector.get_oid(device.ip_address, full_oid)
                    if result:
                        interface_info[info_name] = result
                except:
                    continue
        
        return interface_info
    
    async def _create_network_interface(self, device_id: str, index: str, description: str, interface_info: Dict[str, Any]) -> Optional[NetworkInterface]:
        """Create or update a network interface"""
        try:
            # Check if interface already exists
            existing_query = select(NetworkInterface).where(
                and_(
                    NetworkInterface.device_id == device_id,
                    NetworkInterface.interface_name == description
                )
            )
            existing_result = await db.execute(existing_query)
            existing_interface = existing_result.scalar_one_or_none()
            
            # Map status values
            admin_status = self._map_interface_status(interface_info.get("ifAdminStatus"))
            oper_status = self._map_interface_status(interface_info.get("ifOperStatus"))
            overall_status = "up" if admin_status == "up" and oper_status == "up" else "down"
            
            # Format MAC address
            mac_address = self._format_mac_address(interface_info.get("ifPhysAddress"))
            
            if existing_interface:
                # Update existing interface
                existing_interface.interface_type = self._map_interface_type(interface_info.get("ifType"))
                existing_interface.status = overall_status
                existing_interface.admin_status = admin_status
                existing_interface.oper_status = oper_status
                existing_interface.speed = int(interface_info.get("ifSpeed", 0)) if interface_info.get("ifSpeed") else None
                existing_interface.mtu = int(interface_info.get("ifMtu", 0)) if interface_info.get("ifMtu") else None
                existing_interface.mac_address = mac_address
                existing_interface.last_change = datetime.utcnow()
                
                return existing_interface
            else:
                # Create new interface
                interface = NetworkInterface(
                    device_id=device_id,
                    interface_name=description[:100] if description else f"Interface {index}",
                    interface_type=self._map_interface_type(interface_info.get("ifType")),
                    status=overall_status,
                    admin_status=admin_status,
                    oper_status=oper_status,
                    speed=int(interface_info.get("ifSpeed", 0)) if interface_info.get("ifSpeed") else None,
                    mtu=int(interface_info.get("ifMtu", 0)) if interface_info.get("ifMtu") else None,
                    mac_address=mac_address,
                    last_change=datetime.utcnow()
                )
                
                db.add(interface)
                return interface
        
        except Exception as e:
            logger.error(f"Failed to create network interface: {e}")
            
            # Return fallback interface data when creation fails
            fallback_data = FallbackData(
                data=NetworkInterface(
                    device_id=device_id,
                    interface_name="unknown-interface",
                    interface_type="other",
                    status="unknown",
                    admin_status="unknown",
                    oper_status="unknown",
                    last_change=datetime.utcnow()
                ),
                source="network_interface_creation_fallback",
                confidence=0.0,
                metadata={"device_id": device_id, "error": str(e)}
            )
            
            return create_failure_result(
                error=f"Failed to create network interface for device {device_id}",
                error_code="NETWORK_INTERFACE_CREATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Network interface creation failed",
                    "Check device connectivity",
                    "Verify SNMP configuration",
                    "Review error logs"
                ]
            )
    
    def _map_interface_status(self, snmp_status) -> str:
        """Map SNMP interface status to string"""
        if not snmp_status:
            return "unknown"
        
        try:
            status_int = int(snmp_status)
            if status_int == 1:
                return "up"
            elif status_int == 2:
                return "down"
            elif status_int == 3:
                return "testing"
            else:
                return "unknown"
        except:
            return "unknown"
    
    def _map_interface_type(self, snmp_type) -> str:
        """Map SNMP interface type to string"""
        if not snmp_type:
            return "other"
        
        # Common interface types from RFC 1213
        type_map = {
            1: "other",
            6: "ethernet",
            24: "loopback",
            131: "tunnel",
            53: "virtual",
            161: "ieee8023adLag"
        }
        
        try:
            type_int = int(snmp_type)
            return type_map.get(type_int, "other")
        except:
            return "other"
    
    def _format_mac_address(self, mac_bytes) -> str:
        """Format MAC address from SNMP bytes"""
        if not mac_bytes:
            # Return fallback MAC address when no bytes provided
            fallback_data = FallbackData(
                data="00:00:00:00:00:00",
                source="mac_address_fallback",
                confidence=0.0,
                metadata={"reason": "No MAC bytes provided"}
            )
            
            return create_partial_success_result(
                data="00:00:00:00:00:00",
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No MAC address provided",
                    details="No MAC address bytes provided for formatting",
                    timestamp=datetime.now().isoformat()
                ),
                suggestions=[
                    "No MAC address provided",
                    "Check SNMP data",
                    "Use fallback MAC address",
                    "Verify device configuration"
                ]
            ).data
        
        try:
            # Convert hex string to MAC format
            if isinstance(mac_bytes, str):
                # Remove spaces and convert to proper MAC format
                mac_clean = mac_bytes.replace(" ", "").replace(":", "")
                if len(mac_clean) == 12:
                    return ":".join([mac_clean[i:i+2] for i in range(0, 12, 2)]).upper()
            
            # Return fallback MAC address when formatting fails
            fallback_data = FallbackData(
                data="00:00:00:00:00:00",
                source="mac_address_formatting_fallback",
                confidence=0.0,
                metadata={"mac_bytes": str(mac_bytes), "reason": "MAC formatting failed"}
            )
            
            return create_partial_success_result(
                data="00:00:00:00:00:00",
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="MAC address formatting failed",
                    details=f"Failed to format MAC address from bytes: {mac_bytes}",
                    timestamp=datetime.now().isoformat()
                ),
                suggestions=[
                    "MAC address formatting failed",
                    "Check MAC address format",
                    "Use fallback MAC address",
                    "Verify SNMP data format"
                ]
            ).data
        except Exception as e:
            # Return fallback MAC address when exception occurs
            fallback_data = FallbackData(
                data="00:00:00:00:00:00",
                source="mac_address_exception_fallback",
                confidence=0.0,
                metadata={"mac_bytes": str(mac_bytes), "error": str(e)}
            )
            
            return create_partial_success_result(
                data="00:00:00:00:00:00",
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="MAC address formatting error",
                    details=f"Error formatting MAC address: {e}",
                    timestamp=datetime.now().isoformat()
                ),
                suggestions=[
                    "MAC address formatting error",
                    "Check MAC address data",
                    "Use fallback MAC address",
                    "Review error logs"
                ]
            ).data

# Global component discovery service instance
component_discovery_service = ComponentDiscoveryService()
