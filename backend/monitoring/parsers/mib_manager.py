"""
MIB Management System for proper SNMP OID handling
"""

import logging
import os
import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import hashlib

try:
    from pysmi.reader import FileReader, HttpReader
    from pysmi.searcher import AnyFileSearcher
    from pysmi.writer import PyFileWriter
    from pysmi.parser import SmiV1Parser, SmiV2Parser
    from pysmi.codegen import PySnmpCodeGen
    from pysmi.compiler import MibCompiler
    from pysmi import debug
    PYSMI_AVAILABLE = True
except ImportError:
    PYSMI_AVAILABLE = False

try:
    from pysnmp.smi import builder, view, error
    from pysnmp.smi.rfc1902 import ObjectIdentity
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

logger = logging.getLogger(__name__)

# Import result objects
from ..utils.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


@dataclass
class OIDInfo:
    """Information about an SNMP OID"""
    oid: str
    name: str
    description: str
    syntax: str
    access: str
    status: str
    module: str
    vendor: Optional[str] = None
    validated: bool = False
    last_validated: Optional[datetime] = None


@dataclass
class VendorMIBInfo:
    """Information about vendor-specific MIBs"""
    vendor: str
    enterprise_number: int
    mibs: List[str]
    download_urls: List[str]
    local_path: Optional[str] = None
    last_updated: Optional[datetime] = None


class MIBManager:
    """Manages MIB compilation and OID validation"""
    
    def __init__(self, mib_dir: Optional[str] = None):
        self.mib_dir = Path(mib_dir) if mib_dir else Path(__file__).parent / "mibs"
        self.compiled_dir = self.mib_dir / "compiled"
        self.sources_dir = self.mib_dir / "sources"
        self.cache_file = self.mib_dir / "oid_cache.json"
        
        # Create directories
        self.mib_dir.mkdir(exist_ok=True)
        self.compiled_dir.mkdir(exist_ok=True)
        self.sources_dir.mkdir(exist_ok=True)
        
        # OID cache
        self.oid_cache: Dict[str, OIDInfo] = {}
        self.vendor_mibs: Dict[str, VendorMIBInfo] = {}
        
        # MIB compiler
        self.compiler: Optional[MibCompiler] = None
        self.mib_builder: Optional[builder.MibBuilder] = None
        self.mib_view: Optional[view.MibViewController] = None
        
        # Initialize if dependencies available
        if PYSMI_AVAILABLE and PYSNMP_AVAILABLE:
            self._initialize_compiler()
        else:
            logger.warning("PySMI or PySNMP not available - MIB compilation disabled")
        
        # Load cache
        self._load_cache()
        self._setup_vendor_mibs()
    
    def _initialize_compiler(self):
        """Initialize MIB compiler"""
        try:
            # Create MIB compiler
            self.compiler = MibCompiler(
                SmiV1Parser(), SmiV2Parser(),
                PySnmpCodeGen(),
                PyFileWriter(str(self.compiled_dir))
            )
            
            # Add MIB sources
            self.compiler.addSources(
                # Local files
                FileReader(str(self.sources_dir)),
                # Standard MIBs from web
                HttpReader('https://www.iana.org/assignments/smi-numbers', 'mibs'),
                HttpReader('https://mibs.pysnmp.com/asn1', '@mib@')
            )
            
            # Add searchers for finding MIBs
            self.compiler.addSearchers(
                AnyFileSearcher(str(self.sources_dir)),
                AnyFileSearcher(str(self.compiled_dir))
            )
            
            # Initialize SNMP MIB builder
            self.mib_builder = builder.MibBuilder()
            self.mib_builder.addMibSources(
                builder.DirMibSource(str(self.compiled_dir))
            )
            
            # Load standard MIBs
            self._load_standard_mibs()
            
            logger.info("MIB compiler initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize MIB compiler: {e}")
            self.compiler = None
    
    def _load_standard_mibs(self):
        """Load standard MIBs"""
        standard_mibs = [
            'SNMPv2-SMI', 'SNMPv2-TC', 'SNMPv2-CONF', 'SNMPv2-MIB',
            'SNMP-FRAMEWORK-MIB', 'SNMP-TARGET-MIB',
            'IF-MIB', 'IP-MIB', 'TCP-MIB', 'UDP-MIB',
            'HOST-RESOURCES-MIB', 'ENTITY-MIB'
        ]
        
        for mib in standard_mibs:
            try:
                if self.compiler:
                    self.compiler.compile(mib)
                if self.mib_builder:
                    self.mib_builder.loadModules(mib)
            except Exception as e:
                logger.debug(f"Could not load standard MIB {mib}: {e}")
    
    def _setup_vendor_mibs(self):
        """Setup vendor-specific MIB information"""
        self.vendor_mibs = {
            'cisco': VendorMIBInfo(
                vendor='cisco',
                enterprise_number=9,
                mibs=[
                    'CISCO-SMI', 'CISCO-TC', 'CISCO-VTP-MIB',
                    'CISCO-MEMORY-POOL-MIB', 'CISCO-PROCESS-MIB',
                    'CISCO-ENTITY-VENDORTYPE-OID-MIB', 'CISCO-PRODUCTS-MIB'
                ],
                download_urls=[
                    'https://mibs.pysnmp.com/asn1/CISCO-SMI',
                    'https://mibs.pysnmp.com/asn1/CISCO-MEMORY-POOL-MIB',
                    'https://mibs.pysnmp.com/asn1/CISCO-PROCESS-MIB'
                ]
            ),
            'juniper': VendorMIBInfo(
                vendor='juniper',
                enterprise_number=2636,
                mibs=[
                    'JUNIPER-SMI', 'JUNIPER-MIB', 'JUNIPER-CHASSIS-DEFINES-MIB',
                    'JUNIPER-JS-SMI', 'JUNIPER-SRX5000-SPU-MONITORING-MIB'
                ],
                download_urls=[
                    'https://mibs.pysnmp.com/asn1/JUNIPER-SMI',
                    'https://mibs.pysnmp.com/asn1/JUNIPER-MIB'
                ]
            ),
            'arista': VendorMIBInfo(
                vendor='arista',
                enterprise_number=30065,
                mibs=[
                    'ARISTA-SMI-MIB', 'ARISTA-SW-IP-FORWARDING-MIB',
                    'ARISTA-ENTITY-SENSOR-MIB'
                ],
                download_urls=[
                    'https://mibs.pysnmp.com/asn1/ARISTA-SMI-MIB'
                ]
            ),
            'hp': VendorMIBInfo(
                vendor='hp',
                enterprise_number=11,
                mibs=[
                    'HP-ICF-OID', 'STATISTICS-MIB', 'HP-ICF-CHASSIS-MIB'
                ],
                download_urls=[
                    'https://mibs.pysnmp.com/asn1/HP-ICF-OID'
                ]
            )
        }
    
    def _load_cache(self):
        """Load OID cache from file"""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    
                for oid, data in cache_data.items():
                    # Convert datetime strings back to datetime objects
                    if data.get('last_validated'):
                        data['last_validated'] = datetime.fromisoformat(data['last_validated'])
                    
                    self.oid_cache[oid] = OIDInfo(**data)
                
                logger.info(f"Loaded {len(self.oid_cache)} OIDs from cache")
        except Exception as e:
            logger.error(f"Failed to load OID cache: {e}")
            self.oid_cache = {}
    
    def _save_cache(self):
        """Save OID cache to file"""
        try:
            cache_data = {}
            for oid, info in self.oid_cache.items():
                data = asdict(info)
                # Convert datetime to string
                if data.get('last_validated'):
                    data['last_validated'] = data['last_validated'].isoformat()
                cache_data[oid] = data
            
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save OID cache: {e}")
    
    async def compile_vendor_mibs(self, vendor: str) -> bool:
        """Compile MIBs for a specific vendor"""
        if not self.compiler or vendor not in self.vendor_mibs:
            return False
        
        vendor_info = self.vendor_mibs[vendor]
        success_count = 0
        
        logger.info(f"Compiling MIBs for vendor: {vendor}")
        
        for mib_name in vendor_info.mibs:
            try:
                # Try to compile the MIB
                result = self.compiler.compile(mib_name)
                
                if result:
                    success_count += 1
                    logger.debug(f"Successfully compiled MIB: {mib_name}")
                    
                    # Load into MIB builder
                    if self.mib_builder:
                        try:
                            self.mib_builder.loadModules(mib_name)
                        except Exception as e:
                            logger.warning(f"Could not load compiled MIB {mib_name}: {e}")
                else:
                    logger.warning(f"Failed to compile MIB: {mib_name}")
                    
            except Exception as e:
                logger.warning(f"Error compiling MIB {mib_name}: {e}")
        
        # Update vendor info
        if success_count > 0:
            vendor_info.last_updated = datetime.utcnow()
            logger.info(f"Successfully compiled {success_count}/{len(vendor_info.mibs)} MIBs for {vendor}")
            return True
        
        return False
    
    async def validate_oid(self, oid: str, vendor: Optional[str] = None) -> Optional[OIDInfo]:
        """Validate an OID and return its information"""
        # Check cache first
        if oid in self.oid_cache:
            cached_info = self.oid_cache[oid]
            # Check if validation is still fresh (24 hours)
            if (cached_info.last_validated and 
                datetime.utcnow() - cached_info.last_validated < timedelta(hours=24)):
                return cached_info
        
        # Try to resolve OID
        oid_info = await self._resolve_oid(oid, vendor)
        
        if oid_info:
            # Cache the result
            self.oid_cache[oid] = oid_info
            self._save_cache()
        
        return oid_info
    
    async def _resolve_oid(self, oid: str, vendor: Optional[str] = None):
        """Resolve OID information using MIB data"""
        if not self.mib_builder:
            return create_partial_success_result(
                data=None,
                error_code="MIB_BUILDER_NOT_AVAILABLE",
                message="MIB builder is not available",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="MIB builder unavailable",
                        details="MIB builder has not been initialized"
                    )
                ),
                suggestions=["Initialize MIB builder", "Load MIB files", "Check MIB configuration"]
            )
        
        try:
            # Ensure vendor MIBs are loaded
            if vendor and vendor in self.vendor_mibs:
                await self.compile_vendor_mibs(vendor)
            
            # Create MIB view
            if not self.mib_view:
                self.mib_view = view.MibViewController(self.mib_builder)
            
            # Try to resolve the OID
            try:
                oid_identity = ObjectIdentity(oid)
                oid_identity.resolveWithMib(self.mib_view)
                
                # Get MIB node information
                mib_node = self.mib_view.getNodeByOid(oid_identity.getOid())
                
                if mib_node:
                    node_name, node_desc = mib_node
                    
                    # Extract information
                    module_name = getattr(node_desc, 'moduleName', 'Unknown')
                    description = getattr(node_desc, 'description', '')
                    syntax = str(getattr(node_desc, 'syntax', 'Unknown'))
                    access = str(getattr(node_desc, 'maxAccess', 'Unknown'))
                    status = str(getattr(node_desc, 'status', 'Unknown'))
                    
                    return OIDInfo(
                        oid=oid,
                        name=str(node_name),
                        description=description,
                        syntax=syntax,
                        access=access,
                        status=status,
                        module=module_name,
                        vendor=vendor,
                        validated=True,
                        last_validated=datetime.utcnow()
                    )
                    
            except error.SmiError as e:
                logger.debug(f"Could not resolve OID {oid}: {e}")
                
        except Exception as e:
            logger.error(f"Error resolving OID {oid}: {e}")
        
        # Return basic info if resolution failed
        return OIDInfo(
            oid=oid,
            name=f"oid_{oid.replace('.', '_')}",
            description=f"Unresolved OID {oid}",
            syntax="Unknown",
            access="Unknown",
            status="Unknown",
            module="Unknown",
            vendor=vendor,
            validated=False,
            last_validated=datetime.utcnow()
        )
    
    def get_vendor_oids(self, vendor: str) -> Dict[str, str]:
        """Get validated OIDs for a specific vendor"""
        if vendor.lower() == 'cisco':
            return {
                # CPU utilization OIDs (validated Cisco OIDs)
                'cpmCPUTotal5secRev': '1.3.6.1.4.1.9.9.109.1.1.1.1.6.1',  # 5 sec avg
                'cpmCPUTotal1minRev': '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1',   # 1 min avg
                'cpmCPUTotal5minRev': '1.3.6.1.4.1.9.9.109.1.1.1.1.8.1',   # 5 min avg
                # Memory pool OIDs
                'ciscoMemoryPoolUsed': '1.3.6.1.4.1.9.9.48.1.1.1.5',
                'ciscoMemoryPoolFree': '1.3.6.1.4.1.9.9.48.1.1.1.6',
                'ciscoMemoryPoolName': '1.3.6.1.4.1.9.9.48.1.1.1.2',
                # Temperature OIDs
                'ciscoEnvMonTemperatureValue': '1.3.6.1.4.1.9.9.13.1.3.1.3',
                'ciscoEnvMonTemperatureState': '1.3.6.1.4.1.9.9.13.1.3.1.6',
            }
        
        elif vendor.lower() == 'juniper':
            return {
                # Operating table OIDs (validated Juniper OIDs)
                'jnxOperatingDescr': '1.3.6.1.4.1.2636.3.1.13.1.5',
                'jnxOperatingTemp': '1.3.6.1.4.1.2636.3.1.13.1.7',
                'jnxOperatingCPU': '1.3.6.1.4.1.2636.3.1.13.1.8',
                'jnxOperatingBuffer': '1.3.6.1.4.1.2636.3.1.13.1.11',
                'jnxOperatingMemory': '1.3.6.1.4.1.2636.3.1.13.1.15',
                # Route engine utilization
                'jnxJsSPUMonitoringCPUUsage': '1.3.6.1.4.1.2636.3.39.1.12.1.1.1.6',
                'jnxJsSPUMonitoringMemoryUsage': '1.3.6.1.4.1.2636.3.39.1.12.1.1.1.7',
            }
        
        elif vendor.lower() == 'arista':
            # Note: Arista uses standard MIBs mostly, enterprise OIDs are limited
            return {
                # Use standard HOST-RESOURCES-MIB for Arista
                'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
                'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
                'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
                # Arista-specific (these are real but limited)
                'aristaSwFwdIpStatsIPv4HostCount': '1.3.6.1.4.1.30065.3.2.1.1.1.2',
            }
        
        elif vendor.lower() in ['hp', 'aruba']:
            return {
                # HP/Aruba validated OIDs
                'hpicfSensorValue': '1.3.6.1.4.1.11.2.14.11.1.2.6.1.4',
                'hpicfSensorStatus': '1.3.6.1.4.1.11.2.14.11.1.2.6.1.5',
                # CPU and memory via HOST-RESOURCES-MIB
                'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
                'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
                'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
            }
        
        # Fallback to standard MIBs
        return {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',
            'hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
            'hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
        }
    
    async def validate_vendor_oids(self, vendor: str) -> Dict[str, bool]:
        """Validate all OIDs for a vendor"""
        vendor_oids = self.get_vendor_oids(vendor)
        validation_results = {}
        
        for name, oid in vendor_oids.items():
            oid_info = await self.validate_oid(oid, vendor)
            validation_results[name] = oid_info.validated if oid_info else False
        
        return validation_results
    
    def get_cached_oids(self, vendor: Optional[str] = None) -> List[OIDInfo]:
        """Get cached OID information"""
        if vendor:
            return [info for info in self.oid_cache.values() if info.vendor == vendor]
        return list(self.oid_cache.values())
    
    def get_stats(self) -> Dict[str, Any]:
        """Get MIB manager statistics"""
        return {
            'mib_dir': str(self.mib_dir),
            'compiled_mibs': len(list(self.compiled_dir.glob('*.py'))) if self.compiled_dir.exists() else 0,
            'cached_oids': len(self.oid_cache),
            'validated_oids': sum(1 for info in self.oid_cache.values() if info.validated),
            'vendor_mibs': list(self.vendor_mibs.keys()),
            'compiler_available': self.compiler is not None,
            'dependencies': {
                'pysmi': PYSMI_AVAILABLE,
                'pysnmp': PYSNMP_AVAILABLE
            }
        }


# Global MIB manager instance
mib_manager = MIBManager()