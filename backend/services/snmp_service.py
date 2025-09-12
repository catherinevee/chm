"""
SNMP Service for network device monitoring in CHM.

This module provides comprehensive SNMP functionality including:
- SNMPv1, v2c, and v3 support
- Bulk operations for efficient data collection
- MIB management and OID translation
- Trap handling and processing
- Performance optimization with connection pooling
- Error handling and retry logic
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from enum import Enum
from dataclasses import dataclass, field
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict

from pysnmp.hlapi import *
from pysnmp.smi import builder, view, compiler
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pydantic import BaseModel, Field, validator

from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from backend.common.exceptions import (
    DeviceConnectionError, SNMPError,
    TimeoutError, ValidationError
)
# Cache manager not yet implemented
cache_manager = None




class SNMPVersion(str, Enum):
    """SNMP protocol versions."""
    V1 = "1"
    V2C = "2c"
    V3 = "3"


class SNMPAuthProtocol(str, Enum):
    """SNMPv3 authentication protocols."""
    NO_AUTH = "noAuth"
    MD5 = "MD5"
    SHA = "SHA"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"


class SNMPPrivProtocol(str, Enum):
    """SNMPv3 privacy protocols."""
    NO_PRIV = "noPriv"
    DES = "DES"
    AES = "AES"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"
    DES3 = "3DES"


class OIDCategory(str, Enum):
    """Categories of SNMP OIDs."""
    SYSTEM = "system"
    INTERFACE = "interface"
    CPU = "cpu"
    MEMORY = "memory"
    DISK = "disk"
    NETWORK = "network"
    PROCESS = "process"
    TEMPERATURE = "temperature"
    POWER = "power"
    CUSTOM = "custom"


@dataclass
class SNMPCredentials:
    """SNMP connection credentials."""
    version: SNMPVersion
    community: Optional[str] = None  # For v1/v2c
    username: Optional[str] = None  # For v3
    auth_protocol: Optional[SNMPAuthProtocol] = None  # For v3
    auth_password: Optional[str] = None  # For v3
    priv_protocol: Optional[SNMPPrivProtocol] = None  # For v3
    priv_password: Optional[str] = None  # For v3
    context: Optional[str] = None  # For v3
    port: int = 161
    timeout: int = 5
    retries: int = 3


@dataclass
class OIDMapping:
    """OID to human-readable name mapping."""
    oid: str
    name: str
    category: OIDCategory
    description: Optional[str] = None
    unit: Optional[str] = None
    transform: Optional[str] = None  # Expression to transform value


class SNMPConfig(BaseModel):
    """SNMP service configuration."""
    max_connections: int = 100
    bulk_max_repetitions: int = 25
    walk_max_rows: int = 1000
    cache_ttl: int = 300
    thread_pool_size: int = 10
    trap_port: int = 162
    enable_mib_loading: bool = True
    mib_sources: List[str] = []


class SNMPResult(BaseModel):
    """Result from SNMP operation."""
    success: bool
    oid: str
    value: Optional[Any] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    response_time: Optional[float] = None


class SNMPService:
    """Service for SNMP operations."""
    
    # Common OID mappings
    STANDARD_OIDS = {
        # System OIDs
        "1.3.6.1.2.1.1.1.0": OIDMapping(
            oid="1.3.6.1.2.1.1.1.0",
            name="sysDescr",
            category=OIDCategory.SYSTEM,
            description="System description"
        ),
        "1.3.6.1.2.1.1.2.0": OIDMapping(
            oid="1.3.6.1.2.1.1.2.0",
            name="sysObjectID",
            category=OIDCategory.SYSTEM,
            description="System object identifier"
        ),
        "1.3.6.1.2.1.1.3.0": OIDMapping(
            oid="1.3.6.1.2.1.1.3.0",
            name="sysUpTime",
            category=OIDCategory.SYSTEM,
            description="System uptime",
            unit="ticks"
        ),
        "1.3.6.1.2.1.1.4.0": OIDMapping(
            oid="1.3.6.1.2.1.1.4.0",
            name="sysContact",
            category=OIDCategory.SYSTEM,
            description="System contact"
        ),
        "1.3.6.1.2.1.1.5.0": OIDMapping(
            oid="1.3.6.1.2.1.1.5.0",
            name="sysName",
            category=OIDCategory.SYSTEM,
            description="System name"
        ),
        "1.3.6.1.2.1.1.6.0": OIDMapping(
            oid="1.3.6.1.2.1.1.6.0",
            name="sysLocation",
            category=OIDCategory.SYSTEM,
            description="System location"
        ),
        
        # Interface OIDs
        "1.3.6.1.2.1.2.1.0": OIDMapping(
            oid="1.3.6.1.2.1.2.1.0",
            name="ifNumber",
            category=OIDCategory.INTERFACE,
            description="Number of interfaces"
        ),
        "1.3.6.1.2.1.2.2.1.1": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.1",
            name="ifIndex",
            category=OIDCategory.INTERFACE,
            description="Interface index"
        ),
        "1.3.6.1.2.1.2.2.1.2": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.2",
            name="ifDescr",
            category=OIDCategory.INTERFACE,
            description="Interface description"
        ),
        "1.3.6.1.2.1.2.2.1.3": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.3",
            name="ifType",
            category=OIDCategory.INTERFACE,
            description="Interface type"
        ),
        "1.3.6.1.2.1.2.2.1.5": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.5",
            name="ifSpeed",
            category=OIDCategory.INTERFACE,
            description="Interface speed",
            unit="bps"
        ),
        "1.3.6.1.2.1.2.2.1.8": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.8",
            name="ifOperStatus",
            category=OIDCategory.INTERFACE,
            description="Interface operational status"
        ),
        "1.3.6.1.2.1.2.2.1.10": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.10",
            name="ifInOctets",
            category=OIDCategory.INTERFACE,
            description="Interface input octets",
            unit="bytes"
        ),
        "1.3.6.1.2.1.2.2.1.16": OIDMapping(
            oid="1.3.6.1.2.1.2.2.1.16",
            name="ifOutOctets",
            category=OIDCategory.INTERFACE,
            description="Interface output octets",
            unit="bytes"
        ),
        
        # CPU OIDs (vendor-specific, example for Cisco)
        "1.3.6.1.4.1.9.9.109.1.1.1.1.5": OIDMapping(
            oid="1.3.6.1.4.1.9.9.109.1.1.1.1.5",
            name="cpmCPUTotal5min",
            category=OIDCategory.CPU,
            description="CPU utilization (5 min average)",
            unit="percent"
        ),
        
        # Memory OIDs
        "1.3.6.1.4.1.9.9.48.1.1.1.5": OIDMapping(
            oid="1.3.6.1.4.1.9.9.48.1.1.1.5",
            name="ciscoMemoryPoolUsed",
            category=OIDCategory.MEMORY,
            description="Memory pool used",
            unit="bytes"
        ),
        "1.3.6.1.4.1.9.9.48.1.1.1.6": OIDMapping(
            oid="1.3.6.1.4.1.9.9.48.1.1.1.6",
            name="ciscoMemoryPoolFree",
            category=OIDCategory.MEMORY,
            description="Memory pool free",
            unit="bytes"
        )
    }
    
    def __init__(self, config: Optional[SNMPConfig] = None):
        """Initialize SNMP service."""
        self.config = config or SNMPConfig()
        self.connection_pool: Dict[str, Any] = {}
        self.oid_cache: Dict[str, SNMPResult] = {}
        self.custom_oids: Dict[str, OIDMapping] = {}
        self._executor = ThreadPoolExecutor(max_workers=self.config.thread_pool_size)
        self._trap_receiver = None
        self._initialize_mib_builder()
    
    def _initialize_mib_builder(self):
        """Initialize MIB builder for OID translation."""
        if not self.config.enable_mib_loading:
            return
        
        try:
            self.mib_builder = builder.MibBuilder()
            self.mib_view = view.MibViewController(self.mib_builder)
            
            # Add MIB sources
            for source in self.config.mib_sources:
                self.mib_builder.addMibSources(
                    builder.DirMibSource(source)
                )
            
            # Load common MIBs
            self.mib_builder.loadModules(
                'SNMPv2-MIB', 'IF-MIB', 'IP-MIB', 'TCP-MIB', 'UDP-MIB'
            )
            
            logger.info("MIB builder initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize MIB builder: {e}")
            self.mib_builder = None
            self.mib_view = None
    
    async def get(
        self,
        host: str,
        oid: str,
        credentials: SNMPCredentials
    ) -> SNMPResult:
        """Perform SNMP GET operation."""
        start_time = time.time()
        
        try:
            # Check cache
            cache_key = f"{host}:{oid}"
            if cache_key in self.oid_cache:
                cached = self.oid_cache[cache_key]
                if (datetime.utcnow() - cached.timestamp).seconds < self.config.cache_ttl:
                    return cached
            
            # Build SNMP command
            auth_data = self._build_auth_data(credentials)
            transport = await self._get_transport(host, credentials.port)
            
            # Perform SNMP GET
            error_indication, error_status, error_index, var_binds = await getCmd(
                SnmpEngine(),
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            response_time = time.time() - start_time
            
            if error_indication:
                return SNMPResult(
                    success=False,
                    oid=oid,
                    error=str(error_indication),
                    response_time=response_time
                )
            
            if error_status:
                return SNMPResult(
                    success=False,
                    oid=oid,
                    error=f"SNMP error: {error_status.prettyPrint()}",
                    response_time=response_time
                )
            
            # Extract value
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value = self._process_value(var_bind[1])
                
                result = SNMPResult(
                    success=True,
                    oid=oid_str,
                    value=value,
                    response_time=response_time
                )
                
                # Cache result
                self.oid_cache[cache_key] = result
                
                return result
            
            return SNMPResult(
                success=False,
                oid=oid,
                error="No data returned",
                response_time=response_time
            )
            
        except Exception as e:
            logger.error(f"SNMP GET failed for {host}:{oid} - {e}")
            return SNMPResult(
                success=False,
                oid=oid,
                error=str(e),
                response_time=time.time() - start_time
            )
    
    async def get_bulk(
        self,
        host: str,
        oids: List[str],
        credentials: SNMPCredentials
    ) -> List[SNMPResult]:
        """Perform SNMP GET BULK operation."""
        if credentials.version == SNMPVersion.V1:
            # Fallback to regular GET for SNMPv1
            results = []
            for oid in oids:
                result = await self.get(host, oid, credentials)
                results.append(result)
            return results
        
        start_time = time.time()
        results = []
        
        try:
            auth_data = self._build_auth_data(credentials)
            transport = await self._get_transport(host, credentials.port)
            
            # Prepare OID objects
            oid_objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]
            
            # Perform SNMP BULK GET
            error_indication, error_status, error_index, var_binds = await bulkCmd(
                SnmpEngine(),
                auth_data,
                transport,
                ContextData(),
                0,  # non-repeaters
                self.config.bulk_max_repetitions,  # max-repetitions
                *oid_objects
            )
            
            response_time = time.time() - start_time
            
            if error_indication:
                for oid in oids:
                    results.append(SNMPResult(
                        success=False,
                        oid=oid,
                        error=str(error_indication),
                        response_time=response_time
                    ))
                return results
            
            # Process results
            for var_bind in var_binds:
                oid_str = str(var_bind[0])
                value = self._process_value(var_bind[1])
                
                results.append(SNMPResult(
                    success=True,
                    oid=oid_str,
                    value=value,
                    response_time=response_time
                ))
            
            return results
            
        except Exception as e:
            logger.error(f"SNMP BULK GET failed for {host} - {e}")
            for oid in oids:
                results.append(SNMPResult(
                    success=False,
                    oid=oid,
                    error=str(e),
                    response_time=time.time() - start_time
                ))
            return results
    
    async def walk(
        self,
        host: str,
        base_oid: str,
        credentials: SNMPCredentials,
        max_rows: Optional[int] = None
    ) -> List[SNMPResult]:
        """Perform SNMP WALK operation."""
        start_time = time.time()
        results = []
        max_rows = max_rows or self.config.walk_max_rows
        
        try:
            auth_data = self._build_auth_data(credentials)
            transport = await self._get_transport(host, credentials.port)
            
            # Perform SNMP WALK
            if credentials.version == SNMPVersion.V1:
                cmd_gen = nextCmd
            else:
                cmd_gen = bulkCmd
            
            row_count = 0
            for error_indication, error_status, error_index, var_binds in cmd_gen(
                SnmpEngine(),
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(base_oid)),
                lexicographicMode=False
            ):
                if error_indication:
                    logger.error(f"SNMP WALK error: {error_indication}")
                    break
                
                if error_status:
                    logger.error(f"SNMP WALK status: {error_status.prettyPrint()}")
                    break
                
                for var_bind in var_binds:
                    oid_str = str(var_bind[0])
                    
                    # Check if we're still within the base OID tree
                    if not oid_str.startswith(base_oid):
                        return results
                    
                    value = self._process_value(var_bind[1])
                    
                    results.append(SNMPResult(
                        success=True,
                        oid=oid_str,
                        value=value,
                        response_time=time.time() - start_time
                    ))
                    
                    row_count += 1
                    if row_count >= max_rows:
                        return results
            
            return results
            
        except Exception as e:
            logger.error(f"SNMP WALK failed for {host}:{base_oid} - {e}")
            return results
    
    async def set(
        self,
        host: str,
        oid: str,
        value: Any,
        value_type: str,
        credentials: SNMPCredentials
    ) -> SNMPResult:
        """Perform SNMP SET operation."""
        start_time = time.time()
        
        try:
            auth_data = self._build_auth_data(credentials)
            transport = await self._get_transport(host, credentials.port)
            
            # Convert value to appropriate SNMP type
            snmp_value = self._convert_to_snmp_type(value, value_type)
            
            # Perform SNMP SET
            error_indication, error_status, error_index, var_binds = await setCmd(
                SnmpEngine(),
                auth_data,
                transport,
                ContextData(),
                ObjectType(ObjectIdentity(oid), snmp_value)
            )
            
            response_time = time.time() - start_time
            
            if error_indication:
                return SNMPResult(
                    success=False,
                    oid=oid,
                    error=str(error_indication),
                    response_time=response_time
                )
            
            if error_status:
                return SNMPResult(
                    success=False,
                    oid=oid,
                    error=f"SNMP error: {error_status.prettyPrint()}",
                    response_time=response_time
                )
            
            return SNMPResult(
                success=True,
                oid=oid,
                value=value,
                response_time=response_time
            )
            
        except Exception as e:
            logger.error(f"SNMP SET failed for {host}:{oid} - {e}")
            return SNMPResult(
                success=False,
                oid=oid,
                error=str(e),
                response_time=time.time() - start_time
            )
    
    async def get_system_info(
        self,
        host: str,
        credentials: SNMPCredentials
    ) -> Dict[str, Any]:
        """Get basic system information via SNMP."""
        system_oids = [
            "1.3.6.1.2.1.1.1.0",  # sysDescr
            "1.3.6.1.2.1.1.2.0",  # sysObjectID
            "1.3.6.1.2.1.1.3.0",  # sysUpTime
            "1.3.6.1.2.1.1.4.0",  # sysContact
            "1.3.6.1.2.1.1.5.0",  # sysName
            "1.3.6.1.2.1.1.6.0",  # sysLocation
        ]
        
        results = await self.get_bulk(host, system_oids, credentials)
        
        system_info = {}
        for result in results:
            if result.success:
                oid_mapping = self.STANDARD_OIDS.get(result.oid)
                if oid_mapping:
                    system_info[oid_mapping.name] = result.value
                else:
                    system_info[result.oid] = result.value
        
        # Convert uptime from ticks to human-readable format
        if "sysUpTime" in system_info:
            ticks = int(system_info["sysUpTime"])
            system_info["uptimeSeconds"] = ticks / 100
            system_info["uptimeFormatted"] = self._format_uptime(ticks)
        
        return system_info
    
    async def get_interface_stats(
        self,
        host: str,
        credentials: SNMPCredentials
    ) -> List[Dict[str, Any]]:
        """Get interface statistics via SNMP."""
        interfaces = []
        
        # Walk interface table
        if_index_results = await self.walk(host, "1.3.6.1.2.1.2.2.1.1", credentials)
        
        for index_result in if_index_results:
            if not index_result.success:
                continue
            
            # Extract interface index from OID
            if_index = index_result.oid.split(".")[-1]
            
            # Get interface details
            interface_oids = [
                f"1.3.6.1.2.1.2.2.1.2.{if_index}",   # ifDescr
                f"1.3.6.1.2.1.2.2.1.3.{if_index}",   # ifType
                f"1.3.6.1.2.1.2.2.1.5.{if_index}",   # ifSpeed
                f"1.3.6.1.2.1.2.2.1.8.{if_index}",   # ifOperStatus
                f"1.3.6.1.2.1.2.2.1.10.{if_index}",  # ifInOctets
                f"1.3.6.1.2.1.2.2.1.16.{if_index}",  # ifOutOctets
                f"1.3.6.1.2.1.2.2.1.13.{if_index}",  # ifInDiscards
                f"1.3.6.1.2.1.2.2.1.14.{if_index}",  # ifInErrors
                f"1.3.6.1.2.1.2.2.1.19.{if_index}",  # ifOutDiscards
                f"1.3.6.1.2.1.2.2.1.20.{if_index}",  # ifOutErrors
            ]
            
            results = await self.get_bulk(host, interface_oids, credentials)
            
            interface_data = {"index": if_index}
            for result in results:
                if result.success:
                    # Map OID to field name
                    oid_base = ".".join(result.oid.split(".")[:-1])
                    if oid_base == "1.3.6.1.2.1.2.2.1.2":
                        interface_data["description"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.3":
                        interface_data["type"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.5":
                        interface_data["speed"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.8":
                        interface_data["operStatus"] = self._decode_oper_status(result.value)
                    elif oid_base == "1.3.6.1.2.1.2.2.1.10":
                        interface_data["inOctets"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.16":
                        interface_data["outOctets"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.13":
                        interface_data["inDiscards"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.14":
                        interface_data["inErrors"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.19":
                        interface_data["outDiscards"] = result.value
                    elif oid_base == "1.3.6.1.2.1.2.2.1.20":
                        interface_data["outErrors"] = result.value
            
            interfaces.append(interface_data)
        
        return interfaces
    
    async def monitor_oids(
        self,
        host: str,
        oids: List[str],
        credentials: SNMPCredentials,
        interval: int = 60,
        callback: Optional[callable] = None
    ) -> asyncio.Task:
        """Monitor OIDs continuously."""
        async def monitor_loop():
            while True:
                try:
                    results = await self.get_bulk(host, oids, credentials)
                    
                    if callback:
                        await callback(host, results)
                    
                    await asyncio.sleep(interval)
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Monitoring error for {host}: {e}")
                    await asyncio.sleep(interval)
        
        task = asyncio.create_task(monitor_loop())
        return task
    
    def add_custom_oid(
        self,
        oid: str,
        name: str,
        category: OIDCategory,
        description: Optional[str] = None,
        unit: Optional[str] = None,
        transform: Optional[str] = None
    ):
        """Add custom OID mapping."""
        self.custom_oids[oid] = OIDMapping(
            oid=oid,
            name=name,
            category=category,
            description=description,
            unit=unit,
            transform=transform
        )
    
    def start_trap_receiver(
        self,
        port: int = 162,
        callback: Optional[callable] = None
    ):
        """Start SNMP trap receiver."""
        def trap_handler(snmp_engine, state_reference, context_engine_id,
                        context_name, var_binds, cb_ctx):
            try:
                trap_data = {
                    "timestamp": datetime.utcnow(),
                    "source": None,
                    "oids": []
                }
                
                # Extract trap source
                transport_domain, transport_address = snmp_engine.msgAndPduDsp.getTransportInfo(state_reference)
                trap_data["source"] = f"{transport_address[0]}:{transport_address[1]}"
                
                # Extract OIDs and values
                for oid, value in var_binds:
                    trap_data["oids"].append({
                        "oid": str(oid),
                        "value": self._process_value(value)
                    })
                
                if callback:
                    callback(trap_data)
                
                logger.info(f"Received trap from {trap_data['source']}")
                
            except Exception as e:
                logger.error(f"Trap handler error: {e}")
        
        try:
            # Create SNMP engine
            snmp_engine = engine.SnmpEngine()
            
            # Configure transport
            config.addTransport(
                snmp_engine,
                udp.domainName,
                udp.UdpTransport().openServerMode(("0.0.0.0", port))
            )
            
            # Configure SNMPv1/v2c community
            config.addV1System(snmp_engine, "public", "public")
            
            # Register trap handler
            ntfrcv.NotificationReceiver(snmp_engine, trap_handler)
            
            # Start dispatcher
            snmp_engine.transportDispatcher.jobStarted(1)
            
            def run_dispatcher():
                try:
                    snmp_engine.transportDispatcher.runDispatcher()
                except Exception as e:

                    logger.debug(f"Exception: {e}")
                    snmp_engine.transportDispatcher.closeDispatcher()
                    raise
            
            # Run in separate thread
            trap_thread = threading.Thread(target=run_dispatcher)
            trap_thread.daemon = True
            trap_thread.start()
            
            self._trap_receiver = snmp_engine
            logger.info(f"SNMP trap receiver started on port {port}")
            
        except Exception as e:
            logger.error(f"Failed to start trap receiver: {e}")
    
    def stop_trap_receiver(self):
        """Stop SNMP trap receiver."""
        if self._trap_receiver:
            self._trap_receiver.transportDispatcher.jobFinished(1)
            self._trap_receiver = None
            logger.info("SNMP trap receiver stopped")
    
    # Private helper methods
    
    def _build_auth_data(self, credentials: SNMPCredentials):
        """Build authentication data for SNMP."""
        if credentials.version in [SNMPVersion.V1, SNMPVersion.V2C]:
            return CommunityData(credentials.community or "public")
        
        elif credentials.version == SNMPVersion.V3:
            auth_protocol = self._get_auth_protocol(credentials.auth_protocol)
            priv_protocol = self._get_priv_protocol(credentials.priv_protocol)
            
            return UsmUserData(
                credentials.username,
                authKey=credentials.auth_password if auth_protocol else None,
                privKey=credentials.priv_password if priv_protocol else None,
                authProtocol=auth_protocol,
                privProtocol=priv_protocol
            )
        
        else:
            raise ValueError(f"Unsupported SNMP version: {credentials.version}")
    
    def _get_auth_protocol(self, protocol: Optional[SNMPAuthProtocol]):
        """Get pysnmp auth protocol object."""
        if not protocol or protocol == SNMPAuthProtocol.NO_AUTH:
            return None
        
        protocol_map = {
            SNMPAuthProtocol.MD5: usmHMACMD5AuthProtocol,
            SNMPAuthProtocol.SHA: usmHMACSHAAuthProtocol,
            # Add more as needed
        }
        
        return protocol_map.get(protocol)
    
    def _get_priv_protocol(self, protocol: Optional[SNMPPrivProtocol]):
        """Get pysnmp privacy protocol object."""
        if not protocol or protocol == SNMPPrivProtocol.NO_PRIV:
            return None
        
        protocol_map = {
            SNMPPrivProtocol.DES: usmDESPrivProtocol,
            SNMPPrivProtocol.AES: usmAesCfb128Protocol,
            # Add more as needed
        }
        
        return protocol_map.get(protocol)
    
    async def _get_transport(self, host: str, port: int):
        """Get SNMP transport."""
        return UdpTransportTarget((host, port))
    
    def _process_value(self, value):
        """Process SNMP value to Python type."""
        if isinstance(value, OctetString):
            return str(value)
        elif isinstance(value, Integer):
            return int(value)
        elif isinstance(value, ObjectIdentifier):
            return str(value)
        elif isinstance(value, IpAddress):
            return str(value)
        elif isinstance(value, Counter32):
            return int(value)
        elif isinstance(value, Counter64):
            return int(value)
        elif isinstance(value, Gauge32):
            return int(value)
        elif isinstance(value, TimeTicks):
            return int(value)
        else:
            return str(value)
    
    def _convert_to_snmp_type(self, value: Any, value_type: str):
        """Convert Python value to SNMP type."""
        if value_type == "integer":
            return Integer(value)
        elif value_type == "string":
            return OctetString(value)
        elif value_type == "oid":
            return ObjectIdentifier(value)
        elif value_type == "ipaddress":
            return IpAddress(value)
        elif value_type == "counter32":
            return Counter32(value)
        elif value_type == "counter64":
            return Counter64(value)
        elif value_type == "gauge32":
            return Gauge32(value)
        elif value_type == "timeticks":
            return TimeTicks(value)
        else:
            return OctetString(str(value))
    
    def _format_uptime(self, ticks: int) -> str:
        """Format uptime from ticks to human-readable."""
        seconds = ticks / 100
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        minutes = int((seconds % 3600) // 60)
        secs = int(seconds % 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if secs > 0 or not parts:
            parts.append(f"{secs}s")
        
        return " ".join(parts)
    
    def _decode_oper_status(self, status: int) -> str:
        """Decode interface operational status."""
        status_map = {
            1: "up",
            2: "down",
            3: "testing",
            4: "unknown",
            5: "dormant",
            6: "notPresent",
            7: "lowerLayerDown"
        }
        return status_map.get(status, "unknown")


# Create singleton instance
snmp_service = SNMPService()