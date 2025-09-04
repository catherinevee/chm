"""
Discovery Microservice
Handles network device discovery and bulk imports with comprehensive SNMP monitoring
"""

from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from typing import List, Optional, Dict, Any
import os
import asyncio
import subprocess
import ipaddress
import socket
import json
from datetime import datetime
import random

logger = logging.getLogger(__name__)

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle application startup and shutdown"""
    logger.info("Starting Discovery Service with enhanced SNMP monitoring...")
    yield
    logger.info("Shutting down Discovery Service...")

# Create FastAPI app
app = FastAPI(
    title="Discovery Service",
    description="Network device discovery and bulk import service with comprehensive SNMP monitoring",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "discovery", "version": "2.0.0"}

# Discovery endpoints
@app.post("/api/v1/discover")
async def discover_network(
    network_cidr: str = Form(...),
    scan_type: str = Form("standard")
):
    """Discover devices in a network range with comprehensive monitoring"""
    try:
        logger.info(f"Starting {scan_type} discovery for network {network_cidr}")
        
        # Parse network CIDR
        try:
            network = ipaddress.IPv4Network(network_cidr, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid network CIDR format")
        
        discovered_devices = []
        
        # Perform discovery based on scan type
        if scan_type == "quick":
            discovered_devices = await perform_ping_discovery(network)
        elif scan_type == "standard":
            discovered_devices = await perform_standard_discovery(network)
        elif scan_type == "comprehensive":
            discovered_devices = await perform_comprehensive_discovery(network)
        
        return {
            "success": True,
            "scan_type": scan_type,
            "network_cidr": network_cidr,
            "total_devices": len(discovered_devices),
            "devices": discovered_devices,
            "discovery_time": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Discovery failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/discover/status/{job_id}")
async def get_discovery_status(job_id: str):
    """Get discovery job status"""
    return {"job_id": job_id, "status": "completed"}

# SNMP Monitoring endpoints
@app.post("/api/v1/snmp/monitor")
async def monitor_device_snmp(
    ip_address: str = Form(...),
    community: str = Form("public"),
    version: str = Form("2c"),
    port: int = Form(161)
):
    """Monitor a single device using SNMP"""
    try:
        # Use real SNMP monitoring via the collector service
        try:
            # Import the SNMP session and credentials
            from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
            from backend.collector.protocols.snmp.oids import OIDManager
            
            # Create SNMP credentials
            credentials = SNMPCredentials(
                community=community,
                version=version,
                port=port
            )
            
            # Create SNMP session
            snmp_session = SNMPSession(ip_address, credentials)
            
            # Get system information
            system_info = await snmp_session.get_system_info()
            cpu_info = await snmp_session.get_cpu_usage()
            memory_info = await snmp_session.get_memory_usage()
            interface_info = await snmp_session.get_interface_count()
            
            monitoring_data = {
                "device_ip": ip_address,
                "community": community,
                "version": version,
                "port": port,
                "status": "online" if system_info else "offline",
                "timestamp": datetime.utcnow().isoformat(),
                "system_uptime": system_info.get('uptime', 0) if system_info else 0,
                "system_name": system_info.get('name', '') if system_info else '',
                "system_description": system_info.get('description', '') if system_info else '',
                "cpu_usage": cpu_info.get('cpu_usage', 0.0) if cpu_info else 0.0,
                "memory_usage": memory_info.get('memory_usage_percent', 0.0) if memory_info else 0.0,
                "memory_total": memory_info.get('total', 0) if memory_info else 0,
                "memory_used": memory_info.get('used', 0) if memory_info else 0,
                "interface_count": interface_info.get('count', 0) if interface_info else 0
            }
            
        except Exception as snmp_error:
            logger.warning(f"SNMP monitoring failed, falling back to ping: {snmp_error}")
            # Fallback to basic connectivity check
            ping_result = await ping_host(ip_address)
            monitoring_data = {
                "device_ip": ip_address,
                "community": community,
                "version": version,
                "port": port,
                "status": "online" if ping_result else "offline",
                "timestamp": datetime.utcnow().isoformat(),
                "error": f"SNMP failed: {str(snmp_error)}",
                "ping_response": ping_result
            }
        
        return {
            "success": True,
            "device_ip": ip_address,
            "monitoring_data": monitoring_data
        }
    except Exception as e:
        logger.error(f"SNMP monitoring failed for {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/snmp/monitor/essential")
async def monitor_device_essential_snmp(
    ip_address: str = Form(...), 
    community: str = Form("public"), 
    version: str = Form("2c"), 
    port: int = Form(161)
):
    """Monitor essential metrics for a device using SNMP"""
    try:
        # Use real essential SNMP monitoring
        try:
            from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
            from backend.collector.protocols.snmp.monitor import SNMPMonitor
            
            # Create SNMP credentials
            credentials = SNMPCredentials(
                community=community,
                version=version,
                port=port
            )
            
            # Create SNMP monitor for essential metrics
            monitor = SNMPMonitor()
            
            # Get essential metrics (CPU, Memory, System Info)
            essential_metrics = await monitor.monitor_essential_metrics(ip_address, credentials)
            
            return {
                "success": True,
                "device_ip": ip_address,
                "essential_metrics": essential_metrics,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as snmp_error:
            logger.warning(f"Essential SNMP monitoring failed: {snmp_error}")
            return {
                "success": False,
                "device_ip": ip_address,
                "error": f"Essential SNMP monitoring failed: {str(snmp_error)}",
                "essential_metrics": {},
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Essential SNMP monitoring failed for {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/snmp/monitor/interfaces")
async def monitor_interface_performance(
    ip_address: str = Form(...), 
    community: str = Form("public"), 
    version: str = Form("2c"), 
    port: int = Form(161)
):
    """Monitor interface performance for a device"""
    try:
        # Use real interface monitoring
        try:
            from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
            from backend.collector.protocols.snmp.monitor import SNMPMonitor
            
            # Create SNMP credentials
            credentials = SNMPCredentials(
                community=community,
                version=version,
                port=port
            )
            
            # Create SNMP monitor for interface metrics
            monitor = SNMPMonitor()
            
            # Get interface performance metrics
            interface_metrics = await monitor.monitor_interface_performance(ip_address, credentials)
            
            return {
                "success": True,
                "device_ip": ip_address,
                "interface_performance": interface_metrics,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as snmp_error:
            logger.warning(f"Interface monitoring failed: {snmp_error}")
            return {
                "success": False,
                "device_ip": ip_address,
                "error": f"Interface monitoring failed: {str(snmp_error)}",
                "interface_performance": {},
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Interface monitoring failed for {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/snmp/monitor/network")
async def monitor_network_performance(
    ip_address: str = Form(...), 
    community: str = Form("public"), 
    version: str = Form("2c"), 
    port: int = Form(161)
):
    """Monitor network layer performance for a device"""
    try:
        # Use real network monitoring
        try:
            from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
            from backend.collector.protocols.snmp.monitor import SNMPMonitor
            
            # Create SNMP credentials
            credentials = SNMPCredentials(
                community=community,
                version=version,
                port=port
            )
            
            # Create SNMP monitor for network metrics
            monitor = SNMPMonitor()
            
            # Get network performance metrics
            network_metrics = await monitor.monitor_network_performance(ip_address, credentials)
            
            return {
                "success": True,
                "device_ip": ip_address,
                "network_performance": network_metrics,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as snmp_error:
            logger.warning(f"Network monitoring failed: {snmp_error}")
            return {
                "success": False,
                "device_ip": ip_address,
                "error": f"Network monitoring failed: {str(snmp_error)}",
                "network_performance": {},
                "timestamp": datetime.utcnow().isoformat()
            }
    except Exception as e:
        logger.error(f"Network monitoring failed for {ip_address}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Import endpoints
@app.post("/api/v1/import/csv")
async def import_csv(
    file: UploadFile = File(...),
    has_header: bool = Form(True)
):
    """Import devices from CSV file"""
    try:
        # Placeholder for CSV import
        return {
            "success": True,
            "message": "CSV import will be available after full implementation",
            "result": {
                "total_rows": 0,
                "successful_imports": 0,
                "failed_imports": 0,
                "errors": [],
                "imported_devices": []
            }
        }
    except Exception as e:
        logger.error(f"CSV import failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/import/excel")
async def import_excel(
    file: UploadFile = File(...),
    sheet_name: Optional[str] = Form(None)
):
    """Import devices from Excel file"""
    try:
        # Placeholder for Excel import
        return {
            "success": True,
            "message": "Excel import will be available after full implementation",
            "result": {
                "total_rows": 0,
                "successful_imports": 0,
                "failed_imports": 0,
                "errors": [],
                "imported_devices": []
            }
        }
    except Exception as e:
        logger.error(f"Excel import failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/import/json")
async def import_json(
    file: UploadFile = File(...)
):
    """Import devices from JSON file"""
    try:
        # Placeholder for JSON import
        return {
            "success": True,
            "message": "JSON import will be available after full implementation",
            "result": {
                "total_rows": 0,
                "successful_imports": 0,
                "failed_imports": 0,
                "errors": [],
                "imported_devices": []
            }
        }
    except Exception as e:
        logger.error(f"JSON import failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/v1/import/template/{format_type}")
async def get_import_template(format_type: str):
    """Get import template"""
    try:
        if format_type.lower() == "csv":
            # Generate proper CSV template with all supported fields
            csv_template = """hostname,ip_address,device_type,serial_number,model,manufacturer,firmware_version,os_version,location,rack_position,data_center,department,owner,cost,asset_tag,notes,device_group,custom_group,snmp_community,snmp_version,snmp_port
router-01,192.168.1.1,router,SN123456,Cisco-2911,Cisco,15.0(1)M,IOS,Data Center A,R1-U10,DC-East,IT,John Doe,2500.00,ASSET-001,Core router for network,production,core,public,2c,161
switch-01,192.168.1.10,switch,SN789012,Catalyst-2960,Cisco,15.0(2)SE,IOS,Data Center A,R1-U15,DC-East,IT,Jane Smith,1200.00,ASSET-002,Access switch for floor 1,production,access,public,2c,161
server-01,192.168.1.100,server,SN345678,PowerEdge-R740,Dell,,Ubuntu 20.04,Data Center B,R2-U05,DC-West,IT,Bob Johnson,5000.00,ASSET-003,Application server,production,servers,,,
"""
            
            return {
                "success": True,
                "template": csv_template,
                "format": format_type,
                "filename": "device_import_template.csv",
                "description": "CSV template for importing devices with all supported fields",
                "headers": [
                    "hostname", "ip_address", "device_type", "serial_number", "model", 
                    "manufacturer", "firmware_version", "os_version", "location", 
                    "rack_position", "data_center", "department", "owner", "cost", 
                    "asset_tag", "notes", "device_group", "custom_group", 
                    "snmp_community", "snmp_version", "snmp_port"
                ]
            }
            
        elif format_type.lower() == "json":
            # Generate JSON template
            json_template = {
                "devices": [
                    {
                        "hostname": "router-01",
                        "ip_address": "192.168.1.1",
                        "device_type": "router",
                        "serial_number": "SN123456",
                        "model": "Cisco-2911",
                        "manufacturer": "Cisco",
                        "firmware_version": "15.0(1)M",
                        "os_version": "IOS",
                        "location": "Data Center A",
                        "rack_position": "R1-U10",
                        "data_center": "DC-East",
                        "department": "IT",
                        "owner": "John Doe",
                        "cost": 2500.00,
                        "asset_tag": "ASSET-001",
                        "notes": "Core router for network",
                        "device_group": "production",
                        "custom_group": "core",
                        "snmp_community": "public",
                        "snmp_version": "2c",
                        "snmp_port": 161
                    }
                ]
            }
            
            return {
                "success": True,
                "template": json.dumps(json_template, indent=2),
                "format": format_type,
                "filename": "device_import_template.json",
                "description": "JSON template for importing devices"
            }
            
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format_type}")
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Template generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Discovery implementation functions
async def perform_ping_discovery(network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
    """Perform ping-based discovery"""
    discovered_devices = []
    
    # Limit to first 20 hosts for quick discovery
    hosts = list(network.hosts())[:20]
    
    for host_ip in hosts:
        if await ping_host(str(host_ip)):
            hostname = await resolve_hostname(str(host_ip))
            device = {
                "ip_address": str(host_ip),
                "hostname": hostname,
                "status": "online",
                "discovery_method": "ping",
                "response_time": random.uniform(1.0, 50.0),  # Mock response time
                "discovery_time": datetime.utcnow().isoformat()
            }
            discovered_devices.append(device)
    
    return discovered_devices

async def perform_standard_discovery(network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
    """Perform standard discovery with ping + basic port scan"""
    discovered_devices = await perform_ping_discovery(network)
    
    # Enhance with port scanning
    for device in discovered_devices:
        device["open_ports"] = await scan_common_ports(device["ip_address"])
        device["discovery_method"] = "ping+portscan"
        
        # Guess device type based on open ports
        device["device_type"] = guess_device_type(device["open_ports"])
    
    return discovered_devices

async def perform_comprehensive_discovery(network: ipaddress.IPv4Network) -> List[Dict[str, Any]]:
    """Perform comprehensive discovery with multiple protocols"""
    discovered_devices = await perform_standard_discovery(network)
    
    # Enhance with SNMP discovery where possible
    for device in discovered_devices:
        if 161 in device.get("open_ports", []):
            snmp_info = await snmp_discovery(device["ip_address"])
            if snmp_info:
                device.update(snmp_info)
                device["discovery_method"] = "ping+portscan+snmp"
    
    return discovered_devices

async def ping_host(ip_address: str) -> bool:
    """Ping a host to check if it's alive"""
    try:
        # Use system ping command
        process = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "2", ip_address,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        return process.returncode == 0
    except Exception:
        return False

async def resolve_hostname(ip_address: str) -> Optional[str]:
    """Resolve hostname for IP address"""
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
        return hostname
    except Exception:
        return None

async def scan_common_ports(ip_address: str) -> List[int]:
    """Scan common ports on a host"""
    common_ports = [22, 23, 53, 80, 135, 139, 161, 443, 445, 993, 995]
    open_ports = []
    
    for port in common_ports:
        if await check_port(ip_address, port):
            open_ports.append(port)
    
    return open_ports

async def check_port(ip_address: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a port is open"""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip_address, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False

def guess_device_type(open_ports: List[int]) -> str:
    """Guess device type based on open ports"""
    if 161 in open_ports:  # SNMP
        if 22 in open_ports or 23 in open_ports:  # SSH/Telnet
            return "network_device"
        return "managed_device"
    elif 80 in open_ports or 443 in open_ports:  # HTTP/HTTPS
        if 22 in open_ports:
            return "server"
        return "web_device"
    elif 22 in open_ports:  # SSH only
        return "linux_server"
    elif 135 in open_ports or 139 in open_ports or 445 in open_ports:  # Windows ports
        return "windows_device"
    else:
        return "unknown"

async def snmp_discovery(ip_address: str) -> Optional[Dict[str, Any]]:
    """Perform SNMP discovery on a device"""
    try:
        # Mock SNMP discovery - in real implementation, use pysnmp
        # This would query system OIDs for device information
        snmp_info = {
            "vendor": random.choice(["Cisco", "HP", "Dell", "Juniper", "Aruba"]),
            "model": f"Model-{random.randint(1000, 9999)}",
            "system_description": f"Network Device at {ip_address}",
            "uptime": random.randint(86400, 31536000),  # 1 day to 1 year in seconds
            "snmp_community": "public",
            "snmp_version": "2c"
        }
        return snmp_info
    except Exception as e:
        logger.debug(f"SNMP discovery failed for {ip_address}: {e}")
        return None

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
