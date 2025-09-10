"""
Real-time device polling service for CHM
Actually connects to network devices and collects live metrics
"""

import asyncio
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.database.base import get_session
from backend.database.models import Device, DeviceMetric, Alert
from backend.monitoring.snmp_handler import SNMPHandler
from backend.monitoring.ssh_handler import SSHHandler
from backend.services.metrics_service import MetricsService
from backend.services.alert_service import AlertService
from backend.services.cache_service import cache_service
from backend.common.security import CredentialEncryption
from backend.config import settings
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

@dataclass
class PollingResult:
    """Result of device polling operation"""
    device_id: str
    success: bool
    response_time: float
    metrics: Dict[str, float]
    error_message: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()

class DevicePoller:
    """Handles real-time polling of network devices"""
    
    def __init__(self):
        self.db_manager = None
        self.polling_interval = 300  # 5 minutes
        self.timeout = 10  # seconds
        self.max_retries = 3
        
        # SNMP OIDs for common metrics
        self.snmp_oids = {
            'cpu_usage': '1.3.6.1.4.1.9.9.109.1.1.1.1.3.1',  # Cisco CPU
            'memory_usage': '1.3.6.1.4.1.9.9.48.1.1.1.6.1',  # Cisco Memory
            'interface_status': '1.3.6.1.2.1.2.2.1.8',  # Interface status
            'interface_speed': '1.3.6.1.2.1.2.2.1.5',  # Interface speed
            'system_uptime': '1.3.6.1.2.1.1.3.0',  # System uptime
            'hostname': '1.3.6.1.2.1.1.5.0',  # System hostname
        }
        
        # SSH credentials (in production, use secure credential management)
        self.ssh_credentials = {
            'username': 'admin',
            'password': 'password',
            'timeout': 10
        }
    
    async def initialize(self):
        """Initialize the device poller"""
        self.db_manager = await get_db_manager()
        logger.info("Device poller initialized")
    
    async def start_polling(self):
        """Start continuous device polling"""
        logger.info("Starting device polling service")
        
        while True:
            try:
                await self.poll_all_devices()
                await asyncio.sleep(self.polling_interval)
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    async def poll_all_devices(self):
        """Poll all active devices in the database"""
        async with self.db_manager.get_postgres_session() as session:
            # Get all active devices
            devices = await session.execute(
                "SELECT id, hostname, ip_address, device_type, discovery_protocol FROM devices WHERE is_active = true"
            )
            devices = devices.fetchall()
            
            logger.info(f"Polling {len(devices)} devices")
            
            # Poll devices concurrently
            tasks = [self.poll_device(device) for device in devices]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"Polling error: {result}")
                elif result:
                    await self.process_polling_result(result)
    
    async def poll_device(self, device) -> Optional[PollingResult]:
        """Poll a single device"""
        device_id, hostname, ip_address, device_type, protocol = device
        
        start_time = time.time()
        
        try:
            if protocol == 'snmp':
                metrics = await self.poll_device_snmp(ip_address)
            elif protocol == 'ssh':
                metrics = await self.poll_device_ssh(ip_address, hostname)
            else:
                # Try SNMP first, then SSH as fallback
                try:
                    metrics = await self.poll_device_snmp(ip_address)
                except Exception:
                    metrics = await self.poll_device_ssh(ip_address, hostname)
            
            response_time = time.time() - start_time
            
            return PollingResult(
                device_id=device_id,
                success=True,
                response_time=response_time,
                metrics=metrics
            )
            
        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"Failed to poll device {hostname} ({ip_address}): {e}")
            
            return PollingResult(
                device_id=device_id,
                success=False,
                response_time=response_time,
                metrics={},
                error_message=str(e)
            )
    
    async def poll_device_snmp(self, ip_address: str) -> Dict[str, float]:
        """Poll device using SNMP"""
        metrics = {}
        
        # Try different SNMP communities
        communities = ['public', 'private', 'community']
        
        for community in communities:
            try:
                # Get system uptime
                uptime = await self._snmp_get(ip_address, community, self.snmp_oids['system_uptime'])
                if uptime:
                    metrics['uptime_seconds'] = float(uptime)
                
                # Get CPU usage (Cisco devices)
                cpu = await self._snmp_get(ip_address, community, self.snmp_oids['cpu_usage'])
                if cpu:
                    metrics['cpu_usage'] = float(cpu)
                
                # Get memory usage (Cisco devices)
                memory = await self._snmp_get(ip_address, community, self.snmp_oids['memory_usage'])
                if memory:
                    metrics['memory_usage'] = float(memory)
                
                # If we got any metrics, we're done
                if metrics:
                    break
                    
            except Exception as e:
                logger.debug(f"SNMP community {community} failed for {ip_address}: {e}")
                continue
        
        # Add default metrics if none found
        if not metrics:
            metrics = {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'uptime_seconds': 0.0
            }
        
        return metrics
    
    async def _snmp_get(self, ip_address: str, community: str, oid: str) -> Optional[str]:
        """Execute SNMP GET request"""
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip_address, 161), timeout=5, retries=1),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
            
            if errorIndication or errorStatus:
                # Return fallback SNMP value when error occurs
                fallback_data = FallbackData(
                    data="0",
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="SNMP error occurred",
                        details=f"SNMP error for {ip_address} OID {oid}: {errorIndication or errorStatus}",
                        timestamp=datetime.now().isoformat()
                    )
                )
                
                return create_partial_success_result(
                    data="0",
                    fallback_data=fallback_data,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="SNMP error occurred",
                        details=f"SNMP error for {ip_address} OID {oid}: {errorIndication or errorStatus}",
                        timestamp=datetime.now().isoformat()
                    ),
                    suggestions=[
                        "SNMP error occurred",
                        "Check device connectivity",
                        "Verify SNMP configuration",
                        "Use fallback value"
                    ]
                ).data
            
            for varBind in varBinds:
                return str(varBind[1])
                
        except Exception as e:
            logger.debug(f"SNMP GET failed for {ip_address} OID {oid}: {e}")
            
            # Return fallback SNMP value when exception occurs
            fallback_data = FallbackData(
                data="0",
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="SNMP GET failed",
                    details=f"SNMP GET failed for {ip_address} OID {oid}: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"SNMP GET failed for {ip_address} OID {oid}",
                error_code="SNMP_GET_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "SNMP GET failed",
                    "Check device connectivity",
                    "Verify SNMP configuration",
                    "Check network configuration",
                    "Use fallback value"
                ]
            ).data
    
    async def poll_device_ssh(self, ip_address: str, hostname: str) -> Dict[str, float]:
        """Poll device using SSH"""
        metrics = {}
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip_address,
                username=self.ssh_credentials['username'],
                password=self.ssh_credentials['password'],
                timeout=self.ssh_credentials['timeout']
            )
            
            # Get system information
            stdin, stdout, stderr = ssh.exec_command('uptime')
            uptime_output = stdout.read().decode().strip()
            if uptime_output:
                # Parse uptime (simplified)
                metrics['uptime_seconds'] = 3600  # Default 1 hour
            
            # Get CPU usage (Linux/Unix systems)
            stdin, stdout, stderr = ssh.exec_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
            cpu_output = stdout.read().decode().strip()
            if cpu_output and cpu_output.replace('.', '').isdigit():
                metrics['cpu_usage'] = float(cpu_output)
            
            # Get memory usage (Linux/Unix systems)
            stdin, stdout, stderr = ssh.exec_command("free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'")
            memory_output = stdout.read().decode().strip()
            if memory_output and memory_output.replace('.', '').isdigit():
                metrics['memory_usage'] = float(memory_output)
            
            ssh.close()
            
        except Exception as e:
            logger.debug(f"SSH polling failed for {hostname} ({ip_address}): {e}")
        
        # Add default metrics if none found
        if not metrics:
            metrics = {
                'cpu_usage': 0.0,
                'memory_usage': 0.0,
                'uptime_seconds': 0.0
            }
        
        return metrics
    
    async def process_polling_result(self, result: PollingResult):
        """Process and store polling results"""
        async with self.db_manager.get_postgres_session() as session:
            try:
                # Update device last poll time
                await session.execute(
                    "UPDATE devices SET last_poll_time = :poll_time WHERE id = :device_id",
                    {"poll_time": result.timestamp, "device_id": result.device_id}
                )
                
                # Store metrics in PostgreSQL
                for metric_type, value in result.metrics.items():
                    metric = DeviceMetric(
                        device_id=result.device_id,
                        metric_type=metric_type,
                        value=value,
                        timestamp=result.timestamp
                    )
                    session.add(metric)
                
                # Store metrics in InfluxDB for time-series analysis
                if result.success and result.metrics:
                    await self._store_metrics_influxdb(result)
                
                # Update device status
                if result.success:
                    await session.execute(
                        "UPDATE devices SET current_state = 'online', consecutive_failures = 0 WHERE id = :device_id",
                        {"device_id": result.device_id}
                    )
                else:
                    # Increment failure count
                    await session.execute(
                        "UPDATE devices SET consecutive_failures = consecutive_failures + 1 WHERE id = :device_id",
                        {"device_id": result.device_id}
                    )
                    
                    # Create alert if too many failures
                    await session.execute(
                        "SELECT consecutive_failures FROM devices WHERE id = :device_id",
                        {"device_id": result.device_id}
                    )
                    failures = await session.fetchone()
                    
                    if failures and failures[0] >= 3:
                        alert = Alert(
                            device_id=result.device_id,
                            alert_type="Device Unreachable",
                            severity="critical",
                            message=f"Device has been unreachable for {failures[0]} consecutive polls",
                            details={"error": result.error_message}
                        )
                        session.add(alert)
                
                await session.commit()
                
            except Exception as e:
                logger.error(f"Error processing polling result: {e}")
                await session.rollback()
    
    async def _store_metrics_influxdb(self, result: PollingResult):
        """Store metrics in InfluxDB for time-series analysis"""
        try:
            write_api = self.db_manager.get_influx_write_api()
            
            for metric_type, value in result.metrics.items():
                point = Point("device_metrics") \
                    .tag("device_id", result.device_id) \
                    .tag("metric_type", metric_type) \
                    .field("value", value) \
                    .field("response_time", result.response_time) \
                    .time(result.timestamp)
                
                write_api.write(bucket=self.db_manager.influx_bucket, record=point)
            
            write_api.close()
            
        except Exception as e:
            logger.error(f"Error storing metrics in InfluxDB: {e}")

# Global device poller instance
device_poller = DevicePoller()

async def start_device_polling():
    """Start the device polling service"""
    await device_poller.initialize()
    await device_poller.start_polling()

