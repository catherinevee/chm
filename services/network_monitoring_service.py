"""
CHM Network Monitoring Service
Core service for real-time network device monitoring with SNMP/SSH capabilities
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import time
import json

# SNMP imports
try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity, nextCmd
    )
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    logging.warning("PySNMP not available - SNMP functionality disabled")

# SSH imports
try:
    import asyncssh
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False
    logging.warning("AsyncSSH not available - SSH functionality disabled")

from core.database import get_db
from models.device import Device, DeviceStatus, DeviceProtocol
from models.device_credentials import DeviceCredentials, CredentialType
from models.metric import Metric, MetricType, MetricCategory
from models.alert import Alert, AlertSeverity, AlertStatus, AlertCategory
from models.result_objects import (
    DeviceStatusResult, MetricsCollectionResult, OperationStatus
)
from services.credential_manager import credential_manager
from services.notification_service import notification_service

logger = logging.getLogger(__name__)

@dataclass
class MonitoringConfig:
    """Configuration for network monitoring"""
    default_poll_interval: int = 300  # 5 minutes
    snmp_timeout: int = 10
    ssh_timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    batch_size: int = 10
    enable_alerting: bool = True
    enable_metrics_collection: bool = True

@dataclass
class DeviceMetrics:
    """Device metrics collected during monitoring"""
    device_id: int
    timestamp: datetime
    cpu_usage: Optional[float] = None
    memory_usage: Optional[float] = None
    disk_usage: Optional[float] = None
    network_in: Optional[float] = None
    network_out: Optional[float] = None
    uptime: Optional[int] = None
    temperature: Optional[float] = None
    response_time_ms: Optional[float] = None
    status: str = "unknown"

class NetworkMonitoringService:
    """Service for comprehensive network device monitoring"""
    
    def __init__(self, config: MonitoringConfig = None):
        """Initialize network monitoring service"""
        self.config = config or MonitoringConfig()
        self.monitoring_tasks: Dict[int, asyncio.Task] = {}
        self.is_running = False
        
        # SNMP OIDs for common metrics
        self.snmp_oids = {
            'system_description': '1.3.6.1.2.1.1.1.0',
            'system_uptime': '1.3.6.1.2.1.1.3.0',
            'system_contact': '1.3.6.1.2.1.1.4.0',
            'system_name': '1.3.6.1.2.1.1.5.0',
            'system_location': '1.3.6.1.2.1.1.6.0',
            'interfaces_number': '1.3.6.1.2.1.2.1.0',
            'if_table': '1.3.6.1.2.1.2.2.1',
            'if_oper_status': '1.3.6.1.2.1.2.2.1.8',
            'if_in_octets': '1.3.6.1.2.1.2.2.1.10',
            'if_out_octets': '1.3.6.1.2.1.2.2.1.16',
            'if_speed': '1.3.6.1.2.1.2.2.1.5',
            'if_mtu': '1.3.6.1.2.1.2.2.1.4',
            'if_phys_address': '1.3.6.1.2.1.2.2.1.6',
            'if_admin_status': '1.3.6.1.2.1.2.2.1.7',
            'if_in_errors': '1.3.6.1.2.1.2.2.1.14',
            'if_out_errors': '1.3.6.1.2.1.2.2.1.20',
            'if_in_discards': '1.3.6.1.2.1.2.2.1.13',
            'if_out_discards': '1.3.6.1.2.1.2.2.1.19',
        }
        
        # Cisco-specific OIDs
        self.cisco_oids = {
            'cpu_5min': '1.3.6.1.4.1.9.9.109.1.1.1.1.7',
            'cpu_1min': '1.3.6.1.4.1.9.9.109.1.1.1.1.6',
            'memory_used': '1.3.6.1.4.1.9.9.48.1.1.1.5',
            'memory_free': '1.3.6.1.4.1.9.9.48.1.1.1.6',
            'temperature': '1.3.6.1.4.1.9.9.13.1.3.1.3',
        }
    
    async def start_monitoring(self):
        """Start the network monitoring service"""
        if self.is_running:
            logger.warning("Network monitoring service is already running")
            return
        
        self.is_running = True
        logger.info("Starting network monitoring service")
        
        try:
            # Get all monitored devices
            async for db in get_db():
                devices = db.query(Device).filter(
                    Device.is_monitored == True,
                    Device.status != DeviceStatus.OFFLINE
                ).all()
                
                # Start monitoring tasks for each device
                for device in devices:
                    await self.start_device_monitoring(device.id)
                
                logger.info(f"Started monitoring for {len(devices)} devices")
                break
                
        except Exception as e:
            logger.error(f"Failed to start monitoring service: {e}")
            self.is_running = False
            raise
    
    async def stop_monitoring(self):
        """Stop the network monitoring service"""
        if not self.is_running:
            logger.warning("Network monitoring service is not running")
            return
        
        logger.info("Stopping network monitoring service")
        self.is_running = False
        
        # Cancel all monitoring tasks
        for device_id, task in self.monitoring_tasks.items():
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        self.monitoring_tasks.clear()
        logger.info("Network monitoring service stopped")
    
    async def start_device_monitoring(self, device_id: int):
        """Start monitoring for a specific device"""
        try:
            # Cancel existing task if any
            if device_id in self.monitoring_tasks:
                self.monitoring_tasks[device_id].cancel()
            
            # Create new monitoring task
            task = asyncio.create_task(self._monitor_device_loop(device_id))
            self.monitoring_tasks[device_id] = task
            
            logger.info(f"Started monitoring for device {device_id}")
            
        except Exception as e:
            logger.error(f"Failed to start monitoring for device {device_id}: {e}")
    
    async def stop_device_monitoring(self, device_id: int):
        """Stop monitoring for a specific device"""
        if device_id in self.monitoring_tasks:
            task = self.monitoring_tasks[device_id]
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            
            del self.monitoring_tasks[device_id]
            logger.info(f"Stopped monitoring for device {device_id}")
    
    async def _monitor_device_loop(self, device_id: int):
        """Main monitoring loop for a device"""
        while self.is_running:
            try:
                # Get device and poll interval
                async for db in get_db():
                    device = db.query(Device).filter(Device.id == device_id).first()
                    if not device or not device.is_monitored:
                        logger.info(f"Device {device_id} no longer monitored, stopping")
                        return
                    
                    poll_interval = device.poll_interval or self.config.default_poll_interval
                    break
                
                # Perform monitoring cycle
                await self._monitor_device_cycle(device_id)
                
                # Wait for next poll
                await asyncio.sleep(poll_interval)
                
            except asyncio.CancelledError:
                logger.info(f"Monitoring cancelled for device {device_id}")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop for device {device_id}: {e}")
                # Wait before retrying
                await asyncio.sleep(30)
    
    async def _monitor_device_cycle(self, device_id: int):
        """Single monitoring cycle for a device"""
        start_time = time.time()
        
        try:
            # Get device and credentials
            async for db in get_db():
                device = db.query(Device).filter(Device.id == device_id).first()
                if not device:
                    logger.error(f"Device {device_id} not found")
                    return
                
                credentials = db.query(DeviceCredentials).filter(
                    DeviceCredentials.device_id == device_id,
                    DeviceCredentials.is_primary == True
                ).first()
                break
            
            if not credentials:
                logger.warning(f"No primary credentials found for device {device_id}")
                return
            
            # Collect metrics based on protocol
            metrics = None
            if device.protocol == DeviceProtocol.SNMP:
                metrics = await self._collect_snmp_metrics(device, credentials)
            elif device.protocol == DeviceProtocol.SSH:
                metrics = await self._collect_ssh_metrics(device, credentials)
            else:
                logger.warning(f"Unsupported protocol {device.protocol} for device {device_id}")
                return
            
            if metrics:
                # Store metrics in database
                await self._store_metrics(device_id, metrics)
                
                # Check for alerts
                if self.config.enable_alerting:
                    await self._check_device_alerts(device_id, metrics)
                
                # Update device status
                await self._update_device_status(device_id, metrics)
            
            response_time = (time.time() - start_time) * 1000
            logger.debug(f"Monitoring cycle completed for device {device_id} in {response_time:.2f}ms")
            
        except Exception as e:
            logger.error(f"Monitoring cycle failed for device {device_id}: {e}")
            # Create alert for monitoring failure
            if self.config.enable_alerting:
                await self._create_monitoring_failure_alert(device_id, str(e))
    
    async def _collect_snmp_metrics(self, device: Device, credentials: DeviceCredentials) -> Optional[DeviceMetrics]:
        """Collect metrics via SNMP"""
        if not SNMP_AVAILABLE:
            logger.warning("SNMP not available")
            return None
        
        try:
            # Decrypt credentials
            community_string = await credential_manager.decrypt_credentials(credentials)
            if not community_string:
                logger.error(f"Failed to decrypt SNMP credentials for device {device.id}")
                return None
            
            metrics = DeviceMetrics(
                device_id=device.id,
                timestamp=datetime.utcnow(),
                response_time_ms=0.0
            )
            
            # Create SNMP engine and transport
            snmp_engine = SnmpEngine()
            transport = UdpTransportTarget(
                (device.ip_address, 161), 
                timeout=self.config.snmp_timeout, 
                retries=0
            )
            community = CommunityData(community_string)
            context = ContextData()
            
            # Collect basic system information
            await self._snmp_get_system_info(snmp_engine, transport, community, context, metrics)
            
            # Collect interface information
            await self._snmp_get_interface_info(snmp_engine, transport, community, context, metrics)
            
            # Collect vendor-specific metrics
            if device.vendor and device.vendor.lower() == 'cisco':
                await self._snmp_get_cisco_metrics(snmp_engine, transport, community, context, metrics)
            
            metrics.status = "online"
            return metrics
            
        except Exception as e:
            logger.error(f"SNMP metrics collection failed for device {device.id}: {e}")
            return DeviceMetrics(
                device_id=device.id,
                timestamp=datetime.utcnow(),
                status="offline"
            )
    
    async def _snmp_get_system_info(self, snmp_engine, transport, community, context, metrics: DeviceMetrics):
        """Get basic system information via SNMP"""
        try:
            # Get system uptime
            object_identity = ObjectIdentity(self.snmp_oids['system_uptime'])
            
            error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: getCmd(snmp_engine, community, transport, context, object_identity)
            )
            
            if not error_indication and not error_status:
                for var_bind in var_binds:
                    uptime_ticks = int(var_bind[1])
                    metrics.uptime = uptime_ticks // 100  # Convert to seconds
                    
        except Exception as e:
            logger.debug(f"Failed to get system info: {e}")
    
    async def _snmp_get_interface_info(self, snmp_engine, transport, community, context, metrics: DeviceMetrics):
        """Get interface information via SNMP"""
        try:
            # Get number of interfaces
            object_identity = ObjectIdentity(self.snmp_oids['interfaces_number'])
            
            error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: getCmd(snmp_engine, community, transport, context, object_identity)
            )
            
            if not error_indication and not error_status:
                num_interfaces = int(var_binds[0][1])
                
                # Get interface statistics for first few interfaces
                for i in range(1, min(num_interfaces + 1, 4)):  # Limit to first 3 interfaces
                    await self._snmp_get_interface_stats(snmp_engine, transport, community, context, i, metrics)
                    
        except Exception as e:
            logger.debug(f"Failed to get interface info: {e}")
    
    async def _snmp_get_interface_stats(self, snmp_engine, transport, community, context, interface_index, metrics: DeviceMetrics):
        """Get statistics for a specific interface"""
        try:
            # Get interface operational status
            status_oid = f"{self.snmp_oids['if_oper_status']}.{interface_index}"
            object_identity = ObjectIdentity(status_oid)
            
            error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: getCmd(snmp_engine, community, transport, context, object_identity)
            )
            
            if not error_indication and not error_status:
                status = int(var_binds[0][1])
                if status == 1:  # Interface is up
                    # Get interface traffic statistics
                    await self._snmp_get_interface_traffic(snmp_engine, transport, community, context, interface_index, metrics)
                    
        except Exception as e:
            logger.debug(f"Failed to get interface stats for interface {interface_index}: {e}")
    
    async def _snmp_get_interface_traffic(self, snmp_engine, transport, community, context, interface_index, metrics: DeviceMetrics):
        """Get traffic statistics for an interface"""
        try:
            # Get input octets
            in_oid = f"{self.snmp_oids['if_in_octets']}.{interface_index}"
            out_oid = f"{self.snmp_oids['if_out_octets']}.{interface_index}"
            
            for oid, metric_name in [(in_oid, 'network_in'), (out_oid, 'network_out')]:
                object_identity = ObjectIdentity(oid)
                
                error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: getCmd(snmp_engine, community, transport, context, object_identity)
                )
                
                if not error_indication and not error_status:
                    octets = int(var_binds[0][1])
                    setattr(metrics, metric_name, octets)
                    
        except Exception as e:
            logger.debug(f"Failed to get interface traffic for interface {interface_index}: {e}")
    
    async def _snmp_get_cisco_metrics(self, snmp_engine, transport, community, context, metrics: DeviceMetrics):
        """Get Cisco-specific metrics"""
        try:
            # Get CPU usage (5-minute average)
            cpu_oid = f"{self.cisco_oids['cpu_5min']}.1"
            object_identity = ObjectIdentity(cpu_oid)
            
            error_indication, error_status, error_index, var_binds = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: getCmd(snmp_engine, community, transport, context, object_identity)
            )
            
            if not error_indication and not error_status:
                cpu_usage = int(var_binds[0][1])
                metrics.cpu_usage = cpu_usage
                
        except Exception as e:
            logger.debug(f"Failed to get Cisco metrics: {e}")
    
    async def _collect_ssh_metrics(self, device: Device, credentials: DeviceCredentials) -> Optional[DeviceMetrics]:
        """Collect metrics via SSH"""
        if not SSH_AVAILABLE:
            logger.warning("SSH not available")
            return None
        
        try:
            # Decrypt credentials
            ssh_password = await credential_manager.decrypt_credentials(credentials)
            if not ssh_password:
                logger.error(f"Failed to decrypt SSH credentials for device {device.id}")
                return None
            
            metrics = DeviceMetrics(
                device_id=device.id,
                timestamp=datetime.utcnow(),
                response_time_ms=0.0
            )
            
            # SSH connection and command execution
            async with asyncssh.connect(
                device.ip_address,
                username=device.ssh_username or 'admin',
                password=ssh_password,
                known_hosts=None,  # In production, use proper host key verification
                timeout=self.config.ssh_timeout
            ) as conn:
                
                # Execute commands to get system information
                await self._ssh_get_system_info(conn, metrics)
                await self._ssh_get_network_info(conn, metrics)
                
            metrics.status = "online"
            return metrics
            
        except Exception as e:
            logger.error(f"SSH metrics collection failed for device {device.id}: {e}")
            return DeviceMetrics(
                device_id=device.id,
                timestamp=datetime.utcnow(),
                status="offline"
            )
    
    async def _ssh_get_system_info(self, conn, metrics: DeviceMetrics):
        """Get system information via SSH"""
        try:
            # Get uptime
            result = await conn.run('uptime')
            if result.exit_status == 0:
                uptime_output = result.stdout.strip()
                # Parse uptime (simplified)
                if 'up' in uptime_output:
                    metrics.uptime = 3600  # Default to 1 hour if parsing fails
            
            # Get CPU usage (Linux/Unix systems)
            result = await conn.run('top -bn1 | grep "Cpu(s)" | awk \'{print $2}\' | awk -F\'%\' \'{print $1}\'')
            if result.exit_status == 0 and result.stdout.strip():
                try:
                    cpu_usage = float(result.stdout.strip())
                    metrics.cpu_usage = cpu_usage
                except ValueError:
                    pass
            
            # Get memory usage
            result = await conn.run('free | grep Mem | awk \'{printf "%.2f", $3/$2 * 100.0}\'')
            if result.exit_status == 0 and result.stdout.strip():
                try:
                    memory_usage = float(result.stdout.strip())
                    metrics.memory_usage = memory_usage
                except ValueError:
                    pass
                    
        except Exception as e:
            logger.debug(f"Failed to get system info via SSH: {e}")
    
    async def _ssh_get_network_info(self, conn, metrics: DeviceMetrics):
        """Get network information via SSH"""
        try:
            # Get network interface statistics
            result = await conn.run('cat /proc/net/dev | grep -v "lo:" | head -1')
            if result.exit_status == 0:
                # This is a simplified implementation
                # In production, you'd parse the actual interface statistics
                metrics.network_in = 0
                metrics.network_out = 0
                
        except Exception as e:
            logger.debug(f"Failed to get network info via SSH: {e}")
    
    async def _store_metrics(self, device_id: int, metrics: DeviceMetrics):
        """Store collected metrics in database"""
        try:
            async for db in get_db():
                # Store CPU usage
                if metrics.cpu_usage is not None:
                    cpu_metric = Metric(
                        device_id=device_id,
                        metric_type=MetricType.GAUGE,
                        category=MetricCategory.SYSTEM,
                        name="cpu_usage",
                        value=metrics.cpu_usage,
                        unit="percent",
                        timestamp=metrics.timestamp,
                        labels={"interface": "all"}
                    )
                    db.add(cpu_metric)
                
                # Store memory usage
                if metrics.memory_usage is not None:
                    memory_metric = Metric(
                        device_id=device_id,
                        metric_type=MetricType.GAUGE,
                        category=MetricCategory.SYSTEM,
                        name="memory_usage",
                        value=metrics.memory_usage,
                        unit="percent",
                        timestamp=metrics.timestamp,
                        labels={"type": "used"}
                    )
                    db.add(memory_metric)
                
                # Store network metrics
                if metrics.network_in is not None:
                    network_in_metric = Metric(
                        device_id=device_id,
                        metric_type=MetricType.COUNTER,
                        category=MetricCategory.NETWORK,
                        name="network_in_bytes",
                        value=metrics.network_in,
                        unit="bytes",
                        timestamp=metrics.timestamp,
                        labels={"direction": "in"}
                    )
                    db.add(network_in_metric)
                
                if metrics.network_out is not None:
                    network_out_metric = Metric(
                        device_id=device_id,
                        metric_type=MetricType.COUNTER,
                        category=MetricCategory.NETWORK,
                        name="network_out_bytes",
                        value=metrics.network_out,
                        unit="bytes",
                        timestamp=metrics.timestamp,
                        labels={"direction": "out"}
                    )
                    db.add(network_out_metric)
                
                # Store uptime
                if metrics.uptime is not None:
                    uptime_metric = Metric(
                        device_id=device_id,
                        metric_type=MetricType.GAUGE,
                        category=MetricCategory.SYSTEM,
                        name="uptime_seconds",
                        value=metrics.uptime,
                        unit="seconds",
                        timestamp=metrics.timestamp,
                        labels={}
                    )
                    db.add(uptime_metric)
                
                db.commit()
                break
                
        except Exception as e:
            logger.error(f"Failed to store metrics for device {device_id}: {e}")
    
    async def _check_device_alerts(self, device_id: int, metrics: DeviceMetrics):
        """Check for alert conditions based on collected metrics"""
        try:
            async for db in get_db():
                # Check CPU usage
                if metrics.cpu_usage is not None and metrics.cpu_usage > 90:
                    await self._create_alert(
                        db, device_id, "High CPU Usage",
                        f"CPU usage is {metrics.cpu_usage:.1f}%",
                        AlertSeverity.HIGH, AlertCategory.PERFORMANCE,
                        {"cpu_usage": metrics.cpu_usage}
                    )
                
                # Check memory usage
                if metrics.memory_usage is not None and metrics.memory_usage > 85:
                    await self._create_alert(
                        db, device_id, "High Memory Usage",
                        f"Memory usage is {metrics.memory_usage:.1f}%",
                        AlertSeverity.MEDIUM, AlertCategory.PERFORMANCE,
                        {"memory_usage": metrics.memory_usage}
                    )
                
                # Check device status
                if metrics.status == "offline":
                    await self._create_alert(
                        db, device_id, "Device Offline",
                        "Device is not responding to monitoring",
                        AlertSeverity.CRITICAL, AlertCategory.AVAILABILITY,
                        {"status": metrics.status}
                    )
                
                break
                
        except Exception as e:
            logger.error(f"Failed to check alerts for device {device_id}: {e}")
    
    async def _create_alert(self, db, device_id: int, title: str, message: str, 
                          severity: AlertSeverity, category: AlertCategory, details: Dict[str, Any]):
        """Create an alert in the database"""
        try:
            # Check if similar alert already exists
            existing_alert = db.query(Alert).filter(
                Alert.device_id == device_id,
                Alert.alert_type == title,
                Alert.status == AlertStatus.ACTIVE
            ).first()
            
            if existing_alert:
                # Update existing alert timestamp
                existing_alert.updated_at = datetime.utcnow()
                existing_alert.details = details
            else:
                # Create new alert
                new_alert = Alert(
                    device_id=device_id,
                    alert_type=title,
                    severity=severity,
                    message=message,
                    details=details,
                    status=AlertStatus.ACTIVE,
                    category=category,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.add(new_alert)
            
            db.commit()
            
        except Exception as e:
            logger.error(f"Failed to create alert for device {device_id}: {e}")
    
    async def _create_monitoring_failure_alert(self, device_id: int, error_message: str):
        """Create an alert for monitoring failure"""
        try:
            async for db in get_db():
                await self._create_alert(
                    db, device_id, "Monitoring Failure",
                    f"Failed to monitor device: {error_message}",
                    AlertSeverity.MEDIUM, AlertCategory.SYSTEM,
                    {"error": error_message, "timestamp": datetime.utcnow().isoformat()}
                )
                break
                
        except Exception as e:
            logger.error(f"Failed to create monitoring failure alert for device {device_id}: {e}")
    
    async def _update_device_status(self, device_id: int, metrics: DeviceMetrics):
        """Update device status in database"""
        try:
            async for db in get_db():
                device = db.query(Device).filter(Device.id == device_id).first()
                if device:
                    # Update device status
                    if metrics.status == "online":
                        device.status = DeviceStatus.ONLINE
                    elif metrics.status == "offline":
                        device.status = DeviceStatus.OFFLINE
                    else:
                        device.status = DeviceStatus.DEGRADED
                    
                    device.last_seen = metrics.timestamp
                    device.updated_at = datetime.utcnow()
                    
                    db.commit()
                break
                
        except Exception as e:
            logger.error(f"Failed to update device status for device {device_id}: {e}")
    
    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get current monitoring service status"""
        return {
            "is_running": self.is_running,
            "monitored_devices": len(self.monitoring_tasks),
            "active_tasks": [device_id for device_id, task in self.monitoring_tasks.items() if not task.done()],
            "config": {
                "default_poll_interval": self.config.default_poll_interval,
                "snmp_timeout": self.config.snmp_timeout,
                "ssh_timeout": self.config.ssh_timeout,
                "max_retries": self.config.max_retries,
                "enable_alerting": self.config.enable_alerting,
                "enable_metrics_collection": self.config.enable_metrics_collection
            }
        }

# Global network monitoring service instance
network_monitoring_service = NetworkMonitoringService()
