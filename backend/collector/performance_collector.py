"""
Enhanced Performance Metrics Collector
Collects comprehensive performance data including disk, temperature, interfaces, etc.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import psutil
import subprocess
import json
import re

from ...common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
from backend.storage.database import db
from backend.storage.models import Device, PerformanceMetrics

logger = logging.getLogger(__name__)

@dataclass
class MetricResult:
    """Result of a metric collection"""
    metric_name: str
    metric_type: str
    value: float
    unit: str
    interface_name: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None

class EnhancedPerformanceCollector:
    """Enhanced performance metrics collector with support for additional metrics"""
    
    # Standard SNMP OIDs for various metrics
    SNMP_OIDS = {
        # System metrics
        'system_uptime': '1.3.6.1.2.1.1.3.0',
        'system_description': '1.3.6.1.2.1.1.1.0',
        'system_name': '1.3.6.1.2.1.1.5.0',
        
        # CPU metrics
        'cpu_usage_1min': '1.3.6.1.4.1.9.9.109.1.1.1.1.7.1',  # Cisco specific
        'cpu_usage_5min': '1.3.6.1.4.1.9.9.109.1.1.1.1.8.1',
        'cpu_usage_5sec': '1.3.6.1.4.1.9.9.109.1.1.1.1.6.1',
        
        # Memory metrics
        'memory_used': '1.3.6.1.4.1.9.9.48.1.1.1.5.1',  # Cisco specific
        'memory_free': '1.3.6.1.4.1.9.9.48.1.1.1.6.1',
        'memory_total': '1.3.6.1.4.1.9.9.48.1.1.1.7.1',
        
        # Temperature sensors (Cisco)
        'temperature_sensors': '1.3.6.1.4.1.9.9.13.1.3.1.3',
        'temperature_values': '1.3.6.1.4.1.9.9.13.1.3.1.4',
        'temperature_thresholds': '1.3.6.1.4.1.9.9.13.1.3.1.5',
        
        # Interface metrics
        'interface_names': '1.3.6.1.2.1.2.2.1.2',
        'interface_types': '1.3.6.1.2.1.2.2.1.3',
        'interface_speeds': '1.3.6.1.2.1.2.2.1.5',
        'interface_admin_status': '1.3.6.1.2.1.2.2.1.7',
        'interface_oper_status': '1.3.6.1.2.1.2.2.1.8',
        'interface_in_octets': '1.3.6.1.2.1.2.2.1.10',
        'interface_out_octets': '1.3.6.1.2.1.2.2.1.16',
        'interface_in_errors': '1.3.6.1.2.1.2.2.1.14',
        'interface_out_errors': '1.3.6.1.2.1.2.2.1.20',
        'interface_in_discards': '1.3.6.1.2.1.2.2.1.13',
        'interface_out_discards': '1.3.6.1.2.1.2.2.1.19',
        
        # Disk/Storage metrics (various vendors)
        'storage_hrStorageIndex': '1.3.6.1.2.1.25.2.3.1.1',
        'storage_hrStorageType': '1.3.6.1.2.1.25.2.3.1.2',
        'storage_hrStorageDescr': '1.3.6.1.2.1.25.2.3.1.3',
        'storage_hrStorageSize': '1.3.6.1.2.1.25.2.3.1.5',
        'storage_hrStorageUsed': '1.3.6.1.2.1.25.2.3.1.6',
    }
    
    def __init__(self):
        self.session_cache = {}  # Cache SNMP sessions
    
    async def collect_all_metrics(self, device: Device) -> List[MetricResult]:
        """Collect all available performance metrics for a device"""
        
        metrics = []
        
        try:
            # Get SNMP session
            session = await self._get_snmp_session(device)
            
            if session:
                # Collect different metric types
                metrics.extend(await self._collect_cpu_metrics(session, device))
                metrics.extend(await self._collect_memory_metrics(session, device))
                metrics.extend(await self._collect_temperature_metrics(session, device))
                metrics.extend(await self._collect_interface_metrics(session, device))
                metrics.extend(await self._collect_disk_metrics(session, device))
                metrics.extend(await self._collect_uptime_metrics(session, device))
            
            # For local devices, also collect system metrics
            if device.ip_address in ['127.0.0.1', 'localhost'] or device.hostname == 'localhost':
                metrics.extend(await self._collect_local_system_metrics())
            
            logger.info(f"Collected {len(metrics)} metrics for device {device.hostname}")
            
        except Exception as e:
            logger.error(f"Failed to collect metrics for device {device.hostname}: {e}")
        
        return metrics
    
    async def _get_snmp_session(self, device: Device) -> Optional[SNMPSession]:
        """Get or create SNMP session for device"""
        
        try:
            # Check cache first
            if device.id in self.session_cache:
                return self.session_cache[device.id]
            
            # Create SNMP credentials (default to v2c if not specified)
            credentials = SNMPCredentials(
                version="2c",
                community="public"
            )
            
            # TODO: Get actual SNMP credentials from device configuration
            # This should be enhanced to use stored device credentials
            
            session = SNMPSession(host=device.ip_address, credentials=credentials)
            
            if await session.connect():
                self.session_cache[device.id] = session
                return session
            
        except Exception as e:
            logger.error(f"Failed to create SNMP session for {device.hostname}: {e}")
        
        # Return fallback SNMP session data when creation fails
        fallback_data = FallbackData(
            data=None,
            source="session_fallback",
            confidence=0.0,
            metadata={"reason": "SNMP session creation failed", "device_hostname": device.hostname, "error": str(e)}
        )
        
        return create_failure_result(
            error=f"Failed to create SNMP session for {device.hostname}",
            error_code="SNMP_SESSION_CREATION_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Check SNMP configuration on the device",
                "Verify SNMP community strings and version",
                "Check network connectivity to the device",
                "Verify SNMP port accessibility",
                "Check firewall rules for SNMP",
                "Consider alternative monitoring methods"
            ]
        )
    
    async def _collect_cpu_metrics(self, session: SNMPSession, device: Device) -> List[MetricResult]:
        """Collect CPU usage metrics"""
        
        metrics = []
        
        try:
            # Try Cisco-specific OIDs first
            cpu_1min = await session.get_single_oid(self.SNMP_OIDS['cpu_usage_1min'])
            if cpu_1min:
                metrics.append(MetricResult(
                    metric_name="CPU Usage (1min)",
                    metric_type="cpu",
                    value=float(cpu_1min),
                    unit="%",
                    timestamp=datetime.utcnow()
                ))
            
            cpu_5min = await session.get_single_oid(self.SNMP_OIDS['cpu_usage_5min'])
            if cpu_5min:
                metrics.append(MetricResult(
                    metric_name="CPU Usage (5min)",
                    metric_type="cpu",
                    value=float(cpu_5min),
                    unit="%",
                    timestamp=datetime.utcnow()
                ))
            
            cpu_5sec = await session.get_single_oid(self.SNMP_OIDS['cpu_usage_5sec'])
            if cpu_5sec:
                metrics.append(MetricResult(
                    metric_name="CPU Usage (5sec)",
                    metric_type="cpu",
                    value=float(cpu_5sec),
                    unit="%",
                    timestamp=datetime.utcnow()
                ))
            
        except Exception as e:
            logger.error(f"Failed to collect CPU metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _collect_memory_metrics(self, session: SNMPSession, device: Device) -> List[MetricResult]:
        """Collect memory usage metrics"""
        
        metrics = []
        
        try:
            memory_used = await session.get_single_oid(self.SNMP_OIDS['memory_used'])
            memory_free = await session.get_single_oid(self.SNMP_OIDS['memory_free'])
            
            if memory_used and memory_free:
                used = float(memory_used)
                free = float(memory_free)
                total = used + free
                usage_percent = (used / total) * 100 if total > 0 else 0
                
                metrics.extend([
                    MetricResult(
                        metric_name="Memory Used",
                        metric_type="memory",
                        value=used,
                        unit="bytes",
                        timestamp=datetime.utcnow()
                    ),
                    MetricResult(
                        metric_name="Memory Free",
                        metric_type="memory",
                        value=free,
                        unit="bytes",
                        timestamp=datetime.utcnow()
                    ),
                    MetricResult(
                        metric_name="Memory Usage",
                        metric_type="memory",
                        value=usage_percent,
                        unit="%",
                        timestamp=datetime.utcnow()
                    )
                ])
            
        except Exception as e:
            logger.error(f"Failed to collect memory metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _collect_temperature_metrics(self, session: SNMPSession, device: Device) -> List[MetricResult]:
        """Collect temperature sensor metrics"""
        
        metrics = []
        
        try:
            # Walk temperature sensors
            temp_sensors = await session.walk_oid(self.SNMP_OIDS['temperature_sensors'])
            temp_values = await session.walk_oid(self.SNMP_OIDS['temperature_values'])
            
            if temp_sensors and temp_values:
                for i, (sensor_oid, sensor_name) in enumerate(temp_sensors):
                    if i < len(temp_values):
                        temp_oid, temp_value = temp_values[i]
                        
                        # Convert from Celsius * 1000 to Celsius (common format)
                        temp_celsius = float(temp_value) / 1000 if temp_value else 0
                        
                        metrics.append(MetricResult(
                            metric_name=f"Temperature - {sensor_name}",
                            metric_type="temperature",
                            value=temp_celsius,
                            unit="°C",
                            timestamp=datetime.utcnow(),
                            metadata={"sensor_name": str(sensor_name)}
                        ))
            
        except Exception as e:
            logger.error(f"Failed to collect temperature metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _collect_interface_metrics(self, session: SNMPSession, device: Device) -> List[MetricResult]:
        """Collect network interface metrics"""
        
        metrics = []
        
        try:
            # Get interface names
            interface_names = await session.walk_oid(self.SNMP_OIDS['interface_names'])
            interface_speeds = await session.walk_oid(self.SNMP_OIDS['interface_speeds'])
            interface_admin_status = await session.walk_oid(self.SNMP_OIDS['interface_admin_status'])
            interface_oper_status = await session.walk_oid(self.SNMP_OIDS['interface_oper_status'])
            interface_in_octets = await session.walk_oid(self.SNMP_OIDS['interface_in_octets'])
            interface_out_octets = await session.walk_oid(self.SNMP_OIDS['interface_out_octets'])
            interface_in_errors = await session.walk_oid(self.SNMP_OIDS['interface_in_errors'])
            interface_out_errors = await session.walk_oid(self.SNMP_OIDS['interface_out_errors'])
            
            if interface_names:
                for i, (name_oid, interface_name) in enumerate(interface_names):
                    if_name = str(interface_name)
                    
                    # Skip loopback and null interfaces
                    if 'loopback' in if_name.lower() or 'null' in if_name.lower():
                        continue
                    
                    # Interface speed
                    if i < len(interface_speeds):
                        speed_value = interface_speeds[i][1]
                        if speed_value and int(speed_value) > 0:
                            metrics.append(MetricResult(
                                metric_name="Interface Speed",
                                metric_type="interface",
                                value=float(speed_value) / 1000000,  # Convert to Mbps
                                unit="Mbps",
                                interface_name=if_name,
                                timestamp=datetime.utcnow()
                            ))
                    
                    # Interface status
                    if i < len(interface_oper_status):
                        oper_status = interface_oper_status[i][1]
                        status_value = 1 if int(oper_status) == 1 else 0  # 1=up, 2=down
                        metrics.append(MetricResult(
                            metric_name="Interface Status",
                            metric_type="interface",
                            value=status_value,
                            unit="status",
                            interface_name=if_name,
                            timestamp=datetime.utcnow()
                        ))
                    
                    # Traffic metrics
                    if i < len(interface_in_octets):
                        in_octets = interface_in_octets[i][1]
                        if in_octets:
                            metrics.append(MetricResult(
                                metric_name="Interface In Octets",
                                metric_type="bandwidth",
                                value=float(in_octets),
                                unit="bytes",
                                interface_name=if_name,
                                timestamp=datetime.utcnow()
                            ))
                    
                    if i < len(interface_out_octets):
                        out_octets = interface_out_octets[i][1]
                        if out_octets:
                            metrics.append(MetricResult(
                                metric_name="Interface Out Octets",
                                metric_type="bandwidth",
                                value=float(out_octets),
                                unit="bytes",
                                interface_name=if_name,
                                timestamp=datetime.utcnow()
                            ))
                    
                    # Error metrics
                    if i < len(interface_in_errors):
                        in_errors = interface_in_errors[i][1]
                        if in_errors:
                            metrics.append(MetricResult(
                                metric_name="Interface In Errors",
                                metric_type="packet_loss",
                                value=float(in_errors),
                                unit="errors",
                                interface_name=if_name,
                                timestamp=datetime.utcnow()
                            ))
                    
                    if i < len(interface_out_errors):
                        out_errors = interface_out_errors[i][1]
                        if out_errors:
                            metrics.append(MetricResult(
                                metric_name="Interface Out Errors",
                                metric_type="packet_loss",
                                value=float(out_errors),
                                unit="errors",
                                interface_name=if_name,
                                timestamp=datetime.utcnow()
                            ))
            
        except Exception as e:
            logger.error(f"Failed to collect interface metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _collect_disk_metrics(self, session: SNMPSession, device: Device) -> List[MetricResult]:
        """Collect disk/storage metrics"""
        
        metrics = []
        
        try:
            # Get storage information using HOST-RESOURCES-MIB
            storage_descriptions = await session.walk_oid(self.SNMP_OIDS['storage_hrStorageDescr'])
            storage_sizes = await session.walk_oid(self.SNMP_OIDS['storage_hrStorageSize'])
            storage_used = await session.walk_oid(self.SNMP_OIDS['storage_hrStorageUsed'])
            
            if storage_descriptions and storage_sizes and storage_used:
                for i, (desc_oid, description) in enumerate(storage_descriptions):
                    desc = str(description)
                    
                    # Filter for disk/filesystem entries
                    if any(keyword in desc.lower() for keyword in ['disk', 'filesystem', 'flash', 'nvram']):
                        if i < len(storage_sizes) and i < len(storage_used):
                            size_value = storage_sizes[i][1]
                            used_value = storage_used[i][1]
                            
                            if size_value and used_value and int(size_value) > 0:
                                size = float(size_value)
                                used = float(used_value)
                                usage_percent = (used / size) * 100
                                
                                metrics.extend([
                                    MetricResult(
                                        metric_name=f"Disk Size - {desc}",
                                        metric_type="disk",
                                        value=size,
                                        unit="blocks",
                                        timestamp=datetime.utcnow(),
                                        metadata={"storage_name": desc}
                                    ),
                                    MetricResult(
                                        metric_name=f"Disk Used - {desc}",
                                        metric_type="disk",
                                        value=used,
                                        unit="blocks",
                                        timestamp=datetime.utcnow(),
                                        metadata={"storage_name": desc}
                                    ),
                                    MetricResult(
                                        metric_name=f"Disk Usage - {desc}",
                                        metric_type="disk",
                                        value=usage_percent,
                                        unit="%",
                                        timestamp=datetime.utcnow(),
                                        metadata={"storage_name": desc}
                                    )
                                ])
            
        except Exception as e:
            logger.error(f"Failed to collect disk metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _collect_uptime_metrics(self, session: SNMPSession, device: Device) -> List[MetricResult]:
        """Collect system uptime metrics"""
        
        metrics = []
        
        try:
            uptime_ticks = await session.get_single_oid(self.SNMP_OIDS['system_uptime'])
            
            if uptime_ticks:
                # Convert from centiseconds to days
                uptime_days = float(uptime_ticks) / 100 / 86400
                
                metrics.append(MetricResult(
                    metric_name="System Uptime",
                    metric_type="uptime",
                    value=uptime_days,
                    unit="days",
                    timestamp=datetime.utcnow()
                ))
            
        except Exception as e:
            logger.error(f"Failed to collect uptime metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _collect_local_system_metrics(self) -> List[MetricResult]:
        """Collect metrics from local system using psutil"""
        
        metrics = []
        
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            metrics.append(MetricResult(
                metric_name="Local CPU Usage",
                metric_type="cpu",
                value=cpu_percent,
                unit="%",
                timestamp=datetime.utcnow()
            ))
            
            # Memory metrics
            memory = psutil.virtual_memory()
            metrics.extend([
                MetricResult(
                    metric_name="Local Memory Usage",
                    metric_type="memory",
                    value=memory.percent,
                    unit="%",
                    timestamp=datetime.utcnow()
                ),
                MetricResult(
                    metric_name="Local Memory Available",
                    metric_type="memory",
                    value=memory.available,
                    unit="bytes",
                    timestamp=datetime.utcnow()
                )
            ])
            
            # Disk metrics
            for partition in psutil.disk_partitions():
                try:
                    disk_usage = psutil.disk_usage(partition.mountpoint)
                    metrics.extend([
                        MetricResult(
                            metric_name=f"Local Disk Usage - {partition.device}",
                            metric_type="disk",
                            value=(disk_usage.used / disk_usage.total) * 100,
                            unit="%",
                            timestamp=datetime.utcnow(),
                            metadata={"device": partition.device, "mountpoint": partition.mountpoint}
                        ),
                        MetricResult(
                            metric_name=f"Local Disk Free - {partition.device}",
                            metric_type="disk",
                            value=disk_usage.free,
                            unit="bytes",
                            timestamp=datetime.utcnow(),
                            metadata={"device": partition.device, "mountpoint": partition.mountpoint}
                        )
                    ])
                except PermissionError:
                    # Skip inaccessible partitions
                    continue
            
            # Temperature (if available)
            try:
                temps = psutil.sensors_temperatures()
                for name, sensors in temps.items():
                    for sensor in sensors:
                        metrics.append(MetricResult(
                            metric_name=f"Local Temperature - {name} {sensor.label or 'Sensor'}",
                            metric_type="temperature",
                            value=sensor.current,
                            unit="°C",
                            timestamp=datetime.utcnow(),
                            metadata={"sensor_name": name, "label": sensor.label}
                        ))
            except AttributeError:
                # Temperature sensors not available on this system
                pass
            
        except Exception as e:
            logger.error(f"Failed to collect local system metrics: {e}")
        
        return metrics
    
    async def calculate_latency_metrics(self, device: Device) -> List[MetricResult]:
        """Calculate latency metrics using ping"""
        
        metrics = []
        
        try:
            # Ping the device to measure latency
            if device.ip_address:
                ping_result = await self._ping_device(device.ip_address)
                
                if ping_result:
                    metrics.append(MetricResult(
                        metric_name="Network Latency",
                        metric_type="latency",
                        value=ping_result['avg_time'],
                        unit="ms",
                        timestamp=datetime.utcnow(),
                        metadata={
                            "min_time": ping_result['min_time'],
                            "max_time": ping_result['max_time'],
                            "packet_loss": ping_result['packet_loss']
                        }
                    ))
                    
                    if ping_result['packet_loss'] > 0:
                        metrics.append(MetricResult(
                            metric_name="Packet Loss",
                            metric_type="packet_loss",
                            value=ping_result['packet_loss'],
                            unit="%",
                            timestamp=datetime.utcnow()
                        ))
            
        except Exception as e:
            logger.error(f"Failed to calculate latency metrics for {device.hostname}: {e}")
        
        return metrics
    
    async def _ping_device(self, ip_address: str, count: int = 4) -> Optional[Dict[str, float]]:
        """Ping device to measure latency and packet loss"""
        
        try:
            # Use system ping command
            cmd = ['ping', '-c', str(count), ip_address]
            
            # On Windows, use different parameters
            import platform
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', str(count), ip_address]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode()
                return self._parse_ping_output(output)
            
        except Exception as e:
            logger.error(f"Failed to ping {ip_address}: {e}")
        
        # Return fallback ping data when ping fails
        fallback_data = FallbackData(
            data={
                'min_time': 999.0,  # High latency to indicate failure
                'max_time': 999.0,
                'avg_time': 999.0,
                'packet_loss': 100.0  # 100% packet loss
            },
            source="ping_fallback",
            confidence=0.0,
            metadata={"reason": "Ping failed", "ip_address": ip_address, "error": str(e)}
        )
        
        return create_failure_result(
            error=f"Failed to ping {ip_address}",
            error_code="PING_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Check network connectivity to the device",
                "Verify the IP address is correct",
                "Check firewall rules and access lists",
                "Verify the device is powered on and accessible",
                "Check if ICMP is blocked on the network",
                "Consider alternative connectivity tests"
            ]
        )
    
    def _parse_ping_output(self, output: str) -> Dict[str, float]:
        """Parse ping command output to extract latency statistics"""
        
        result = {
            'min_time': 0.0,
            'max_time': 0.0,
            'avg_time': 0.0,
            'packet_loss': 0.0
        }
        
        try:
            # Look for packet loss percentage
            loss_match = re.search(r'(\d+)% packet loss', output)
            if loss_match:
                result['packet_loss'] = float(loss_match.group(1))
            
            # Look for timing statistics (Linux/Mac format)
            time_match = re.search(r'min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
            if time_match:
                result['min_time'] = float(time_match.group(1))
                result['avg_time'] = float(time_match.group(2))
                result['max_time'] = float(time_match.group(3))
            else:
                # Windows format
                times = re.findall(r'time[<=]([\d.]+)ms', output)
                if times:
                    time_values = [float(t) for t in times]
                    result['min_time'] = min(time_values)
                    result['max_time'] = max(time_values)
                    result['avg_time'] = sum(time_values) / len(time_values)
            
        except Exception as e:
            logger.error(f"Failed to parse ping output: {e}")
        
        return result
    
    async def store_metrics(self, device: Device, metrics: List[MetricResult]):
        """Store collected metrics to database"""
        
        try:
            for metric in metrics:
                performance_metric = PerformanceMetrics(
                    device_id=device.id,
                    metric_name=metric.metric_name,
                    metric_type=metric.metric_type,
                    metric_value=metric.value,
                    metric_unit=metric.unit,
                    interface_name=metric.interface_name,
                    timestamp=metric.timestamp or datetime.utcnow(),
                    metric_metadata=metric.metadata
                )
                
                await db.add(performance_metric)
            
            await db.commit()
            logger.info(f"Stored {len(metrics)} metrics for device {device.hostname}")
            
        except Exception as e:
            logger.error(f"Failed to store metrics for device {device.hostname}: {e}")
            await db.rollback()

# Global performance collector instance
performance_collector = EnhancedPerformanceCollector()
