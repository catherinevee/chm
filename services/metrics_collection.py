"""
CHM Metrics Collection Service
Core service for collecting metrics from network devices
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import time

from pysnmp.hlapi import (
    SnmpEngine, CommunityData, UdpTransportTarget, 
    ContextData, ObjectType, ObjectIdentity, getCmd
)
import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from ..models import Device, DeviceCredentials, Metric, CollectionMethod, MetricQuality
from ..models.result_objects import MetricsCollectionResult, OperationStatus
from .device_operations import DeviceOperationsService
from .credential_manager import CredentialManager

logger = logging.getLogger(__name__)

@dataclass
class CollectionConfig:
    """Configuration for metric collection"""
    timeout_seconds: int = 30
    max_retries: int = 3
    retry_delay_seconds: float = 1.0
    batch_size: int = 10
    quality_threshold: float = 0.7
    enable_validation: bool = True
    enable_quality_scoring: bool = True

@dataclass
class CollectionResult:
    """Result of a single metric collection"""
    success: bool
    metric_name: str
    value: Optional[float] = None
    unit: Optional[str] = None
    raw_value: Optional[str] = None
    collection_duration_ms: Optional[float] = None
    error: Optional[str] = None
    quality_score: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None

class MetricsCollectionService:
    """Service for collecting metrics from network devices"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.device_ops = DeviceOperationsService()
        self.credential_manager = CredentialManager()
        self.config = CollectionConfig()
        
        # SNMP OID mappings for common metrics
        self.snmp_oids = {
            "cpu_usage": "1.3.6.1.4.1.9.9.109.1.1.1.1.3.1",  # Cisco CPU
            "memory_usage": "1.3.6.1.4.1.9.9.48.1.1.1.6.1",   # Cisco Memory
            "interface_in_octets": "1.3.6.1.2.1.2.2.1.10",     # IF-MIB
            "interface_out_octets": "1.3.6.1.2.1.2.2.1.16",   # IF-MIB
            "interface_status": "1.3.6.1.2.1.2.2.1.8",        # IF-MIB
            "system_uptime": "1.3.6.1.2.1.1.3.0",             # System Uptime
            "system_description": "1.3.6.1.2.1.1.1.0",        # System Description
        }
        
        # SSH command mappings for common metrics
        self.ssh_commands = {
            "cpu_usage": "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1",
            "memory_usage": "free | grep Mem | awk '{printf \"%.2f\", $3/$2 * 100.0}'",
            "disk_usage": "df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1",
            "load_average": "uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | cut -d',' -f1",
            "uptime": "uptime -p",
            "process_count": "ps aux | wc -l",
        }
    
    async def collect_device_metrics(
        self, 
        device_id: int, 
        metric_names: Optional[List[str]] = None
    ) -> MetricsCollectionResult:
        """Collect metrics from a specific device"""
        start_time = time.time()
        
        try:
            # Get device and credentials
            device = await self._get_device(device_id)
            if not device:
                return MetricsCollectionResult.failure(
                    device_id=device_id,
                    error="Device not found"
                )
            
            credentials = await self._get_device_credentials(device_id)
            if not credentials:
                return MetricsCollectionResult.failure(
                    device_id=device_id,
                    error="No credentials found for device"
                )
            
            # Determine collection method based on device protocol
            if device.protocol == "snmp":
                metrics = await self._collect_snmp_metrics(device, credentials, metric_names)
            elif device.protocol == "ssh":
                metrics = await self._collect_ssh_metrics(device, credentials, metric_names)
            else:
                return MetricsCollectionResult.failure(
                    device_id=device_id,
                    error=f"Unsupported protocol: {device.protocol}"
                )
            
            # Store collected metrics
            stored_count = await self._store_metrics(metrics)
            
            collection_time = time.time() - start_time
            
            return MetricsCollectionResult.success(
                device_id=device_id,
                metrics_count=stored_count
            )
            
        except Exception as e:
            logger.error(f"Error collecting metrics from device {device_id}: {str(e)}")
            return MetricsCollectionResult.failure(
                device_id=device_id,
                error=str(e)
            )
    
    async def collect_batch_metrics(
        self, 
        device_ids: List[int], 
        metric_names: Optional[List[str]] = None
    ) -> List[MetricsCollectionResult]:
        """Collect metrics from multiple devices concurrently"""
        tasks = []
        for device_id in device_ids:
            task = self.collect_device_metrics(device_id, metric_names)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to failure results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                processed_results.append(MetricsCollectionResult.failure(
                    device_id=device_ids[i],
                    error=str(result)
                ))
            else:
                processed_results.append(result)
        
        return processed_results
    
    async def _collect_snmp_metrics(
        self, 
        device: Device, 
        credentials: DeviceCredentials, 
        metric_names: Optional[List[str]] = None
    ) -> List[Metric]:
        """Collect metrics using SNMP"""
        metrics = []
        
        # Determine which OIDs to query
        oids_to_query = self._get_oids_to_query(metric_names)
        
        for metric_name, oid in oids_to_query.items():
            try:
                result = await self._execute_snmp_query(
                    device.ip_address, 
                    credentials, 
                    oid
                )
                
                if result.success:
                    metric = self._create_metric_from_snmp(
                        device, metric_name, result, CollectionMethod.SNMP, oid
                    )
                    metrics.append(metric)
                    
            except Exception as e:
                logger.warning(f"Failed to collect SNMP metric {metric_name} from {device.ip_address}: {str(e)}")
                continue
        
        return metrics
    
    async def _collect_ssh_metrics(
        self, 
        device: Device, 
        credentials: DeviceCredentials, 
        metric_names: Optional[List[str]] = None
    ) -> List[Metric]:
        """Collect metrics using SSH"""
        metrics = []
        
        # Determine which commands to execute
        commands_to_execute = self._get_commands_to_execute(metric_names)
        
        try:
            # Establish SSH connection
            async with asyncssh.connect(
                host=device.ip_address,
                username=credentials.ssh_username,
                password=await self.credential_manager.decrypt_credentials(credentials),
                port=device.port or 22,
                timeout=self.config.timeout_seconds
            ) as conn:
                
                for metric_name, command in commands_to_execute.items():
                    try:
                        result = await self._execute_ssh_command(conn, command)
                        
                        if result.success:
                            metric = self._create_metric_from_ssh(
                                device, metric_name, result, CollectionMethod.SSH, command
                            )
                            metrics.append(metric)
                            
                    except Exception as e:
                        logger.warning(f"Failed to execute SSH command {command} on {device.ip_address}: {str(e)}")
                        continue
                        
        except Exception as e:
            logger.error(f"Failed to establish SSH connection to {device.ip_address}: {str(e)}")
        
        return metrics
    
    async def _execute_snmp_query(
        self, 
        ip_address: str, 
        credentials: DeviceCredentials, 
        oid: str
    ) -> CollectionResult:
        """Execute a single SNMP query"""
        start_time = time.time()
        
        try:
            # Extract SNMP community from credentials
            community = await self.credential_manager.decrypt_credentials(credentials)
            
            # Execute SNMP query
            for (errorIndication, errorStatus, errorIndex, varBinds) in getCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip_address, 161), timeout=self.config.timeout_seconds),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            ):
                if errorIndication or errorStatus:
                    return CollectionResult(
                        success=False,
                        metric_name="",
                        error=f"SNMP error: {errorIndication or errorStatus}"
                    )
                
                for varBind in varBinds:
                    raw_value = str(varBind[1])
                    # Try to convert to float
                    try:
                        value = float(raw_value)
                        unit = None
                    except ValueError:
                        value = None
                        unit = None
                    
                    collection_duration = (time.time() - start_time) * 1000
                    
                    return CollectionResult(
                        success=True,
                        metric_name="",
                        value=value,
                        unit=unit,
                        raw_value=raw_value,
                        collection_duration_ms=collection_duration
                    )
            
            return CollectionResult(
                success=False,
                metric_name="",
                error="No SNMP response"
            )
            
        except Exception as e:
            return CollectionResult(
                success=False,
                metric_name="",
                error=str(e)
            )
    
    async def _execute_ssh_command(
        self, 
        conn: asyncssh.SSHClientConnection, 
        command: str
    ) -> CollectionResult:
        """Execute a single SSH command"""
        start_time = time.time()
        
        try:
            result = await conn.run(command)
            
            if result.exit_status == 0:
                raw_value = result.stdout.strip()
                # Try to convert to float
                try:
                    value = float(raw_value)
                    unit = None
                except ValueError:
                    value = None
                    unit = None
                
                collection_duration = (time.time() - start_time) * 1000
                
                return CollectionResult(
                    success=True,
                    metric_name="",
                    value=value,
                    unit=unit,
                    raw_value=raw_value,
                    collection_duration_ms=collection_duration
                )
            else:
                return CollectionResult(
                    success=False,
                    metric_name="",
                    error=f"SSH command failed with exit status {result.exit_status}"
                )
                
        except Exception as e:
            return CollectionResult(
                success=False,
                metric_name="",
                error=str(e)
            )
    
    def _create_metric_from_snmp(
        self, 
        device: Device, 
        metric_name: str, 
        result: CollectionResult, 
        method: CollectionMethod, 
        source: str
    ) -> Metric:
        """Create a Metric object from SNMP collection result"""
        metric = Metric(
            device_id=device.id,
            name=metric_name,
            value=result.value or 0.0,
            unit=result.unit,
            raw_value=result.raw_value,
            collection_method=method,
            collection_source=source,
            collection_duration_ms=result.collection_duration_ms,
            timestamp=datetime.now(),
            metadata={
                "snmp_oid": source,
                "collection_method": method.value,
                "device_protocol": device.protocol
            }
        )
        
        # Calculate quality score
        if self.config.enable_quality_scoring:
            quality_score = self._calculate_quality_score(result)
            metric.update_quality_score(quality_score)
        
        return metric
    
    def _create_metric_from_ssh(
        self, 
        device: Device, 
        metric_name: str, 
        result: CollectionResult, 
        method: CollectionMethod, 
        source: str
    ) -> Metric:
        """Create a Metric object from SSH collection result"""
        metric = Metric(
            device_id=device.id,
            name=metric_name,
            value=result.value or 0.0,
            unit=result.unit,
            raw_value=result.raw_value,
            collection_method=method,
            collection_source=source,
            collection_duration_ms=result.collection_duration_ms,
            timestamp=datetime.now(),
            metadata={
                "ssh_command": source,
                "collection_method": method.value,
                "device_protocol": device.protocol
            }
        )
        
        # Calculate quality score
        if self.config.enable_quality_scoring:
            quality_score = self._calculate_quality_score(result)
            metric.update_quality_score(quality_score)
        
        return metric
    
    def _calculate_quality_score(self, result: CollectionResult) -> float:
        """Calculate quality score for a collection result"""
        if not result.success:
            return 0.0
        
        score = 1.0
        
        # Penalize for long collection time
        if result.collection_duration_ms:
            if result.collection_duration_ms > 5000:  # > 5 seconds
                score *= 0.8
            elif result.collection_duration_ms > 1000:  # > 1 second
                score *= 0.9
        
        # Penalize for missing value conversion
        if result.value is None:
            score *= 0.7
        
        # Penalize for missing unit
        if result.unit is None:
            score *= 0.95
        
        return max(0.0, min(1.0, score))
    
    def _get_oids_to_query(self, metric_names: Optional[List[str]] = None) -> Dict[str, str]:
        """Get OIDs to query based on requested metric names"""
        if metric_names is None:
            return self.snmp_oids
        
        return {name: oid for name, oid in self.snmp_oids.items() if name in metric_names}
    
    def _get_commands_to_execute(self, metric_names: Optional[List[str]] = None) -> Dict[str, str]:
        """Get commands to execute based on requested metric names"""
        if metric_names is None:
            return self.ssh_commands
        
        return {name: cmd for name, cmd in self.ssh_commands.items() if name in metric_names}
    
    async def _get_device(self, device_id: int) -> Optional[Device]:
        """Get device by ID"""
        result = await self.db_session.execute(
            select(Device).where(Device.id == device_id)
        )
        return result.scalar_one_or_none()
    
    async def _get_device_credentials(self, device_id: int) -> Optional[DeviceCredentials]:
        """Get device credentials by device ID"""
        result = await self.db_session.execute(
            select(DeviceCredentials).where(
                and_(
                    DeviceCredentials.device_id == device_id,
                    DeviceCredentials.status == "active",
                    DeviceCredentials.is_deleted == False
                )
            )
        )
        return result.scalar_one_or_none()
    
    async def _store_metrics(self, metrics: List[Metric]) -> int:
        """Store collected metrics in database"""
        if not metrics:
            return 0
        
        try:
            self.db_session.add_all(metrics)
            await self.db_session.commit()
            return len(metrics)
        except Exception as e:
            logger.error(f"Failed to store metrics: {str(e)}")
            await self.db_session.rollback()
            return 0
    
    def update_config(self, config: CollectionConfig):
        """Update collection configuration"""
        self.config = config
        logger.info(f"Updated metrics collection config: {config}")
    
    async def get_collection_stats(self, device_id: int, hours: int = 24) -> Dict[str, Any]:
        """Get collection statistics for a device"""
        since = datetime.now() - timedelta(hours=hours)
        
        # Get metrics count
        result = await self.db_session.execute(
            select(Metric).where(
                and_(
                    Metric.device_id == device_id,
                    Metric.collected_at >= since,
                    Metric.is_deleted == False
                )
            )
        )
        metrics = result.scalars().all()
        
        if not metrics:
            return {
                "total_metrics": 0,
                "success_rate": 0.0,
                "average_quality": 0.0,
                "collection_methods": {},
                "errors": []
            }
        
        # Calculate statistics
        total_metrics = len(metrics)
        valid_metrics = sum(1 for m in metrics if m.is_valid)
        success_rate = (valid_metrics / total_metrics) * 100 if total_metrics > 0 else 0
        
        quality_scores = [m.quality_score for m in metrics if m.quality_score is not None]
        average_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0
        
        collection_methods = {}
        for metric in metrics:
            method = metric.collection_method.value if metric.collection_method else "unknown"
            collection_methods[method] = collection_methods.get(method, 0) + 1
        
        return {
            "total_metrics": total_metrics,
            "success_rate": round(success_rate, 2),
            "average_quality": round(average_quality, 3),
            "collection_methods": collection_methods,
            "time_range_hours": hours
        }
