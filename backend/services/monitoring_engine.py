"""
Monitoring Engine for real-time data collection in CHM.

This module provides the core monitoring functionality including:
- Real-time device monitoring orchestration
- Multi-protocol data collection (SNMP, SSH, API)
- Metric scheduling and collection
- Threshold monitoring and alerting
- Performance optimization with async operations
- Data aggregation and preprocessing
- Health check monitoring
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict, deque
import statistics
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, update
from pydantic import BaseModel, Field, validator

from models.device import Device
from models.alert import Alert
from models.metric import Metric as DeviceMetric
# MonitoringProfile not yet implemented
class MonitoringProfile:
    pass
from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from backend.common.exceptions import (
    MonitoringError, ValidationError,
    DeviceConnectionError
)
from backend.services.snmp_service import snmp_service, SNMPCredentials, SNMPVersion
from backend.services.ssh_service import ssh_service, SSHCredentials, DeviceVendor
from backend.services.device_service import device_service
from backend.services.alert_service import alert_service
# Cache manager not yet implemented
cache_manager = None




class MonitoringStatus(str, Enum):
    """Monitoring task status."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


class CollectionMethod(str, Enum):
    """Data collection methods."""
    SNMP = "snmp"
    SSH = "ssh"
    API = "api"
    PING = "ping"
    HTTP = "http"
    CUSTOM = "custom"


class MetricType(str, Enum):
    """Types of metrics."""
    GAUGE = "gauge"  # Point-in-time value
    COUNTER = "counter"  # Cumulative value
    DERIVE = "derive"  # Rate of change
    ABSOLUTE = "absolute"  # Resets on read
    TEXT = "text"  # Text/string value


class AggregationMethod(str, Enum):
    """Metric aggregation methods."""
    AVERAGE = "average"
    SUM = "sum"
    MIN = "min"
    MAX = "max"
    MEDIAN = "median"
    PERCENTILE_95 = "percentile_95"
    LAST = "last"
    FIRST = "first"


@dataclass
class MetricDefinition:
    """Definition of a metric to collect."""
    name: str
    method: CollectionMethod
    type: MetricType
    target: str  # OID for SNMP, command for SSH, etc.
    interval: int = 300  # Collection interval in seconds
    unit: Optional[str] = None
    description: Optional[str] = None
    transform: Optional[str] = None  # Expression to transform value
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    enabled: bool = True


@dataclass
class MonitoringTask:
    """Individual monitoring task."""
    id: str
    device_id: int
    metrics: List[MetricDefinition]
    status: MonitoringStatus = MonitoringStatus.IDLE
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    error_count: int = 0
    consecutive_errors: int = 0
    task: Optional[asyncio.Task] = None


@dataclass
class CollectionResult:
    """Result from metric collection."""
    device_id: int
    metric_name: str
    value: Any
    timestamp: datetime
    success: bool
    error: Optional[str] = None
    collection_time: float = 0.0


class MonitoringConfig(BaseModel):
    """Monitoring engine configuration."""
    max_concurrent_tasks: int = 100
    default_interval: int = 300
    min_interval: int = 30
    max_interval: int = 3600
    retry_count: int = 3
    retry_delay: int = 60
    error_threshold: int = 5
    batch_size: int = 50
    aggregation_window: int = 3600
    history_retention: int = 86400  # 24 hours
    enable_caching: bool = True
    cache_ttl: int = 60


class MonitoringProfile(BaseModel):
    """Monitoring profile for device types."""
    name: str
    device_type: str
    vendor: Optional[str] = None
    metrics: List[MetricDefinition]
    enabled: bool = True


class MonitoringEngine:
    """Core monitoring engine for CHM."""
    
    # Default metric definitions
    DEFAULT_METRICS = {
        "cpu_usage": MetricDefinition(
            name="cpu_usage",
            method=CollectionMethod.SNMP,
            type=MetricType.GAUGE,
            target="1.3.6.1.4.1.9.9.109.1.1.1.1.5",  # Cisco CPU
            interval=300,
            unit="percent",
            description="CPU utilization",
            threshold_warning=70,
            threshold_critical=90
        ),
        "memory_usage": MetricDefinition(
            name="memory_usage",
            method=CollectionMethod.SNMP,
            type=MetricType.GAUGE,
            target="1.3.6.1.4.1.9.9.48.1.1.1.5",  # Cisco memory
            interval=300,
            unit="bytes",
            description="Memory usage",
            threshold_warning=80,
            threshold_critical=95
        ),
        "interface_traffic_in": MetricDefinition(
            name="interface_traffic_in",
            method=CollectionMethod.SNMP,
            type=MetricType.COUNTER,
            target="1.3.6.1.2.1.2.2.1.10",  # ifInOctets
            interval=60,
            unit="bytes",
            description="Interface input traffic"
        ),
        "interface_traffic_out": MetricDefinition(
            name="interface_traffic_out",
            method=CollectionMethod.SNMP,
            type=MetricType.COUNTER,
            target="1.3.6.1.2.1.2.2.1.16",  # ifOutOctets
            interval=60,
            unit="bytes",
            description="Interface output traffic"
        ),
        "device_uptime": MetricDefinition(
            name="device_uptime",
            method=CollectionMethod.SNMP,
            type=MetricType.GAUGE,
            target="1.3.6.1.2.1.1.3.0",  # sysUpTime
            interval=300,
            unit="ticks",
            description="Device uptime"
        ),
        "ping_latency": MetricDefinition(
            name="ping_latency",
            method=CollectionMethod.PING,
            type=MetricType.GAUGE,
            target="",
            interval=60,
            unit="ms",
            description="Ping latency",
            threshold_warning=100,
            threshold_critical=500
        )
    }
    
    def __init__(self, config: Optional[MonitoringConfig] = None):
        """Initialize monitoring engine."""
        self.config = config or MonitoringConfig()
        self.tasks: Dict[str, MonitoringTask] = {}
        self.metrics_buffer: Dict[int, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.aggregated_metrics: Dict[str, Dict[str, float]] = defaultdict(dict)
        self.status = MonitoringStatus.IDLE
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._scheduler_task: Optional[asyncio.Task] = None
        self._collector_tasks: List[asyncio.Task] = []
        self._stop_event = asyncio.Event()
    
    async def start(self, db: AsyncSession):
        """Start monitoring engine."""
        if self.status == MonitoringStatus.RUNNING:
            logger.warning("Monitoring engine already running")
            return
        
        try:
            self.status = MonitoringStatus.RUNNING
            self._stop_event.clear()
            
            # Load monitoring tasks from database
            await self._load_monitoring_tasks(db)
            
            # Start scheduler
            self._scheduler_task = asyncio.create_task(self._scheduler_loop(db))
            
            # Start metric aggregator
            asyncio.create_task(self._aggregator_loop(db))
            
            # Start health checker
            asyncio.create_task(self._health_check_loop(db))
            
            logger.info("Monitoring engine started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start monitoring engine: {e}")
            self.status = MonitoringStatus.ERROR
            raise MonitoringError(f"Failed to start monitoring engine: {e}")
    
    async def stop(self):
        """Stop monitoring engine."""
        logger.info("Stopping monitoring engine...")
        
        self.status = MonitoringStatus.STOPPED
        self._stop_event.set()
        
        # Cancel scheduler
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        # Cancel all collector tasks
        for task in self._collector_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self._collector_tasks:
            await asyncio.gather(*self._collector_tasks, return_exceptions=True)
        
        self._collector_tasks.clear()
        self.tasks.clear()
        
        logger.info("Monitoring engine stopped")
    
    async def pause(self):
        """Pause monitoring engine."""
        self.status = MonitoringStatus.PAUSED
        logger.info("Monitoring engine paused")
    
    async def resume(self):
        """Resume monitoring engine."""
        self.status = MonitoringStatus.RUNNING
        logger.info("Monitoring engine resumed")
    
    async def add_device_monitoring(
        self,
        db: AsyncSession,
        device_id: int,
        profile_name: Optional[str] = None,
        custom_metrics: Optional[List[MetricDefinition]] = None
    ) -> str:
        """Add device to monitoring."""
        try:
            # Get device
            device = await device_service.get_device_by_id(db, device_id)
            if not device:
                raise ValidationError(f"Device {device_id} not found")
            
            # Determine metrics to collect
            metrics = []
            
            if profile_name:
                # Load profile metrics
                profile = await self._get_monitoring_profile(db, profile_name)
                if profile:
                    metrics.extend(profile.metrics)
            
            if custom_metrics:
                metrics.extend(custom_metrics)
            
            if not metrics:
                # Use default metrics
                metrics = list(self.DEFAULT_METRICS.values())
            
            # Create monitoring task
            task_id = f"device_{device_id}_{int(time.time())}"
            monitoring_task = MonitoringTask(
                id=task_id,
                device_id=device_id,
                metrics=metrics,
                status=MonitoringStatus.IDLE,
                next_run=datetime.utcnow()
            )
            
            self.tasks[task_id] = monitoring_task
            
            logger.info(f"Added monitoring for device {device_id} with task {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Failed to add device monitoring: {e}")
            raise
    
    async def remove_device_monitoring(
        self,
        device_id: int
    ) -> bool:
        """Remove device from monitoring."""
        removed_tasks = []
        
        for task_id, task in list(self.tasks.items()):
            if task.device_id == device_id:
                # Cancel task if running
                if task.task and not task.task.done():
                    task.task.cancel()
                
                del self.tasks[task_id]
                removed_tasks.append(task_id)
        
        if removed_tasks:
            logger.info(f"Removed monitoring tasks for device {device_id}: {removed_tasks}")
            return True
        
        return False
    
    async def collect_metrics(
        self,
        db: AsyncSession,
        device_id: int,
        metrics: List[MetricDefinition]
    ) -> List[CollectionResult]:
        """Collect metrics for a device."""
        results = []
        
        # Get device and credentials
        device = await device_service.get_device_by_id(db, device_id)
        if not device:
            logger.error(f"Device {device_id} not found")
            return results
        
        # Group metrics by collection method
        method_groups = defaultdict(list)
        for metric in metrics:
            if metric.enabled:
                method_groups[metric.method].append(metric)
        
        # Collect metrics for each method
        for method, method_metrics in method_groups.items():
            if method == CollectionMethod.SNMP:
                method_results = await self._collect_snmp_metrics(
                    db, device, method_metrics
                )
            elif method == CollectionMethod.SSH:
                method_results = await self._collect_ssh_metrics(
                    db, device, method_metrics
                )
            elif method == CollectionMethod.PING:
                method_results = await self._collect_ping_metrics(
                    device, method_metrics
                )
            else:
                logger.warning(f"Unsupported collection method: {method}")
                continue
            
            results.extend(method_results)
        
        # Store metrics
        await self._store_metrics(db, results)
        
        # Check thresholds and create alerts
        await self._check_thresholds(db, device_id, metrics, results)
        
        return results
    
    async def get_device_metrics(
        self,
        device_id: int,
        metric_name: Optional[str] = None,
        time_range: Optional[int] = None
    ) -> Dict[str, Any]:
        """Get collected metrics for a device."""
        if device_id not in self.metrics_buffer:
            return {}
        
        device_metrics = list(self.metrics_buffer[device_id])
        
        # Filter by metric name if specified
        if metric_name:
            device_metrics = [
                m for m in device_metrics
                if m.get("metric_name") == metric_name
            ]
        
        # Filter by time range if specified
        if time_range:
            cutoff_time = datetime.utcnow() - timedelta(seconds=time_range)
            device_metrics = [
                m for m in device_metrics
                if m.get("timestamp") >= cutoff_time
            ]
        
        return {
            "device_id": device_id,
            "metrics": device_metrics,
            "count": len(device_metrics)
        }
    
    async def get_aggregated_metrics(
        self,
        device_id: int,
        metric_name: str,
        aggregation: AggregationMethod = AggregationMethod.AVERAGE,
        window: Optional[int] = None
    ) -> Optional[float]:
        """Get aggregated metric value."""
        key = f"{device_id}:{metric_name}:{aggregation.value}"
        
        if key in self.aggregated_metrics:
            return self.aggregated_metrics[key].get("value")
        
        # Calculate aggregation on demand
        metrics = await self.get_device_metrics(device_id, metric_name, window)
        if not metrics.get("metrics"):
            return None
        
        values = [m["value"] for m in metrics["metrics"] if m.get("value") is not None]
        if not values:
            return None
        
        return self._calculate_aggregation(values, aggregation)
    
    async def get_monitoring_status(self) -> Dict[str, Any]:
        """Get monitoring engine status."""
        return {
            "status": self.status.value,
            "total_tasks": len(self.tasks),
            "active_tasks": sum(1 for t in self.tasks.values() if t.status == MonitoringStatus.RUNNING),
            "error_tasks": sum(1 for t in self.tasks.values() if t.status == MonitoringStatus.ERROR),
            "devices_monitored": len(set(t.device_id for t in self.tasks.values())),
            "metrics_collected": sum(len(buffer) for buffer in self.metrics_buffer.values()),
            "aggregated_metrics": len(self.aggregated_metrics)
        }
    
    # Private helper methods
    
    async def _scheduler_loop(self, db: AsyncSession):
        """Main scheduler loop."""
        while not self._stop_event.is_set():
            try:
                if self.status != MonitoringStatus.RUNNING:
                    await asyncio.sleep(1)
                    continue
                
                # Check for tasks to run
                now = datetime.utcnow()
                tasks_to_run = []
                
                for task_id, task in self.tasks.items():
                    if task.status == MonitoringStatus.ERROR:
                        if task.consecutive_errors >= self.config.error_threshold:
                            continue
                    
                    if task.next_run and task.next_run <= now:
                        if not task.task or task.task.done():
                            tasks_to_run.append(task)
                
                # Start collection tasks
                for task in tasks_to_run[:self.config.max_concurrent_tasks]:
                    if len(self._collector_tasks) >= self.config.max_concurrent_tasks:
                        break
                    
                    collector_task = asyncio.create_task(
                        self._run_collection_task(db, task)
                    )
                    task.task = collector_task
                    self._collector_tasks.append(collector_task)
                
                # Clean up completed tasks
                self._collector_tasks = [
                    t for t in self._collector_tasks if not t.done()
                ]
                
                await asyncio.sleep(1)
                
            except Exception as e:
                logger.error(f"Scheduler loop error: {e}")
                await asyncio.sleep(5)
    
    async def _run_collection_task(
        self,
        db: AsyncSession,
        task: MonitoringTask
    ):
        """Run individual collection task."""
        task.status = MonitoringStatus.RUNNING
        task.last_run = datetime.utcnow()
        
        try:
            # Collect metrics
            results = await self.collect_metrics(db, task.device_id, task.metrics)
            
            # Update task status
            if all(r.success for r in results):
                task.consecutive_errors = 0
                task.status = MonitoringStatus.IDLE
            else:
                task.error_count += 1
                task.consecutive_errors += 1
                if task.consecutive_errors >= self.config.error_threshold:
                    task.status = MonitoringStatus.ERROR
                else:
                    task.status = MonitoringStatus.IDLE
            
            # Calculate next run time
            min_interval = min(m.interval for m in task.metrics if m.enabled)
            task.next_run = datetime.utcnow() + timedelta(seconds=min_interval)
            
        except Exception as e:
            logger.error(f"Collection task error for device {task.device_id}: {e}")
            task.error_count += 1
            task.consecutive_errors += 1
            task.status = MonitoringStatus.ERROR
            task.next_run = datetime.utcnow() + timedelta(seconds=self.config.retry_delay)
    
    async def _collect_snmp_metrics(
        self,
        db: AsyncSession,
        device: Device,
        metrics: List[MetricDefinition]
    ) -> List[CollectionResult]:
        """Collect SNMP metrics."""
        results = []
        
        # Get SNMP credentials
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community="public",  # Should get from device credentials
            host=device.ip_address
        )
        
        # Collect metrics
        oids = [m.target for m in metrics]
        snmp_results = await snmp_service.get_bulk(
            device.ip_address,
            oids,
            credentials
        )
        
        # Process results
        for metric, snmp_result in zip(metrics, snmp_results):
            value = snmp_result.value
            
            # Apply transformation if specified
            if metric.transform and value is not None:
                try:
                    value = eval(metric.transform, {"value": value})
                except Exception as e:
                    logger.error(f"Transform error for {metric.name}: {e}")
            
            results.append(CollectionResult(
                device_id=device.id,
                metric_name=metric.name,
                value=value,
                timestamp=datetime.utcnow(),
                success=snmp_result.success,
                error=snmp_result.error,
                collection_time=snmp_result.response_time or 0
            ))
        
        return results
    
    async def _collect_ssh_metrics(
        self,
        db: AsyncSession,
        device: Device,
        metrics: List[MetricDefinition]
    ) -> List[CollectionResult]:
        """Collect SSH metrics."""
        results = []
        
        # Get SSH credentials
        credentials = SSHCredentials(
            host=device.ip_address,
            username="admin",  # Should get from device credentials
            password="password",  # Should get from device credentials
            vendor=DeviceVendor.GENERIC
        )
        
        # Collect metrics
        for metric in metrics:
            start_time = time.time()
            
            result = await ssh_service.execute_command(
                credentials,
                metric.target
            )
            
            value = None
            if result.success:
                # Parse output based on metric type
                value = self._parse_ssh_output(result.output, metric)
            
            results.append(CollectionResult(
                device_id=device.id,
                metric_name=metric.name,
                value=value,
                timestamp=datetime.utcnow(),
                success=result.success,
                error=result.error,
                collection_time=time.time() - start_time
            ))
        
        return results
    
    async def _collect_ping_metrics(
        self,
        device: Device,
        metrics: List[MetricDefinition]
    ) -> List[CollectionResult]:
        """Collect ping metrics."""
        results = []
        
        for metric in metrics:
            start_time = time.time()
            
            # Perform ping
            latency = await self._ping_device(device.ip_address)
            
            results.append(CollectionResult(
                device_id=device.id,
                metric_name=metric.name,
                value=latency,
                timestamp=datetime.utcnow(),
                success=latency is not None,
                error=None if latency is not None else "Ping failed",
                collection_time=time.time() - start_time
            ))
        
        return results
    
    async def _ping_device(self, ip_address: str) -> Optional[float]:
        """Ping device and return latency."""
        # Simplified ping implementation
        import subprocess
        
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip_address],
                capture_output=True,
                text=True,
                timeout=2
            )
            
            if result.returncode == 0:
                # Parse latency from output
                import re
                match = re.search(r"time=(\d+\.?\d*)", result.stdout)
                if match:
                    return float(match.group(1))
            
            return None
            
        except Exception as e:
            logger.error(f"Ping failed for {ip_address}: {e}")
            return None
    
    def _parse_ssh_output(self, output: str, metric: MetricDefinition) -> Any:
        """Parse SSH command output."""
        # Simple parsing - should be enhanced based on metric type
        try:
            # Try to extract numeric value
            import re
            numbers = re.findall(r'\d+\.?\d*', output)
            if numbers:
                return float(numbers[0])
            
            # Return text for text metrics
            if metric.type == MetricType.TEXT:
                return output.strip()
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to parse SSH output: {e}")
            return None
    
    async def _store_metrics(
        self,
        db: AsyncSession,
        results: List[CollectionResult]
    ):
        """Store collected metrics."""
        for result in results:
            if result.success and result.value is not None:
                # Add to buffer
                self.metrics_buffer[result.device_id].append({
                    "metric_name": result.metric_name,
                    "value": result.value,
                    "timestamp": result.timestamp,
                    "collection_time": result.collection_time
                })
                
                # Store in database
                try:
                    metric = DeviceMetric(
                        device_id=result.device_id,
                        metric_name=result.metric_name,
                        value=float(result.value) if isinstance(result.value, (int, float)) else 0,
                        unit="",
                        collected_at=result.timestamp
                    )
                    db.add(metric)
                    
                except Exception as e:
                    logger.error(f"Failed to store metric: {e}")
        
        try:
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to commit metrics: {e}")
            await db.rollback()
    
    async def _check_thresholds(
        self,
        db: AsyncSession,
        device_id: int,
        metrics: List[MetricDefinition],
        results: List[CollectionResult]
    ):
        """Check metric thresholds and create alerts."""
        for metric, result in zip(metrics, results):
            if not result.success or result.value is None:
                continue
            
            alert_severity = None
            threshold = None
            
            if metric.threshold_critical and result.value >= metric.threshold_critical:
                alert_severity = "critical"
                threshold = metric.threshold_critical
            elif metric.threshold_warning and result.value >= metric.threshold_warning:
                alert_severity = "warning"
                threshold = metric.threshold_warning
            
            if alert_severity:
                # Create alert
                await alert_service.create_alert(
                    db=db,
                    device_id=device_id,
                    metric_name=metric.name,
                    severity=alert_severity,
                    message=f"{metric.name} exceeded threshold: {result.value} (threshold: {threshold})",
                    value=result.value,
                    threshold=threshold
                )
    
    async def _aggregator_loop(self, db: AsyncSession):
        """Aggregate metrics periodically."""
        while not self._stop_event.is_set():
            try:
                if self.status != MonitoringStatus.RUNNING:
                    await asyncio.sleep(60)
                    continue
                
                # Aggregate metrics for each device
                for device_id, buffer in self.metrics_buffer.items():
                    if not buffer:
                        continue
                    
                    # Group by metric name
                    metric_groups = defaultdict(list)
                    for item in buffer:
                        metric_groups[item["metric_name"]].append(item["value"])
                    
                    # Calculate aggregations
                    for metric_name, values in metric_groups.items():
                        for method in AggregationMethod:
                            key = f"{device_id}:{metric_name}:{method.value}"
                            self.aggregated_metrics[key] = {
                                "value": self._calculate_aggregation(values, method),
                                "timestamp": datetime.utcnow(),
                                "count": len(values)
                            }
                
                # Clean old data
                cutoff_time = datetime.utcnow() - timedelta(seconds=self.config.history_retention)
                for device_id, buffer in self.metrics_buffer.items():
                    while buffer and buffer[0]["timestamp"] < cutoff_time:
                        buffer.popleft()
                
                await asyncio.sleep(60)
                
            except Exception as e:
                logger.error(f"Aggregator loop error: {e}")
                await asyncio.sleep(60)
    
    async def _health_check_loop(self, db: AsyncSession):
        """Perform health checks on monitoring tasks."""
        while not self._stop_event.is_set():
            try:
                if self.status != MonitoringStatus.RUNNING:
                    await asyncio.sleep(30)
                    continue
                
                # Check for stuck tasks
                for task_id, task in self.tasks.items():
                    if task.status == MonitoringStatus.RUNNING:
                        if task.last_run:
                            elapsed = (datetime.utcnow() - task.last_run).seconds
                            if elapsed > self.config.max_interval:
                                logger.warning(f"Task {task_id} appears stuck, resetting")
                                task.status = MonitoringStatus.ERROR
                                if task.task:
                                    task.task.cancel()
                
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
                await asyncio.sleep(30)
    
    async def _load_monitoring_tasks(self, db: AsyncSession):
        """Load monitoring tasks from database."""
        try:
            # Load devices with monitoring enabled
            devices = await device_service.list_devices(
                db,
                filters={"monitoring_enabled": True}
            )
            
            for device in devices:
                await self.add_device_monitoring(db, device.id)
            
            logger.info(f"Loaded monitoring for {len(devices)} devices")
            
        except Exception as e:
            logger.error(f"Failed to load monitoring tasks: {e}")
    
    async def _get_monitoring_profile(
        self,
        db: AsyncSession,
        profile_name: str
    ) -> Optional[MonitoringProfile]:
        """Get monitoring profile from database."""
        # Simplified - should load from database
        return None
    
    def _calculate_aggregation(
        self,
        values: List[float],
        method: AggregationMethod
    ) -> float:
        """Calculate aggregation of values."""
        if not values:
            return 0
        
        if method == AggregationMethod.AVERAGE:
            return statistics.mean(values)
        elif method == AggregationMethod.SUM:
            return sum(values)
        elif method == AggregationMethod.MIN:
            return min(values)
        elif method == AggregationMethod.MAX:
            return max(values)
        elif method == AggregationMethod.MEDIAN:
            return statistics.median(values)
        elif method == AggregationMethod.PERCENTILE_95:
            sorted_values = sorted(values)
            index = int(len(sorted_values) * 0.95)
            return sorted_values[index] if index < len(sorted_values) else sorted_values[-1]
        elif method == AggregationMethod.LAST:
            return values[-1]
        elif method == AggregationMethod.FIRST:
            return values[0]
        else:
            return 0


# Create singleton instance
monitoring_engine = MonitoringEngine()