"""
Production health monitoring and metrics collection system.
Provides comprehensive monitoring of system health, performance metrics, and service status.
"""

import asyncio
import time
import psutil
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Tuple
from dataclasses import dataclass, field
from enum import Enum
import json
import socket
import threading
from pathlib import Path
import logging
from collections import defaultdict, deque
import weakref
import gc

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

try:
    from prometheus_client import (
        Counter, Histogram, Gauge, Summary, CollectorRegistry, 
        generate_latest, push_to_gateway, REGISTRY
    )
    from prometheus_client.parser import text_string_to_metric_families
    PROMETHEUS_AVAILABLE = True
except ImportError:
    # Install prometheus_client if not available
    import subprocess
    import sys
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "prometheus-client"], 
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        from prometheus_client import (
            Counter, Histogram, Gauge, Summary, CollectorRegistry,
            generate_latest, push_to_gateway, REGISTRY
        )
        from prometheus_client.parser import text_string_to_metric_families
        PROMETHEUS_AVAILABLE = True
        logger.info("Successfully installed prometheus-client")
    except Exception as e:
        logger.warning(f"prometheus-client not available and could not be installed: {e}")
        PROMETHEUS_AVAILABLE = False
        # Define dummy classes for compatibility
        class DummyMetric:
            def __init__(self, *args, **kwargs): pass
            def labels(self, **kwargs): return self
            def inc(self, amount=1): pass
            def dec(self, amount=1): pass
            def set(self, value): pass
            def observe(self, value): pass
        Counter = Histogram = Gauge = Summary = DummyMetric
        REGISTRY = None


logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class MetricType(Enum):
    """Types of metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"


@dataclass
class HealthCheck:
    """Individual health check configuration"""
    name: str
    check_func: Callable[[], bool]
    timeout: float = 5.0
    interval: float = 30.0
    retries: int = 2
    critical: bool = False
    description: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    last_run: Optional[datetime] = None
    last_status: HealthStatus = HealthStatus.UNKNOWN
    consecutive_failures: int = 0


@dataclass
class MetricDefinition:
    """Metric definition for collection"""
    name: str
    metric_type: MetricType
    description: str = ""
    labels: List[str] = field(default_factory=list)
    buckets: Optional[List[float]] = None  # For histograms


@dataclass
class HealthCheckResult:
    """Result of a health check execution"""
    name: str
    status: HealthStatus
    message: str = ""
    duration_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemMetrics:
    """System-level performance metrics"""
    timestamp: datetime
    cpu_percent: float
    memory_percent: float
    memory_used_mb: float
    memory_available_mb: float
    disk_usage_percent: float
    disk_used_gb: float
    disk_free_gb: float
    network_bytes_sent: int
    network_bytes_recv: int
    load_average: Tuple[float, float, float]
    open_files: int
    active_connections: int


class MetricsCollector:
    """Production-grade metrics collection system"""
    
    def __init__(self, registry=None):
        self.registry = registry or (REGISTRY if PROMETHEUS_AVAILABLE else None)
        self._metrics: Dict[str, Any] = {}
        self._metric_definitions: Dict[str, MetricDefinition] = {}
        self._lock = threading.Lock()
        
        # Initialize built-in metrics if Prometheus is available
        if PROMETHEUS_AVAILABLE and self.registry:
            self._init_builtin_metrics()
    
    def _init_builtin_metrics(self):
        """Initialize built-in system metrics"""
        self._system_cpu = Gauge('chm_system_cpu_percent', 'System CPU usage percentage', registry=self.registry)
        self._system_memory = Gauge('chm_system_memory_percent', 'System memory usage percentage', registry=self.registry)
        self._system_memory_bytes = Gauge('chm_system_memory_bytes', 'System memory usage in bytes', ['type'], registry=self.registry)
        self._system_disk = Gauge('chm_system_disk_percent', 'System disk usage percentage', registry=self.registry)
        self._system_network = Counter('chm_system_network_bytes_total', 'System network bytes', ['direction'], registry=self.registry)
        self._health_checks = Gauge('chm_health_check_status', 'Health check status (1=healthy, 0=unhealthy)', ['check_name'], registry=self.registry)
        self._response_time = Histogram('chm_response_time_seconds', 'Response time distribution', ['operation'], registry=self.registry)
        self._error_count = Counter('chm_errors_total', 'Total error count', ['error_type'], registry=self.registry)
        
    def define_metric(self, definition: MetricDefinition):
        """Define a custom metric"""
        with self._lock:
            self._metric_definitions[definition.name] = definition
            
            if PROMETHEUS_AVAILABLE and self.registry:
                if definition.metric_type == MetricType.COUNTER:
                    metric = Counter(definition.name, definition.description, definition.labels, registry=self.registry)
                elif definition.metric_type == MetricType.GAUGE:
                    metric = Gauge(definition.name, definition.description, definition.labels, registry=self.registry)
                elif definition.metric_type == MetricType.HISTOGRAM:
                    buckets = definition.buckets or (.005, .01, .025, .05, .075, .1, .25, .5, .75, 1.0, 2.5, 5.0, 7.5, 10.0)
                    metric = Histogram(definition.name, definition.description, definition.labels, buckets=buckets, registry=self.registry)
                else:
                    return False
                
                self._metrics[definition.name] = metric
                return True
            
            # Fallback for non-Prometheus environments
            self._metrics[definition.name] = {
                'type': definition.metric_type,
                'value': 0.0 if definition.metric_type in [MetricType.GAUGE, MetricType.COUNTER] else [],
                'labels': {},
                'definition': definition
            }
            return True
    
    def increment_counter(self, name: str, amount: float = 1.0, labels: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        if name not in self._metrics:
            return False
            
        metric = self._metrics[name]
        if PROMETHEUS_AVAILABLE and hasattr(metric, 'inc'):
            if labels:
                metric.labels(**labels).inc(amount)
            else:
                metric.inc(amount)
        else:
            # Fallback implementation
            with self._lock:
                if isinstance(metric, dict):
                    metric['value'] += amount
        
        return True
    
    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Set a gauge metric value"""
        if name not in self._metrics:
            return False
            
        metric = self._metrics[name]
        if PROMETHEUS_AVAILABLE and hasattr(metric, 'set'):
            if labels:
                metric.labels(**labels).set(value)
            else:
                metric.set(value)
        else:
            # Fallback implementation
            with self._lock:
                if isinstance(metric, dict):
                    metric['value'] = value
        
        return True
    
    def observe_histogram(self, name: str, value: float, labels: Optional[Dict[str, str]] = None):
        """Record an observation in a histogram"""
        if name not in self._metrics:
            return False
            
        metric = self._metrics[name]
        if PROMETHEUS_AVAILABLE and hasattr(metric, 'observe'):
            if labels:
                metric.labels(**labels).observe(value)
            else:
                metric.observe(value)
        else:
            # Fallback implementation
            with self._lock:
                if isinstance(metric, dict) and isinstance(metric['value'], list):
                    metric['value'].append({'value': value, 'timestamp': time.time(), 'labels': labels or {}})
                    # Keep only last 1000 observations
                    if len(metric['value']) > 1000:
                        metric['value'] = metric['value'][-1000:]
        
        return True
    
    def update_system_metrics(self, system_metrics: SystemMetrics):
        """Update system-level metrics"""
        if PROMETHEUS_AVAILABLE:
            if hasattr(self, '_system_cpu'):
                self._system_cpu.set(system_metrics.cpu_percent)
            if hasattr(self, '_system_memory'):
                self._system_memory.set(system_metrics.memory_percent)
                self._system_memory_bytes.labels(type='used').set(system_metrics.memory_used_mb * 1024 * 1024)
                self._system_memory_bytes.labels(type='available').set(system_metrics.memory_available_mb * 1024 * 1024)
            if hasattr(self, '_system_disk'):
                self._system_disk.set(system_metrics.disk_usage_percent)
    
    def get_metrics_text(self) -> str:
        """Get metrics in Prometheus text format"""
        if PROMETHEUS_AVAILABLE and self.registry:
            return generate_latest(self.registry).decode('utf-8')
        else:
            # Simple text format fallback
            lines = []
            with self._lock:
                for name, metric in self._metrics.items():
                    if isinstance(metric, dict):
                        lines.append(f"# TYPE {name} {metric['type'].value}")
                        if metric['type'] in [MetricType.COUNTER, MetricType.GAUGE]:
                            lines.append(f"{name} {metric['value']}")
                        elif metric['type'] == MetricType.HISTOGRAM and isinstance(metric['value'], list):
                            count = len(metric['value'])
                            total = sum(obs['value'] for obs in metric['value'])
                            lines.append(f"{name}_count {count}")
                            lines.append(f"{name}_sum {total}")
            return '\n'.join(lines)


class HealthMonitor:
    """Production health monitoring system"""
    
    def __init__(self, 
                 metrics_collector: Optional[MetricsCollector] = None,
                 redis_client: Optional[Any] = None,
                 check_interval: float = 30.0):
        self.metrics_collector = metrics_collector or MetricsCollector()
        self.redis_client = redis_client
        self.check_interval = check_interval
        
        self._health_checks: Dict[str, HealthCheck] = {}
        self._check_results: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._system_metrics_history: deque = deque(maxlen=1440)  # 24 hours at 1 minute intervals
        
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()
        
        # System monitoring
        self._last_network_stats = None
        
        # Initialize built-in health checks
        self._init_builtin_checks()
    
    def _init_builtin_checks(self):
        """Initialize built-in health checks"""
        # System resource checks
        self.register_health_check(HealthCheck(
            name="system_cpu",
            check_func=lambda: psutil.cpu_percent(interval=1) < 95.0,
            timeout=5.0,
            interval=60.0,
            critical=True,
            description="System CPU usage below critical threshold"
        ))
        
        self.register_health_check(HealthCheck(
            name="system_memory", 
            check_func=lambda: psutil.virtual_memory().percent < 95.0,
            timeout=5.0,
            interval=60.0,
            critical=True,
            description="System memory usage below critical threshold"
        ))
        
        self.register_health_check(HealthCheck(
            name="system_disk",
            check_func=lambda: psutil.disk_usage('/').percent < 95.0,
            timeout=5.0,
            interval=300.0,  # 5 minutes
            critical=True,
            description="System disk usage below critical threshold"
        ))
        
        # Redis connectivity check with async support
        if self.redis_client and REDIS_AVAILABLE:
            self.register_health_check(HealthCheck(
                name="redis_connectivity",
                check_func=self._check_redis_connectivity,  # Now properly async
                timeout=10.0,
                interval=60.0,
                critical=False,
                description="Redis server connectivity"
            ))
    
    def register_health_check(self, check: HealthCheck):
        """Register a new health check"""
        self._health_checks[check.name] = check
        logger.info(f"Registered health check: {check.name}")
    
    def unregister_health_check(self, name: str) -> bool:
        """Unregister a health check"""
        if name in self._health_checks:
            del self._health_checks[name]
            if name in self._check_results:
                del self._check_results[name]
            logger.info(f"Unregistered health check: {name}")
            return True
        return False
    
    async def start_monitoring(self):
        """Start the health monitoring loop"""
        if self._running:
            return False
        
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Health monitoring started")
        return True
    
    async def stop_monitoring(self):
        """Stop the health monitoring loop"""
        if not self._running:
            return
        
        self._running = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Health monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        try:
            while self._running:
                start_time = time.time()
                
                # Collect system metrics
                await self._collect_system_metrics()
                
                # Run health checks
                await self._run_health_checks()
                
                # Cleanup old data
                self._cleanup_old_data()
                
                # Calculate next sleep time
                elapsed = time.time() - start_time
                sleep_time = max(0, self.check_interval - elapsed)
                
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in monitoring loop: {e}")
            if self.metrics_collector:
                self.metrics_collector.increment_counter('chm_errors_total', 1.0, {'error_type': 'monitoring_loop'})
    
    async def _collect_system_metrics(self):
        """Collect system-level performance metrics with comprehensive error handling"""
        try:
            # CPU and memory with proper error handling
            try:
                cpu_percent = psutil.cpu_percent(interval=None)
            except Exception as e:
                logger.warning(f"Failed to get CPU metrics: {e}")
                cpu_percent = -1.0  # Negative indicates error
            
            try:
                memory = psutil.virtual_memory()
            except Exception as e:
                logger.warning(f"Failed to get memory metrics: {e}")
                # Create fallback memory object
                memory = type('obj', (object,), {
                    'percent': -1.0,
                    'used': 0,
                    'available': 0
                })()
            
            # Disk usage with proper path handling
            try:
                # Try root path based on OS
                import platform
                disk_path = 'C:\\' if platform.system() == 'Windows' else '/'
                disk = psutil.disk_usage(disk_path)
            except Exception as e:
                logger.warning(f"Failed to get disk metrics for {disk_path}: {e}")
                # Try current directory as fallback
                try:
                    disk = psutil.disk_usage('.')
                except Exception:
                    disk = type('obj', (object,), {
                        'percent': -1.0,
                        'used': 0,
                        'free': 0
                    })()
            
            # Network statistics with error handling
            try:
                network = psutil.net_io_counters()
            except Exception as e:
                logger.warning(f"Failed to get network metrics: {e}")
                network = type('obj', (object,), {
                    'bytes_sent': 0,
                    'bytes_recv': 0
                })()
            
            # Load average (Unix-like systems) with proper platform detection
            try:
                if hasattr(psutil, 'getloadavg'):
                    load_avg = psutil.getloadavg()
                else:
                    # Windows doesn't have load average, use CPU percent as approximation
                    cpu_1min = cpu_percent / 100.0 if cpu_percent >= 0 else 0.0
                    load_avg = (cpu_1min, cpu_1min, cpu_1min)
            except Exception as e:
                logger.debug(f"Load average not available: {e}")
                load_avg = (0.0, 0.0, 0.0)
            
            # Process information with robust error handling
            open_files = 0
            connections = 0
            try:
                process = psutil.Process()
                try:
                    open_files = len(process.open_files())
                except (psutil.AccessDenied, NotImplementedError):
                    # Try alternative method
                    try:
                        open_files = process.num_fds()
                    except (AttributeError, psutil.AccessDenied):
                        logger.debug("Cannot access open file count")
                
                try:
                    connections = len(process.connections(kind='all'))
                except (psutil.AccessDenied, NotImplementedError):
                    logger.debug("Cannot access connection count")
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                logger.warning(f"Cannot access process information: {e}")
            
            # Create system metrics
            system_metrics = SystemMetrics(
                timestamp=datetime.now(),
                cpu_percent=cpu_percent,
                memory_percent=memory.percent,
                memory_used_mb=memory.used / (1024 * 1024),
                memory_available_mb=memory.available / (1024 * 1024),
                disk_usage_percent=disk.percent,
                disk_used_gb=disk.used / (1024 * 1024 * 1024),
                disk_free_gb=disk.free / (1024 * 1024 * 1024),
                network_bytes_sent=network.bytes_sent,
                network_bytes_recv=network.bytes_recv,
                load_average=load_avg,
                open_files=open_files,
                active_connections=connections
            )
            
            # Store in history
            self._system_metrics_history.append(system_metrics)
            
            # Update metrics collector
            if self.metrics_collector:
                self.metrics_collector.update_system_metrics(system_metrics)
            
        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}")
            if self.metrics_collector:
                self.metrics_collector.increment_counter('chm_errors_total', 1.0, {'error_type': 'system_metrics'})
    
    async def _run_health_checks(self):
        """Run all registered health checks"""
        current_time = datetime.now()
        
        for name, check in self._health_checks.items():
            # Skip if not time to run
            if (check.last_run and 
                (current_time - check.last_run).total_seconds() < check.interval):
                continue
            
            result = await self._execute_health_check(check)
            
            # Store result
            self._check_results[name].append(result)
            
            # Update health check status
            check.last_run = current_time
            check.last_status = result.status
            
            if result.status != HealthStatus.HEALTHY:
                check.consecutive_failures += 1
            else:
                check.consecutive_failures = 0
            
            # Update metrics
            if self.metrics_collector and hasattr(self.metrics_collector, '_health_checks'):
                status_value = 1.0 if result.status == HealthStatus.HEALTHY else 0.0
                self.metrics_collector.set_gauge('chm_health_check_status', status_value, {'check_name': name})
            
            # Log critical failures
            if check.critical and result.status != HealthStatus.HEALTHY:
                logger.error(f"Critical health check failed: {name} - {result.message}")
    
    async def _execute_health_check(self, check: HealthCheck) -> HealthCheckResult:
        """Execute a single health check with retries"""
        for attempt in range(check.retries + 1):
            start_time = time.time()
            
            try:
                # Run check with timeout
                if asyncio.iscoroutinefunction(check.check_func):
                    result = await asyncio.wait_for(check.check_func(), timeout=check.timeout)
                else:
                    result = await asyncio.wait_for(
                        asyncio.to_thread(check.check_func),
                        timeout=check.timeout
                    )
                
                duration_ms = (time.time() - start_time) * 1000
                
                if result:
                    return HealthCheckResult(
                        name=check.name,
                        status=HealthStatus.HEALTHY,
                        message="Check passed",
                        duration_ms=duration_ms
                    )
                else:
                    status = HealthStatus.DEGRADED if attempt < check.retries else HealthStatus.UNHEALTHY
                    return HealthCheckResult(
                        name=check.name,
                        status=status,
                        message=f"Check failed (attempt {attempt + 1})",
                        duration_ms=duration_ms
                    )
                    
            except asyncio.TimeoutError:
                duration_ms = check.timeout * 1000
                status = HealthStatus.DEGRADED if attempt < check.retries else HealthStatus.UNHEALTHY
                return HealthCheckResult(
                    name=check.name,
                    status=status,
                    message=f"Check timed out after {check.timeout}s",
                    duration_ms=duration_ms
                )
            except Exception as e:
                duration_ms = (time.time() - start_time) * 1000
                if attempt == check.retries:
                    return HealthCheckResult(
                        name=check.name,
                        status=HealthStatus.UNHEALTHY,
                        message=f"Check failed with error: {str(e)}",
                        duration_ms=duration_ms
                    )
        
        # Should not reach here
        return HealthCheckResult(
            name=check.name,
            status=HealthStatus.UNKNOWN,
            message="Unexpected execution path",
            duration_ms=0.0
        )
    
    async def _check_redis_connectivity(self) -> bool:
        """Check Redis server connectivity with proper async implementation"""
        if not self.redis_client:
            return False
        
        try:
            if REDIS_AVAILABLE:
                # Proper async Redis ping with timeout
                result = await asyncio.wait_for(
                    self.redis_client.ping(),
                    timeout=5.0
                )
                return result is True
            return False
        except asyncio.TimeoutError:
            logger.warning("Redis connectivity check timed out")
            return False
        except Exception as e:
            logger.error(f"Redis connectivity check failed: {e}")
            return False
    
    def _cleanup_old_data(self):
        """Clean up old monitoring data"""
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for name, results in self._check_results.items():
            # Remove results older than 24 hours
            while results and results[0].timestamp < cutoff_time:
                results.popleft()
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get current overall health status"""
        async with self._lock:
            overall_status = HealthStatus.HEALTHY
            critical_failures = []
            degraded_checks = []
            
            for name, check in self._health_checks.items():
                if check.last_status == HealthStatus.UNHEALTHY:
                    if check.critical:
                        critical_failures.append(name)
                        overall_status = HealthStatus.UNHEALTHY
                    else:
                        degraded_checks.append(name)
                        if overall_status == HealthStatus.HEALTHY:
                            overall_status = HealthStatus.DEGRADED
                elif check.last_status == HealthStatus.DEGRADED:
                    degraded_checks.append(name)
                    if overall_status == HealthStatus.HEALTHY:
                        overall_status = HealthStatus.DEGRADED
            
            return {
                'status': overall_status.value,
                'timestamp': datetime.now().isoformat(),
                'checks': {
                    name: {
                        'status': check.last_status.value,
                        'last_run': check.last_run.isoformat() if check.last_run else None,
                        'consecutive_failures': check.consecutive_failures,
                        'critical': check.critical,
                        'description': check.description
                    }
                    for name, check in self._health_checks.items()
                },
                'critical_failures': critical_failures,
                'degraded_checks': degraded_checks,
                'system_metrics': self._get_latest_system_metrics()
            }
    
    def _get_latest_system_metrics(self) -> Dict[str, Any]:
        """Get latest system metrics as dictionary"""
        if not self._system_metrics_history:
            # Return fallback system metrics when no history available
            fallback_data = FallbackData(
                data={
                    'timestamp': datetime.utcnow().isoformat(),
                    'cpu_percent': 0.0,
                    'memory_percent': 0.0,
                    'memory_used_mb': 0,
                    'memory_available_mb': 0,
                    'disk_usage_percent': 0.0,
                    'disk_used_gb': 0,
                    'disk_free_gb': 0,
                    'network_bytes_sent': 0,
                    'network_bytes_recv': 0,
                    'load_average': 0.0,
                    'open_files': 0,
                    'active_connections': 0
                },
                source="system_metrics_fallback",
                confidence=0.0,
                metadata={"reason": "No system metrics history available"}
            )
            
            return create_partial_success_result(
                data=fallback_data.data,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="No system metrics history available",
                    fallback_available=True
                ),
                suggestions=[
                    "No system metrics history available",
                    "Check metrics collection",
                    "Verify monitoring configuration",
                    "Use fallback metrics"
                ]
            ).data
        
        latest = self._system_metrics_history[-1]
        return {
            'timestamp': latest.timestamp.isoformat(),
            'cpu_percent': latest.cpu_percent,
            'memory_percent': latest.memory_percent,
            'memory_used_mb': latest.memory_used_mb,
            'memory_available_mb': latest.memory_available_mb,
            'disk_usage_percent': latest.disk_usage_percent,
            'disk_used_gb': latest.disk_used_gb,
            'disk_free_gb': latest.disk_free_gb,
            'network_bytes_sent': latest.network_bytes_sent,
            'network_bytes_recv': latest.network_bytes_recv,
            'load_average': latest.load_average,
            'open_files': latest.open_files,
            'active_connections': latest.active_connections
        }
    
    async def get_metrics(self) -> str:
        """Get metrics in Prometheus format"""
        return self.metrics_collector.get_metrics_text()


class HealthCheckServer:
    """HTTP server for health checks and metrics endpoints"""
    
    def __init__(self, 
                 health_monitor: HealthMonitor,
                 host: str = "0.0.0.0",
                 port: int = 8080):
        self.health_monitor = health_monitor
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
    
    async def start(self):
        """Start the health check server"""
        self.server = await asyncio.start_server(
            self._handle_request,
            self.host,
            self.port
        )
        logger.info(f"Health check server started on {self.host}:{self.port}")
    
    async def stop(self):
        """Stop the health check server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("Health check server stopped")
    
    async def _handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle HTTP requests"""
        try:
            # Read request line
            request_line = await reader.readline()
            request = request_line.decode('utf-8').strip()
            
            if not request:
                await self._send_response(writer, 400, "Bad Request")
                return
            
            # Parse method and path
            parts = request.split(' ')
            if len(parts) < 2:
                await self._send_response(writer, 400, "Bad Request")
                return
            
            method, path = parts[0], parts[1]
            
            # Skip headers for simplicity
            while True:
                header = await reader.readline()
                if header == b'\r\n' or header == b'\n' or not header:
                    break
            
            # Route requests
            if method == "GET":
                if path == "/health":
                    await self._handle_health(writer)
                elif path == "/metrics":
                    await self._handle_metrics(writer)
                elif path == "/ready":
                    await self._handle_ready(writer)
                else:
                    await self._send_response(writer, 404, "Not Found")
            else:
                await self._send_response(writer, 405, "Method Not Allowed")
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            await self._send_response(writer, 500, "Internal Server Error")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    
    async def _handle_health(self, writer: asyncio.StreamWriter):
        """Handle health check endpoint"""
        try:
            health_status = await self.health_monitor.get_health_status()
            status_code = 200 if health_status['status'] == 'healthy' else 503
            
            response_body = json.dumps(health_status, indent=2)
            await self._send_response(
                writer, 
                status_code, 
                "OK" if status_code == 200 else "Service Unavailable",
                response_body,
                "application/json"
            )
        except Exception as e:
            logger.error(f"Error in health endpoint: {e}")
            await self._send_response(writer, 500, "Internal Server Error")
    
    async def _handle_metrics(self, writer: asyncio.StreamWriter):
        """Handle metrics endpoint"""
        try:
            metrics_text = await self.health_monitor.get_metrics()
            await self._send_response(
                writer,
                200,
                "OK",
                metrics_text,
                "text/plain; version=0.0.4; charset=utf-8"
            )
        except Exception as e:
            logger.error(f"Error in metrics endpoint: {e}")
            await self._send_response(writer, 500, "Internal Server Error")
    
    async def _handle_ready(self, writer: asyncio.StreamWriter):
        """Handle readiness probe endpoint"""
        try:
            # Simple readiness check
            health_status = await self.health_monitor.get_health_status()
            
            # Ready if no critical failures
            ready = health_status['status'] in ['healthy', 'degraded']
            status_code = 200 if ready else 503
            
            response_body = json.dumps({
                'ready': ready,
                'status': health_status['status'],
                'timestamp': datetime.now().isoformat()
            })
            
            await self._send_response(
                writer,
                status_code,
                "OK" if ready else "Service Unavailable",
                response_body,
                "application/json"
            )
        except Exception as e:
            logger.error(f"Error in ready endpoint: {e}")
            await self._send_response(writer, 500, "Internal Server Error")
    
    async def _send_response(self, 
                           writer: asyncio.StreamWriter,
                           status_code: int,
                           status_text: str,
                           body: str = "",
                           content_type: str = "text/plain"):
        """Send HTTP response"""
        response_lines = [
            f"HTTP/1.1 {status_code} {status_text}",
            f"Content-Type: {content_type}",
            f"Content-Length: {len(body)}",
            "Connection: close",
            "",
            body
        ]
        
        response = "\r\n".join(response_lines).encode('utf-8')
        writer.write(response)
        await writer.drain()