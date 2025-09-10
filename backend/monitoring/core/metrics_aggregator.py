"""
Distributed metrics aggregation system with statistical analysis,
multi-node coordination, and storage optimization.
"""

import asyncio
import hashlib
import json
import logging
import math
import struct
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union, Callable
from threading import Lock
import statistics

try:
    import redis.asyncio as redis
    from redis.asyncio import Redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import prometheus_client
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, CollectorRegistry,
        multiprocess, generate_latest, CONTENT_TYPE_LATEST
    )
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


logger = logging.getLogger(__name__)

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge" 
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TIMER = "timer"
    RATE = "rate"


class AggregationStrategy(Enum):
    """Aggregation strategies for distributed metrics."""
    SUM = "sum"
    AVERAGE = "average"
    MIN = "min"
    MAX = "max"
    COUNT = "count"
    P50 = "p50"
    P90 = "p90"
    P95 = "p95"
    P99 = "p99"
    STDDEV = "stddev"
    RATE_PER_SECOND = "rate_per_second"


@dataclass
class MetricSample:
    """Individual metric sample."""
    timestamp: float
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp,
            'value': self.value,
            'labels': self.labels
        }


@dataclass
class AggregatedMetric:
    """Aggregated metric result."""
    name: str
    metric_type: MetricType
    aggregation: AggregationStrategy
    value: float
    timestamp: float
    window_size: float
    sample_count: int
    labels: Dict[str, str] = field(default_factory=dict)
    percentiles: Optional[Dict[str, float]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'name': self.name,
            'type': self.metric_type.value,
            'aggregation': self.aggregation.value,
            'value': self.value,
            'timestamp': self.timestamp,
            'window_size': self.window_size,
            'sample_count': self.sample_count,
            'labels': self.labels
        }
        
        if self.percentiles:
            result['percentiles'] = self.percentiles
            
        return result


class MetricBuffer:
    """Thread-safe buffer for metric samples."""
    
    def __init__(self, max_size: int = 10000):
        self.max_size = max_size
        self._samples: deque = deque(maxlen=max_size)
        self._lock = Lock()
        self._total_samples = 0
    
    def add_sample(self, sample: MetricSample):
        """Add a metric sample."""
        with self._lock:
            self._samples.append(sample)
            self._total_samples += 1
    
    def get_samples(
        self,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        clear: bool = False
    ) -> List[MetricSample]:
        """Get samples within time range."""
        with self._lock:
            samples = list(self._samples)
            
            if clear:
                self._samples.clear()
            
            if start_time or end_time:
                filtered = []
                for sample in samples:
                    if start_time and sample.timestamp < start_time:
                        continue
                    if end_time and sample.timestamp > end_time:
                        continue
                    filtered.append(sample)
                return filtered
            
            return samples
    
    def clear(self):
        """Clear all samples."""
        with self._lock:
            self._samples.clear()
    
    @property
    def size(self) -> int:
        """Get current buffer size."""
        with self._lock:
            return len(self._samples)
    
    @property
    def total_samples(self) -> int:
        """Get total samples processed."""
        return self._total_samples


class StatisticalAnalyzer:
    """Advanced statistical analysis for metrics."""
    
    @staticmethod
    def calculate_percentiles(
        values: List[float],
        percentiles: List[float] = [50.0, 90.0, 95.0, 99.0]
    ) -> Dict[str, float]:
        """Calculate percentiles with proper interpolation."""
        if not values:
            return {f"p{p}": 0.0 for p in percentiles}
        
        sorted_values = sorted(values)
        n = len(sorted_values)
        result = {}
        
        for p in percentiles:
            if p <= 0:
                result[f"p{p}"] = sorted_values[0]
            elif p >= 100:
                result[f"p{p}"] = sorted_values[-1]
            else:
                # Linear interpolation method
                index = (p / 100.0) * (n - 1)
                lower_index = int(math.floor(index))
                upper_index = int(math.ceil(index))
                
                if lower_index == upper_index:
                    result[f"p{p}"] = sorted_values[lower_index]
                else:
                    # Interpolate between the two values
                    weight = index - lower_index
                    lower_value = sorted_values[lower_index]
                    upper_value = sorted_values[upper_index]
                    result[f"p{p}"] = lower_value + weight * (upper_value - lower_value)
        
        return result
    
    @staticmethod
    def calculate_histogram_buckets(
        values: List[float],
        bucket_count: int = 20
    ) -> Dict[str, int]:
        """Calculate histogram buckets."""
        if not values:
            return {}
        
        min_val = min(values)
        max_val = max(values)
        
        if min_val == max_val:
            return {str(min_val): len(values)}
        
        bucket_width = (max_val - min_val) / bucket_count
        buckets = {}
        
        for i in range(bucket_count):
            bucket_min = min_val + i * bucket_width
            bucket_max = bucket_min + bucket_width
            bucket_key = f"[{bucket_min:.2f}, {bucket_max:.2f})"
            
            count = sum(1 for v in values if bucket_min <= v < bucket_max)
            buckets[bucket_key] = count
        
        # Handle edge case for maximum value
        if values:
            max_bucket_key = f"[{max_val - bucket_width:.2f}, {max_val:.2f}]"
            if max_bucket_key not in buckets:
                buckets[max_bucket_key] = sum(1 for v in values if v == max_val)
        
        return buckets
    
    @staticmethod
    def detect_anomalies(
        values: List[float],
        threshold_multiplier: float = 2.0
    ) -> List[Tuple[int, float]]:
        """Detect anomalies using z-score method."""
        if len(values) < 3:
            return []
        
        mean_val = statistics.mean(values)
        try:
            std_dev = statistics.stdev(values)
        except statistics.StatisticsError:
            return []
        
        if std_dev == 0:
            return []
        
        anomalies = []
        for i, value in enumerate(values):
            z_score = abs((value - mean_val) / std_dev)
            if z_score > threshold_multiplier:
                anomalies.append((i, value))
        
        return anomalies
    
    @staticmethod
    def calculate_trend(
        timestamps: List[float],
        values: List[float]
    ) -> Dict[str, float]:
        """Calculate trend information using linear regression."""
        if len(values) < 2:
            return {'slope': 0.0, 'correlation': 0.0, 'trend': 'stable'}
        
        n = len(values)
        sum_x = sum(timestamps)
        sum_y = sum(values)
        sum_xy = sum(x * y for x, y in zip(timestamps, values))
        sum_x2 = sum(x * x for x in timestamps)
        sum_y2 = sum(y * y for y in values)
        
        # Calculate slope (linear regression)
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            slope = 0.0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator
        
        # Calculate correlation coefficient
        num = n * sum_xy - sum_x * sum_y
        den = math.sqrt((n * sum_x2 - sum_x**2) * (n * sum_y2 - sum_y**2))
        
        correlation = num / den if den != 0 else 0.0
        
        # Determine trend
        if abs(slope) < 0.001:  # Very small slope
            trend = 'stable'
        elif slope > 0:
            trend = 'increasing'
        else:
            trend = 'decreasing'
        
        return {
            'slope': slope,
            'correlation': correlation,
            'trend': trend
        }


class DistributedMetricsCoordinator:
    """Coordinates metrics collection across multiple nodes."""
    
    def __init__(
        self,
        node_id: str,
        redis_client: Optional['Redis'] = None,
        coordination_key: str = "metrics:coordination",
        heartbeat_interval: float = 30.0,
        node_timeout: float = 90.0
    ):
        self.node_id = node_id
        self.redis_client = redis_client
        self.coordination_key = coordination_key
        self.heartbeat_interval = heartbeat_interval
        self.node_timeout = node_timeout
        
        self._active_nodes: Set[str] = set()
        self._last_heartbeat = 0.0
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._shutdown = False
    
    async def start(self):
        """Start coordination."""
        if self.redis_client and REDIS_AVAILABLE:
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            await self._register_node()
    
    async def stop(self):
        """Stop coordination."""
        self._shutdown = True
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self.redis_client and REDIS_AVAILABLE:
            await self._unregister_node()
    
    async def _heartbeat_loop(self):
        """Heartbeat loop to maintain node registry."""
        while not self._shutdown:
            try:
                await self._send_heartbeat()
                await self._cleanup_inactive_nodes()
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)  # Retry after short delay
    
    async def _register_node(self):
        """Register this node."""
        node_info = {
            'node_id': self.node_id,
            'registered_at': time.time(),
            'last_heartbeat': time.time()
        }
        
        await self.redis_client.hset(
            f"{self.coordination_key}:nodes",
            self.node_id,
            json.dumps(node_info)
        )
        
        self._active_nodes.add(self.node_id)
        logger.info(f"Registered metrics node: {self.node_id}")
    
    async def _unregister_node(self):
        """Unregister this node."""
        await self.redis_client.hdel(
            f"{self.coordination_key}:nodes",
            self.node_id
        )
        
        self._active_nodes.discard(self.node_id)
        logger.info(f"Unregistered metrics node: {self.node_id}")
    
    async def _send_heartbeat(self):
        """Send heartbeat."""
        self._last_heartbeat = time.time()
        
        node_info = {
            'node_id': self.node_id,
            'last_heartbeat': self._last_heartbeat
        }
        
        await self.redis_client.hset(
            f"{self.coordination_key}:nodes",
            self.node_id,
            json.dumps(node_info)
        )
    
    async def _cleanup_inactive_nodes(self):
        """Remove inactive nodes."""
        current_time = time.time()
        node_data = await self.redis_client.hgetall(f"{self.coordination_key}:nodes")
        
        active_nodes = set()
        inactive_nodes = []
        
        for node_id, data in node_data.items():
            if isinstance(node_id, bytes):
                node_id = node_id.decode()
            if isinstance(data, bytes):
                data = data.decode()
            
            try:
                node_info = json.loads(data)
                last_heartbeat = node_info.get('last_heartbeat', 0)
                
                if current_time - last_heartbeat < self.node_timeout:
                    active_nodes.add(node_id)
                else:
                    inactive_nodes.append(node_id)
            except json.JSONDecodeError:
                inactive_nodes.append(node_id)
        
        # Remove inactive nodes
        if inactive_nodes:
            await self.redis_client.hdel(
                f"{self.coordination_key}:nodes",
                *inactive_nodes
            )
            logger.info(f"Removed inactive nodes: {inactive_nodes}")
        
        self._active_nodes = active_nodes
    
    async def get_active_nodes(self) -> Set[str]:
        """Get list of active nodes."""
        await self._cleanup_inactive_nodes()
        return self._active_nodes.copy()
    
    async def coordinate_aggregation(
        self,
        metric_name: str,
        aggregation_window: float
    ) -> bool:
        """Check if this node should perform aggregation for a metric."""
        if not self.redis_client or not REDIS_AVAILABLE:
            return True  # Single node mode
        
        active_nodes = await self.get_active_nodes()
        if not active_nodes:
            return True
        
        # Use consistent hashing to determine coordinator
        sorted_nodes = sorted(active_nodes)
        hash_key = f"{metric_name}:{int(time.time() // aggregation_window)}"
        hash_value = hashlib.sha256(hash_key.encode()).hexdigest()
        hash_int = int(hash_value[:8], 16)
        coordinator_index = hash_int % len(sorted_nodes)
        coordinator = sorted_nodes[coordinator_index]
        
        return coordinator == self.node_id


class MetricsAggregator:
    """Main metrics aggregation engine."""
    
    def __init__(
        self,
        node_id: Optional[str] = None,
        redis_client: Optional['Redis'] = None,
        aggregation_interval: float = 60.0,
        retention_days: int = 30,
        enable_prometheus: bool = True
    ):
        self.node_id = node_id or f"metrics-{uuid.uuid4().hex[:8]}"
        self.redis_client = redis_client
        self.aggregation_interval = aggregation_interval
        self.retention_days = retention_days
        self.enable_prometheus = enable_prometheus
        
        # Core components
        self._buffers: Dict[str, MetricBuffer] = {}
        self._analyzer = StatisticalAnalyzer()
        self._coordinator = DistributedMetricsCoordinator(
            self.node_id,
            redis_client
        ) if redis_client else None
        
        # Prometheus integration
        if enable_prometheus and PROMETHEUS_AVAILABLE:
            self._prometheus_registry = CollectorRegistry()
            self._prometheus_metrics: Dict[str, Any] = {}
        
        # Background tasks
        self._aggregation_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        self._shutdown = False
        
        # Aggregation strategies
        self._strategy_handlers = {
            AggregationStrategy.SUM: self._aggregate_sum,
            AggregationStrategy.AVERAGE: self._aggregate_average,
            AggregationStrategy.MIN: self._aggregate_min,
            AggregationStrategy.MAX: self._aggregate_max,
            AggregationStrategy.COUNT: self._aggregate_count,
            AggregationStrategy.P50: self._aggregate_percentile,
            AggregationStrategy.P90: self._aggregate_percentile,
            AggregationStrategy.P95: self._aggregate_percentile,
            AggregationStrategy.P99: self._aggregate_percentile,
            AggregationStrategy.STDDEV: self._aggregate_stddev,
            AggregationStrategy.RATE_PER_SECOND: self._aggregate_rate
        }
    
    async def start(self):
        """Start the aggregator."""
        if self._coordinator:
            await self._coordinator.start()
        
        self._aggregation_task = asyncio.create_task(self._aggregation_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info(f"Started metrics aggregator: {self.node_id}")
    
    async def stop(self):
        """Stop the aggregator."""
        self._shutdown = True
        
        if self._aggregation_task:
            self._aggregation_task.cancel()
            try:
                await self._aggregation_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._coordinator:
            await self._coordinator.stop()
        
        logger.info(f"Stopped metrics aggregator: {self.node_id}")
    
    def record_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType = MetricType.GAUGE,
        labels: Optional[Dict[str, str]] = None,
        timestamp: Optional[float] = None
    ):
        """Record a metric sample."""
        sample = MetricSample(
            timestamp=timestamp or time.time(),
            value=value,
            labels=labels or {}
        )
        
        # Get or create buffer
        buffer_key = f"{name}:{metric_type.value}"
        if buffer_key not in self._buffers:
            self._buffers[buffer_key] = MetricBuffer()
        
        self._buffers[buffer_key].add_sample(sample)
        
        # Update Prometheus metrics
        if self.enable_prometheus and PROMETHEUS_AVAILABLE:
            self._update_prometheus_metric(name, value, metric_type, labels)
    
    def _update_prometheus_metric(
        self,
        name: str,
        value: float,
        metric_type: MetricType,
        labels: Optional[Dict[str, str]]
    ):
        """Update Prometheus metric."""
        if name not in self._prometheus_metrics:
            if metric_type == MetricType.COUNTER:
                self._prometheus_metrics[name] = Counter(
                    name, f"Counter metric {name}",
                    labelnames=list(labels.keys()) if labels else [],
                    registry=self._prometheus_registry
                )
            elif metric_type == MetricType.GAUGE:
                self._prometheus_metrics[name] = Gauge(
                    name, f"Gauge metric {name}",
                    labelnames=list(labels.keys()) if labels else [],
                    registry=self._prometheus_registry
                )
            elif metric_type == MetricType.HISTOGRAM:
                self._prometheus_metrics[name] = Histogram(
                    name, f"Histogram metric {name}",
                    labelnames=list(labels.keys()) if labels else [],
                    registry=self._prometheus_registry
                )
        
        prom_metric = self._prometheus_metrics[name]
        
        if labels:
            prom_metric = prom_metric.labels(**labels)
        
        if metric_type == MetricType.COUNTER:
            prom_metric.inc(value)
        elif metric_type == MetricType.GAUGE:
            prom_metric.set(value)
        elif metric_type == MetricType.HISTOGRAM:
            prom_metric.observe(value)
    
    async def _aggregation_loop(self):
        """Main aggregation loop."""
        while not self._shutdown:
            try:
                await self._perform_aggregation()
                await asyncio.sleep(self.aggregation_interval)
            except Exception as e:
                logger.error(f"Aggregation error: {e}")
                await asyncio.sleep(5)
    
    async def _perform_aggregation(self):
        """Perform metric aggregation."""
        current_time = time.time()
        window_start = current_time - self.aggregation_interval
        
        for buffer_key, buffer in self._buffers.items():
            metric_name, metric_type_str = buffer_key.split(":", 1)
            metric_type = MetricType(metric_type_str)
            
            # Check if this node should aggregate this metric
            if self._coordinator:
                should_aggregate = await self._coordinator.coordinate_aggregation(
                    metric_name, self.aggregation_interval
                )
                if not should_aggregate:
                    continue
            
            # Get samples for aggregation window
            samples = buffer.get_samples(window_start, current_time, clear=True)
            
            if not samples:
                continue
            
            # Aggregate with different strategies
            strategies = self._get_aggregation_strategies(metric_type)
            
            for strategy in strategies:
                try:
                    aggregated = await self._aggregate_samples(
                        metric_name,
                        metric_type,
                        strategy,
                        samples,
                        self.aggregation_interval
                    )
                    
                    if aggregated:
                        await self._store_aggregated_metric(aggregated)
                except Exception as e:
                    logger.error(f"Error aggregating {metric_name} with {strategy}: {e}")
    
    def _get_aggregation_strategies(self, metric_type: MetricType) -> List[AggregationStrategy]:
        """Get appropriate aggregation strategies for metric type."""
        if metric_type == MetricType.COUNTER:
            return [AggregationStrategy.SUM, AggregationStrategy.RATE_PER_SECOND]
        elif metric_type == MetricType.GAUGE:
            return [
                AggregationStrategy.AVERAGE,
                AggregationStrategy.MIN,
                AggregationStrategy.MAX,
                AggregationStrategy.P95
            ]
        elif metric_type in [MetricType.HISTOGRAM, MetricType.TIMER]:
            return [
                AggregationStrategy.P50,
                AggregationStrategy.P90,
                AggregationStrategy.P95,
                AggregationStrategy.P99,
                AggregationStrategy.AVERAGE,
                AggregationStrategy.MIN,
                AggregationStrategy.MAX
            ]
        else:
            return [AggregationStrategy.AVERAGE]
    
    async def _aggregate_samples(
        self,
        metric_name: str,
        metric_type: MetricType,
        strategy: AggregationStrategy,
        samples: List[MetricSample],
        window_size: float
    ) -> Optional[AggregatedMetric]:
        """Aggregate samples using specified strategy."""
        if not samples:
            return create_partial_success_result(
                data=None,
                error_code="NO_SAMPLES_AVAILABLE",
                message="No metric samples available for aggregation",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No samples for aggregation",
                        details="Empty sample list provided for metric aggregation"
                    )
                ),
                suggestions=["Check data collection", "Verify metric sources", "Review sampling configuration"]
            )
        
        handler = self._strategy_handlers.get(strategy)
        if not handler:
            logger.warning(f"No handler for aggregation strategy: {strategy}")
            return create_partial_success_result(
                data=None,
                error_code="UNSUPPORTED_AGGREGATION_STRATEGY",
                message=f"Unsupported aggregation strategy: {strategy}",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Unsupported strategy",
                        details=f"No handler available for strategy: {strategy}"
                    )
                ),
                suggestions=["Use supported aggregation strategies", "Check strategy configuration", "Verify handler registration"]
            )
        
        try:
            value, percentiles = await handler(samples, strategy)
            
            return AggregatedMetric(
                name=metric_name,
                metric_type=metric_type,
                aggregation=strategy,
                value=value,
                timestamp=time.time(),
                window_size=window_size,
                sample_count=len(samples),
                percentiles=percentiles
            )
        except Exception as e:
            logger.error(f"Error in {strategy} aggregation: {e}")
            return create_failure_result(
                error_code="AGGREGATION_ERROR",
                message=f"Failed to aggregate metrics using {strategy}",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.ERROR,
                        message="Aggregation failed",
                        details=f"Error in {strategy} aggregation: {str(e)}"
                    )
                ),
                suggestions=["Check sample data format", "Verify aggregation logic", "Review error details"]
            )
    
    async def _aggregate_sum(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Sum aggregation."""
        total = sum(sample.value for sample in samples)
        return total, None
    
    async def _aggregate_average(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Average aggregation."""
        if not samples:
            return 0.0, None
        avg = sum(sample.value for sample in samples) / len(samples)
        return avg, None
    
    async def _aggregate_min(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Minimum aggregation."""
        min_val = min(sample.value for sample in samples)
        return min_val, None
    
    async def _aggregate_max(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Maximum aggregation."""
        max_val = max(sample.value for sample in samples)
        return max_val, None
    
    async def _aggregate_count(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Count aggregation."""
        return float(len(samples)), None
    
    async def _aggregate_percentile(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Percentile aggregation."""
        values = [sample.value for sample in samples]
        
        # Extract percentile from strategy
        percentile_map = {
            AggregationStrategy.P50: 50.0,
            AggregationStrategy.P90: 90.0,
            AggregationStrategy.P95: 95.0,
            AggregationStrategy.P99: 99.0
        }
        
        target_percentile = percentile_map.get(strategy, 50.0)
        percentiles = self._analyzer.calculate_percentiles(values, [target_percentile])
        
        return percentiles[f"p{target_percentile}"], percentiles
    
    async def _aggregate_stddev(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Standard deviation aggregation."""
        if len(samples) < 2:
            return 0.0, None
        
        values = [sample.value for sample in samples]
        try:
            stddev = statistics.stdev(values)
            return stddev, None
        except statistics.StatisticsError:
            return 0.0, None
    
    async def _aggregate_rate(self, samples: List[MetricSample], strategy: AggregationStrategy) -> Tuple[float, Optional[Dict[str, float]]]:
        """Rate per second aggregation."""
        if len(samples) < 2:
            return 0.0, None
        
        # Sort by timestamp
        sorted_samples = sorted(samples, key=lambda s: s.timestamp)
        
        # Calculate total value change and time span
        total_change = sorted_samples[-1].value - sorted_samples[0].value
        time_span = sorted_samples[-1].timestamp - sorted_samples[0].timestamp
        
        if time_span <= 0:
            return 0.0, None
        
        rate = total_change / time_span
        return max(0.0, rate), None  # Rates shouldn't be negative
    
    async def _store_aggregated_metric(self, metric: AggregatedMetric):
        """Store aggregated metric."""
        if self.redis_client and REDIS_AVAILABLE:
            # Store in Redis with expiration
            key = f"metrics:aggregated:{metric.name}:{metric.aggregation.value}"
            data = json.dumps(metric.to_dict())
            
            # Use sorted set for time-based queries
            timestamp_score = metric.timestamp
            await self.redis_client.zadd(key, {data: timestamp_score})
            
            # Set expiration
            expiry_seconds = self.retention_days * 24 * 3600
            await self.redis_client.expire(key, expiry_seconds)
    
    async def _cleanup_loop(self):
        """Cleanup old metrics data."""
        while not self._shutdown:
            try:
                await self._cleanup_old_data()
                await asyncio.sleep(3600)  # Run hourly
            except Exception as e:
                logger.error(f"Cleanup error: {e}")
                await asyncio.sleep(300)  # Retry after 5 minutes
    
    async def _cleanup_old_data(self):
        """Remove old metric data."""
        if not self.redis_client or not REDIS_AVAILABLE:
            return
        
        cutoff_time = time.time() - (self.retention_days * 24 * 3600)
        
        # Find all aggregated metric keys
        pattern = "metrics:aggregated:*"
        keys = await self.redis_client.keys(pattern)
        
        for key in keys:
            # Remove old entries from sorted sets
            removed = await self.redis_client.zremrangebyscore(key, 0, cutoff_time)
            if removed > 0:
                logger.debug(f"Cleaned up {removed} old entries from {key}")
    
    async def query_metrics(
        self,
        metric_name: str,
        aggregation: AggregationStrategy,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Query aggregated metrics."""
        if not self.redis_client or not REDIS_AVAILABLE:
            return []
        
        key = f"metrics:aggregated:{metric_name}:{aggregation.value}"
        
        # Default time range
        if end_time is None:
            end_time = time.time()
        if start_time is None:
            start_time = end_time - 3600  # Last hour
        
        # Query from Redis sorted set
        raw_data = await self.redis_client.zrangebyscore(
            key, start_time, end_time, withscores=True
        )
        
        results = []
        for data, score in raw_data[-limit:]:  # Get latest entries
            try:
                if isinstance(data, bytes):
                    data = data.decode()
                metric_data = json.loads(data)
                results.append(metric_data)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse metric data: {data}")
        
        return results
    
    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        if not self.enable_prometheus or not PROMETHEUS_AVAILABLE:
            return ""
        
        return generate_latest(self._prometheus_registry).decode()
    
    async def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time aggregator statistics."""
        stats = {
            'node_id': self.node_id,
            'active_buffers': len(self._buffers),
            'total_samples': sum(buffer.total_samples for buffer in self._buffers.values()),
            'buffer_sizes': {
                name: buffer.size for name, buffer in self._buffers.items()
            }
        }
        
        if self._coordinator:
            active_nodes = await self._coordinator.get_active_nodes()
            stats['active_nodes'] = list(active_nodes)
            stats['cluster_size'] = len(active_nodes)
        
        return stats