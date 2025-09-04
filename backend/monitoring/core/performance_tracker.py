"""
Production performance tracking and monitoring system.
Tracks application performance, response times, throughput, and resource utilization.
"""

import asyncio
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Union, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics
import json
import logging
import functools
from contextlib import asynccontextmanager, contextmanager
import weakref

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)


class PerformanceLevel(Enum):
    """Performance classification levels"""
    EXCELLENT = "excellent"  # < p50
    GOOD = "good"           # p50 - p75
    FAIR = "fair"           # p75 - p90
    POOR = "poor"           # p90 - p95
    CRITICAL = "critical"   # > p95


class MetricAggregation(Enum):
    """Metric aggregation methods"""
    AVERAGE = "average"
    SUM = "sum"
    COUNT = "count"
    MIN = "min"
    MAX = "max"
    PERCENTILE = "percentile"
    RATE = "rate"


@dataclass
class PerformanceMetric:
    """Individual performance measurement"""
    name: str
    value: float
    timestamp: datetime
    duration_ms: Optional[float] = None
    labels: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceWindow:
    """Performance metrics for a time window"""
    start_time: datetime
    end_time: datetime
    metrics: List[PerformanceMetric]
    
    @property
    def duration(self) -> timedelta:
        return self.end_time - self.start_time
    
    def get_values(self, metric_name: str) -> List[float]:
        """Get all values for a specific metric"""
        return [m.value for m in self.metrics if m.name == metric_name]
    
    def get_durations(self, metric_name: str) -> List[float]:
        """Get all durations for a specific metric"""
        return [m.duration_ms for m in self.metrics 
                if m.name == metric_name and m.duration_ms is not None]


@dataclass
class PerformanceStats:
    """Aggregated performance statistics"""
    metric_name: str
    count: int
    min_value: float
    max_value: float
    mean: float
    median: float
    std_dev: float
    percentile_50: float
    percentile_75: float
    percentile_90: float
    percentile_95: float
    percentile_99: float
    rate_per_second: float
    total_duration: float
    
    @property
    def performance_level(self) -> PerformanceLevel:
        """Classify performance based on percentiles"""
        if self.mean <= self.percentile_50:
            return PerformanceLevel.EXCELLENT
        elif self.mean <= self.percentile_75:
            return PerformanceLevel.GOOD
        elif self.mean <= self.percentile_90:
            return PerformanceLevel.FAIR
        elif self.mean <= self.percentile_95:
            return PerformanceLevel.POOR
        else:
            return PerformanceLevel.CRITICAL


class PerformanceTracker:
    """High-performance metrics tracking system"""
    
    def __init__(self, 
                 max_history_minutes: int = 1440,  # 24 hours
                 window_size_seconds: int = 60,    # 1 minute windows
                 max_metrics_per_window: int = 10000):
        self.max_history_minutes = max_history_minutes
        self.window_size_seconds = window_size_seconds
        self.max_metrics_per_window = max_metrics_per_window
        
        # Thread-safe storage
        self._lock = threading.RLock()
        self._metrics: deque = deque(maxlen=max_metrics_per_window * max_history_minutes)
        self._metric_counts: Dict[str, int] = defaultdict(int)
        self._metric_sums: Dict[str, float] = defaultdict(float)
        self._metric_windows: Dict[int, PerformanceWindow] = {}
        
        # Performance tracking
        self._active_operations: Dict[str, float] = {}
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._error_counts: Dict[str, int] = defaultdict(int)
        
        # Background cleanup
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Statistics cache
        self._stats_cache: Dict[str, Tuple[datetime, PerformanceStats]] = {}
        self._cache_ttl = timedelta(seconds=30)
    
    async def start(self):
        """Start the performance tracker"""
        if self._running:
            return
        
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Performance tracker started")
    
    async def stop(self):
        """Stop the performance tracker"""
        if not self._running:
            return
        
        self._running = False
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Performance tracker stopped")
    
    def record_metric(self, 
                     name: str, 
                     value: float,
                     duration_ms: Optional[float] = None,
                     labels: Optional[Dict[str, str]] = None,
                     metadata: Optional[Dict[str, Any]] = None):
        """Record a performance metric"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            timestamp=datetime.now(),
            duration_ms=duration_ms,
            labels=labels or {},
            metadata=metadata or {}
        )
        
        with self._lock:
            self._metrics.append(metric)
            self._metric_counts[name] += 1
            self._metric_sums[name] += value
            
            # Invalidate cache for this metric
            if name in self._stats_cache:
                del self._stats_cache[name]
    
    def record_operation_start(self, operation_id: str) -> str:
        """Start tracking an operation"""
        with self._lock:
            self._active_operations[operation_id] = time.time()
        return operation_id
    
    def record_operation_end(self, 
                           operation_id: str, 
                           metric_name: str,
                           success: bool = True,
                           value: float = 1.0,
                           labels: Optional[Dict[str, str]] = None,
                           metadata: Optional[Dict[str, Any]] = None):
        """End tracking an operation and record metrics"""
        with self._lock:
            start_time = self._active_operations.pop(operation_id, None)
            
            if start_time is None:
                logger.warning(f"Operation {operation_id} was not found in active operations")
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=0.0,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="Operation not found",
                            details=f"Operation {operation_id} was not found in active operations",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="OPERATION_NOT_FOUND",
                    error_message=f"Operation {operation_id} was not found in active operations",
                    details=f"Operation {operation_id} was not found in active operations",
                    suggestions=["Check operation ID", "Verify operation tracking", "Ensure operation was started"]
                )
            
            duration_ms = (time.time() - start_time) * 1000
            
            # Record the metric
            self.record_metric(
                name=metric_name,
                value=value,
                duration_ms=duration_ms,
                labels=labels,
                metadata=metadata
            )
            
            # Update operation counts
            self._operation_counts[metric_name] += 1
            if not success:
                self._error_counts[metric_name] += 1
            
            return create_success_result(
                fallback_data=FallbackData(
                    data=duration_ms,
                    health_status=HealthStatus(
                        level=HealthLevel.HEALTHY,
                        message="Operation completed successfully",
                        details=f"Operation {operation_id} completed in {duration_ms:.2f}ms",
                        timestamp=datetime.now().isoformat()
                    )
                )
            )
    
    @contextmanager
    def track_operation(self, 
                       metric_name: str,
                       value: float = 1.0,
                       labels: Optional[Dict[str, str]] = None,
                       metadata: Optional[Dict[str, Any]] = None):
        """Context manager for tracking operations"""
        operation_id = f"{metric_name}_{id(threading.current_thread())}_{time.time()}"
        success = True
        
        try:
            self.record_operation_start(operation_id)
            yield operation_id
        except Exception as e:
            success = False
            if metadata is None:
                metadata = {}
            metadata['error'] = str(e)
            raise
        finally:
            self.record_operation_end(
                operation_id=operation_id,
                metric_name=metric_name,
                success=success,
                value=value,
                labels=labels,
                metadata=metadata
            )
    
    @asynccontextmanager
    async def track_async_operation(self,
                                  metric_name: str,
                                  value: float = 1.0,
                                  labels: Optional[Dict[str, str]] = None,
                                  metadata: Optional[Dict[str, Any]] = None):
        """Async context manager for tracking operations"""
        operation_id = f"{metric_name}_{id(asyncio.current_task())}_{time.time()}"
        success = True
        
        try:
            self.record_operation_start(operation_id)
            yield operation_id
        except Exception as e:
            success = False
            if metadata is None:
                metadata = {}
            metadata['error'] = str(e)
            raise
        finally:
            self.record_operation_end(
                operation_id=operation_id,
                metric_name=metric_name,
                success=success,
                value=value,
                labels=labels,
                metadata=metadata
            )
    
    def get_metric_stats(self, 
                        metric_name: str, 
                        time_window: Optional[timedelta] = None) -> Optional[PerformanceStats]:
        """Get aggregated statistics for a metric"""
        # Check cache first
        with self._lock:
            cache_key = f"{metric_name}_{time_window}"
            if cache_key in self._stats_cache:
                cached_time, cached_stats = self._stats_cache[cache_key]
                if datetime.now() - cached_time < self._cache_ttl:
                    return cached_stats
        
        # Filter metrics by time window
        now = datetime.now()
        cutoff_time = now - (time_window or timedelta(hours=1))
        
        with self._lock:
            filtered_metrics = [
                m for m in self._metrics 
                if m.name == metric_name and m.timestamp >= cutoff_time
            ]
        
        if not filtered_metrics:
            # Return fallback performance stats when no metrics available
            fallback_data = FallbackData(
                data=PerformanceStats(
                    metric_name=metric_name,
                    count=0,
                    min_value=0.0,
                    max_value=0.0,
                    mean=0.0,
                    median=0.0,
                    std_dev=0.0,
                    percentile_50=0.0,
                    percentile_75=0.0,
                    percentile_90=0.0,
                    percentile_95=0.0,
                    percentile_99=0.0,
                    rate_per_second=0.0,
                    total_duration=0.0
                ),
                source="performance_stats_fallback",
                confidence=0.0,
                metadata={"metric_name": metric_name, "reason": "No metrics available"}
            )
            
            return create_partial_success_result(
                data=fallback_data.data,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="No metrics available for performance calculation",
                    fallback_available=True
                ),
                suggestions=[
                    "No metrics available",
                    "Check metrics collection",
                    "Verify monitoring configuration",
                    "Use fallback performance stats"
                ]
            ).data
        
        # Calculate statistics
        values = [m.value for m in filtered_metrics]
        durations = [m.duration_ms for m in filtered_metrics if m.duration_ms is not None]
        
        if not values:
            # Return fallback performance stats when no values available
            fallback_data = FallbackData(
                data=PerformanceStats(
                    metric_name=metric_name,
                    count=0,
                    min_value=0.0,
                    max_value=0.0,
                    mean=0.0,
                    median=0.0,
                    std_dev=0.0,
                    percentile_50=0.0,
                    percentile_75=0.0,
                    percentile_90=0.0,
                    percentile_95=0.0,
                    percentile_99=0.0,
                    rate_per_second=0.0,
                    total_duration=0.0
                ),
                source="performance_values_fallback",
                confidence=0.0,
                metadata={"metric_name": metric_name, "reason": "No values available"}
            )
            
            return create_partial_success_result(
                data=fallback_data.data,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="No values available for performance calculation",
                    fallback_available=True
                ),
                suggestions=[
                    "No values available",
                    "Check metrics collection",
                    "Verify monitoring configuration",
                    "Use fallback performance stats"
                ]
            ).data
        
        # Use numpy for better performance if available
        if NUMPY_AVAILABLE:
            values_array = np.array(values)
            stats = PerformanceStats(
                metric_name=metric_name,
                count=len(values),
                min_value=float(np.min(values_array)),
                max_value=float(np.max(values_array)),
                mean=float(np.mean(values_array)),
                median=float(np.median(values_array)),
                std_dev=float(np.std(values_array)),
                percentile_50=float(np.percentile(values_array, 50)),
                percentile_75=float(np.percentile(values_array, 75)),
                percentile_90=float(np.percentile(values_array, 90)),
                percentile_95=float(np.percentile(values_array, 95)),
                percentile_99=float(np.percentile(values_array, 99)),
                rate_per_second=len(values) / (time_window or timedelta(hours=1)).total_seconds(),
                total_duration=sum(durations) if durations else 0.0
            )
        else:
            # Fallback to standard library
            sorted_values = sorted(values)
            stats = PerformanceStats(
                metric_name=metric_name,
                count=len(values),
                min_value=min(values),
                max_value=max(values),
                mean=statistics.mean(values),
                median=statistics.median(values),
                std_dev=statistics.stdev(values) if len(values) > 1 else 0.0,
                percentile_50=sorted_values[int(len(sorted_values) * 0.50)],
                percentile_75=sorted_values[int(len(sorted_values) * 0.75)],
                percentile_90=sorted_values[int(len(sorted_values) * 0.90)],
                percentile_95=sorted_values[int(len(sorted_values) * 0.95)],
                percentile_99=sorted_values[int(len(sorted_values) * 0.99)],
                rate_per_second=len(values) / (time_window or timedelta(hours=1)).total_seconds(),
                total_duration=sum(durations) if durations else 0.0
            )
        
        # Cache the result
        with self._lock:
            self._stats_cache[cache_key] = (datetime.now(), stats)
        
        return stats
    
    def get_performance_summary(self, 
                              time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get performance summary for all metrics"""
        time_window = time_window or timedelta(hours=1)
        now = datetime.now()
        cutoff_time = now - time_window
        
        with self._lock:
            # Get unique metric names
            metric_names = set(m.name for m in self._metrics if m.timestamp >= cutoff_time)
            
            summary = {
                'time_window': {
                    'start': cutoff_time.isoformat(),
                    'end': now.isoformat(),
                    'duration_seconds': time_window.total_seconds()
                },
                'metrics': {},
                'totals': {
                    'total_operations': sum(1 for m in self._metrics if m.timestamp >= cutoff_time),
                    'unique_metrics': len(metric_names),
                    'error_rate': 0.0
                }
            }
            
            total_operations = 0
            total_errors = 0
            
            for metric_name in metric_names:
                stats = self.get_metric_stats(metric_name, time_window)
                if stats:
                    summary['metrics'][metric_name] = {
                        'count': stats.count,
                        'rate_per_second': stats.rate_per_second,
                        'avg_duration_ms': stats.mean,
                        'p95_duration_ms': stats.percentile_95,
                        'performance_level': stats.performance_level.value,
                        'error_count': self._error_counts.get(metric_name, 0)
                    }
                    
                    total_operations += stats.count
                    total_errors += self._error_counts.get(metric_name, 0)
            
            if total_operations > 0:
                summary['totals']['error_rate'] = total_errors / total_operations
        
        return summary
    
    def get_slow_operations(self, 
                          percentile_threshold: float = 95.0,
                          time_window: Optional[timedelta] = None) -> List[Dict[str, Any]]:
        """Get operations that are performing slowly"""
        time_window = time_window or timedelta(hours=1)
        now = datetime.now()
        cutoff_time = now - time_window
        
        slow_operations = []
        
        with self._lock:
            metric_names = set(m.name for m in self._metrics if m.timestamp >= cutoff_time)
        
        for metric_name in metric_names:
            stats = self.get_metric_stats(metric_name, time_window)
            if stats and stats.count > 10:  # Only consider metrics with sufficient data
                threshold_value = getattr(stats, f'percentile_{int(percentile_threshold)}')
                
                if stats.mean > threshold_value * 1.5:  # Mean significantly above threshold
                    slow_operations.append({
                        'metric_name': metric_name,
                        'mean_duration_ms': stats.mean,
                        'p95_duration_ms': stats.percentile_95,
                        'count': stats.count,
                        'performance_level': stats.performance_level.value,
                        'slowdown_factor': stats.mean / threshold_value
                    })
        
        return sorted(slow_operations, key=lambda x: x['slowdown_factor'], reverse=True)
    
    def get_error_analysis(self, 
                          time_window: Optional[timedelta] = None) -> Dict[str, Any]:
        """Get error analysis and patterns"""
        time_window = time_window or timedelta(hours=1)
        now = datetime.now()
        cutoff_time = now - time_window
        
        with self._lock:
            # Get metrics with errors
            error_metrics = []
            for m in self._metrics:
                if (m.timestamp >= cutoff_time and 
                    m.metadata and 
                    'error' in m.metadata):
                    error_metrics.append(m)
        
        if not error_metrics:
            return {
                'total_errors': 0,
                'error_rate': 0.0,
                'error_patterns': {}
            }
        
        # Analyze error patterns
        error_patterns = defaultdict(int)
        error_by_metric = defaultdict(int)
        
        for metric in error_metrics:
            error_msg = str(metric.metadata.get('error', ''))
            
            # Classify error types
            if 'timeout' in error_msg.lower():
                error_patterns['timeout'] += 1
            elif 'connection' in error_msg.lower():
                error_patterns['connection'] += 1
            elif 'permission' in error_msg.lower() or 'access' in error_msg.lower():
                error_patterns['permission'] += 1
            elif 'memory' in error_msg.lower():
                error_patterns['memory'] += 1
            else:
                error_patterns['other'] += 1
            
            error_by_metric[metric.name] += 1
        
        total_operations = len([m for m in self._metrics if m.timestamp >= cutoff_time])
        
        return {
            'total_errors': len(error_metrics),
            'error_rate': len(error_metrics) / max(total_operations, 1),
            'error_patterns': dict(error_patterns),
            'errors_by_metric': dict(error_by_metric),
            'top_error_metrics': sorted(
                error_by_metric.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        }
    
    async def _cleanup_loop(self):
        """Background cleanup task"""
        try:
            while self._running:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                self._cleanup_old_metrics()
                self._cleanup_cache()
                
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in performance tracker cleanup: {e}")
    
    def _cleanup_old_metrics(self):
        """Remove old metrics beyond retention period"""
        cutoff_time = datetime.now() - timedelta(minutes=self.max_history_minutes)
        
        with self._lock:
            # Convert to list to avoid modifying deque during iteration
            metrics_list = list(self._metrics)
            self._metrics.clear()
            
            # Re-add only recent metrics
            for metric in metrics_list:
                if metric.timestamp >= cutoff_time:
                    self._metrics.append(metric)
            
            logger.debug(f"Cleaned up old metrics, kept {len(self._metrics)} metrics")
    
    def _cleanup_cache(self):
        """Clean up expired cache entries"""
        now = datetime.now()
        
        with self._lock:
            expired_keys = [
                key for key, (timestamp, _) in self._stats_cache.items()
                if now - timestamp > self._cache_ttl
            ]
            
            for key in expired_keys:
                del self._stats_cache[key]
            
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")


def performance_monitor(metric_name: str, 
                       tracker: PerformanceTracker,
                       labels: Optional[Dict[str, str]] = None):
    """Decorator for monitoring function performance"""
    def decorator(func):
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                async with tracker.track_async_operation(
                    metric_name=metric_name,
                    labels=labels
                ):
                    return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                with tracker.track_operation(
                    metric_name=metric_name,
                    labels=labels
                ):
                    return func(*args, **kwargs)
            return sync_wrapper
    return decorator