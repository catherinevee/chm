"""
Production API endpoints for monitoring, health checks, and metrics.
Provides comprehensive monitoring endpoints for operational visibility.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from fastapi import FastAPI, HTTPException, Depends, Response, Query, Path
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, Field, validator
import logging
from enum import Enum

# Import our monitoring components
from backend.monitoring.health_monitor import (
    HealthMonitor, MetricsCollector, HealthStatus, 
    HealthCheckResult, SystemMetrics
)
from backend.monitoring.performance_tracker import (
    PerformanceTracker, PerformanceStats, PerformanceLevel
)

logger = logging.getLogger(__name__)


class HealthStatusResponse(BaseModel):
    """Health status API response"""
    status: str = Field(..., description="Overall health status")
    timestamp: str = Field(..., description="Check timestamp")
    checks: Dict[str, Dict[str, Any]] = Field(..., description="Individual check results")
    critical_failures: List[str] = Field(..., description="List of critical failures")
    degraded_checks: List[str] = Field(..., description="List of degraded checks")
    system_metrics: Optional[Dict[str, Any]] = Field(None, description="Latest system metrics")


class MetricDefinitionRequest(BaseModel):
    """Request to define a custom metric"""
    name: str = Field(..., description="Metric name")
    metric_type: str = Field(..., description="Metric type (counter, gauge, histogram)")
    description: str = Field("", description="Metric description")
    labels: List[str] = Field(default_factory=list, description="Metric labels")
    buckets: Optional[List[float]] = Field(None, description="Histogram buckets")
    
    @validator('metric_type')
    def validate_metric_type(cls, v):
        valid_types = ['counter', 'gauge', 'histogram', 'summary']
        if v not in valid_types:
            raise ValueError(f"metric_type must be one of {valid_types}")
        return v


class MetricRecordRequest(BaseModel):
    """Request to record a metric value"""
    name: str = Field(..., description="Metric name")
    value: float = Field(..., description="Metric value")
    labels: Optional[Dict[str, str]] = Field(None, description="Metric labels")
    timestamp: Optional[str] = Field(None, description="Custom timestamp (ISO format)")


class PerformanceStatsResponse(BaseModel):
    """Performance statistics API response"""
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
    performance_level: str


class MonitoringAPI:
    """Production monitoring API endpoints"""
    
    def __init__(self, 
                 health_monitor: HealthMonitor,
                 performance_tracker: PerformanceTracker,
                 metrics_collector: Optional[MetricsCollector] = None):
        self.health_monitor = health_monitor
        self.performance_tracker = performance_tracker
        self.metrics_collector = metrics_collector or health_monitor.metrics_collector
        
        # FastAPI app for monitoring endpoints
        self.app = FastAPI(
            title="CHM Monitoring API",
            description="Catalyst Health Monitoring API for CHM System",
            version="1.0.0",
            docs_url="/monitoring/docs",
            redoc_url="/monitoring/redoc"
        )
        
        self._setup_routes()
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/health", 
                     response_model=HealthStatusResponse,
                     summary="System Health Check",
                     description="Get comprehensive system health status including all checks and metrics")
        async def get_health():
            """Get system health status"""
            try:
                health_data = await self.health_monitor.get_health_status()
                
                return HealthStatusResponse(
                    status=health_data['status'],
                    timestamp=health_data['timestamp'],
                    checks=health_data['checks'],
                    critical_failures=health_data['critical_failures'],
                    degraded_checks=health_data['degraded_checks'],
                    system_metrics=health_data.get('system_metrics')
                )
            except Exception as e:
                logger.error(f"Error getting health status: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/health/{check_name}",
                     summary="Individual Health Check",
                     description="Get status of a specific health check")
        async def get_health_check(check_name: str = Path(..., description="Name of the health check")):
            """Get individual health check status"""
            try:
                health_data = await self.health_monitor.get_health_status()
                
                if check_name not in health_data['checks']:
                    raise HTTPException(status_code=404, detail=f"Health check '{check_name}' not found")
                
                check_data = health_data['checks'][check_name]
                
                return {
                    'name': check_name,
                    'status': check_data['status'],
                    'last_run': check_data['last_run'],
                    'consecutive_failures': check_data['consecutive_failures'],
                    'critical': check_data['critical'],
                    'description': check_data['description']
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error getting health check {check_name}: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/ready",
                     summary="Readiness Probe",
                     description="Kubernetes-style readiness probe")
        async def get_readiness():
            """Readiness probe for Kubernetes"""
            try:
                health_data = await self.health_monitor.get_health_status()
                ready = health_data['status'] in ['healthy', 'degraded']
                
                if ready:
                    return JSONResponse(
                        content={
                            'ready': True,
                            'status': health_data['status'],
                            'timestamp': datetime.now().isoformat()
                        },
                        status_code=200
                    )
                else:
                    return JSONResponse(
                        content={
                            'ready': False,
                            'status': health_data['status'],
                            'critical_failures': health_data['critical_failures'],
                            'timestamp': datetime.now().isoformat()
                        },
                        status_code=503
                    )
            except Exception as e:
                logger.error(f"Error in readiness probe: {e}")
                return JSONResponse(
                    content={
                        'ready': False,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    },
                    status_code=503
                )
        
        @self.app.get("/live",
                     summary="Liveness Probe",
                     description="Kubernetes-style liveness probe")
        async def get_liveness():
            """Liveness probe for Kubernetes"""
            try:
                # Simple liveness check - just verify the monitoring system is running
                if self.health_monitor._running:
                    return JSONResponse(
                        content={
                            'alive': True,
                            'timestamp': datetime.now().isoformat()
                        },
                        status_code=200
                    )
                else:
                    return JSONResponse(
                        content={
                            'alive': False,
                            'message': 'Health monitor not running',
                            'timestamp': datetime.now().isoformat()
                        },
                        status_code=503
                    )
            except Exception as e:
                logger.error(f"Error in liveness probe: {e}")
                return JSONResponse(
                    content={
                        'alive': False,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    },
                    status_code=503
                )
        
        @self.app.get("/metrics",
                     response_class=PlainTextResponse,
                     summary="Prometheus Metrics",
                     description="Get metrics in Prometheus text format")
        async def get_metrics():
            """Get Prometheus-format metrics"""
            try:
                metrics_text = await self.health_monitor.get_metrics()
                return PlainTextResponse(
                    content=metrics_text,
                    media_type="text/plain; version=0.0.4; charset=utf-8"
                )
            except Exception as e:
                logger.error(f"Error getting metrics: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.post("/metrics/define",
                      summary="Define Custom Metric",
                      description="Define a new custom metric for collection")
        async def define_metric(request: MetricDefinitionRequest):
            """Define a custom metric"""
            try:
                from backend.monitoring.health_monitor import MetricDefinition, MetricType
                
                # Convert string to enum
                metric_type_map = {
                    'counter': MetricType.COUNTER,
                    'gauge': MetricType.GAUGE,
                    'histogram': MetricType.HISTOGRAM,
                    'summary': MetricType.SUMMARY
                }
                
                definition = MetricDefinition(
                    name=request.name,
                    metric_type=metric_type_map[request.metric_type],
                    description=request.description,
                    labels=request.labels,
                    buckets=request.buckets
                )
                
                success = self.metrics_collector.define_metric(definition)
                
                if success:
                    return {
                        'success': True,
                        'message': f"Metric '{request.name}' defined successfully"
                    }
                else:
                    raise HTTPException(status_code=400, detail="Failed to define metric")
                    
            except Exception as e:
                logger.error(f"Error defining metric: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/metrics/record",
                      summary="Record Metric Value",
                      description="Record a value for a defined metric")
        async def record_metric(request: MetricRecordRequest):
            """Record a metric value with proper type detection"""
            try:
                # Handle custom timestamp if provided
                timestamp = None
                if request.timestamp:
                    timestamp = datetime.fromisoformat(request.timestamp.replace('Z', '+00:00'))
                
                # Determine metric type from definition
                metric_name = request.name
                success = False
                
                # Check if metric is defined and get its type
                if metric_name in self.metrics_collector._metric_definitions:
                    metric_def = self.metrics_collector._metric_definitions[metric_name]
                    metric_type = metric_def.metric_type
                    
                    # Route to appropriate recording method based on type
                    from backend.monitoring.health_monitor import MetricType
                    
                    if metric_type == MetricType.COUNTER:
                        # Counters can only increment
                        if request.value < 0:
                            raise HTTPException(
                                status_code=400, 
                                detail="Counter values must be non-negative"
                            )
                        success = self.metrics_collector.increment_counter(
                            name=metric_name,
                            amount=request.value,
                            labels=request.labels
                        )
                    elif metric_type == MetricType.GAUGE:
                        # Gauges can be set to any value
                        success = self.metrics_collector.set_gauge(
                            name=metric_name,
                            value=request.value,
                            labels=request.labels
                        )
                    elif metric_type == MetricType.HISTOGRAM:
                        # Histograms record observations
                        success = self.metrics_collector.observe_histogram(
                            name=metric_name,
                            value=request.value,
                            labels=request.labels
                        )
                    elif metric_type == MetricType.SUMMARY:
                        # Summary is similar to histogram
                        success = self.metrics_collector.observe_histogram(
                            name=metric_name,
                            value=request.value,
                            labels=request.labels
                        )
                    else:
                        raise HTTPException(
                            status_code=400,
                            detail=f"Unknown metric type for '{metric_name}'"
                        )
                else:
                    # Metric not defined, try to auto-detect based on name patterns
                    if any(pattern in metric_name.lower() for pattern in 
                          ['_total', '_count', 'counter', 'requests', 'errors']):
                        # Likely a counter
                        if request.value < 0:
                            raise HTTPException(
                                status_code=400,
                                detail="Counter-like metrics must have non-negative values"
                            )
                        # Auto-define as counter
                        from backend.monitoring.health_monitor import MetricDefinition, MetricType
                        definition = MetricDefinition(
                            name=metric_name,
                            metric_type=MetricType.COUNTER,
                            description=f"Auto-defined counter: {metric_name}",
                            labels=list(request.labels.keys()) if request.labels else []
                        )
                        self.metrics_collector.define_metric(definition)
                        success = self.metrics_collector.increment_counter(
                            name=metric_name,
                            amount=request.value,
                            labels=request.labels
                        )
                    elif any(pattern in metric_name.lower() for pattern in
                            ['duration', 'latency', 'time', '_ms', '_seconds']):
                        # Likely a histogram for timing
                        from backend.monitoring.health_monitor import MetricDefinition, MetricType
                        definition = MetricDefinition(
                            name=metric_name,
                            metric_type=MetricType.HISTOGRAM,
                            description=f"Auto-defined histogram: {metric_name}",
                            labels=list(request.labels.keys()) if request.labels else []
                        )
                        self.metrics_collector.define_metric(definition)
                        success = self.metrics_collector.observe_histogram(
                            name=metric_name,
                            value=request.value,
                            labels=request.labels
                        )
                    else:
                        # Default to gauge for unknown metrics
                        from backend.monitoring.health_monitor import MetricDefinition, MetricType
                        definition = MetricDefinition(
                            name=metric_name,
                            metric_type=MetricType.GAUGE,
                            description=f"Auto-defined gauge: {metric_name}",
                            labels=list(request.labels.keys()) if request.labels else []
                        )
                        self.metrics_collector.define_metric(definition)
                        success = self.metrics_collector.set_gauge(
                            name=metric_name,
                            value=request.value,
                            labels=request.labels
                        )
                
                if success:
                    return {
                        'success': True,
                        'message': f"Metric '{request.name}' recorded successfully",
                        'auto_defined': metric_name not in self.metrics_collector._metric_definitions
                    }
                else:
                    raise HTTPException(status_code=400, detail="Failed to record metric")
                    
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error recording metric: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/performance/summary",
                     summary="Performance Summary",
                     description="Get overall performance summary for all metrics")
        async def get_performance_summary(
            hours: float = Query(1.0, description="Time window in hours", ge=0.1, le=24.0)
        ):
            """Get performance summary"""
            try:
                time_window = timedelta(hours=hours)
                summary = self.performance_tracker.get_performance_summary(time_window)
                return summary
            except Exception as e:
                logger.error(f"Error getting performance summary: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/performance/stats/{metric_name}",
                     response_model=PerformanceStatsResponse,
                     summary="Performance Statistics",
                     description="Get detailed performance statistics for a specific metric")
        async def get_performance_stats(
            metric_name: str = Path(..., description="Name of the metric"),
            hours: float = Query(1.0, description="Time window in hours", ge=0.1, le=24.0)
        ):
            """Get performance statistics for a specific metric"""
            try:
                time_window = timedelta(hours=hours)
                stats = self.performance_tracker.get_metric_stats(metric_name, time_window)
                
                if stats is None:
                    raise HTTPException(
                        status_code=404, 
                        detail=f"No performance data found for metric '{metric_name}'"
                    )
                
                return PerformanceStatsResponse(
                    metric_name=stats.metric_name,
                    count=stats.count,
                    min_value=stats.min_value,
                    max_value=stats.max_value,
                    mean=stats.mean,
                    median=stats.median,
                    std_dev=stats.std_dev,
                    percentile_50=stats.percentile_50,
                    percentile_75=stats.percentile_75,
                    percentile_90=stats.percentile_90,
                    percentile_95=stats.percentile_95,
                    percentile_99=stats.percentile_99,
                    rate_per_second=stats.rate_per_second,
                    total_duration=stats.total_duration,
                    performance_level=stats.performance_level.value
                )
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error getting performance stats for {metric_name}: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/performance/slow",
                     summary="Slow Operations",
                     description="Get operations that are performing below expected levels")
        async def get_slow_operations(
            percentile: float = Query(95.0, description="Percentile threshold", ge=50.0, le=99.9),
            hours: float = Query(1.0, description="Time window in hours", ge=0.1, le=24.0)
        ):
            """Get slow-performing operations"""
            try:
                time_window = timedelta(hours=hours)
                slow_ops = self.performance_tracker.get_slow_operations(percentile, time_window)
                return {
                    'time_window_hours': hours,
                    'percentile_threshold': percentile,
                    'slow_operations_count': len(slow_ops),
                    'slow_operations': slow_ops
                }
            except Exception as e:
                logger.error(f"Error getting slow operations: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/performance/errors",
                     summary="Error Analysis",
                     description="Get error analysis and patterns")
        async def get_error_analysis(
            hours: float = Query(1.0, description="Time window in hours", ge=0.1, le=24.0)
        ):
            """Get error analysis"""
            try:
                time_window = timedelta(hours=hours)
                error_analysis = self.performance_tracker.get_error_analysis(time_window)
                return {
                    'time_window_hours': hours,
                    **error_analysis
                }
            except Exception as e:
                logger.error(f"Error getting error analysis: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/system/resources",
                     summary="System Resources",
                     description="Get current system resource utilization")
        async def get_system_resources():
            """Get system resource information"""
            try:
                health_data = await self.health_monitor.get_health_status()
                system_metrics = health_data.get('system_metrics')
                
                if not system_metrics:
                    raise HTTPException(status_code=404, detail="System metrics not available")
                
                return {
                    'timestamp': system_metrics['timestamp'],
                    'cpu': {
                        'percent': system_metrics['cpu_percent'],
                        'load_average': system_metrics['load_average']
                    },
                    'memory': {
                        'percent': system_metrics['memory_percent'],
                        'used_mb': system_metrics['memory_used_mb'],
                        'available_mb': system_metrics['memory_available_mb']
                    },
                    'disk': {
                        'percent': system_metrics['disk_usage_percent'],
                        'used_gb': system_metrics['disk_used_gb'],
                        'free_gb': system_metrics['disk_free_gb']
                    },
                    'network': {
                        'bytes_sent': system_metrics['network_bytes_sent'],
                        'bytes_recv': system_metrics['network_bytes_recv']
                    },
                    'process': {
                        'open_files': system_metrics['open_files'],
                        'active_connections': system_metrics['active_connections']
                    }
                }
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error getting system resources: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")
        
        @self.app.get("/debug/info",
                     summary="Debug Information",
                     description="Get debugging and diagnostic information")
        async def get_debug_info():
            """Get debug information"""
            try:
                import sys
                import platform
                
                return {
                    'timestamp': datetime.now().isoformat(),
                    'python': {
                        'version': sys.version,
                        'platform': platform.platform(),
                        'architecture': platform.architecture()
                    },
                    'monitoring': {
                        'health_monitor_running': self.health_monitor._running,
                        'performance_tracker_running': self.performance_tracker._running,
                        'registered_health_checks': len(self.health_monitor._health_checks),
                        'active_operations': len(self.performance_tracker._active_operations)
                    },
                    'memory': {
                        'metric_count': len(self.performance_tracker._metrics),
                        'cache_size': len(self.performance_tracker._stats_cache)
                    }
                }
            except Exception as e:
                logger.error(f"Error getting debug info: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")


def create_monitoring_app(
    health_monitor: HealthMonitor,
    performance_tracker: PerformanceTracker,
    metrics_collector: Optional[MetricsCollector] = None
) -> FastAPI:
    """Factory function to create monitoring FastAPI app"""
    monitoring_api = MonitoringAPI(
        health_monitor=health_monitor,
        performance_tracker=performance_tracker,
        metrics_collector=metrics_collector
    )
    
    return monitoring_api.app