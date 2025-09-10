"""
Prometheus metrics for application monitoring
"""

import asyncio
import time
from functools import wraps

from prometheus_client import Counter, Gauge, Histogram, Info

# Define metrics
snmp_requests_total = Counter(
    'snmp_requests_total',
    'Total number of SNMP requests',
    ['device_type', 'version', 'status']
)

snmp_response_time_seconds = Histogram(
    'snmp_response_time_seconds',
    'SNMP response time in seconds',
    ['device_type', 'version'],
    buckets=(0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0)
)

device_health_status = Gauge(
    'device_health_status',
    'Current health status of devices (1=healthy, 2=degraded, 3=critical, 4=unreachable)',
    ['hostname', 'device_type']
)

collector_polls_total = Counter(
    'collector_polls_total',
    'Total number of device polls',
    ['status']
)

alerts_generated_total = Counter(
    'alerts_generated_total',
    'Total number of alerts generated',
    ['severity', 'metric_name']
)

emergency_responses_total = Counter(
    'emergency_responses_total',
    'Total number of emergency responses triggered',
    ['response_type']
)

active_websocket_connections = Gauge(
    'active_websocket_connections',
    'Number of active WebSocket connections'
)

database_pool_size = Gauge(
    'database_pool_size',
    'Database connection pool size',
    ['pool_name']
)

app_info = Info(
    'app_info',
    'Application information'
)

# Set application info
app_info.info({
    'version': '1.0.0',
    'environment': 'production'
})

def track_time(metric: Histogram):
    """Decorator to track execution time"""
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                metric.observe(time.time() - start)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = time.time()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                metric.observe(time.time() - start)
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    return decorator

from fastapi import Response

# Export metrics endpoint
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest


async def metrics_endpoint():
    """Endpoint to export Prometheus metrics"""
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )
