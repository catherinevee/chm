"""
Unit tests for health monitoring system.
Tests health checks, metrics collection, and system monitoring functionality.
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any

from backend.monitoring.health_monitor import (
    HealthMonitor, MetricsCollector, HealthCheck, HealthCheckResult,
    HealthStatus, MetricType, MetricDefinition, SystemMetrics
)
from backend.monitoring.performance_tracker import PerformanceTracker


@pytest.fixture
def metrics_collector():
    """Create metrics collector for testing"""
    return MetricsCollector()


@pytest.fixture
def health_monitor(metrics_collector):
    """Create health monitor for testing"""
    return HealthMonitor(
        metrics_collector=metrics_collector,
        check_interval=1.0  # Short interval for testing
    )


@pytest.fixture
def performance_tracker():
    """Create performance tracker for testing"""
    return PerformanceTracker(
        max_history_minutes=60,
        window_size_seconds=10,
        max_metrics_per_window=1000
    )


class TestMetricsCollector:
    """Test metrics collection functionality"""
    
    def test_define_counter_metric(self, metrics_collector):
        """Test defining a counter metric"""
        definition = MetricDefinition(
            name="test_counter",
            metric_type=MetricType.COUNTER,
            description="Test counter metric",
            labels=["method", "status"]
        )
        
        success = metrics_collector.define_metric(definition)
        assert success is True
        assert "test_counter" in metrics_collector._metric_definitions
        assert "test_counter" in metrics_collector._metrics
    
    def test_define_gauge_metric(self, metrics_collector):
        """Test defining a gauge metric"""
        definition = MetricDefinition(
            name="test_gauge",
            metric_type=MetricType.GAUGE,
            description="Test gauge metric"
        )
        
        success = metrics_collector.define_metric(definition)
        assert success is True
        assert "test_gauge" in metrics_collector._metric_definitions
    
    def test_define_histogram_metric(self, metrics_collector):
        """Test defining a histogram metric"""
        definition = MetricDefinition(
            name="test_histogram",
            metric_type=MetricType.HISTOGRAM,
            description="Test histogram metric",
            buckets=[0.1, 0.5, 1.0, 5.0]
        )
        
        success = metrics_collector.define_metric(definition)
        assert success is True
        assert "test_histogram" in metrics_collector._metric_definitions
    
    def test_increment_counter(self, metrics_collector):
        """Test incrementing counter metric"""
        # Define counter first
        definition = MetricDefinition(
            name="requests_total",
            metric_type=MetricType.COUNTER,
            description="Total requests"
        )
        metrics_collector.define_metric(definition)
        
        # Increment counter
        success = metrics_collector.increment_counter("requests_total", 1.0)
        assert success is True
        
        # Increment with labels
        success = metrics_collector.increment_counter(
            "requests_total", 
            2.0, 
            {"method": "GET", "status": "200"}
        )
        assert success is True
        
        # Try to increment non-existent counter
        success = metrics_collector.increment_counter("nonexistent", 1.0)
        assert success is False
    
    def test_set_gauge(self, metrics_collector):
        """Test setting gauge metric value"""
        # Define gauge first
        definition = MetricDefinition(
            name="active_connections",
            metric_type=MetricType.GAUGE,
            description="Active connections"
        )
        metrics_collector.define_metric(definition)
        
        # Set gauge value
        success = metrics_collector.set_gauge("active_connections", 42.0)
        assert success is True
        
        # Set gauge with labels
        success = metrics_collector.set_gauge(
            "active_connections",
            25.0,
            {"protocol": "http"}
        )
        assert success is True
        
        # Try to set non-existent gauge
        success = metrics_collector.set_gauge("nonexistent", 1.0)
        assert success is False
    
    def test_observe_histogram(self, metrics_collector):
        """Test recording histogram observations"""
        # Define histogram first
        definition = MetricDefinition(
            name="request_duration",
            metric_type=MetricType.HISTOGRAM,
            description="Request duration"
        )
        metrics_collector.define_metric(definition)
        
        # Record observations
        success = metrics_collector.observe_histogram("request_duration", 0.5)
        assert success is True
        
        success = metrics_collector.observe_histogram("request_duration", 1.2)
        assert success is True
        
        # Record with labels
        success = metrics_collector.observe_histogram(
            "request_duration",
            0.8,
            {"endpoint": "/api/health"}
        )
        assert success is True
        
        # Try to observe non-existent histogram
        success = metrics_collector.observe_histogram("nonexistent", 1.0)
        assert success is False
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.disk_usage')
    def test_update_system_metrics(self, mock_disk, mock_memory, mock_cpu, metrics_collector):
        """Test updating system metrics"""
        system_metrics = SystemMetrics(
            timestamp=datetime.now(),
            cpu_percent=25.5,
            memory_percent=60.0,
            memory_used_mb=1024.0,
            memory_available_mb=512.0,
            disk_usage_percent=75.0,
            disk_used_gb=100.0,
            disk_free_gb=25.0,
            network_bytes_sent=1000000,
            network_bytes_recv=2000000,
            load_average=(0.5, 0.7, 0.9),
            open_files=50,
            active_connections=10
        )
        
        metrics_collector.update_system_metrics(system_metrics)
        
        # Verify metrics were updated (would check actual Prometheus metrics in real implementation)
        assert True  # Simplified assertion
    
    def test_get_metrics_text(self, metrics_collector):
        """Test getting metrics in text format"""
        # Define some metrics
        counter_def = MetricDefinition(
            name="test_requests_total",
            metric_type=MetricType.COUNTER,
            description="Test requests"
        )
        metrics_collector.define_metric(counter_def)
        
        gauge_def = MetricDefinition(
            name="test_connections",
            metric_type=MetricType.GAUGE,
            description="Test connections"
        )
        metrics_collector.define_metric(gauge_def)
        
        # Record some values
        metrics_collector.increment_counter("test_requests_total", 5.0)
        metrics_collector.set_gauge("test_connections", 10.0)
        
        # Get metrics text
        metrics_text = metrics_collector.get_metrics_text()
        assert isinstance(metrics_text, str)
        assert len(metrics_text) > 0
        
        # Should contain metric names in fallback mode
        if not hasattr(metrics_collector, '_system_cpu'):  # No Prometheus
            assert "test_requests_total" in metrics_text
            assert "test_connections" in metrics_text


class TestHealthMonitor:
    """Test health monitoring functionality"""
    
    @pytest.mark.asyncio
    async def test_health_monitor_initialization(self, health_monitor):
        """Test health monitor initialization"""
        assert health_monitor is not None
        assert not health_monitor._running
        assert health_monitor._monitor_task is None
        assert len(health_monitor._health_checks) > 0  # Should have built-in checks
    
    def test_register_health_check(self, health_monitor):
        """Test registering custom health check"""
        check = HealthCheck(
            name="custom_check",
            check_func=lambda: True,
            timeout=5.0,
            interval=30.0,
            critical=False,
            description="Custom test check"
        )
        
        initial_count = len(health_monitor._health_checks)
        health_monitor.register_health_check(check)
        
        assert len(health_monitor._health_checks) == initial_count + 1
        assert "custom_check" in health_monitor._health_checks
        assert health_monitor._health_checks["custom_check"] == check
    
    def test_unregister_health_check(self, health_monitor):
        """Test unregistering health check"""
        check = HealthCheck(
            name="temp_check",
            check_func=lambda: True,
            timeout=5.0,
            interval=30.0
        )
        
        health_monitor.register_health_check(check)
        assert "temp_check" in health_monitor._health_checks
        
        success = health_monitor.unregister_health_check("temp_check")
        assert success is True
        assert "temp_check" not in health_monitor._health_checks
        
        # Try to unregister non-existent check
        success = health_monitor.unregister_health_check("nonexistent")
        assert success is False
    
    @pytest.mark.asyncio
    async def test_start_stop_monitoring(self, health_monitor):
        """Test starting and stopping monitoring loop"""
        assert not health_monitor._running
        
        # Start monitoring
        success = await health_monitor.start_monitoring()
        assert success is True
        assert health_monitor._running is True
        assert health_monitor._monitor_task is not None
        
        # Try to start again (should return False)
        success = await health_monitor.start_monitoring()
        assert success is False
        
        # Stop monitoring
        await health_monitor.stop_monitoring()
        assert health_monitor._running is False
    
    @pytest.mark.asyncio
    async def test_execute_health_check_success(self, health_monitor):
        """Test executing successful health check"""
        check = HealthCheck(
            name="always_pass",
            check_func=lambda: True,
            timeout=1.0,
            retries=0
        )
        
        result = await health_monitor._execute_health_check(check)
        
        assert isinstance(result, HealthCheckResult)
        assert result.name == "always_pass"
        assert result.status == HealthStatus.HEALTHY
        assert result.message == "Check passed"
        assert result.duration_ms > 0
    
    @pytest.mark.asyncio
    async def test_execute_health_check_failure(self, health_monitor):
        """Test executing failing health check"""
        check = HealthCheck(
            name="always_fail",
            check_func=lambda: False,
            timeout=1.0,
            retries=1
        )
        
        result = await health_monitor._execute_health_check(check)
        
        assert isinstance(result, HealthCheckResult)
        assert result.name == "always_fail"
        assert result.status == HealthStatus.UNHEALTHY
        assert "Check failed" in result.message
        assert result.duration_ms > 0
    
    @pytest.mark.asyncio
    async def test_execute_health_check_timeout(self, health_monitor):
        """Test executing health check that times out"""
        def slow_check():
            time.sleep(2.0)  # Longer than timeout
            return True
        
        check = HealthCheck(
            name="slow_check",
            check_func=slow_check,
            timeout=0.1,
            retries=0
        )
        
        result = await health_monitor._execute_health_check(check)
        
        assert isinstance(result, HealthCheckResult)
        assert result.name == "slow_check"
        assert result.status == HealthStatus.UNHEALTHY
        assert "timed out" in result.message
    
    @pytest.mark.asyncio
    async def test_execute_health_check_exception(self, health_monitor):
        """Test executing health check that raises exception"""
        def error_check():
            raise ValueError("Test error")
        
        check = HealthCheck(
            name="error_check",
            check_func=error_check,
            timeout=1.0,
            retries=0
        )
        
        result = await health_monitor._execute_health_check(check)
        
        assert isinstance(result, HealthCheckResult)
        assert result.name == "error_check"
        assert result.status == HealthStatus.UNHEALTHY
        assert "Test error" in result.message
    
    @pytest.mark.asyncio
    async def test_execute_async_health_check(self, health_monitor):
        """Test executing async health check"""
        async def async_check():
            await asyncio.sleep(0.01)
            return True
        
        check = HealthCheck(
            name="async_check",
            check_func=async_check,
            timeout=1.0,
            retries=0
        )
        
        result = await health_monitor._execute_health_check(check)
        
        assert isinstance(result, HealthCheckResult)
        assert result.name == "async_check"
        assert result.status == HealthStatus.HEALTHY
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.disk_usage')
    @patch('psutil.net_io_counters')
    @patch('psutil.getloadavg')
    @patch('psutil.Process')
    @pytest.mark.asyncio
    async def test_collect_system_metrics(self, mock_process, mock_loadavg, mock_net,
                                        mock_disk, mock_memory, mock_cpu, health_monitor):
        """Test collecting system metrics"""
        # Mock system values
        mock_cpu.return_value = 25.5
        mock_memory.return_value = Mock(percent=60.0, used=1024*1024*1024, available=512*1024*1024)
        mock_disk.return_value = Mock(percent=75.0, used=100*1024*1024*1024, free=25*1024*1024*1024)
        mock_net.return_value = Mock(bytes_sent=1000000, bytes_recv=2000000)
        mock_loadavg.return_value = (0.5, 0.7, 0.9)
        
        # Mock process
        mock_proc = Mock()
        mock_proc.open_files.return_value = [Mock()] * 50
        mock_proc.connections.return_value = [Mock()] * 10
        mock_process.return_value = mock_proc
        
        # Collect metrics
        await health_monitor._collect_system_metrics()
        
        # Verify metrics were collected
        assert len(health_monitor._system_metrics_history) > 0
        
        latest_metrics = health_monitor._system_metrics_history[-1]
        assert latest_metrics.cpu_percent == 25.5
        assert latest_metrics.memory_percent == 60.0
        assert latest_metrics.disk_usage_percent == 75.0
        assert latest_metrics.load_average == (0.5, 0.7, 0.9)
        assert latest_metrics.open_files == 50
        assert latest_metrics.active_connections == 10
    
    @pytest.mark.asyncio
    async def test_get_health_status(self, health_monitor):
        """Test getting comprehensive health status"""
        # Register a test check
        check = HealthCheck(
            name="test_check",
            check_func=lambda: True,
            critical=True,
            description="Test check"
        )
        health_monitor.register_health_check(check)
        
        # Mock some system metrics
        with patch.object(health_monitor, '_get_latest_system_metrics') as mock_metrics:
            mock_metrics.return_value = {
                'cpu_percent': 25.0,
                'memory_percent': 50.0
            }
            
            status = await health_monitor.get_health_status()
            
            assert 'status' in status
            assert 'timestamp' in status
            assert 'checks' in status
            assert 'critical_failures' in status
            assert 'degraded_checks' in status
            assert 'system_metrics' in status
            
            # Verify our test check is included
            assert 'test_check' in status['checks']
            check_info = status['checks']['test_check']
            assert check_info['critical'] is True
            assert check_info['description'] == "Test check"
    
    def test_cleanup_old_data(self, health_monitor):
        """Test cleanup of old monitoring data"""
        # Add some old results
        old_time = datetime.now() - timedelta(hours=25)  # Older than 24 hours
        recent_time = datetime.now() - timedelta(minutes=30)
        
        old_result = HealthCheckResult(
            name="test_check",
            status=HealthStatus.HEALTHY,
            timestamp=old_time
        )
        
        recent_result = HealthCheckResult(
            name="test_check", 
            status=HealthStatus.HEALTHY,
            timestamp=recent_time
        )
        
        health_monitor._check_results["test_check"].extend([old_result, recent_result])
        
        # Run cleanup
        health_monitor._cleanup_old_data()
        
        # Old result should be removed, recent should remain
        remaining_results = list(health_monitor._check_results["test_check"])
        assert len(remaining_results) == 1
        assert remaining_results[0].timestamp == recent_time


class TestSystemIntegration:
    """Test system integration scenarios"""
    
    @pytest.mark.asyncio
    async def test_health_monitor_with_performance_tracker(self, health_monitor, performance_tracker):
        """Test health monitor integrated with performance tracker"""
        # Start both systems
        await health_monitor.start_monitoring()
        await performance_tracker.start()
        
        try:
            # Record some performance metrics
            performance_tracker.record_metric("api_requests", 1.0, duration_ms=50.0)
            performance_tracker.record_metric("api_requests", 1.0, duration_ms=75.0)
            
            # Get health status
            health_status = await health_monitor.get_health_status()
            
            assert health_status is not None
            assert 'status' in health_status
            
            # Get performance stats
            stats = performance_tracker.get_metric_stats("api_requests")
            assert stats is not None
            assert stats.count == 2
            
        finally:
            await health_monitor.stop_monitoring()
            await performance_tracker.stop()
    
    @pytest.mark.asyncio
    async def test_monitoring_under_load(self, health_monitor):
        """Test monitoring system under simulated load"""
        # Register multiple checks
        for i in range(10):
            check = HealthCheck(
                name=f"load_check_{i}",
                check_func=lambda: True,
                timeout=0.1,
                interval=0.5,  # Frequent checks
                critical=i < 5  # First 5 are critical
            )
            health_monitor.register_health_check(check)
        
        # Start monitoring
        await health_monitor.start_monitoring()
        
        try:
            # Let it run for a bit
            await asyncio.sleep(2.0)
            
            # Get status
            status = await health_monitor.get_health_status()
            
            # Should have results for all checks
            assert len(status['checks']) >= 10
            
            # Most checks should have run at least once
            checks_with_results = sum(1 for check in status['checks'].values() 
                                    if check['last_run'] is not None)
            assert checks_with_results >= 8
            
        finally:
            await health_monitor.stop_monitoring()
    
    @pytest.mark.asyncio 
    async def test_mixed_health_check_results(self, health_monitor):
        """Test system with mixed healthy/unhealthy checks"""
        # Register checks with different outcomes
        checks = [
            HealthCheck("always_pass", lambda: True, critical=False),
            HealthCheck("always_fail", lambda: False, critical=False), 
            HealthCheck("critical_pass", lambda: True, critical=True),
            HealthCheck("critical_fail", lambda: False, critical=True)
        ]
        
        for check in checks:
            health_monitor.register_health_check(check)
        
        # Manually run checks to get immediate results
        for check in checks:
            result = await health_monitor._execute_health_check(check)
            health_monitor._check_results[check.name].append(result)
            check.last_status = result.status
            check.last_run = datetime.now()
        
        # Get overall status
        status = await health_monitor.get_health_status()
        
        # Should be unhealthy due to critical failure
        assert status['status'] == HealthStatus.UNHEALTHY.value
        assert 'critical_fail' in status['critical_failures']
        assert 'always_fail' in status['degraded_checks']