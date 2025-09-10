"""
Unit tests for Metrics Collector Service
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
from typing import Dict, List

from backend.services.metrics_collector import (
    metrics_collector, MetricSeries, ThresholdConfig, AggregationType
)
from backend.services.polling_engine import PollResult, PollStatus
from models.device import Device, DeviceType, DeviceStatus
from models.metric import MetricType, MetricStatus
from models.alert import AlertSeverity


@pytest.fixture
def mock_device():
    """Create a mock device for testing"""
    device = Mock(spec=Device)
    device.id = 1
    device.name = "test-device"
    device.ip_address = "192.168.1.1"
    device.device_type = DeviceType.ROUTER
    device.vendor = "Cisco"
    device.status = DeviceStatus.ACTIVE
    return device


@pytest.fixture
def poll_result():
    """Create a sample poll result"""
    return PollResult(
        device_id=1,
        device_ip="192.168.1.1",
        status=PollStatus.SUCCESS,
        timestamp=datetime.utcnow(),
        duration_ms=100,
        metrics={
            "cpu_usage": 75.5,
            "memory_percent": 62.3,
            "interface_in_octets": 1024000,
            "interface_out_octets": 2048000,
            "temperature": 45.2
        }
    )


@pytest.fixture
def threshold_config():
    """Create threshold configuration"""
    return ThresholdConfig(
        metric_name="cpu_usage",
        warning_threshold=70.0,
        critical_threshold=90.0,
        comparison="gt",
        duration=1
    )


class TestMetricsCollector:
    """Test metrics collector functionality"""
    
    @pytest.mark.asyncio
    async def test_collect_device_metrics(self, mock_device, poll_result):
        """Test collecting metrics from poll result"""
        with patch.object(metrics_collector, '_store_poll_result') as mock_store:
            mock_store.return_value = None
            
            metrics = await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            assert len(metrics) > 0
            assert any("cpu_usage" in key for key in metrics.keys())
            assert any("memory_percent" in key for key in metrics.keys())
            
            # Check metric series created
            for series_key, series in metrics.items():
                assert isinstance(series, MetricSeries)
                assert series.device_id == mock_device.id
                assert len(series.points) > 0
    
    @pytest.mark.asyncio
    async def test_poll_and_collect(self, mock_device):
        """Test polling and collecting metrics in one operation"""
        with patch('services.polling_engine.polling_engine.poll_device') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=100,
                metrics={"cpu": 45.5}
            )
            
            with patch.object(metrics_collector, '_store_poll_result'):
                metrics = await metrics_collector.poll_and_collect(mock_device)
                
                assert len(metrics) > 0
                mock_poll.assert_called_once()
    
    def test_metric_series_creation(self):
        """Test MetricSeries creation and operations"""
        series = MetricSeries(
            name="cpu_usage",
            device_id=1,
            metric_type=MetricType.CPU
        )
        
        # Add data points
        base_time = datetime.utcnow()
        for i in range(10):
            series.add_point(
                base_time + timedelta(minutes=i),
                50.0 + (i * 2)
            )
        
        assert len(series.points) == 10
        assert series.get_latest_value() == 68.0  # 50 + (9 * 2)
        assert series.name == "cpu_usage"
        assert series.device_id == 1
    
    def test_metric_series_max_points(self):
        """Test metric series respects max points limit"""
        series = MetricSeries(
            name="test_metric",
            device_id=1,
            metric_type=MetricType.CUSTOM,
            max_points=5
        )
        
        # Add more than max points
        base_time = datetime.utcnow()
        for i in range(10):
            series.add_point(base_time + timedelta(minutes=i), float(i))
        
        # Should only keep last 5 points
        assert len(series.points) == 5
        assert series.points[0][1] == 5.0  # Oldest point should be 5
        assert series.points[-1][1] == 9.0  # Newest point should be 9
    
    def test_metric_aggregation_avg(self):
        """Test average aggregation"""
        series = MetricSeries(
            name="test_metric",
            device_id=1,
            metric_type=MetricType.CUSTOM
        )
        
        # Add data points
        base_time = datetime.utcnow()
        for i in range(10):
            series.add_point(
                base_time + timedelta(minutes=i),
                float(i * 10)
            )
        
        # Aggregate with 5-minute window
        aggregated = series.aggregate(
            AggregationType.AVG,
            timedelta(minutes=5)
        )
        
        assert len(aggregated) > 0
        # First window average should be (0+10+20+30+40)/5 = 20
        assert aggregated[0][1] == 20.0
    
    def test_metric_aggregation_max(self):
        """Test maximum aggregation"""
        series = MetricSeries(
            name="test_metric",
            device_id=1,
            metric_type=MetricType.CUSTOM
        )
        
        # Add data points
        base_time = datetime.utcnow()
        values = [10, 25, 15, 30, 20]
        for i, val in enumerate(values):
            series.add_point(
                base_time + timedelta(minutes=i),
                float(val)
            )
        
        # Aggregate with 10-minute window (all points)
        aggregated = series.aggregate(
            AggregationType.MAX,
            timedelta(minutes=10)
        )
        
        assert len(aggregated) == 1
        assert aggregated[0][1] == 30.0  # Maximum value
    
    def test_metric_aggregation_min(self):
        """Test minimum aggregation"""
        series = MetricSeries(
            name="test_metric",
            device_id=1,
            metric_type=MetricType.CUSTOM
        )
        
        # Add data points
        base_time = datetime.utcnow()
        values = [10, 25, 15, 30, 20]
        for i, val in enumerate(values):
            series.add_point(
                base_time + timedelta(minutes=i),
                float(val)
            )
        
        # Aggregate with 10-minute window
        aggregated = series.aggregate(
            AggregationType.MIN,
            timedelta(minutes=10)
        )
        
        assert len(aggregated) == 1
        assert aggregated[0][1] == 10.0  # Minimum value
    
    @pytest.mark.asyncio
    async def test_threshold_violation_warning(self, mock_device, threshold_config):
        """Test warning threshold violation detection"""
        # Create poll result with high CPU
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={"cpu_usage": 75.0}  # Above warning (70) but below critical (90)
        )
        
        # Set threshold
        metrics_collector.thresholds["cpu_usage"] = threshold_config
        
        with patch.object(metrics_collector, '_generate_alert') as mock_alert:
            with patch.object(metrics_collector, '_store_poll_result'):
                await metrics_collector.collect_device_metrics(
                    mock_device,
                    poll_result
                )
                
                # Should generate warning alert
                mock_alert.assert_called()
                call_args = mock_alert.call_args[0]
                assert call_args[3] == AlertSeverity.WARNING
    
    @pytest.mark.asyncio
    async def test_threshold_violation_critical(self, mock_device, threshold_config):
        """Test critical threshold violation detection"""
        # Create poll result with very high CPU
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={"cpu_usage": 95.0}  # Above critical threshold (90)
        )
        
        # Set threshold
        metrics_collector.thresholds["cpu_usage"] = threshold_config
        
        with patch.object(metrics_collector, '_generate_alert') as mock_alert:
            with patch.object(metrics_collector, '_store_poll_result'):
                await metrics_collector.collect_device_metrics(
                    mock_device,
                    poll_result
                )
                
                # Should generate critical alert
                mock_alert.assert_called()
                call_args = mock_alert.call_args[0]
                assert call_args[3] == AlertSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_no_threshold_violation(self, mock_device, threshold_config):
        """Test no alert when threshold not violated"""
        # Create poll result with normal CPU
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={"cpu_usage": 45.0}  # Below warning threshold (70)
        )
        
        # Set threshold
        metrics_collector.thresholds["cpu_usage"] = threshold_config
        
        with patch.object(metrics_collector, '_generate_alert') as mock_alert:
            with patch.object(metrics_collector, '_store_poll_result'):
                await metrics_collector.collect_device_metrics(
                    mock_device,
                    poll_result
                )
                
                # Should not generate alert
                mock_alert.assert_not_called()
    
    def test_get_device_metrics(self):
        """Test retrieving metrics for a specific device"""
        # Add metrics to buffer
        series1 = MetricSeries("cpu", 1, MetricType.CPU)
        series1.add_point(datetime.utcnow(), 45.0)
        
        series2 = MetricSeries("memory", 1, MetricType.MEMORY)
        series2.add_point(datetime.utcnow(), 2048.0)
        
        series3 = MetricSeries("cpu", 2, MetricType.CPU)  # Different device
        series3.add_point(datetime.utcnow(), 60.0)
        
        metrics_collector.metric_buffer = {
            "1:cpu": series1,
            "1:memory": series2,
            "2:cpu": series3
        }
        
        # Get metrics for device 1
        device_metrics = metrics_collector.get_device_metrics(1)
        
        assert len(device_metrics) == 2
        assert "1:cpu" in device_metrics
        assert "1:memory" in device_metrics
        assert "2:cpu" not in device_metrics
    
    def test_get_metric_series(self):
        """Test retrieving a specific metric series"""
        # Add metric to buffer
        series = MetricSeries("temperature", 1, MetricType.CUSTOM)
        series.add_point(datetime.utcnow(), 45.5)
        
        metrics_collector.metric_buffer["1:temperature"] = series
        
        # Retrieve the series
        retrieved = metrics_collector.get_metric_series(1, "temperature")
        
        assert retrieved is not None
        assert retrieved.name == "temperature"
        assert retrieved.get_latest_value() == 45.5
    
    @pytest.mark.asyncio
    async def test_bulk_collect_metrics(self):
        """Test collecting metrics from multiple devices"""
        devices = []
        poll_results = []
        
        for i in range(3):
            device = Mock(spec=Device)
            device.id = i + 1
            device.name = f"device-{i+1}"
            devices.append(device)
            
            result = PollResult(
                device_id=device.id,
                device_ip=f"192.168.1.{i+1}",
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=100,
                metrics={"cpu": 40.0 + (i * 10)}
            )
            poll_results.append(result)
        
        with patch.object(metrics_collector, '_store_poll_result'):
            all_metrics = await metrics_collector.bulk_collect_metrics(
                list(zip(devices, poll_results))
            )
            
            assert len(all_metrics) == 3
            for device_id, metrics in all_metrics.items():
                assert len(metrics) > 0
    
    def test_clear_old_metrics(self):
        """Test clearing old metrics from buffer"""
        # Add old and new metrics
        old_time = datetime.utcnow() - timedelta(hours=25)
        new_time = datetime.utcnow()
        
        old_series = MetricSeries("old_metric", 1, MetricType.CUSTOM)
        old_series.add_point(old_time, 100.0)
        
        new_series = MetricSeries("new_metric", 1, MetricType.CUSTOM)
        new_series.add_point(new_time, 200.0)
        
        metrics_collector.metric_buffer = {
            "1:old": old_series,
            "1:new": new_series
        }
        
        # Clear metrics older than 24 hours
        metrics_collector.clear_old_metrics(timedelta(hours=24))
        
        # Old series should have no points
        assert len(metrics_collector.metric_buffer["1:old"].points) == 0
        # New series should still have points
        assert len(metrics_collector.metric_buffer["1:new"].points) == 1
    
    def test_get_statistics(self):
        """Test getting collector statistics"""
        # Add some metrics
        series1 = MetricSeries("cpu", 1, MetricType.CPU)
        series1.add_point(datetime.utcnow(), 45.0)
        
        series2 = MetricSeries("memory", 2, MetricType.MEMORY)
        series2.add_point(datetime.utcnow(), 2048.0)
        
        metrics_collector.metric_buffer = {
            "1:cpu": series1,
            "2:memory": series2
        }
        
        metrics_collector.stats["metrics_collected"] = 100
        metrics_collector.stats["alerts_generated"] = 5
        
        stats = metrics_collector.get_statistics()
        
        assert stats["buffer_size"] == 2
        assert stats["total_points"] == 2
        assert stats["metrics_collected"] == 100
        assert stats["alerts_generated"] == 5
    
    @pytest.mark.asyncio
    async def test_handle_failed_poll(self, mock_device):
        """Test handling failed poll results"""
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.FAILED,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={},
            errors=["Connection timeout"]
        )
        
        with patch.object(metrics_collector, '_store_poll_result'):
            metrics = await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            # Should still return empty metrics dict without error
            assert isinstance(metrics, dict)
            assert len(metrics) == 0
    
    @pytest.mark.asyncio
    async def test_partial_poll_results(self, mock_device):
        """Test handling partial poll results"""
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.PARTIAL,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={
                "cpu_usage": 45.0,
                "memory_percent": None,  # Failed to get
                "temperature": 40.0
            },
            errors=["Failed to retrieve memory metrics"]
        )
        
        with patch.object(metrics_collector, '_store_poll_result'):
            metrics = await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            # Should collect valid metrics only
            assert len(metrics) > 0
            assert any("cpu_usage" in key for key in metrics.keys())
            assert any("temperature" in key for key in metrics.keys())
            # Should not have memory metric
            assert not any("memory_percent" in key for key in metrics.keys())