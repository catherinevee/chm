"""
Integration tests for CHM monitoring system
Tests the complete monitoring workflow from discovery to alerting
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
import json

from backend.services.discovery_service import discovery_service, DiscoveredDevice
from backend.services.polling_engine import polling_engine, PollResult, PollStatus, SNMPConfig
from backend.services.ssh_client import ssh_client, SSHCredentials, VendorType
from backend.services.metrics_collector import metrics_collector, MetricSeries, ThresholdConfig
from backend.services.alert_correlation_engine import AlertCorrelationEngine

from models.device import Device, DeviceStatus, DeviceType, DeviceProtocol
from models.metric import MetricType, MetricStatus
from models.alert import AlertSeverity, AlertStatus
from models.discovery_job import DiscoveryMethod


@pytest.fixture
def mock_device():
    """Create a mock device"""
    device = Mock(spec=Device)
    device.id = 1
    device.ip_address = "192.168.1.1"
    device.hostname = "router-01"
    device.device_type = DeviceType.ROUTER
    device.vendor = "Cisco"
    device.protocol = DeviceProtocol.SNMP
    device.status = DeviceStatus.ACTIVE
    return device


@pytest.fixture
def mock_db():
    """Create mock database session"""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.add = Mock()
    return db


class TestMonitoringIntegration:
    """Test complete monitoring workflow"""
    
    @pytest.mark.asyncio
    async def test_discovery_to_polling_workflow(self, mock_db):
        """Test discovery followed by polling workflow"""
        # Mock network discovery
        discovered = DiscoveredDevice(
            ip_address="10.0.0.1",
            hostname="switch-01",
            device_type=DeviceType.SWITCH,
            vendor="Cisco",
            discovery_method=DiscoveryMethod.SNMP
        )
        
        with patch.object(discovery_service, '_ping_host') as mock_ping:
            mock_ping.return_value = ("10.0.0.1", True)
            
            # Discover device
            discovery_service.discovered_devices["10.0.0.1"] = discovered
            
            # Create device from discovery
            device = Device(
                id=1,
                ip_address=discovered.ip_address,
                hostname=discovered.hostname,
                device_type=discovered.device_type,
                vendor=discovered.vendor,
                protocol=DeviceProtocol.SNMP,
                status=DeviceStatus.ACTIVE
            )
            
            # Poll the discovered device
            with patch.object(polling_engine, '_poll_snmp') as mock_poll:
                poll_result = PollResult(
                    device_id=device.id,
                    device_ip=device.ip_address,
                    status=PollStatus.SUCCESS,
                    timestamp=datetime.utcnow(),
                    duration_ms=100,
                    metrics={
                        "cpu_usage": 45.5,
                        "memory_percent": 62.3,
                        "uptime": "2 days, 3:45:22"
                    }
                )
                mock_poll.return_value = poll_result
                
                # Execute polling
                result = await polling_engine.poll_device(device)
                
                assert result.status == PollStatus.SUCCESS
                assert "cpu_usage" in result.metrics
                assert result.metrics["cpu_usage"] == 45.5
    
    @pytest.mark.asyncio
    async def test_polling_to_metrics_workflow(self, mock_device):
        """Test polling results being stored as metrics"""
        # Create poll result
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=150,
            metrics={
                "cpu_5min": 75.5,
                "memory_used": 2048000,
                "interface_errors": 5
            }
        )
        
        # Collect metrics
        with patch.object(metrics_collector, '_store_poll_result') as mock_store:
            mock_store.return_value = None
            
            metrics = await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            # Verify metrics were collected
            assert len(metrics) > 0
            
            # Check metric series created
            for series_key, series in metrics.items():
                assert isinstance(series, MetricSeries)
                assert series.device_id == mock_device.id
                assert len(series.points) > 0
    
    @pytest.mark.asyncio
    async def test_metrics_to_alerts_workflow(self, mock_device, mock_db):
        """Test threshold violations generating alerts"""
        # Set up threshold
        threshold = ThresholdConfig(
            metric_name="cpu_usage",
            warning_threshold=70.0,
            critical_threshold=90.0,
            comparison="gt",
            duration=1
        )
        
        metrics_collector.thresholds["cpu_usage"] = threshold
        
        # Create high CPU poll result
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={
                "cpu_usage": 92.5  # Above critical threshold
            }
        )
        
        # Mock alert generation
        with patch.object(metrics_collector, '_generate_alert') as mock_alert:
            mock_alert.return_value = None
            
            # Collect metrics (should trigger alert)
            await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            # Verify alert was generated
            mock_alert.assert_called_once()
            call_args = mock_alert.call_args[0]
            assert call_args[0] == mock_device
            assert call_args[1] == "cpu_usage"
            assert call_args[2] == 92.5
            assert call_args[3] == AlertSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_ssh_polling_workflow(self, mock_device):
        """Test SSH-based device polling"""
        mock_device.protocol = DeviceProtocol.SSH
        
        # Mock SSH connection
        with patch.object(ssh_client, 'connect') as mock_connect, \
             patch.object(ssh_client, 'execute_command') as mock_exec:
            
            mock_connect.return_value = True
            mock_exec.return_value = Mock(
                output="CPU utilization: 45%",
                error="",
                exit_status=0,
                success=True
            )
            
            # Set up SSH credentials
            ssh_config = Mock()
            ssh_config.username = "admin"
            ssh_config.password = "password"
            ssh_config.port = 22
            ssh_config.timeout = 30
            
            # Poll via SSH
            with patch.object(polling_engine, '_poll_ssh') as mock_poll_ssh:
                poll_result = PollResult(
                    device_id=mock_device.id,
                    device_ip=mock_device.ip_address,
                    status=PollStatus.SUCCESS,
                    timestamp=datetime.utcnow(),
                    duration_ms=200,
                    metrics={
                        "cpu": "CPU utilization: 45%"
                    }
                )
                mock_poll_ssh.return_value = poll_result
                
                result = await polling_engine.poll_device(
                    mock_device,
                    ssh_config=ssh_config
                )
                
                assert result.status == PollStatus.SUCCESS
                assert "cpu" in result.metrics
    
    @pytest.mark.asyncio
    async def test_alert_correlation_workflow(self, mock_db):
        """Test alert correlation across multiple devices"""
        # Create multiple related alerts
        alerts = []
        for i in range(3):
            alert = Mock()
            alert.id = i + 1
            alert.device_id = i + 1
            alert.alert_type = "threshold_violation"
            alert.metric_name = "interface_down"
            alert.severity = AlertSeverity.WARNING
            alert.created_at = datetime.utcnow()
            alerts.append(alert)
        
        # Test correlation
        correlation_engine = AlertCorrelationEngine()
        
        with patch.object(correlation_engine, 'get_active_alerts') as mock_get:
            mock_get.return_value = alerts
            
            # Find correlated alerts
            groups = await correlation_engine.correlate_alerts(mock_db)
            
            # Alerts should be correlated if they're similar
            # This depends on correlation rules implementation
            assert groups is not None
    
    @pytest.mark.asyncio
    async def test_end_to_end_monitoring(self, mock_device, mock_db):
        """Test complete end-to-end monitoring workflow"""
        # Step 1: Discovery
        discovered = DiscoveredDevice(
            ip_address=mock_device.ip_address,
            hostname=mock_device.hostname,
            device_type=mock_device.device_type,
            discovery_method=DiscoveryMethod.SNMP
        )
        
        # Step 2: Polling
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={
                "cpu_usage": 85.0,
                "memory_percent": 78.0,
                "interface_errors": 100
            }
        )
        
        # Step 3: Metrics Collection
        with patch.object(metrics_collector, '_store_poll_result'):
            metrics = await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            assert len(metrics) > 0
            
            # Step 4: Alert Generation (if thresholds exceeded)
            with patch.object(metrics_collector, '_generate_alert') as mock_alert:
                # Re-collect with high CPU
                poll_result.metrics["cpu_usage"] = 95.0
                await metrics_collector.collect_device_metrics(
                    mock_device,
                    poll_result
                )
                
                # Should generate alert for high CPU
                assert mock_alert.call_count > 0
        
        # Step 5: Verify monitoring stats
        assert metrics_collector.stats["metrics_collected"] > 0
        assert metrics_collector.stats["last_collection"] is not None
    
    @pytest.mark.asyncio
    async def test_metrics_aggregation(self):
        """Test metrics aggregation over time windows"""
        # Create metric series with multiple points
        series = MetricSeries(
            name="cpu_usage",
            device_id=1,
            metric_type=MetricType.CPU
        )
        
        # Add data points over time
        base_time = datetime.utcnow()
        for i in range(10):
            series.add_point(
                base_time + timedelta(minutes=i),
                50.0 + (i * 2)  # Increasing CPU usage
            )
        
        # Test aggregation
        from backend.services.metrics_collector import AggregationType
        
        aggregated = series.aggregate(
            AggregationType.AVG,
            timedelta(minutes=5)
        )
        
        assert len(aggregated) > 0
        # First window average should be around 54 (50+52+54+56+58)/5
        assert 50 <= aggregated[0][1] <= 60
    
    @pytest.mark.asyncio
    async def test_network_range_polling(self):
        """Test polling entire network range"""
        with patch.object(polling_engine, 'poll_device') as mock_poll:
            # Mock successful polls
            mock_poll.return_value = PollResult(
                device_id=0,
                device_ip="192.168.1.1",
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=50,
                metrics={"status": "up"}
            )
            
            # Poll network range
            results = await polling_engine.poll_network_range(
                "192.168.1.0/30",  # Small range for testing
                SNMPConfig()
            )
            
            # Should attempt to poll hosts in range
            assert mock_poll.call_count > 0
    
    @pytest.mark.asyncio
    async def test_monitoring_error_handling(self, mock_device):
        """Test error handling in monitoring workflow"""
        # Test polling failure
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.side_effect = Exception("Connection timeout")
            
            result = await polling_engine.poll_device(mock_device)
            
            assert result.status == PollStatus.FAILED
            assert len(result.errors) > 0
            assert "Connection timeout" in str(result.errors)
        
        # Test metrics collection with invalid data
        poll_result = PollResult(
            device_id=mock_device.id,
            device_ip=mock_device.ip_address,
            status=PollStatus.PARTIAL,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={
                "invalid_metric": {"complex": "data"},
                "valid_metric": 42.0
            }
        )
        
        with patch.object(metrics_collector, '_store_poll_result'):
            metrics = await metrics_collector.collect_device_metrics(
                mock_device,
                poll_result
            )
            
            # Should handle mixed valid/invalid metrics
            assert any("valid_metric" in key for key in metrics.keys())


class TestMonitoringPerformance:
    """Test monitoring system performance"""
    
    @pytest.mark.asyncio
    async def test_concurrent_polling(self):
        """Test concurrent device polling performance"""
        devices = []
        for i in range(10):
            device = Mock(spec=Device)
            device.id = i
            device.ip_address = f"192.168.1.{i+1}"
            device.protocol = DeviceProtocol.SNMP
            device.status = DeviceStatus.ACTIVE
            devices.append(device)
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=1,
                device_ip="192.168.1.1",
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=50,
                metrics={}
            )
            
            # Poll all devices concurrently
            start_time = datetime.utcnow()
            
            tasks = [
                polling_engine.poll_device(device)
                for device in devices
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Should complete quickly with concurrent execution
            assert duration < 5.0  # Should take less than 5 seconds for 10 devices
            assert len(results) == 10
            
            # Check all succeeded
            for result in results:
                if isinstance(result, PollResult):
                    assert result.status == PollStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_metrics_buffer_performance(self):
        """Test metrics buffer can handle high volume"""
        # Add many metrics to buffer
        for device_id in range(100):
            for metric_name in ["cpu", "memory", "disk"]:
                series_key = f"{device_id}:{metric_name}"
                series = MetricSeries(
                    name=metric_name,
                    device_id=device_id,
                    metric_type=MetricType.CUSTOM
                )
                
                # Add 100 points per series
                for i in range(100):
                    series.add_point(
                        datetime.utcnow() + timedelta(seconds=i),
                        float(i)
                    )
                
                metrics_collector.metric_buffer[series_key] = series
        
        # Buffer should handle 30,000 data points
        total_points = sum(
            len(s.points) for s in metrics_collector.metric_buffer.values()
        )
        
        assert total_points == 30000
        
        # Test retrieval performance
        start_time = datetime.utcnow()
        
        # Get metrics for specific device
        device_metrics = {
            k: v for k, v in metrics_collector.metric_buffer.items()
            if v.device_id == 50
        }
        
        duration = (datetime.utcnow() - start_time).total_seconds()
        
        # Should retrieve quickly
        assert duration < 0.1  # Less than 100ms
        assert len(device_metrics) == 3  # cpu, memory, disk