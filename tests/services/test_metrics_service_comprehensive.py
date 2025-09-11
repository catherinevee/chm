"""
Comprehensive tests for Metrics Service
Testing metrics collection, aggregation, storage, and analysis
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, Mock, call
import uuid
import json
import numpy as np
from typing import List, Dict, Any
from decimal import Decimal

# Test infrastructure imports
from tests.test_infrastructure.test_fixtures_comprehensive import (
    TestInfrastructureManager,
    TestDataFactory
)

# Service and model imports
from backend.services.metrics_service import MetricsService
from backend.database.models import DeviceMetric, Device, MetricThreshold, MetricAggregate
from backend.services.alert_service import AlertService


class TestMetricsServiceCore:
    """Core metrics service functionality tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance with mocked dependencies"""
        service = MetricsService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        service.alert_service = AsyncMock(spec=AlertService)
        service.time_series_db = AsyncMock()  # For InfluxDB/TimescaleDB
        return service
    
    @pytest.fixture
    def sample_metric_data(self):
        """Sample metric data for testing"""
        return {
            "device_id": uuid.uuid4(),
            "metric_type": "cpu_usage",
            "value": 75.5,
            "unit": "percent",
            "timestamp": datetime.utcnow(),
            "tags": {
                "core": "0",
                "process": "system"
            },
            "metadata": {
                "collector": "snmp",
                "interval": 60
            }
        }
    
    @pytest.mark.asyncio
    async def test_record_metric(self, metrics_service, sample_metric_data):
        """Test recording a single metric"""
        # Record metric
        metric = await metrics_service.record_metric(sample_metric_data)
        
        # Verify metric stored
        metrics_service.db.add.assert_called_once()
        metrics_service.db.commit.assert_called_once()
        assert metric is not None
        
        # Verify time-series storage
        metrics_service.time_series_db.write.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_batch_record_metrics(self, metrics_service):
        """Test batch metric recording"""
        device_id = uuid.uuid4()
        metrics_data = [
            {"metric_type": "cpu_usage", "value": 75.5, "timestamp": datetime.utcnow()},
            {"metric_type": "memory_usage", "value": 82.3, "timestamp": datetime.utcnow()},
            {"metric_type": "disk_usage", "value": 45.2, "timestamp": datetime.utcnow()}
        ]
        
        # Batch record
        count = await metrics_service.batch_record_metrics(device_id, metrics_data)
        
        assert count == 3
        assert metrics_service.db.add.call_count == 3
        metrics_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_latest_metrics(self, metrics_service):
        """Test getting latest metrics for a device"""
        device_id = uuid.uuid4()
        
        mock_metrics = [
            MagicMock(metric_type="cpu_usage", value=75.5, timestamp=datetime.utcnow()),
            MagicMock(metric_type="memory_usage", value=82.3, timestamp=datetime.utcnow())
        ]
        
        metrics_service.db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = mock_metrics
        
        # Get latest metrics
        metrics = await metrics_service.get_latest_metrics(device_id)
        
        assert len(metrics) == 2
        assert metrics[0].metric_type == "cpu_usage"
    
    @pytest.mark.asyncio
    async def test_get_metrics_time_range(self, metrics_service):
        """Test getting metrics within time range"""
        device_id = uuid.uuid4()
        start_time = datetime.utcnow() - timedelta(hours=1)
        end_time = datetime.utcnow()
        
        mock_metrics = [
            MagicMock(timestamp=start_time + timedelta(minutes=i))
            for i in range(0, 60, 5)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = mock_metrics
        
        # Get metrics in range
        metrics = await metrics_service.get_metrics_range(
            device_id,
            start_time,
            end_time,
            metric_type="cpu_usage"
        )
        
        assert len(metrics) == 12  # One every 5 minutes for an hour
    
    @pytest.mark.asyncio
    async def test_validate_metric_value(self, metrics_service):
        """Test metric value validation"""
        # Valid percentage metric
        valid = await metrics_service.validate_metric_value("cpu_usage", 75.5, "percent")
        assert valid is True
        
        # Invalid percentage (> 100)
        invalid = await metrics_service.validate_metric_value("cpu_usage", 150.0, "percent")
        assert invalid is False
        
        # Valid bytes metric
        valid = await metrics_service.validate_metric_value("network_bytes", 1024000, "bytes")
        assert valid is True
        
        # Invalid negative value
        invalid = await metrics_service.validate_metric_value("memory_free", -100, "MB")
        assert invalid is False


class TestMetricsAggregation:
    """Metrics aggregation and calculation tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        service = MetricsService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_calculate_average(self, metrics_service):
        """Test average metric calculation"""
        metrics = [
            MagicMock(value=70.0),
            MagicMock(value=75.0),
            MagicMock(value=80.0),
            MagicMock(value=85.0),
            MagicMock(value=90.0)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Calculate average
        avg = await metrics_service.calculate_average(
            device_id=uuid.uuid4(),
            metric_type="cpu_usage",
            time_window=timedelta(hours=1)
        )
        
        assert avg == 80.0
    
    @pytest.mark.asyncio
    async def test_calculate_percentiles(self, metrics_service):
        """Test percentile calculation"""
        values = [float(i) for i in range(1, 101)]  # 1 to 100
        metrics = [MagicMock(value=v) for v in values]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Calculate percentiles
        percentiles = await metrics_service.calculate_percentiles(
            device_id=uuid.uuid4(),
            metric_type="response_time",
            percentiles=[50, 95, 99]
        )
        
        assert percentiles[50] == 50.5  # Median
        assert percentiles[95] == 95.5
        assert percentiles[99] == 99.5
    
    @pytest.mark.asyncio
    async def test_calculate_rate_of_change(self, metrics_service):
        """Test rate of change calculation"""
        metrics = [
            MagicMock(value=100, timestamp=datetime.utcnow() - timedelta(minutes=5)),
            MagicMock(value=150, timestamp=datetime.utcnow())
        ]
        
        metrics_service.db.query.return_value.filter.return_value.order_by.return_value.all.return_value = metrics
        
        # Calculate rate of change
        rate = await metrics_service.calculate_rate_of_change(
            device_id=uuid.uuid4(),
            metric_type="network_bytes"
        )
        
        assert rate == 10.0  # 50 units change over 5 minutes = 10 units/minute
    
    @pytest.mark.asyncio
    async def test_aggregate_metrics_hourly(self, metrics_service):
        """Test hourly metric aggregation"""
        device_id = uuid.uuid4()
        
        # Mock raw metrics (every minute for an hour)
        raw_metrics = [
            MagicMock(value=70 + i % 10, timestamp=datetime.utcnow() - timedelta(minutes=60-i))
            for i in range(60)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = raw_metrics
        
        # Aggregate hourly
        aggregated = await metrics_service.aggregate_hourly(
            device_id,
            metric_type="cpu_usage",
            aggregation_type="avg"
        )
        
        assert aggregated is not None
        assert aggregated["min"] == 70
        assert aggregated["max"] == 79
        assert aggregated["avg"] == 74.5
        assert aggregated["count"] == 60
    
    @pytest.mark.asyncio
    async def test_rolling_window_aggregation(self, metrics_service):
        """Test rolling window aggregation"""
        window_size = 5
        metrics = [
            MagicMock(value=float(i), timestamp=datetime.utcnow() - timedelta(minutes=10-i))
            for i in range(10)
        ]
        
        # Calculate rolling average
        rolling_avg = await metrics_service.calculate_rolling_average(
            metrics,
            window_size=window_size
        )
        
        assert len(rolling_avg) == len(metrics) - window_size + 1
        assert rolling_avg[0] == 2.0  # Average of [0,1,2,3,4]
        assert rolling_avg[-1] == 7.0  # Average of [5,6,7,8,9]


class TestMetricsThresholds:
    """Metrics threshold and alerting tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        service = MetricsService()
        service.db = AsyncMock()
        service.alert_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_create_threshold(self, metrics_service):
        """Test threshold creation"""
        threshold_data = {
            "device_id": uuid.uuid4(),
            "metric_type": "cpu_usage",
            "warning_threshold": 70.0,
            "critical_threshold": 90.0,
            "duration": 300,  # 5 minutes
            "enabled": True
        }
        
        # Create threshold
        threshold = await metrics_service.create_threshold(threshold_data)
        
        assert threshold is not None
        metrics_service.db.add.assert_called_once()
        metrics_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_threshold_breach(self, metrics_service):
        """Test threshold breach detection"""
        threshold = MagicMock(spec=MetricThreshold)
        threshold.warning_threshold = 70.0
        threshold.critical_threshold = 90.0
        threshold.duration = 300
        
        # Test warning breach
        breach = await metrics_service.check_threshold_breach(
            value=75.0,
            threshold=threshold
        )
        assert breach == "warning"
        
        # Test critical breach
        breach = await metrics_service.check_threshold_breach(
            value=92.0,
            threshold=threshold
        )
        assert breach == "critical"
        
        # Test no breach
        breach = await metrics_service.check_threshold_breach(
            value=65.0,
            threshold=threshold
        )
        assert breach is None
    
    @pytest.mark.asyncio
    async def test_sustained_threshold_breach(self, metrics_service):
        """Test sustained threshold breach detection"""
        device_id = uuid.uuid4()
        threshold = MagicMock(spec=MetricThreshold)
        threshold.critical_threshold = 90.0
        threshold.duration = 300  # 5 minutes
        
        # Mock metrics above threshold for 6 minutes
        high_metrics = [
            MagicMock(value=92.0, timestamp=datetime.utcnow() - timedelta(minutes=6-i))
            for i in range(6)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = high_metrics
        
        # Check sustained breach
        breach = await metrics_service.check_sustained_breach(
            device_id,
            "cpu_usage",
            threshold
        )
        
        assert breach is True
        metrics_service.alert_service.create_alert.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_dynamic_threshold_calculation(self, metrics_service):
        """Test dynamic threshold calculation based on historical data"""
        device_id = uuid.uuid4()
        
        # Mock historical metrics
        historical_values = [float(i) for i in range(50, 70)]  # Normal range 50-70
        metrics = [MagicMock(value=v) for v in historical_values]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Calculate dynamic thresholds
        thresholds = await metrics_service.calculate_dynamic_thresholds(
            device_id,
            "cpu_usage",
            sensitivity=2.0  # 2 standard deviations
        )
        
        assert thresholds["lower"] < 50
        assert thresholds["upper"] > 70
        assert thresholds["baseline"] == 59.5  # Mean of 50-69
    
    @pytest.mark.asyncio
    async def test_anomaly_detection(self, metrics_service):
        """Test anomaly detection in metrics"""
        # Normal pattern with anomalies
        values = [50, 52, 51, 53, 52, 100, 51, 52, 5, 53]  # 100 and 5 are anomalies
        metrics = [
            MagicMock(value=v, timestamp=datetime.utcnow() - timedelta(minutes=10-i))
            for i, v in enumerate(values)
        ]
        
        # Detect anomalies
        anomalies = await metrics_service.detect_anomalies(
            metrics,
            method="zscore",
            threshold=2.0
        )
        
        assert len(anomalies) == 2
        assert 100 in [a.value for a in anomalies]
        assert 5 in [a.value for a in anomalies]


class TestMetricsAnalysis:
    """Metrics analysis and trending tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        service = MetricsService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_trend_analysis(self, metrics_service):
        """Test trend analysis"""
        # Create upward trend
        metrics = [
            MagicMock(value=50 + i * 2, timestamp=datetime.utcnow() - timedelta(hours=10-i))
            for i in range(10)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Analyze trend
        trend = await metrics_service.analyze_trend(
            device_id=uuid.uuid4(),
            metric_type="memory_usage",
            time_window=timedelta(hours=10)
        )
        
        assert trend["direction"] == "increasing"
        assert trend["slope"] > 0
        assert trend["confidence"] > 0.8
    
    @pytest.mark.asyncio
    async def test_seasonality_detection(self, metrics_service):
        """Test seasonality detection in metrics"""
        # Create daily pattern (high during business hours)
        metrics = []
        for day in range(7):
            for hour in range(24):
                value = 80 if 9 <= hour <= 17 else 30  # Business hours pattern
                timestamp = datetime.utcnow() - timedelta(days=7-day, hours=24-hour)
                metrics.append(MagicMock(value=value, timestamp=timestamp))
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Detect seasonality
        seasonality = await metrics_service.detect_seasonality(
            device_id=uuid.uuid4(),
            metric_type="cpu_usage"
        )
        
        assert seasonality["has_seasonality"] is True
        assert seasonality["period"] == "daily"
        assert seasonality["peak_hours"] == list(range(9, 18))
    
    @pytest.mark.asyncio
    async def test_forecast_metrics(self, metrics_service):
        """Test metric forecasting"""
        # Historical data with linear trend
        historical = [
            MagicMock(value=50 + i, timestamp=datetime.utcnow() - timedelta(hours=24-i))
            for i in range(24)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = historical
        
        # Forecast next 6 hours
        forecast = await metrics_service.forecast_metrics(
            device_id=uuid.uuid4(),
            metric_type="disk_usage",
            horizon_hours=6
        )
        
        assert len(forecast) == 6
        assert all(f["value"] > 73 for f in forecast)  # Should continue upward trend
        assert all("confidence_interval" in f for f in forecast)
    
    @pytest.mark.asyncio
    async def test_correlation_analysis(self, metrics_service):
        """Test correlation between different metrics"""
        device_id = uuid.uuid4()
        
        # Create correlated metrics (CPU and temperature)
        cpu_metrics = [MagicMock(value=50 + i * 2) for i in range(10)]
        temp_metrics = [MagicMock(value=30 + i * 1.5) for i in range(10)]
        
        metrics_service.db.query.return_value.filter.return_value.all.side_effect = [
            cpu_metrics, temp_metrics
        ]
        
        # Analyze correlation
        correlation = await metrics_service.analyze_correlation(
            device_id,
            metric_type1="cpu_usage",
            metric_type2="temperature"
        )
        
        assert correlation["coefficient"] > 0.9  # Strong positive correlation
        assert correlation["relationship"] == "positive"
        assert correlation["strength"] == "strong"
    
    @pytest.mark.asyncio
    async def test_capacity_planning(self, metrics_service):
        """Test capacity planning based on metrics"""
        # Disk usage growing linearly
        metrics = [
            MagicMock(
                value=30 + i * 2,  # Growing 2% per day
                timestamp=datetime.utcnow() - timedelta(days=30-i)
            )
            for i in range(30)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Plan capacity
        planning = await metrics_service.capacity_planning(
            device_id=uuid.uuid4(),
            metric_type="disk_usage",
            threshold=95.0
        )
        
        assert planning["days_until_threshold"] > 0
        assert planning["days_until_threshold"] < 35  # Should hit 95% within 35 days
        assert planning["recommended_action"] is not None


class TestMetricsExport:
    """Metrics export and reporting tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        service = MetricsService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_export_to_csv(self, metrics_service):
        """Test CSV export of metrics"""
        metrics = [
            MagicMock(
                device_id=uuid.uuid4(),
                metric_type="cpu_usage",
                value=75.5,
                timestamp=datetime.utcnow()
            )
            for _ in range(10)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics
        
        # Export to CSV
        csv_data = await metrics_service.export_to_csv(
            device_id=uuid.uuid4(),
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow()
        )
        
        assert csv_data is not None
        assert "device_id,metric_type,value,timestamp" in csv_data
        assert "cpu_usage" in csv_data
    
    @pytest.mark.asyncio
    async def test_export_to_json(self, metrics_service):
        """Test JSON export of metrics"""
        device_id = uuid.uuid4()
        metrics = [
            {
                "device_id": str(device_id),
                "metric_type": "memory_usage",
                "value": 82.3,
                "timestamp": datetime.utcnow().isoformat()
            }
            for _ in range(5)
        ]
        
        # Export to JSON
        json_data = await metrics_service.export_to_json(device_id)
        
        assert json_data is not None
        parsed = json.loads(json_data)
        assert len(parsed["metrics"]) == 5
        assert parsed["device_id"] == str(device_id)
    
    @pytest.mark.asyncio
    async def test_generate_metrics_report(self, metrics_service):
        """Test comprehensive metrics report generation"""
        device_id = uuid.uuid4()
        
        # Mock various metrics
        metrics_service.calculate_average = AsyncMock(return_value=75.5)
        metrics_service.calculate_percentiles = AsyncMock(
            return_value={50: 75, 95: 90, 99: 95}
        )
        metrics_service.analyze_trend = AsyncMock(
            return_value={"direction": "stable", "slope": 0.1}
        )
        
        # Generate report
        report = await metrics_service.generate_report(
            device_id,
            start_time=datetime.utcnow() - timedelta(days=7),
            end_time=datetime.utcnow()
        )
        
        assert report["summary"]["average"] == 75.5
        assert report["summary"]["p95"] == 90
        assert report["trend"]["direction"] == "stable"
        assert "recommendations" in report
    
    @pytest.mark.asyncio
    async def test_dashboard_metrics(self, metrics_service):
        """Test dashboard metrics preparation"""
        devices = [uuid.uuid4() for _ in range(3)]
        
        # Mock current metrics for each device
        for device_id in devices:
            metrics_service.get_latest_metrics = AsyncMock(
                return_value=[
                    MagicMock(metric_type="cpu_usage", value=75),
                    MagicMock(metric_type="memory_usage", value=80)
                ]
            )
        
        # Get dashboard metrics
        dashboard = await metrics_service.get_dashboard_metrics(devices)
        
        assert len(dashboard) == 3
        assert all("cpu_usage" in d for d in dashboard)
        assert all("memory_usage" in d for d in dashboard)


class TestMetricsRetention:
    """Metrics retention and cleanup tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        service = MetricsService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_cleanup_old_metrics(self, metrics_service):
        """Test cleanup of old metrics"""
        retention_days = 30
        
        # Mock old metrics
        old_metrics = [
            MagicMock(id=uuid.uuid4())
            for _ in range(100)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = old_metrics
        
        # Cleanup old metrics
        deleted = await metrics_service.cleanup_old_metrics(retention_days)
        
        assert deleted == 100
        assert metrics_service.db.delete.call_count == 100
        metrics_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_archive_metrics(self, metrics_service):
        """Test metrics archival"""
        # Mock metrics to archive
        metrics_to_archive = [
            MagicMock(
                device_id=uuid.uuid4(),
                metric_type="cpu_usage",
                value=75.5,
                timestamp=datetime.utcnow() - timedelta(days=35)
            )
            for _ in range(50)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = metrics_to_archive
        
        # Archive metrics
        archived = await metrics_service.archive_metrics(
            older_than_days=30,
            archive_location="s3://metrics-archive/"
        )
        
        assert archived == 50
        # Verify metrics moved to archive
        metrics_service.db.delete.assert_called()
    
    @pytest.mark.asyncio
    async def test_retention_policy_enforcement(self, metrics_service):
        """Test retention policy enforcement"""
        policies = [
            {"metric_type": "cpu_usage", "retention_days": 30},
            {"metric_type": "network_bytes", "retention_days": 7},
            {"metric_type": "temperature", "retention_days": 90}
        ]
        
        # Apply retention policies
        for policy in policies:
            deleted = await metrics_service.apply_retention_policy(policy)
            assert deleted >= 0
        
        # Verify correct filters applied
        assert metrics_service.db.query.call_count == len(policies)
    
    @pytest.mark.asyncio
    async def test_downsampling_old_metrics(self, metrics_service):
        """Test downsampling of old high-frequency metrics"""
        # Mock high-frequency metrics (every minute for 24 hours)
        detailed_metrics = [
            MagicMock(value=70 + i % 10, timestamp=datetime.utcnow() - timedelta(hours=24, minutes=-i))
            for i in range(24 * 60)
        ]
        
        metrics_service.db.query.return_value.filter.return_value.all.return_value = detailed_metrics
        
        # Downsample to hourly
        downsampled = await metrics_service.downsample_metrics(
            metric_type="cpu_usage",
            older_than_days=7,
            target_interval="hourly"
        )
        
        assert downsampled == 24  # 24 hourly aggregates
        # Verify old detailed metrics deleted
        assert metrics_service.db.delete.call_count > 0


class TestMetricsIntegration:
    """Metrics service integration tests"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        service = MetricsService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        service.alert_service = AsyncMock()
        service.notification_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_end_to_end_metric_flow(self, metrics_service):
        """Test complete metric flow from collection to alerting"""
        device_id = uuid.uuid4()
        
        # 1. Collect metric
        metric_data = {
            "device_id": device_id,
            "metric_type": "cpu_usage",
            "value": 95.0,  # High value
            "timestamp": datetime.utcnow()
        }
        
        # 2. Record and validate
        metric = await metrics_service.record_metric(metric_data)
        assert metric is not None
        
        # 3. Check threshold
        threshold = MagicMock(critical_threshold=90.0)
        metrics_service.db.query.return_value.filter.return_value.first.return_value = threshold
        
        breach = await metrics_service.check_threshold_breach(95.0, threshold)
        assert breach == "critical"
        
        # 4. Create alert
        metrics_service.alert_service.create_alert.assert_called()
        
        # 5. Store aggregated data
        await metrics_service.aggregate_hourly(device_id, "cpu_usage", "avg")
        metrics_service.db.add.assert_called()
    
    @pytest.mark.asyncio
    async def test_real_time_metrics_processing(self, metrics_service):
        """Test real-time metrics processing pipeline"""
        device_id = uuid.uuid4()
        
        # Simulate real-time metric stream
        metric_stream = [
            {"value": 70 + i * 2, "timestamp": datetime.utcnow() + timedelta(seconds=i)}
            for i in range(10)
        ]
        
        # Process stream
        for metric in metric_stream:
            # Record metric
            await metrics_service.record_metric({
                "device_id": device_id,
                "metric_type": "cpu_usage",
                **metric
            })
            
            # Check for anomalies
            if metric["value"] > 85:
                metrics_service.alert_service.create_alert.assert_called()
            
            # Update real-time cache
            metrics_service.redis.set.assert_called()
        
        # Verify all metrics processed
        assert metrics_service.db.add.call_count == 10