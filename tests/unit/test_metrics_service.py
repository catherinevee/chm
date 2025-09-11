"""
Comprehensive tests for Metrics Service
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.metrics_service import MetricsService
from backend.common.exceptions import (
    ValidationException, ResourceNotFoundException
)
from models.metric import Metric, MetricType
from models.device import Device, DeviceType, DeviceStatus


class TestMetricsService:
    """Test Metrics Service functionality"""
    
    @pytest.fixture
    def metrics_service(self):
        """Create MetricsService instance"""
        return MetricsService()
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)
    
    @pytest.fixture
    def sample_device(self):
        """Sample device for testing"""
        return Device(
            id=1,
            name="Test Router",
            ip_address="192.168.1.1",
            device_type=DeviceType.ROUTER,
            status=DeviceStatus.ACTIVE
        )
    
    @pytest.fixture
    def sample_metric(self):
        """Sample metric for testing"""
        return Metric(
            id=1,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            value=75.5,
            unit="percent",
            timestamp=datetime.now(),
            created_at=datetime.now()
        )
    
    @pytest.fixture
    def cpu_metrics(self):
        """Sample CPU usage metrics"""
        base_time = datetime.now()
        return [
            Metric(
                id=i,
                device_id=1,
                metric_type=MetricType.CPU_USAGE,
                value=70.0 + i * 2.5,
                unit="percent",
                timestamp=base_time - timedelta(minutes=i * 5),
                created_at=base_time - timedelta(minutes=i * 5)
            )
            for i in range(10)
        ]

    def test_init(self, metrics_service):
        """Test MetricsService initialization"""
        assert metrics_service is not None

    @pytest.mark.asyncio
    async def test_collect_metric_success(self, metrics_service, mock_db_session, sample_device):
        """Test successful metric collection"""
        metric_data = {
            "device_id": 1,
            "metric_type": MetricType.CPU_USAGE,
            "value": 80.5,
            "unit": "percent"
        }
        
        new_metric = Metric(**metric_data, id=1, timestamp=datetime.now())
        mock_db_session.add = MagicMock()
        mock_db_session.commit = AsyncMock()
        mock_db_session.refresh = AsyncMock()
        
        with patch.object(metrics_service, '_validate_metric_data'):
            with patch.object(metrics_service, '_ensure_device_exists', return_value=sample_device):
                result = await metrics_service.collect_metric(mock_db_session, metric_data)
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_collect_metric_device_not_found(self, metrics_service, mock_db_session):
        """Test metric collection with non-existent device"""
        metric_data = {
            "device_id": 999,
            "metric_type": MetricType.CPU_USAGE,
            "value": 80.5,
            "unit": "percent"
        }
        
        with patch.object(metrics_service, '_validate_metric_data'):
            with patch.object(metrics_service, '_ensure_device_exists', return_value=None):
                with pytest.raises(ResourceNotFoundException):
                    await metrics_service.collect_metric(mock_db_session, metric_data)

    @pytest.mark.asyncio
    async def test_collect_bulk_metrics_success(self, metrics_service, mock_db_session):
        """Test successful bulk metric collection"""
        metrics_data = [
            {
                "device_id": 1,
                "metric_type": MetricType.CPU_USAGE,
                "value": 75.0,
                "unit": "percent"
            },
            {
                "device_id": 1,
                "metric_type": MetricType.MEMORY_USAGE,
                "value": 60.0,
                "unit": "percent"
            },
            {
                "device_id": 1,
                "metric_type": MetricType.BANDWIDTH_USAGE,
                "value": 1000000,
                "unit": "bytes/sec"
            }
        ]
        
        mock_db_session.add_all = MagicMock()
        mock_db_session.commit = AsyncMock()
        
        with patch.object(metrics_service, '_validate_metric_data'):
            with patch.object(metrics_service, '_ensure_device_exists', return_value=True):
                result = await metrics_service.collect_bulk_metrics(mock_db_session, metrics_data)
                assert result == len(metrics_data)
                mock_db_session.add_all.assert_called_once()
                mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_device_metrics_success(self, metrics_service, mock_db_session, cpu_metrics):
        """Test getting device metrics"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = cpu_metrics
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_device_metrics(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now()
        )
        
        assert len(result) == 10
        assert all(m.metric_type == MetricType.CPU_USAGE for m in result)

    @pytest.mark.asyncio
    async def test_get_device_metrics_no_type_filter(self, metrics_service, mock_db_session):
        """Test getting all device metrics without type filter"""
        mixed_metrics = [
            Metric(id=1, device_id=1, metric_type=MetricType.CPU_USAGE, value=70.0),
            Metric(id=2, device_id=1, metric_type=MetricType.MEMORY_USAGE, value=60.0),
            Metric(id=3, device_id=1, metric_type=MetricType.BANDWIDTH_USAGE, value=1000)
        ]
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mixed_metrics
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_device_metrics(
            mock_db_session,
            device_id=1
        )
        
        assert len(result) == 3
        assert len(set(m.metric_type for m in result)) == 3

    @pytest.mark.asyncio
    async def test_get_latest_metric_success(self, metrics_service, mock_db_session, sample_metric):
        """Test getting latest metric for device"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_metric
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_latest_metric(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE
        )
        
        assert result == sample_metric

    @pytest.mark.asyncio
    async def test_get_latest_metric_not_found(self, metrics_service, mock_db_session):
        """Test getting latest metric when none exists"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_latest_metric(
            mock_db_session,
            device_id=999,
            metric_type=MetricType.CPU_USAGE
        )
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_metric_statistics_success(self, metrics_service, mock_db_session):
        """Test getting metric statistics"""
        # Mock raw SQL result for statistics
        mock_result = MagicMock()
        mock_result.first.return_value = (75.5, 60.0, 90.0, 12)  # avg, min, max, count
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_metric_statistics(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now()
        )
        
        assert result["average"] == 75.5
        assert result["minimum"] == 60.0
        assert result["maximum"] == 90.0
        assert result["count"] == 12

    @pytest.mark.asyncio
    async def test_get_aggregated_metrics_hourly(self, metrics_service, mock_db_session):
        """Test getting hourly aggregated metrics"""
        # Mock aggregated results
        mock_results = [
            (datetime.now() - timedelta(hours=2), 70.0, 65.0, 75.0),
            (datetime.now() - timedelta(hours=1), 80.0, 75.0, 85.0),
            (datetime.now(), 75.0, 70.0, 80.0)
        ]
        
        mock_result = MagicMock()
        mock_result.all.return_value = mock_results
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_aggregated_metrics(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            aggregation="hourly",
            start_time=datetime.now() - timedelta(hours=3),
            end_time=datetime.now()
        )
        
        assert len(result) == 3
        assert all("timestamp" in item for item in result)
        assert all("average" in item for item in result)

    @pytest.mark.asyncio
    async def test_get_aggregated_metrics_daily(self, metrics_service, mock_db_session):
        """Test getting daily aggregated metrics"""
        mock_results = [
            (datetime.now().date() - timedelta(days=1), 70.0, 65.0, 75.0),
            (datetime.now().date(), 80.0, 75.0, 85.0)
        ]
        
        mock_result = MagicMock()
        mock_result.all.return_value = mock_results
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_aggregated_metrics(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            aggregation="daily",
            start_time=datetime.now() - timedelta(days=2),
            end_time=datetime.now()
        )
        
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_delete_old_metrics_success(self, metrics_service, mock_db_session):
        """Test deleting old metrics"""
        cutoff_date = datetime.now() - timedelta(days=30)
        
        mock_result = MagicMock()
        mock_result.rowcount = 500  # Number of deleted rows
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        mock_db_session.commit = AsyncMock()
        
        result = await metrics_service.delete_old_metrics(mock_db_session, cutoff_date)
        
        assert result == 500
        mock_db_session.execute.assert_called_once()
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_metric_trends_success(self, metrics_service, mock_db_session):
        """Test getting metric trends analysis"""
        # Mock trend calculation results
        mock_results = [
            (datetime.now() - timedelta(hours=2), 70.0),
            (datetime.now() - timedelta(hours=1), 75.0),
            (datetime.now(), 80.0)
        ]
        
        mock_result = MagicMock()
        mock_result.all.return_value = mock_results
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.get_metric_trends(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            period_hours=3
        )
        
        assert "trend" in result
        assert "slope" in result
        assert "data_points" in result
        assert result["data_points"] == 3

    @pytest.mark.asyncio
    async def test_calculate_metric_percentiles(self, metrics_service, mock_db_session):
        """Test calculating metric percentiles"""
        # Mock percentile calculation results
        mock_result = MagicMock()
        mock_result.all.return_value = [
            (50.0,),  # 50th percentile
            (90.0,),  # 90th percentile  
            (95.0,),  # 95th percentile
            (99.0,)   # 99th percentile
        ]
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.calculate_metric_percentiles(
            mock_db_session,
            device_id=1,
            metric_type=MetricType.CPU_USAGE,
            percentiles=[50, 90, 95, 99],
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now()
        )
        
        assert result["50th"] == 50.0
        assert result["90th"] == 90.0
        assert result["95th"] == 95.0
        assert result["99th"] == 99.0

    @pytest.mark.asyncio
    async def test_get_device_metrics_summary(self, metrics_service, mock_db_session):
        """Test getting device metrics summary"""
        # Mock summary data for different metric types
        summary_data = {
            MetricType.CPU_USAGE: {"avg": 75.0, "max": 95.0, "min": 60.0},
            MetricType.MEMORY_USAGE: {"avg": 60.0, "max": 80.0, "min": 45.0},
            MetricType.BANDWIDTH_USAGE: {"avg": 1000000.0, "max": 2000000.0, "min": 500000.0}
        }
        
        with patch.object(metrics_service, 'get_metric_statistics') as mock_stats:
            mock_stats.side_effect = lambda db, device_id, metric_type, **kwargs: {
                "average": summary_data[metric_type]["avg"],
                "maximum": summary_data[metric_type]["max"],
                "minimum": summary_data[metric_type]["min"],
                "count": 100
            }
            
            result = await metrics_service.get_device_metrics_summary(
                mock_db_session,
                device_id=1,
                start_time=datetime.now() - timedelta(hours=1),
                end_time=datetime.now()
            )
            
            assert MetricType.CPU_USAGE.value in result
            assert MetricType.MEMORY_USAGE.value in result
            assert MetricType.BANDWIDTH_USAGE.value in result

    def test_validate_metric_data_valid(self, metrics_service):
        """Test metric data validation with valid data"""
        valid_data = {
            "device_id": 1,
            "metric_type": MetricType.CPU_USAGE,
            "value": 75.5,
            "unit": "percent"
        }
        # Should not raise any exception
        metrics_service._validate_metric_data(valid_data)

    def test_validate_metric_data_negative_value(self, metrics_service):
        """Test metric data validation with negative value"""
        invalid_data = {
            "device_id": 1,
            "metric_type": MetricType.CPU_USAGE,
            "value": -10.0,  # Invalid negative value for CPU usage
            "unit": "percent"
        }
        with pytest.raises(ValidationException):
            metrics_service._validate_metric_data(invalid_data)

    def test_validate_metric_data_invalid_percentage(self, metrics_service):
        """Test metric data validation with invalid percentage"""
        invalid_data = {
            "device_id": 1,
            "metric_type": MetricType.CPU_USAGE,
            "value": 150.0,  # Invalid percentage > 100
            "unit": "percent"
        }
        with pytest.raises(ValidationException):
            metrics_service._validate_metric_data(invalid_data)

    def test_validate_metric_data_missing_device_id(self, metrics_service):
        """Test metric data validation with missing device ID"""
        invalid_data = {
            "metric_type": MetricType.CPU_USAGE,
            "value": 75.0,
            "unit": "percent"
        }
        with pytest.raises(ValidationException):
            metrics_service._validate_metric_data(invalid_data)

    @pytest.mark.asyncio
    async def test_ensure_device_exists_success(self, metrics_service, mock_db_session, sample_device):
        """Test device existence check - device exists"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service._ensure_device_exists(mock_db_session, 1)
        assert result == sample_device

    @pytest.mark.asyncio
    async def test_ensure_device_exists_not_found(self, metrics_service, mock_db_session):
        """Test device existence check - device not found"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service._ensure_device_exists(mock_db_session, 999)
        assert result is None

    def test_calculate_trend_increasing(self, metrics_service):
        """Test trend calculation with increasing values"""
        data_points = [
            (datetime.now() - timedelta(hours=2), 60.0),
            (datetime.now() - timedelta(hours=1), 70.0),
            (datetime.now(), 80.0)
        ]
        
        trend = metrics_service._calculate_trend(data_points)
        assert trend["trend"] == "increasing"
        assert trend["slope"] > 0

    def test_calculate_trend_decreasing(self, metrics_service):
        """Test trend calculation with decreasing values"""
        data_points = [
            (datetime.now() - timedelta(hours=2), 80.0),
            (datetime.now() - timedelta(hours=1), 70.0),
            (datetime.now(), 60.0)
        ]
        
        trend = metrics_service._calculate_trend(data_points)
        assert trend["trend"] == "decreasing"
        assert trend["slope"] < 0

    def test_calculate_trend_stable(self, metrics_service):
        """Test trend calculation with stable values"""
        data_points = [
            (datetime.now() - timedelta(hours=2), 70.0),
            (datetime.now() - timedelta(hours=1), 70.5),
            (datetime.now(), 69.5)
        ]
        
        trend = metrics_service._calculate_trend(data_points)
        assert trend["trend"] == "stable"
        assert abs(trend["slope"]) < 1.0  # Small slope indicates stability

    def test_format_aggregation_period_hourly(self, metrics_service):
        """Test aggregation period formatting for hourly"""
        period = metrics_service._format_aggregation_period("hourly")
        assert "HOUR" in period

    def test_format_aggregation_period_daily(self, metrics_service):
        """Test aggregation period formatting for daily"""
        period = metrics_service._format_aggregation_period("daily")
        assert "DAY" in period

    def test_format_aggregation_period_invalid(self, metrics_service):
        """Test aggregation period formatting with invalid period"""
        with pytest.raises(ValidationException):
            metrics_service._format_aggregation_period("invalid")

    @pytest.mark.asyncio
    async def test_cleanup_metrics_by_device(self, metrics_service, mock_db_session):
        """Test cleanup of metrics for specific device"""
        mock_result = MagicMock()
        mock_result.rowcount = 100
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        mock_db_session.commit = AsyncMock()
        
        result = await metrics_service.cleanup_metrics_by_device(mock_db_session, device_id=1)
        
        assert result == 100
        mock_db_session.execute.assert_called_once()
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_export_metrics_csv_format(self, metrics_service, mock_db_session, cpu_metrics):
        """Test exporting metrics in CSV format"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = cpu_metrics
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.export_metrics(
            mock_db_session,
            device_id=1,
            format="csv",
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now()
        )
        
        assert isinstance(result, str)
        assert "timestamp,value,unit" in result  # CSV headers

    @pytest.mark.asyncio
    async def test_export_metrics_json_format(self, metrics_service, mock_db_session, cpu_metrics):
        """Test exporting metrics in JSON format"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = cpu_metrics
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await metrics_service.export_metrics(
            mock_db_session,
            device_id=1,
            format="json",
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now()
        )
        
        import json
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == len(cpu_metrics)