"""
Comprehensive tests for Metrics Service to boost coverage to 65%
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession

# Mock ValidationService before importing
class MockValidationService:
    def __init__(self):
        pass
    
    def validate_metric_data(self, data):
        required_fields = ['value']
        for field in required_fields:
            if field not in data:
                return False
        if not isinstance(data['value'], (int, float)):
            return False
        return True

# Apply the mock
import sys
sys.modules['backend.services.validation_service'] = MagicMock()
sys.modules['backend.services.validation_service'].ValidationService = MockValidationService

from backend.services.metrics_service import MetricsService
from backend.common.exceptions import AppException


class TestMetricsService:
    """Comprehensive test cases for MetricsService"""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock(spec=AsyncSession)
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.add = MagicMock()
        session.get = AsyncMock()
        session.execute = AsyncMock()
        session.scalar = AsyncMock()
        session.delete = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_device(self):
        """Mock device object"""
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        device.ip_address = "192.168.1.1"
        device.configuration = {
            "thresholds": {
                "cpu_usage": {
                    "warning": 80,
                    "critical": 90
                },
                "memory_usage": {
                    "warning": 85,
                    "critical": 95
                }
            }
        }
        return device
    
    @pytest.fixture
    def mock_metric(self):
        """Mock metric object"""
        metric = MagicMock()
        metric.id = uuid4()
        metric.device_id = uuid4()
        metric.metric_type = "cpu_usage"
        metric.value = 75.0
        metric.unit = "percent"
        metric.timestamp = datetime.utcnow()
        return metric
    
    @pytest.fixture
    def metric_data(self):
        """Sample metric data"""
        return {
            "name": "cpu_usage",
            "value": 85.5,
            "unit": "percent",
            "timestamp": datetime.utcnow()
        }
    
    # Test create_metric method
    @pytest.mark.asyncio
    async def test_create_metric_success(self, mock_db_session, mock_device, metric_data):
        """Test successful metric creation"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_metric_update = AsyncMock()
            
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                # Execute
                result = await MetricsService.create_metric(
                    mock_db_session,
                    mock_device.id,
                    metric_data
                )
                
                # Verify
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
                mock_db_session.refresh.assert_called_once()
                mock_ws.broadcast_metric_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_device_not_found(self, mock_db_session, metric_data):
        """Test metric creation with non-existent device"""
        # Setup mocks
        mock_db_session.get.return_value = None
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.create_metric(
                mock_db_session,
                uuid4(),
                metric_data
            )
        
        assert exc_info.value.status_code == 404
        assert "Device" in str(exc_info.value.detail)
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_invalid_data(self, mock_db_session, mock_device):
        """Test metric creation with invalid data"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        invalid_data = {"name": "cpu_usage"}  # Missing value
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.create_metric(
                mock_db_session,
                mock_device.id,
                invalid_data
            )
        
        assert exc_info.value.status_code == 400
        assert "Invalid metric data" in str(exc_info.value.detail)
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_database_error(self, mock_db_session, mock_device, metric_data):
        """Test metric creation with database error"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        mock_db_session.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.create_metric(
                mock_db_session,
                mock_device.id,
                metric_data
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test get_performance_summary method
    @pytest.mark.asyncio
    async def test_get_performance_summary_success(self, mock_db_session):
        """Test successful performance summary retrieval"""
        # Setup mocks
        mock_metric_row1 = MagicMock()
        mock_metric_row1.metric_type = "cpu_usage"
        mock_metric_row1.avg_value = 75.5
        mock_metric_row1.min_value = 50.0
        mock_metric_row1.max_value = 95.0
        mock_metric_row1.sample_count = 100
        
        mock_metric_row2 = MagicMock()
        mock_metric_row2.metric_type = "memory_usage"
        mock_metric_row2.avg_value = 60.2
        mock_metric_row2.min_value = 45.0
        mock_metric_row2.max_value = 80.0
        mock_metric_row2.sample_count = 100
        
        mock_result = AsyncMock()
        mock_result.all.return_value = [mock_metric_row1, mock_metric_row2]
        mock_db_session.execute.return_value = mock_result
        
        with patch.object(MetricsService, '_calculate_availability', return_value=99.5):
            # Execute
            result = await MetricsService.get_performance_summary(
                mock_db_session,
                device_id=uuid4(),
                hours=24
            )
            
            # Verify
            assert result["period_hours"] == 24
            assert "metrics" in result
            assert "cpu_usage" in result["metrics"]
            assert result["metrics"]["cpu_usage"]["average"] == 75.5
            assert result["metrics"]["cpu_usage"]["samples"] == 100
            assert "availability" in result
            assert result["availability"] == 99.5
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_no_device_id(self, mock_db_session):
        """Test performance summary without device ID"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await MetricsService.get_performance_summary(mock_db_session, hours=12)
        
        # Verify
        assert result["period_hours"] == 12
        assert result["metrics"] == {}
        assert "availability" not in result
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_database_error(self, mock_db_session):
        """Test performance summary with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.get_performance_summary(mock_db_session)
        
        assert exc_info.value.status_code == 500
    
    # Test get_graph_data method
    @pytest.mark.asyncio
    async def test_get_graph_data_success(self, mock_db_session):
        """Test successful graph data retrieval"""
        # Setup mock metrics with different timestamps
        mock_metrics = []
        base_time = datetime.utcnow() - timedelta(hours=1)
        
        for i in range(5):
            mock_metric = MagicMock()
            mock_metric.value = 70 + i * 5
            mock_metric.timestamp = base_time + timedelta(minutes=i * 10)
            mock_metrics.append(mock_metric)
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await MetricsService.get_graph_data(
            mock_db_session,
            device_id=uuid4(),
            metric_name="cpu_usage",
            hours=2,
            interval_minutes=10
        )
        
        # Verify
        assert len(result) > 0
        assert "timestamp" in result[0]
        assert "value" in result[0]
        mock_db_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_graph_data_no_data(self, mock_db_session):
        """Test graph data retrieval with no data"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await MetricsService.get_graph_data(
            mock_db_session,
            device_id=uuid4(),
            metric_name="cpu_usage"
        )
        
        # Verify
        assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_get_graph_data_database_error(self, mock_db_session):
        """Test graph data retrieval with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.get_graph_data(
                mock_db_session,
                uuid4(),
                "cpu_usage"
            )
        
        assert exc_info.value.status_code == 500
    
    # Test bulk_create_metrics method
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_success(self, mock_db_session, mock_device):
        """Test successful bulk metric creation"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        metrics_data = [
            {
                "device_id": mock_device.id,
                "name": "cpu_usage",
                "value": 75.0,
                "unit": "percent"
            },
            {
                "device_id": mock_device.id,
                "name": "memory_usage",
                "value": 60.0,
                "unit": "percent"
            }
        ]
        
        with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
            # Execute
            result = await MetricsService.bulk_create_metrics(
                mock_db_session,
                metrics_data
            )
            
            # Verify
            assert len(result) == 2
            mock_db_session.commit.assert_called_once()
            assert mock_db_session.add.call_count == 2
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_invalid_data(self, mock_db_session, mock_device):
        """Test bulk creation with invalid data"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        metrics_data = [
            {
                "device_id": mock_device.id,
                "name": "cpu_usage",
                "value": 75.0
            },
            {
                "device_id": mock_device.id,
                "name": "invalid_metric"
                # Missing value
            }
        ]
        
        with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
            # Execute
            result = await MetricsService.bulk_create_metrics(
                mock_db_session,
                metrics_data
            )
            
            # Verify - should skip invalid metrics
            assert len(result) == 1
            mock_db_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_device_not_found(self, mock_db_session):
        """Test bulk creation with non-existent device"""
        # Setup mocks
        mock_db_session.get.return_value = None
        
        metrics_data = [
            {
                "device_id": uuid4(),
                "name": "cpu_usage",
                "value": 75.0
            }
        ]
        
        # Execute
        result = await MetricsService.bulk_create_metrics(
            mock_db_session,
            metrics_data
        )
        
        # Verify - should skip metrics with invalid device
        assert len(result) == 0
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_database_error(self, mock_db_session, mock_device):
        """Test bulk creation with database error"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        mock_db_session.commit.side_effect = Exception("Database error")
        
        metrics_data = [
            {
                "device_id": mock_device.id,
                "name": "cpu_usage",
                "value": 75.0
            }
        ]
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.bulk_create_metrics(
                mock_db_session,
                metrics_data
            )
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test delete_old_metrics method
    @pytest.mark.asyncio
    async def test_delete_old_metrics_success(self, mock_db_session):
        """Test successful old metrics deletion"""
        # Setup mocks
        old_metric1 = MagicMock()
        old_metric2 = MagicMock()
        old_metric3 = MagicMock()
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [
            old_metric1, old_metric2, old_metric3
        ]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await MetricsService.delete_old_metrics(mock_db_session, days=90)
        
        # Verify
        assert count == 3
        assert mock_db_session.delete.call_count == 3
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_no_data(self, mock_db_session):
        """Test deleting old metrics with no data"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        count = await MetricsService.delete_old_metrics(mock_db_session, days=30)
        
        # Verify
        assert count == 0
        mock_db_session.delete.assert_not_called()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_database_error(self, mock_db_session):
        """Test deleting old metrics with database error"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(AppException) as exc_info:
            await MetricsService.delete_old_metrics(mock_db_session)
        
        assert exc_info.value.status_code == 500
        mock_db_session.rollback.assert_called_once()
    
    # Test private _check_thresholds method
    @pytest.mark.asyncio
    async def test_check_thresholds_critical_exceeded(self, mock_db_session, mock_device, mock_metric):
        """Test threshold checking when critical threshold is exceeded"""
        # Setup mocks
        mock_metric.metric_type = "cpu_usage"
        mock_metric.value = 95.0  # Exceeds critical threshold of 90
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            # Execute
            await MetricsService._check_thresholds(mock_db_session, mock_device, mock_metric)
            
            # Verify
            mock_create_alert.assert_called_once()
            args = mock_create_alert.call_args[0]
            assert args[3] == "critical"  # severity
    
    @pytest.mark.asyncio
    async def test_check_thresholds_warning_exceeded(self, mock_db_session, mock_device, mock_metric):
        """Test threshold checking when warning threshold is exceeded"""
        # Setup device with only warning threshold
        mock_device.configuration = {
            "thresholds": {
                "cpu_usage": {
                    "warning": 80
                }
            }
        }
        mock_metric.metric_type = "cpu_usage"
        mock_metric.value = 85.0  # Exceeds warning threshold
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            # Execute
            await MetricsService._check_thresholds(mock_db_session, mock_device, mock_metric)
            
            # Verify
            mock_create_alert.assert_called_once()
            args = mock_create_alert.call_args[0]
            assert args[3] == "warning"  # severity
    
    @pytest.mark.asyncio
    async def test_check_thresholds_no_threshold_config(self, mock_db_session, mock_device, mock_metric):
        """Test threshold checking with no threshold configuration"""
        # Setup device with no thresholds
        mock_device.configuration = {}
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            # Execute
            await MetricsService._check_thresholds(mock_db_session, mock_device, mock_metric)
            
            # Verify no alert created
            mock_create_alert.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_thresholds_no_configuration(self, mock_db_session, mock_metric):
        """Test threshold checking with device having no configuration attribute"""
        # Setup device without configuration
        mock_device = MagicMock()
        mock_device.configuration = None
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            # Execute
            await MetricsService._check_thresholds(mock_db_session, mock_device, mock_metric)
            
            # Verify no alert created
            mock_create_alert.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_thresholds_below_threshold(self, mock_db_session, mock_device, mock_metric):
        """Test threshold checking when value is below threshold"""
        # Setup mocks
        mock_metric.metric_type = "cpu_usage"
        mock_metric.value = 70.0  # Below warning threshold of 80
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            # Execute
            await MetricsService._check_thresholds(mock_db_session, mock_device, mock_metric)
            
            # Verify no alert created
            mock_create_alert.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_thresholds_error(self, mock_db_session, mock_device, mock_metric):
        """Test error handling in threshold checking"""
        # Setup mocks to cause error
        mock_device.configuration = None
        delattr(mock_device, 'configuration')  # Remove attribute to cause AttributeError
        
        # Execute - should not raise exception, just log error
        await MetricsService._check_thresholds(mock_db_session, mock_device, mock_metric)
        
        # Verify it handled the error gracefully
        assert True
    
    # Test private _create_alert method
    @pytest.mark.asyncio
    async def test_create_alert_new_alert(self, mock_db_session, mock_device, mock_metric):
        """Test creating new alert when none exists"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar.return_value = None  # No existing alert
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        await MetricsService._create_alert(
            mock_db_session,
            mock_device,
            mock_metric,
            "critical",
            "CPU usage too high"
        )
        
        # Verify
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_existing_alert(self, mock_db_session, mock_device, mock_metric):
        """Test creating alert when similar alert already exists"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar.return_value = MagicMock()  # Existing alert
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        await MetricsService._create_alert(
            mock_db_session,
            mock_device,
            mock_metric,
            "critical",
            "CPU usage too high"
        )
        
        # Verify no new alert created
        mock_db_session.add.assert_not_called()
        mock_db_session.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_create_alert_error(self, mock_db_session, mock_device, mock_metric):
        """Test error handling in alert creation"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute - should not raise exception, just log error
        await MetricsService._create_alert(
            mock_db_session,
            mock_device,
            mock_metric,
            "critical",
            "CPU usage too high"
        )
        
        # Verify it handled the error gracefully
        assert True
    
    # Test private _calculate_availability method
    @pytest.mark.asyncio
    async def test_calculate_availability_with_data(self, mock_db_session):
        """Test availability calculation with data"""
        # Setup mocks
        mock_metrics = []
        for i in range(10):
            mock_metric = MagicMock()
            mock_metric.metric_value = 1 if i < 9 else 0  # 90% uptime
            mock_metrics.append(mock_metric)
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        availability = await MetricsService._calculate_availability(
            mock_db_session,
            uuid4(),
            datetime.utcnow() - timedelta(hours=24)
        )
        
        # Verify
        assert availability == 90.0
    
    @pytest.mark.asyncio
    async def test_calculate_availability_no_data(self, mock_db_session):
        """Test availability calculation with no data"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        availability = await MetricsService._calculate_availability(
            mock_db_session,
            uuid4(),
            datetime.utcnow() - timedelta(hours=24)
        )
        
        # Verify
        assert availability == 100.0  # Assume 100% if no data
    
    @pytest.mark.asyncio
    async def test_calculate_availability_all_up(self, mock_db_session):
        """Test availability calculation with all up metrics"""
        # Setup mocks
        mock_metrics = []
        for i in range(5):
            mock_metric = MagicMock()
            mock_metric.metric_value = 1  # All up
            mock_metrics.append(mock_metric)
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        availability = await MetricsService._calculate_availability(
            mock_db_session,
            uuid4(),
            datetime.utcnow() - timedelta(hours=24)
        )
        
        # Verify
        assert availability == 100.0
    
    @pytest.mark.asyncio
    async def test_calculate_availability_all_down(self, mock_db_session):
        """Test availability calculation with all down metrics"""
        # Setup mocks
        mock_metrics = []
        for i in range(5):
            mock_metric = MagicMock()
            mock_metric.metric_value = 0  # All down
            mock_metrics.append(mock_metric)
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        availability = await MetricsService._calculate_availability(
            mock_db_session,
            uuid4(),
            datetime.utcnow() - timedelta(hours=24)
        )
        
        # Verify
        assert availability == 0.0
    
    @pytest.mark.asyncio
    async def test_calculate_availability_error(self, mock_db_session):
        """Test error handling in availability calculation"""
        # Setup mocks
        mock_db_session.execute.side_effect = Exception("Database error")
        
        # Execute
        availability = await MetricsService._calculate_availability(
            mock_db_session,
            uuid4(),
            datetime.utcnow() - timedelta(hours=24)
        )
        
        # Verify error handling returns 0
        assert availability == 0
    
    # Test edge cases and complex scenarios
    @pytest.mark.asyncio
    async def test_get_graph_data_overlapping_intervals(self, mock_db_session):
        """Test graph data with overlapping time intervals"""
        # Setup mock metrics with same timestamp ranges
        mock_metrics = []
        base_time = datetime.utcnow() - timedelta(hours=1)
        
        # Create metrics with same 5-minute interval
        for i in range(3):
            mock_metric = MagicMock()
            mock_metric.value = 70 + i * 10
            mock_metric.timestamp = base_time + timedelta(minutes=2)  # Same interval
            mock_metrics.append(mock_metric)
        
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = mock_metrics
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await MetricsService.get_graph_data(
            mock_db_session,
            device_id=uuid4(),
            metric_name="cpu_usage",
            interval_minutes=5
        )
        
        # Verify - should aggregate overlapping intervals
        assert len(result) == 1  # Should be aggregated into one interval
        assert "timestamp" in result[0]
        assert "value" in result[0]
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_null_values(self, mock_db_session):
        """Test performance summary with null values"""
        # Setup mocks with null values
        mock_metric_row = MagicMock()
        mock_metric_row.metric_type = "cpu_usage"
        mock_metric_row.avg_value = None
        mock_metric_row.min_value = None
        mock_metric_row.max_value = None
        mock_metric_row.sample_count = 0
        
        mock_result = AsyncMock()
        mock_result.all.return_value = [mock_metric_row]
        mock_db_session.execute.return_value = mock_result
        
        # Execute
        result = await MetricsService.get_performance_summary(mock_db_session)
        
        # Verify
        assert result["metrics"]["cpu_usage"]["average"] == 0
        assert result["metrics"]["cpu_usage"]["minimum"] == 0
        assert result["metrics"]["cpu_usage"]["maximum"] == 0
    
    @pytest.mark.asyncio
    async def test_create_metric_without_timestamp(self, mock_db_session, mock_device):
        """Test metric creation without timestamp (should use current time)"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        metric_data = {
            "name": "cpu_usage",
            "value": 75.0,
            "unit": "percent"
            # No timestamp
        }
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_metric_update = AsyncMock()
            
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                # Execute
                result = await MetricsService.create_metric(
                    mock_db_session,
                    mock_device.id,
                    metric_data
                )
                
                # Verify
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_without_unit(self, mock_db_session, mock_device):
        """Test metric creation without unit"""
        # Setup mocks
        mock_db_session.get.return_value = mock_device
        
        metric_data = {
            "name": "cpu_usage",
            "value": 75.0
            # No unit
        }
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_metric_update = AsyncMock()
            
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                # Execute
                result = await MetricsService.create_metric(
                    mock_db_session,
                    mock_device.id,
                    metric_data
                )
                
                # Verify
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()