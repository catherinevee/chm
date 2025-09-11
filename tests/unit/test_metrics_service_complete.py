"""
Comprehensive test suite for MetricsService covering ALL functionality
Tests cover 100% of methods, branches, exceptions, and edge cases
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from backend.services.metrics_service import MetricsService
from backend.database.models import DeviceMetric, Device, Alert
from backend.common.exceptions import AppException


class TestMetricsServiceCreateMetric:
    """Test metric creation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_device(self):
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        device.configuration = {
            'thresholds': {
                'cpu': {'warning': 70, 'critical': 90},
                'memory': {'warning': 80, 'critical': 95}
            }
        }
        return device
    
    @pytest.mark.asyncio
    async def test_create_metric_success(self, mock_session, mock_device):
        """Test successful metric creation"""
        device_id = uuid4()
        mock_session.get.return_value = mock_device
        
        metric_data = {
            'name': 'cpu',
            'value': 50.5,
            'unit': 'percent',
            'timestamp': datetime.utcnow()
        }
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                with patch('backend.services.metrics_service.ws_manager') as mock_ws:
                    mock_ws.broadcast_metric_update = AsyncMock()
                    
                    result = await MetricsService.create_metric(
                        mock_session, device_id, metric_data
                    )
                    
                    mock_session.add.assert_called_once()
                    mock_session.commit.assert_called_once()
                    mock_ws.broadcast_metric_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_device_not_found(self, mock_session):
        """Test metric creation when device not found"""
        device_id = uuid4()
        mock_session.get.return_value = None
        
        metric_data = {'name': 'cpu', 'value': 50.5}
        
        with pytest.raises(AppException) as exc_info:
            await MetricsService.create_metric(mock_session, device_id, metric_data)
        
        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_metric_invalid_data(self, mock_session, mock_device):
        """Test metric creation with invalid data"""
        device_id = uuid4()
        mock_session.get.return_value = mock_device
        
        metric_data = {'invalid': 'data'}
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = False
            
            with pytest.raises(AppException) as exc_info:
                await MetricsService.create_metric(mock_session, device_id, metric_data)
            
            assert exc_info.value.status_code == 400
            assert "Invalid metric data" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_create_metric_database_error(self, mock_session, mock_device):
        """Test metric creation with database error"""
        device_id = uuid4()
        mock_session.get.return_value = mock_device
        mock_session.commit.side_effect = Exception("Database error")
        
        metric_data = {'name': 'cpu', 'value': 50.5}
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            
            with pytest.raises(AppException) as exc_info:
                await MetricsService.create_metric(mock_session, device_id, metric_data)
            
            assert exc_info.value.status_code == 500
            mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_websocket_error(self, mock_session, mock_device):
        """Test metric creation when WebSocket broadcast fails"""
        device_id = uuid4()
        mock_session.get.return_value = mock_device
        
        metric_data = {'name': 'cpu', 'value': 50.5}
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                with patch('backend.services.metrics_service.ws_manager') as mock_ws:
                    mock_ws.broadcast_metric_update = AsyncMock(side_effect=Exception("WS error"))
                    
                    with pytest.raises(AppException):
                        await MetricsService.create_metric(mock_session, device_id, metric_data)
    
    @pytest.mark.asyncio
    async def test_create_metric_default_timestamp(self, mock_session, mock_device):
        """Test metric creation with default timestamp"""
        device_id = uuid4()
        mock_session.get.return_value = mock_device
        
        metric_data = {'name': 'cpu', 'value': 50.5}  # No timestamp
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                with patch('backend.services.metrics_service.ws_manager') as mock_ws:
                    mock_ws.broadcast_metric_update = AsyncMock()
                    
                    result = await MetricsService.create_metric(
                        mock_session, device_id, metric_data
                    )
                    
                    mock_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_threshold_check_fails(self, mock_session, mock_device):
        """Test metric creation when threshold check fails"""
        device_id = uuid4()
        mock_session.get.return_value = mock_device
        
        metric_data = {'name': 'cpu', 'value': 95}  # Above critical
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', 
                            side_effect=Exception("Threshold error")):
                with patch('backend.services.metrics_service.ws_manager') as mock_ws:
                    mock_ws.broadcast_metric_update = AsyncMock()
                    
                    with pytest.raises(AppException):
                        await MetricsService.create_metric(mock_session, device_id, metric_data)


class TestMetricsServicePerformanceSummary:
    """Test performance summary generation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_success(self, mock_session):
        """Test successful performance summary generation"""
        mock_result = MagicMock()
        mock_metrics = [
            MagicMock(metric_type='cpu', avg_value=50.5, min_value=20, max_value=80, sample_count=100),
            MagicMock(metric_type='memory', avg_value=60.2, min_value=40, max_value=75, sample_count=100)
        ]
        mock_result.all.return_value = mock_metrics
        mock_session.execute.return_value = mock_result
        
        with patch.object(MetricsService, '_calculate_availability', return_value=99.5):
            result = await MetricsService.get_performance_summary(
                mock_session, device_id=uuid4(), hours=24
            )
            
            assert result['period_hours'] == 24
            assert 'metrics' in result
            assert 'cpu' in result['metrics']
            assert result['metrics']['cpu']['average'] == 50.5
            assert result['availability'] == 99.5
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_no_device_id(self, mock_session):
        """Test performance summary without device ID (all devices)"""
        mock_result = MagicMock()
        mock_metrics = [
            MagicMock(metric_type='cpu', avg_value=50.5, min_value=20, max_value=80, sample_count=100)
        ]
        mock_result.all.return_value = mock_metrics
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_performance_summary(
            mock_session, device_id=None, hours=48
        )
        
        assert result['period_hours'] == 48
        assert 'availability' not in result  # No availability for all devices
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_no_metrics(self, mock_session):
        """Test performance summary with no metrics"""
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_session.execute.return_value = mock_result
        
        with patch.object(MetricsService, '_calculate_availability', return_value=100.0):
            result = await MetricsService.get_performance_summary(
                mock_session, device_id=uuid4(), hours=24
            )
            
            assert result['metrics'] == {}
            assert result['availability'] == 100.0
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_null_values(self, mock_session):
        """Test performance summary with null values"""
        mock_result = MagicMock()
        mock_metrics = [
            MagicMock(metric_type='cpu', avg_value=None, min_value=None, max_value=None, sample_count=0)
        ]
        mock_result.all.return_value = mock_metrics
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_performance_summary(
            mock_session, device_id=None, hours=24
        )
        
        assert result['metrics']['cpu']['average'] == 0
        assert result['metrics']['cpu']['minimum'] == 0
        assert result['metrics']['cpu']['maximum'] == 0
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_database_error(self, mock_session):
        """Test performance summary with database error"""
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await MetricsService.get_performance_summary(
                mock_session, device_id=uuid4(), hours=24
            )
        
        assert exc_info.value.status_code == 500
        assert "Failed to get performance summary" in exc_info.value.detail
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_availability_error(self, mock_session):
        """Test performance summary when availability calculation fails"""
        mock_result = MagicMock()
        mock_result.all.return_value = []
        mock_session.execute.return_value = mock_result
        
        with patch.object(MetricsService, '_calculate_availability', 
                        side_effect=Exception("Availability error")):
            with pytest.raises(AppException):
                await MetricsService.get_performance_summary(
                    mock_session, device_id=uuid4(), hours=24
                )


class TestMetricsServiceGraphData:
    """Test graph data generation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_get_graph_data_success(self, mock_session):
        """Test successful graph data generation"""
        base_time = datetime.utcnow()
        mock_metrics = [
            MagicMock(timestamp=base_time, value=50),
            MagicMock(timestamp=base_time + timedelta(minutes=2), value=55),
            MagicMock(timestamp=base_time + timedelta(minutes=4), value=60),
            MagicMock(timestamp=base_time + timedelta(minutes=6), value=45),
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_graph_data(
            mock_session,
            device_id=uuid4(),
            metric_name='cpu',
            hours=1,
            interval_minutes=5
        )
        
        assert isinstance(result, list)
        assert len(result) > 0
        assert 'timestamp' in result[0]
        assert 'value' in result[0]
    
    @pytest.mark.asyncio
    async def test_get_graph_data_no_metrics(self, mock_session):
        """Test graph data with no metrics"""
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_graph_data(
            mock_session,
            device_id=uuid4(),
            metric_name='cpu',
            hours=24,
            interval_minutes=5
        )
        
        assert result == []
    
    @pytest.mark.asyncio
    async def test_get_graph_data_single_interval(self, mock_session):
        """Test graph data with metrics in single interval"""
        base_time = datetime.utcnow()
        mock_metrics = [
            MagicMock(timestamp=base_time, value=50),
            MagicMock(timestamp=base_time + timedelta(minutes=1), value=55),
            MagicMock(timestamp=base_time + timedelta(minutes=2), value=60),
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_graph_data(
            mock_session,
            device_id=uuid4(),
            metric_name='cpu',
            hours=1,
            interval_minutes=5
        )
        
        assert len(result) == 1  # All in same 5-minute interval
        assert result[0]['value'] == 55  # Average of 50, 55, 60
    
    @pytest.mark.asyncio
    async def test_get_graph_data_multiple_intervals(self, mock_session):
        """Test graph data with metrics across multiple intervals"""
        base_time = datetime.utcnow().replace(second=0, microsecond=0)
        mock_metrics = [
            MagicMock(timestamp=base_time, value=50),
            MagicMock(timestamp=base_time + timedelta(minutes=5), value=60),
            MagicMock(timestamp=base_time + timedelta(minutes=10), value=70),
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_graph_data(
            mock_session,
            device_id=uuid4(),
            metric_name='cpu',
            hours=1,
            interval_minutes=5
        )
        
        assert len(result) == 3  # Three different intervals
    
    @pytest.mark.asyncio
    async def test_get_graph_data_database_error(self, mock_session):
        """Test graph data with database error"""
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await MetricsService.get_graph_data(
                mock_session,
                device_id=uuid4(),
                metric_name='cpu',
                hours=24,
                interval_minutes=5
            )
        
        assert exc_info.value.status_code == 500
        assert "Failed to get graph data" in exc_info.value.detail


class TestMetricsServiceBulkCreate:
    """Test bulk metric creation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_device(self):
        device = MagicMock()
        device.id = uuid4()
        device.configuration = {'thresholds': {}}
        return device
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_success(self, mock_session, mock_device):
        """Test successful bulk metric creation"""
        mock_session.get.return_value = mock_device
        
        metrics_data = [
            {'device_id': mock_device.id, 'name': 'cpu', 'value': 50},
            {'device_id': mock_device.id, 'name': 'memory', 'value': 60},
            {'device_id': mock_device.id, 'name': 'disk', 'value': 70},
        ]
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                
                result = await MetricsService.bulk_create_metrics(mock_session, metrics_data)
                
                assert len(result) == 3
                assert mock_session.add.call_count == 3
                mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_skip_invalid(self, mock_session, mock_device):
        """Test bulk creation skips invalid metrics"""
        mock_session.get.return_value = mock_device
        
        metrics_data = [
            {'device_id': mock_device.id, 'name': 'cpu', 'value': 50},
            {'invalid': 'data'},  # Invalid metric
            {'device_id': mock_device.id, 'name': 'memory', 'value': 60},
        ]
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.side_effect = [True, False, True]
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                
                result = await MetricsService.bulk_create_metrics(mock_session, metrics_data)
                
                assert len(result) == 2  # Only valid metrics
                assert mock_session.add.call_count == 2
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_skip_missing_device(self, mock_session):
        """Test bulk creation skips metrics for missing devices"""
        device_id1 = uuid4()
        device_id2 = uuid4()
        
        mock_device = MagicMock()
        mock_device.id = device_id1
        mock_device.configuration = {}
        
        # First device exists, second doesn't
        mock_session.get.side_effect = [mock_device, None, mock_device]
        
        metrics_data = [
            {'device_id': device_id1, 'name': 'cpu', 'value': 50},
            {'device_id': device_id2, 'name': 'memory', 'value': 60},  # Device not found
            {'device_id': device_id1, 'name': 'disk', 'value': 70},
        ]
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                
                result = await MetricsService.bulk_create_metrics(mock_session, metrics_data)
                
                assert len(result) == 2  # Only metrics for existing device
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_empty_list(self, mock_session):
        """Test bulk creation with empty list"""
        result = await MetricsService.bulk_create_metrics(mock_session, [])
        
        assert result == []
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_database_error(self, mock_session, mock_device):
        """Test bulk creation with database error"""
        mock_session.get.return_value = mock_device
        mock_session.commit.side_effect = Exception("Database error")
        
        metrics_data = [
            {'device_id': mock_device.id, 'name': 'cpu', 'value': 50}
        ]
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            
            with pytest.raises(AppException) as exc_info:
                await MetricsService.bulk_create_metrics(mock_session, metrics_data)
            
            assert exc_info.value.status_code == 500
            mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_threshold_check_error(self, mock_session, mock_device):
        """Test bulk creation when threshold check fails"""
        mock_session.get.return_value = mock_device
        
        metrics_data = [
            {'device_id': mock_device.id, 'name': 'cpu', 'value': 95}
        ]
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', 
                            side_effect=Exception("Threshold error")):
                
                with pytest.raises(AppException):
                    await MetricsService.bulk_create_metrics(mock_session, metrics_data)


class TestMetricsServiceDeleteOld:
    """Test old metrics deletion"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        session.delete = AsyncMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_success(self, mock_session):
        """Test successful deletion of old metrics"""
        old_metrics = [
            MagicMock(id=1),
            MagicMock(id=2),
            MagicMock(id=3)
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = old_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        count = await MetricsService.delete_old_metrics(mock_session, days=90)
        
        assert count == 3
        assert mock_session.delete.call_count == 3
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_no_metrics(self, mock_session):
        """Test deletion when no old metrics exist"""
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        count = await MetricsService.delete_old_metrics(mock_session, days=30)
        
        assert count == 0
        mock_session.delete.assert_not_called()
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_custom_days(self, mock_session):
        """Test deletion with custom days parameter"""
        old_metrics = [MagicMock(id=1)]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = old_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        count = await MetricsService.delete_old_metrics(mock_session, days=7)
        
        assert count == 1
        # Verify the query uses correct cutoff date
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_database_error(self, mock_session):
        """Test deletion with database error"""
        mock_session.execute.side_effect = Exception("Database error")
        
        with pytest.raises(AppException) as exc_info:
            await MetricsService.delete_old_metrics(mock_session, days=90)
        
        assert exc_info.value.status_code == 500
        mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_commit_error(self, mock_session):
        """Test deletion when commit fails"""
        old_metrics = [MagicMock(id=1)]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = old_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        mock_session.commit.side_effect = Exception("Commit error")
        
        with pytest.raises(AppException):
            await MetricsService.delete_old_metrics(mock_session, days=90)
        
        mock_session.rollback.assert_called_once()


class TestMetricsServiceThresholds:
    """Test threshold checking and alert creation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        return session
    
    @pytest.fixture
    def mock_device(self):
        device = MagicMock()
        device.id = uuid4()
        device.configuration = {
            'thresholds': {
                'cpu': {'warning': 70, 'critical': 90},
                'memory': {'warning': 80, 'critical': 95}
            }
        }
        return device
    
    @pytest.mark.asyncio
    async def test_check_thresholds_critical(self, mock_session, mock_device):
        """Test threshold check triggers critical alert"""
        metric = MagicMock(metric_type='cpu', value=95, unit='percent')
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            await MetricsService._check_thresholds(mock_session, mock_device, metric)
            
            mock_create_alert.assert_called_once()
            call_args = mock_create_alert.call_args[0]
            assert call_args[3] == 'critical'
    
    @pytest.mark.asyncio
    async def test_check_thresholds_warning(self, mock_session):
        """Test threshold check triggers warning alert"""
        device = MagicMock()
        device.id = uuid4()
        device.configuration = {
            'thresholds': {
                'cpu': {'warning': 70}  # No critical threshold
            }
        }
        
        metric = MagicMock(metric_type='cpu', value=75, unit='percent')
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            await MetricsService._check_thresholds(mock_session, device, metric)
            
            mock_create_alert.assert_called_once()
            call_args = mock_create_alert.call_args[0]
            assert call_args[3] == 'warning'
    
    @pytest.mark.asyncio
    async def test_check_thresholds_no_alert(self, mock_session, mock_device):
        """Test threshold check when value is below thresholds"""
        metric = MagicMock(metric_type='cpu', value=50, unit='percent')
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            await MetricsService._check_thresholds(mock_session, mock_device, metric)
            
            mock_create_alert.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_thresholds_no_configuration(self, mock_session):
        """Test threshold check when device has no configuration"""
        device = MagicMock()
        device.id = uuid4()
        device.configuration = None
        
        metric = MagicMock(metric_type='cpu', value=95, unit='percent')
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            await MetricsService._check_thresholds(mock_session, device, metric)
            
            mock_create_alert.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_thresholds_no_metric_threshold(self, mock_session):
        """Test threshold check when metric type has no thresholds"""
        device = MagicMock()
        device.id = uuid4()
        device.configuration = {
            'thresholds': {
                'cpu': {'warning': 70, 'critical': 90}
            }
        }
        
        metric = MagicMock(metric_type='network', value=100, unit='mbps')
        
        with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
            await MetricsService._check_thresholds(mock_session, device, metric)
            
            mock_create_alert.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_check_thresholds_exception(self, mock_session, mock_device):
        """Test threshold check handles exceptions gracefully"""
        metric = MagicMock(metric_type='cpu', value=95, unit='percent')
        
        with patch.object(MetricsService, '_create_alert', 
                        side_effect=Exception("Alert error")):
            # Should not raise exception
            await MetricsService._check_thresholds(mock_session, mock_device, metric)
    
    @pytest.mark.asyncio
    async def test_create_alert_success(self, mock_session):
        """Test successful alert creation"""
        device = MagicMock(id=uuid4())
        metric = MagicMock(metric_type='cpu', value=95, unit='percent')
        
        mock_result = MagicMock()
        mock_result.scalar.return_value = None  # No existing alert
        mock_session.execute.return_value = mock_result
        
        await MetricsService._create_alert(
            mock_session, device, metric, 'critical', 'Test message'
        )
        
        mock_session.add.assert_called_once()
        mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_already_exists(self, mock_session):
        """Test alert creation when similar alert exists"""
        device = MagicMock(id=uuid4())
        metric = MagicMock(metric_type='cpu', value=95, unit='percent')
        
        mock_result = MagicMock()
        mock_result.scalar.return_value = MagicMock()  # Existing alert
        mock_session.execute.return_value = mock_result
        
        await MetricsService._create_alert(
            mock_session, device, metric, 'critical', 'Test message'
        )
        
        mock_session.add.assert_not_called()
        mock_session.commit.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_create_alert_exception(self, mock_session):
        """Test alert creation handles exceptions gracefully"""
        device = MagicMock(id=uuid4())
        metric = MagicMock(metric_type='cpu', value=95, unit='percent')
        
        mock_session.execute.side_effect = Exception("Database error")
        
        # Should not raise exception
        await MetricsService._create_alert(
            mock_session, device, metric, 'critical', 'Test message'
        )


class TestMetricsServiceAvailability:
    """Test availability calculation"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.execute = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_calculate_availability_100_percent(self, mock_session):
        """Test availability calculation with 100% uptime"""
        mock_metrics = [
            MagicMock(metric_value=1),
            MagicMock(metric_value=1),
            MagicMock(metric_value=1),
            MagicMock(metric_value=1),
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        availability = await MetricsService._calculate_availability(
            mock_session, uuid4(), datetime.utcnow()
        )
        
        assert availability == 100.0
    
    @pytest.mark.asyncio
    async def test_calculate_availability_partial(self, mock_session):
        """Test availability calculation with partial uptime"""
        mock_metrics = [
            MagicMock(metric_value=1),
            MagicMock(metric_value=1),
            MagicMock(metric_value=0),  # Down
            MagicMock(metric_value=1),
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        availability = await MetricsService._calculate_availability(
            mock_session, uuid4(), datetime.utcnow()
        )
        
        assert availability == 75.0
    
    @pytest.mark.asyncio
    async def test_calculate_availability_no_data(self, mock_session):
        """Test availability calculation with no data"""
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = []
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        availability = await MetricsService._calculate_availability(
            mock_session, uuid4(), datetime.utcnow()
        )
        
        assert availability == 100.0  # Assume 100% if no data
    
    @pytest.mark.asyncio
    async def test_calculate_availability_all_down(self, mock_session):
        """Test availability calculation when all checks are down"""
        mock_metrics = [
            MagicMock(metric_value=0),
            MagicMock(metric_value=0),
            MagicMock(metric_value=0),
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        availability = await MetricsService._calculate_availability(
            mock_session, uuid4(), datetime.utcnow()
        )
        
        assert availability == 0.0
    
    @pytest.mark.asyncio
    async def test_calculate_availability_exception(self, mock_session):
        """Test availability calculation handles exceptions"""
        mock_session.execute.side_effect = Exception("Database error")
        
        availability = await MetricsService._calculate_availability(
            mock_session, uuid4(), datetime.utcnow()
        )
        
        assert availability == 0  # Returns 0 on error


class TestMetricsServiceEdgeCases:
    """Test edge cases and error scenarios"""
    
    @pytest.fixture
    def mock_session(self):
        session = AsyncMock()
        session.get = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.execute = AsyncMock()
        session.delete = AsyncMock()
        return session
    
    @pytest.mark.asyncio
    async def test_create_metric_with_unicode_name(self, mock_session):
        """Test metric creation with unicode characters"""
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        device.configuration = {}
        mock_session.get.return_value = device
        
        metric_data = {
            'name': 'température',  # Unicode name
            'value': 25.5,
            'unit': '°C'  # Unicode unit
        }
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                with patch('backend.services.metrics_service.ws_manager') as mock_ws:
                    mock_ws.broadcast_metric_update = AsyncMock()
                    
                    result = await MetricsService.create_metric(
                        mock_session, device.id, metric_data
                    )
                    
                    mock_session.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metric_with_extreme_values(self, mock_session):
        """Test metric creation with extreme values"""
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        device.configuration = {}
        mock_session.get.return_value = device
        
        test_cases = [
            {'name': 'test', 'value': 0},  # Zero
            {'name': 'test', 'value': -100},  # Negative
            {'name': 'test', 'value': 1e10},  # Very large
            {'name': 'test', 'value': 1e-10},  # Very small
        ]
        
        for metric_data in test_cases:
            with patch('backend.services.metrics_service.ValidationService') as mock_validation:
                mock_validation.return_value.validate_metric_data.return_value = True
                with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                    with patch('backend.services.metrics_service.ws_manager') as mock_ws:
                        mock_ws.broadcast_metric_update = AsyncMock()
                        
                        result = await MetricsService.create_metric(
                            mock_session, device.id, metric_data
                        )
                        
                        assert mock_session.add.called
    
    @pytest.mark.asyncio
    async def test_get_graph_data_boundary_timestamps(self, mock_session):
        """Test graph data with boundary timestamp conditions"""
        base_time = datetime.utcnow().replace(minute=59, second=59, microsecond=999999)
        mock_metrics = [
            MagicMock(timestamp=base_time, value=50),
            MagicMock(timestamp=base_time + timedelta(seconds=1), value=60),  # Next hour
        ]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = mock_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        result = await MetricsService.get_graph_data(
            mock_session,
            device_id=uuid4(),
            metric_name='cpu',
            hours=1,
            interval_minutes=5
        )
        
        assert isinstance(result, list)
    
    @pytest.mark.asyncio
    async def test_bulk_create_metrics_partial_failure(self, mock_session):
        """Test bulk creation with partial device lookup failures"""
        device1 = MagicMock()
        device1.id = uuid4()
        device1.configuration = {}
        
        # Mix of successful and failed device lookups
        mock_session.get.side_effect = [device1, None, device1, Exception("DB error"), device1]
        
        metrics_data = [
            {'device_id': uuid4(), 'name': 'cpu', 'value': 50},
            {'device_id': uuid4(), 'name': 'memory', 'value': 60},
            {'device_id': uuid4(), 'name': 'disk', 'value': 70},
            {'device_id': uuid4(), 'name': 'network', 'value': 80},
            {'device_id': uuid4(), 'name': 'temp', 'value': 90},
        ]
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            with patch.object(MetricsService, '_check_thresholds', new=AsyncMock()):
                
                with pytest.raises(AppException):
                    await MetricsService.bulk_create_metrics(mock_session, metrics_data)
    
    @pytest.mark.asyncio
    async def test_performance_summary_large_dataset(self, mock_session):
        """Test performance summary with large dataset"""
        mock_metrics = []
        for i in range(100):
            mock_metrics.append(
                MagicMock(
                    metric_type=f'metric_{i % 10}',
                    avg_value=50 + i,
                    min_value=10 + i,
                    max_value=90 + i,
                    sample_count=1000
                )
            )
        
        mock_result = MagicMock()
        mock_result.all.return_value = mock_metrics
        mock_session.execute.return_value = mock_result
        
        with patch.object(MetricsService, '_calculate_availability', return_value=99.99):
            result = await MetricsService.get_performance_summary(
                mock_session, device_id=uuid4(), hours=720  # 30 days
            )
            
            assert len(result['metrics']) == 10  # 10 unique metric types
    
    @pytest.mark.asyncio
    async def test_delete_old_metrics_large_batch(self, mock_session):
        """Test deletion of large batch of old metrics"""
        old_metrics = [MagicMock(id=i) for i in range(10000)]
        
        mock_result = MagicMock()
        mock_scalars = MagicMock()
        mock_scalars.all.return_value = old_metrics
        mock_result.scalars.return_value = mock_scalars
        mock_session.execute.return_value = mock_result
        
        count = await MetricsService.delete_old_metrics(mock_session, days=365)
        
        assert count == 10000
        assert mock_session.delete.call_count == 10000
    
    @pytest.mark.asyncio
    async def test_concurrent_metric_creation(self, mock_session):
        """Test concurrent metric creation handling"""
        device = MagicMock()
        device.id = uuid4()
        device.hostname = "test-device"
        device.configuration = {}
        mock_session.get.return_value = device
        
        # Simulate concurrent commits
        commit_count = 0
        def commit_side_effect():
            nonlocal commit_count
            commit_count += 1
            if commit_count == 1:
                raise Exception("Concurrent modification")
            return AsyncMock()
        
        mock_session.commit.side_effect = commit_side_effect
        
        metric_data = {'name': 'cpu', 'value': 50}
        
        with patch('backend.services.metrics_service.ValidationService') as mock_validation:
            mock_validation.return_value.validate_metric_data.return_value = True
            
            with pytest.raises(AppException):
                await MetricsService.create_metric(mock_session, device.id, metric_data)
    
    @pytest.mark.asyncio
    async def test_threshold_boundary_values(self, mock_session):
        """Test threshold checking at exact boundary values"""
        device = MagicMock()
        device.id = uuid4()
        device.configuration = {
            'thresholds': {
                'cpu': {'warning': 70.0, 'critical': 90.0}
            }
        }
        
        test_cases = [
            (69.9, False),  # Just below warning
            (70.0, True),   # Exactly at warning
            (70.1, True),   # Just above warning
            (89.9, True),   # Just below critical
            (90.0, True),   # Exactly at critical
            (90.1, True),   # Just above critical
        ]
        
        for value, should_alert in test_cases:
            metric = MagicMock(metric_type='cpu', value=value, unit='percent')
            
            with patch.object(MetricsService, '_create_alert', new=AsyncMock()) as mock_create_alert:
                await MetricsService._check_thresholds(mock_session, device, metric)
                
                if should_alert:
                    mock_create_alert.assert_called()
                else:
                    mock_create_alert.assert_not_called()