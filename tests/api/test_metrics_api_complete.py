"""
Comprehensive tests for metrics API endpoints
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import uuid
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.metrics import (
    router,
    MetricData,
    MetricCreate,
    MetricResponse,
    MetricSummary,
    DeviceMetricsSummary,
    PerformanceSummary
)
from backend.database.models import Device, DeviceMetric
from backend.database.user_models import User
from backend.services.validation_service import ValidationError


class TestMetricCreateEndpoint:
    """Test POST /api/v1/metrics endpoint"""
    
    @pytest.mark.asyncio
    async def test_create_metrics_success(self, client, mock_db, mock_user, mock_device):
        """Test successful metric creation"""
        mock_device.id = uuid.uuid4()
        mock_db.get.return_value = mock_device
        
        metric_data = {
            "device_id": str(mock_device.id),
            "metrics": [
                {
                    "metric_type": "cpu_usage",
                    "value": 75.5,
                    "unit": "percent",
                    "timestamp": datetime.utcnow().isoformat()
                },
                {
                    "metric_type": "memory_usage",
                    "value": 60.2,
                    "unit": "percent",
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.side_effect = lambda x: x  # Return same value
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
        mock_db.add.assert_called()
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_metrics_device_not_found(self, client, mock_db, mock_user):
        """Test metric creation with non-existent device"""
        mock_db.get.return_value = None
        
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "cpu_usage",
                    "value": 50.0,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_create_metrics_invalid_metric_type(self, client, mock_db, mock_user, mock_device):
        """Test metric creation with invalid metric type"""
        mock_db.get.return_value = mock_device
        
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "invalid_metric",
                    "value": 50.0,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.side_effect = ValidationError("Invalid metric name")
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 400
        assert "Invalid metric name" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_create_metrics_empty_list(self, client, mock_db, mock_user, mock_device):
        """Test metric creation with empty metrics list"""
        mock_db.get.return_value = mock_device
        
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": []
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 200
        assert response.json() == []
    
    @pytest.mark.asyncio
    async def test_create_metrics_batch(self, client, mock_db, mock_user, mock_device):
        """Test creating multiple metrics in batch"""
        mock_device.id = uuid.uuid4()
        mock_db.get.return_value = mock_device
        
        # Create 10 metrics
        metrics = []
        for i in range(10):
            metrics.append({
                "metric_type": f"metric_{i}",
                "value": float(i * 10),
                "unit": "units",
                "timestamp": (datetime.utcnow() - timedelta(minutes=i)).isoformat()
            })
        
        metric_data = {
            "device_id": str(mock_device.id),
            "metrics": metrics
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.side_effect = lambda x: x
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 10
        assert mock_db.add.call_count == 10
    
    @pytest.mark.asyncio
    async def test_create_metrics_unauthorized(self, client):
        """Test metric creation without authentication"""
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": []
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", side_effect=HTTPException(status_code=401)):
            response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_create_metrics_database_error(self, client, mock_db, mock_user, mock_device):
        """Test metric creation with database error"""
        mock_db.get.return_value = mock_device
        mock_db.commit.side_effect = Exception("Database error")
        
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "cpu_usage",
                    "value": 50.0,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.side_effect = lambda x: x
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 500
        assert "Failed to create metrics" in response.json()["detail"]


class TestPerformanceSummaryEndpoint:
    """Test GET /api/v1/metrics/performance/summary endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_success(self, client, mock_db, mock_user):
        """Test successful performance summary retrieval"""
        # Mock scalar results
        mock_db.scalar.side_effect = [
            10,  # total_devices
            8,   # active_devices
            2,   # devices_with_issues
            65.5,  # cpu_avg
            70.2,  # memory_avg
            150.5  # response_avg
        ]
        
        # Mock top CPU devices
        cpu_result = MagicMock()
        cpu_result.__iter__ = lambda x: iter([
            MagicMock(id=uuid.uuid4(), hostname="cpu-device-1", avg_cpu=95.5),
            MagicMock(id=uuid.uuid4(), hostname="cpu-device-2", avg_cpu=85.2)
        ])
        
        # Mock top memory devices
        memory_result = MagicMock()
        memory_result.__iter__ = lambda x: iter([
            MagicMock(id=uuid.uuid4(), hostname="mem-device-1", avg_memory=90.1),
            MagicMock(id=uuid.uuid4(), hostname="mem-device-2", avg_memory=82.3)
        ])
        
        mock_db.execute.side_effect = [cpu_result, memory_result]
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get("/api/v1/metrics/performance/summary")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_devices"] == 10
        assert data["active_devices"] == 8
        assert data["devices_with_issues"] == 2
        assert data["average_cpu"] == 65.5
        assert data["average_memory"] == 70.2
        assert data["average_response_time"] == 150.5
        assert len(data["top_cpu_devices"]) == 2
        assert len(data["top_memory_devices"]) == 2
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_with_hours(self, client, mock_db, mock_user):
        """Test performance summary with custom hours parameter"""
        mock_db.scalar.side_effect = [5, 4, 1, 50.0, 60.0, 100.0]
        mock_db.execute.side_effect = [MagicMock(), MagicMock()]
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get("/api/v1/metrics/performance/summary", params={"hours": 48})
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_devices"] == 5
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_no_data(self, client, mock_db, mock_user):
        """Test performance summary with no metrics data"""
        mock_db.scalar.side_effect = [0, 0, 0, None, None, None]
        
        empty_result = MagicMock()
        empty_result.__iter__ = lambda x: iter([])
        mock_db.execute.side_effect = [empty_result, empty_result]
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get("/api/v1/metrics/performance/summary")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_devices"] == 0
        assert data["average_cpu"] == 0
        assert data["average_memory"] == 0
        assert data["average_response_time"] == 0
        assert data["top_cpu_devices"] == []
        assert data["top_memory_devices"] == []
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_invalid_hours(self, client, mock_user):
        """Test performance summary with invalid hours parameter"""
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get("/api/v1/metrics/performance/summary", params={"hours": 200})
        
        assert response.status_code == 422  # Validation error (max 168 hours)
    
    @pytest.mark.asyncio
    async def test_get_performance_summary_database_error(self, client, mock_db, mock_user):
        """Test performance summary with database error"""
        mock_db.scalar.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get("/api/v1/metrics/performance/summary")
        
        assert response.status_code == 500
        assert "Failed to get performance summary" in response.json()["detail"]


class TestDevicePerformanceEndpoint:
    """Test GET /api/v1/metrics/performance/{device_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_device_performance_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device performance retrieval"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Mock statistics for each metric type
        stats_result = MagicMock()
        stats_result.one.return_value = MagicMock(
            max_val=95.0,
            min_val=20.0,
            avg_val=55.5,
            last_updated=datetime.utcnow()
        )
        
        # Mock current metric
        current_metric = MagicMock(spec=DeviceMetric)
        current_metric.value = 65.0
        current_metric.unit = "percent"
        
        current_result = MagicMock()
        current_result.scalar_one_or_none.return_value = current_metric
        
        # Return stats and current for each metric type (6 types)
        mock_db.execute.side_effect = [
            stats_result, current_result,  # cpu_usage
            stats_result, current_result,  # memory_usage
            stats_result, current_result,  # disk_usage
            stats_result, current_result,  # network_in
            stats_result, current_result,  # network_out
            stats_result, current_result   # response_time
        ]
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == str(device_id)
        assert data["hostname"] == "test-device"
        assert len(data["metrics"]) == 6
        assert data["metrics"][0]["current_value"] == 65.0
        assert data["metrics"][0]["min_value"] == 20.0
        assert data["metrics"][0]["max_value"] == 95.0
        assert data["metrics"][0]["avg_value"] == 55.5
    
    @pytest.mark.asyncio
    async def test_get_device_performance_device_not_found(self, client, mock_db, mock_user):
        """Test device performance for non-existent device"""
        device_id = uuid.uuid4()
        mock_db.get.return_value = None
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_device_performance_no_metrics(self, client, mock_db, mock_user, mock_device):
        """Test device performance with no metrics data"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Mock no statistics
        stats_result = MagicMock()
        stats_result.one.return_value = MagicMock(
            max_val=None,
            min_val=None,
            avg_val=None,
            last_updated=None
        )
        
        # Return empty stats for all metric types
        mock_db.execute.side_effect = [stats_result] * 6
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == str(device_id)
        assert data["metrics"] == []
    
    @pytest.mark.asyncio
    async def test_get_device_performance_with_hours(self, client, mock_db, mock_user, mock_device):
        """Test device performance with custom hours parameter"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_db.get.return_value = mock_device
        
        stats_result = MagicMock()
        stats_result.one.return_value = MagicMock(max_val=None)
        mock_db.execute.side_effect = [stats_result] * 6
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(
                f"/api/v1/metrics/performance/{device_id}",
                params={"hours": 72}
            )
        
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_get_device_performance_partial_metrics(self, client, mock_db, mock_user, mock_device):
        """Test device performance with only some metric types having data"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Mock statistics - only cpu and memory have data
        stats_with_data = MagicMock()
        stats_with_data.one.return_value = MagicMock(
            max_val=80.0,
            min_val=30.0,
            avg_val=55.0,
            last_updated=datetime.utcnow()
        )
        
        stats_no_data = MagicMock()
        stats_no_data.one.return_value = MagicMock(max_val=None)
        
        current_metric = MagicMock(spec=DeviceMetric)
        current_metric.value = 60.0
        current_metric.unit = "percent"
        
        current_result = MagicMock()
        current_result.scalar_one_or_none.return_value = current_metric
        
        mock_db.execute.side_effect = [
            stats_with_data, current_result,  # cpu_usage - has data
            stats_with_data, current_result,  # memory_usage - has data
            stats_no_data,                     # disk_usage - no data
            stats_no_data,                     # network_in - no data
            stats_no_data,                     # network_out - no data
            stats_no_data                      # response_time - no data
        ]
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["metrics"]) == 2  # Only CPU and memory


class TestDeviceMetricsGraphEndpoint:
    """Test GET /api/v1/metrics/performance/{device_id}/graph endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_metrics_graph_success(self, client, mock_db, mock_user, mock_device):
        """Test successful metrics graph data retrieval"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Mock metrics data
        base_time = datetime.utcnow()
        metrics_data = []
        for i in range(10):
            metrics_data.append(
                MagicMock(
                    timestamp=base_time - timedelta(minutes=i*10),
                    value=50.0 + i * 2,
                    unit="percent"
                )
            )
        
        result = MagicMock()
        result.all.return_value = metrics_data
        mock_db.execute.return_value = result
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.get(
                    f"/api/v1/metrics/performance/{device_id}/graph",
                    params={"metric_type": "cpu_usage"}
                )
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == str(device_id)
        assert data["hostname"] == "test-device"
        assert data["metric_type"] == "cpu_usage"
        assert data["unit"] == "percent"
        assert "data_points" in data
        assert len(data["data_points"]) > 0
    
    @pytest.mark.asyncio
    async def test_get_metrics_graph_device_not_found(self, client, mock_db, mock_user):
        """Test metrics graph for non-existent device"""
        device_id = uuid.uuid4()
        mock_db.get.return_value = None
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(
                f"/api/v1/metrics/performance/{device_id}/graph",
                params={"metric_type": "cpu_usage"}
            )
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_metrics_graph_invalid_metric_type(self, client, mock_db, mock_user, mock_device):
        """Test metrics graph with invalid metric type"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_db.get.return_value = mock_device
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.side_effect = ValidationError("Invalid metric name")
                response = await client.get(
                    f"/api/v1/metrics/performance/{device_id}/graph",
                    params={"metric_type": "invalid_metric"}
                )
        
        assert response.status_code == 400
        assert "Invalid metric name" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_metrics_graph_no_data(self, client, mock_db, mock_user, mock_device):
        """Test metrics graph with no data"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        result = MagicMock()
        result.all.return_value = []
        mock_db.execute.return_value = result
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.get(
                    f"/api/v1/metrics/performance/{device_id}/graph",
                    params={"metric_type": "cpu_usage"}
                )
        
        assert response.status_code == 200
        data = response.json()
        assert data["data_points"] == []
        assert data["unit"] is None
    
    @pytest.mark.asyncio
    async def test_get_metrics_graph_with_interval(self, client, mock_db, mock_user, mock_device):
        """Test metrics graph with custom interval"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Create metrics spanning 2 hours
        base_time = datetime.utcnow()
        metrics_data = []
        for i in range(24):  # 24 data points, 5 minutes apart
            metrics_data.append(
                MagicMock(
                    timestamp=base_time - timedelta(minutes=i*5),
                    value=50.0 + (i % 10),
                    unit="percent"
                )
            )
        
        result = MagicMock()
        result.all.return_value = metrics_data
        mock_db.execute.return_value = result
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.get(
                    f"/api/v1/metrics/performance/{device_id}/graph",
                    params={
                        "metric_type": "cpu_usage",
                        "hours": 2,
                        "interval": 30  # 30-minute buckets
                    }
                )
        
        assert response.status_code == 200
        data = response.json()
        assert data["interval_minutes"] == 30
        assert len(data["data_points"]) <= 4  # At most 4 buckets for 2 hours with 30-min intervals
    
    @pytest.mark.asyncio
    async def test_get_metrics_graph_aggregation(self, client, mock_db, mock_user, mock_device):
        """Test metrics graph data aggregation"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Create metrics that will be aggregated
        base_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        metrics_data = [
            MagicMock(timestamp=base_time, value=10.0, unit="percent"),
            MagicMock(timestamp=base_time + timedelta(minutes=5), value=20.0, unit="percent"),
            MagicMock(timestamp=base_time + timedelta(minutes=10), value=30.0, unit="percent"),
            MagicMock(timestamp=base_time + timedelta(minutes=15), value=40.0, unit="percent"),
        ]
        
        result = MagicMock()
        result.all.return_value = metrics_data
        mock_db.execute.return_value = result
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.get(
                    f"/api/v1/metrics/performance/{device_id}/graph",
                    params={
                        "metric_type": "cpu_usage",
                        "interval": 60  # 60-minute buckets - all should aggregate into one
                    }
                )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["data_points"]) == 1
        assert data["data_points"][0]["value"] == 25.0  # Average of 10, 20, 30, 40
        assert data["data_points"][0]["min"] == 10.0
        assert data["data_points"][0]["max"] == 40.0
        assert data["data_points"][0]["count"] == 4


class TestMetricsValidation:
    """Test metrics data validation"""
    
    @pytest.mark.asyncio
    async def test_metric_value_validation(self, client, mock_db, mock_user, mock_device):
        """Test metric value validation"""
        mock_db.get.return_value = mock_device
        
        # Test with negative value (should be allowed for some metrics)
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "temperature",
                    "value": -10.5,  # Negative temperature
                    "unit": "celsius",
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "temperature"
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_metric_timestamp_validation(self, client, mock_user):
        """Test metric timestamp validation"""
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "cpu_usage",
                    "value": 50.0,
                    "timestamp": "invalid-timestamp"  # Invalid timestamp format
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_graph_parameter_validation(self, client, mock_user):
        """Test graph endpoint parameter validation"""
        device_id = uuid.uuid4()
        
        # Test invalid hours
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(
                f"/api/v1/metrics/performance/{device_id}/graph",
                params={
                    "metric_type": "cpu_usage",
                    "hours": 200  # Above max of 168
                }
            )
        
        assert response.status_code == 422
        
        # Test invalid interval
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get(
                f"/api/v1/metrics/performance/{device_id}/graph",
                params={
                    "metric_type": "cpu_usage",
                    "interval": 4000  # Above max of 3600
                }
            )
        
        assert response.status_code == 422


class TestMetricsEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.mark.asyncio
    async def test_create_metrics_future_timestamp(self, client, mock_db, mock_user, mock_device):
        """Test creating metrics with future timestamp"""
        mock_db.get.return_value = mock_device
        
        future_time = datetime.utcnow() + timedelta(hours=1)
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "cpu_usage",
                    "value": 50.0,
                    "timestamp": future_time.isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        # Should accept future timestamps (might be timezone differences)
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_performance_summary_partial_failures(self, client, mock_db, mock_user):
        """Test performance summary with partial database failures"""
        # Some queries succeed, some return None
        mock_db.scalar.side_effect = [10, 8, 2, None, 60.0, None]
        
        cpu_result = MagicMock()
        cpu_result.__iter__ = lambda x: iter([])
        
        memory_result = MagicMock()
        memory_result.__iter__ = lambda x: iter([
            MagicMock(id=uuid.uuid4(), hostname="device1", avg_memory=80.0)
        ])
        
        mock_db.execute.side_effect = [cpu_result, memory_result]
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            response = await client.get("/api/v1/metrics/performance/summary")
        
        assert response.status_code == 200
        data = response.json()
        assert data["average_cpu"] == 0  # None becomes 0
        assert data["average_memory"] == 60.0
        assert data["average_response_time"] == 0
    
    @pytest.mark.asyncio
    async def test_graph_with_single_data_point(self, client, mock_db, mock_user, mock_device):
        """Test graph generation with single data point"""
        device_id = uuid.uuid4()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        # Single data point
        metrics_data = [
            MagicMock(
                timestamp=datetime.utcnow(),
                value=75.0,
                unit="percent"
            )
        ]
        
        result = MagicMock()
        result.all.return_value = metrics_data
        mock_db.execute.return_value = result
        
        with patch("backend.api.routers.metrics.require_metrics_read", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.get(
                    f"/api/v1/metrics/performance/{device_id}/graph",
                    params={"metric_type": "cpu_usage"}
                )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["data_points"]) == 1
        assert data["data_points"][0]["value"] == 75.0
        assert data["data_points"][0]["count"] == 1
    
    @pytest.mark.asyncio
    async def test_concurrent_metric_creation(self, client, mock_db, mock_user, mock_device):
        """Test handling concurrent metric creation"""
        mock_db.get.return_value = mock_device
        
        # Simulate optimistic locking failure
        mock_db.commit.side_effect = [Exception("Concurrent update"), None]
        
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": [
                {
                    "metric_type": "cpu_usage",
                    "value": 50.0,
                    "timestamp": datetime.utcnow().isoformat()
                }
            ]
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        # First attempt fails
        assert response.status_code == 500
    
    @pytest.mark.asyncio
    async def test_large_batch_metrics(self, client, mock_db, mock_user, mock_device):
        """Test creating very large batch of metrics"""
        mock_db.get.return_value = mock_device
        
        # Create 1000 metrics
        metrics = []
        base_time = datetime.utcnow()
        for i in range(1000):
            metrics.append({
                "metric_type": "cpu_usage",
                "value": float(i % 100),
                "unit": "percent",
                "timestamp": (base_time - timedelta(seconds=i)).isoformat()
            })
        
        metric_data = {
            "device_id": str(uuid.uuid4()),
            "metrics": metrics
        }
        
        with patch("backend.api.routers.metrics.require_metrics_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_metric_name") as mock_validate:
                mock_validate.return_value = "cpu_usage"
                response = await client.post("/api/v1/metrics", json=metric_data)
        
        assert response.status_code == 200
        assert len(response.json()) == 1000


# Fixtures for tests
@pytest.fixture
def client():
    """Create test client"""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    
    app = FastAPI()
    app.include_router(router)
    
    return TestClient(app)


@pytest.fixture
def mock_db():
    """Create mock database session"""
    mock = AsyncMock(spec=AsyncSession)
    mock.scalar = AsyncMock()
    mock.execute = AsyncMock()
    mock.add = MagicMock()
    mock.commit = AsyncMock()
    mock.refresh = AsyncMock()
    mock.get = AsyncMock()
    return mock


@pytest.fixture
def mock_user():
    """Create mock user"""
    user = MagicMock(spec=User)
    user.id = uuid.uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.is_active = True
    user.is_superuser = False
    return user


@pytest.fixture
def mock_device():
    """Create mock device"""
    device = MagicMock(spec=Device)
    device.id = uuid.uuid4()
    device.hostname = "test-device"
    device.ip_address = "192.168.1.1"
    device.device_type = "router"
    return device