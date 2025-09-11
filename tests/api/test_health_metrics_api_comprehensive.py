"""
Comprehensive tests for Health and Metrics API endpoints
Testing all health and metrics router endpoints for complete coverage
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import json
from uuid import uuid4

# Mock modules that might not be available during testing
@pytest.fixture
def mock_validation_service():
    """Mock ValidationService"""
    with patch('backend.api.routers.metrics.ValidationService') as mock:
        mock.validate_metric_name = MagicMock(side_effect=lambda x: x)
        yield mock


@pytest.fixture
def mock_psutil():
    """Mock psutil module"""
    with patch('backend.api.routers.health.psutil') as mock:
        # Mock CPU usage
        mock.cpu_percent.return_value = 45.2
        
        # Mock memory usage
        mock_memory = MagicMock()
        mock_memory.percent = 65.3
        mock_memory.used = 8 * 1024 * 1024 * 1024  # 8GB in bytes
        mock_memory.available = 4 * 1024 * 1024 * 1024  # 4GB in bytes
        mock.virtual_memory.return_value = mock_memory
        
        # Mock disk usage
        mock_disk = MagicMock()
        mock_disk.percent = 75.1
        mock.disk_usage.return_value = mock_disk
        
        # Mock process info
        mock_process = MagicMock()
        mock_process.num_threads.return_value = 12
        mock.Process.return_value = mock_process
        mock.pids.return_value = list(range(100))  # 100 processes
        
        yield mock


@pytest.fixture
def mock_device():
    """Mock device object"""
    device = MagicMock()
    device.id = uuid4()
    device.hostname = "test-device"
    device.ip_address = "192.168.1.100"
    device.is_active = True
    device.current_state = "active"
    return device


@pytest.fixture
def mock_metric():
    """Mock device metric object"""
    metric = MagicMock()
    metric.id = uuid4()
    metric.device_id = uuid4()
    metric.metric_type = "cpu_usage"
    metric.value = 75.5
    metric.unit = "percent"
    metric.timestamp = datetime.utcnow()
    metric.created_at = datetime.utcnow()
    return metric


@pytest.fixture
def mock_db_session(mock_device, mock_metric):
    """Mock database session for health and metrics"""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.get = AsyncMock(return_value=mock_device)
    mock_session.scalar = AsyncMock(return_value=10)  # Default count
    
    # Mock query results
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_metric
    mock_result.all.return_value = [mock_metric]
    mock_result.one.return_value = MagicMock(max_val=100.0, min_val=10.0, avg_val=55.0, last_updated=datetime.utcnow())
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    return mock_session


@pytest.fixture
def health_app():
    """Create test FastAPI app with health router"""
    from fastapi import FastAPI
    from backend.api.routers.health import router as health_router
    
    app = FastAPI()
    app.include_router(health_router)
    
    return app


@pytest.fixture
def metrics_app():
    """Create test FastAPI app with metrics router"""
    from fastapi import FastAPI
    from backend.api.routers.metrics import router as metrics_router
    
    app = FastAPI()
    app.include_router(metrics_router)
    
    return app


@pytest.fixture
def health_client(health_app):
    """Test client for health API testing"""
    return TestClient(health_app)


@pytest.fixture
def metrics_client(metrics_app):
    """Test client for metrics API testing"""
    return TestClient(metrics_app)


@pytest.fixture
def mock_dependencies():
    """Mock all authentication dependencies"""
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.username = "testuser"
    
    with patch('backend.api.routers.health.get_optional_current_user', return_value=mock_user), \
         patch('backend.api.routers.metrics.require_metrics_read', return_value=mock_user), \
         patch('backend.api.routers.metrics.require_metrics_write', return_value=mock_user), \
         patch('backend.api.routers.metrics.standard_rate_limit'), \
         patch('backend.api.routers.health.get_db', return_value=AsyncMock()), \
         patch('backend.api.routers.metrics.get_db', return_value=AsyncMock()):
        yield mock_user


class TestHealthEndpoints:
    """Test health check endpoints"""
    
    def test_basic_health_check_success(self, health_client):
        """Test basic health check endpoint"""
        with patch('backend.api.routers.health.APP_START_TIME', datetime.utcnow() - timedelta(minutes=30)):
            response = health_client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert "uptime_seconds" in data
        assert "version" in data
        assert data["uptime_seconds"] > 0
    
    def test_basic_health_check_exception(self, health_client):
        """Test basic health check with exception"""
        with patch('backend.api.routers.health.datetime') as mock_dt:
            mock_dt.utcnow.side_effect = Exception("Time error")
            response = health_client.get("/api/v1/health")
        
        assert response.status_code == 503
        assert "Service unhealthy" in response.json()["detail"]
    
    def test_detailed_health_check_success(self, health_client, mock_dependencies, mock_db_session, mock_psutil):
        """Test detailed health check endpoint"""
        # Mock health check functions
        with patch('backend.api.routers.health.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.health.check_database_health') as mock_db_health, \
             patch('backend.api.routers.health.check_background_tasks_health') as mock_bg_health, \
             patch('backend.api.routers.health.check_websocket_health') as mock_ws_health, \
             patch('backend.api.routers.health.check_discovery_health') as mock_discovery_health, \
             patch('backend.api.routers.health.get_system_metrics') as mock_system_metrics, \
             patch('backend.api.routers.health.get_application_statistics') as mock_app_stats, \
             patch('backend.api.routers.health.APP_START_TIME', datetime.utcnow() - timedelta(hours=1)):
            
            # Configure mock responses
            mock_db_health.return_value = MagicMock(connected=True)
            mock_bg_health.return_value = MagicMock(healthy=True)
            mock_ws_health.return_value = MagicMock(healthy=True)
            mock_discovery_health.return_value = MagicMock(healthy=True)
            mock_system_metrics.return_value = MagicMock()
            mock_app_stats.return_value = {"test": "stats"}
            
            response = health_client.get("/api/v1/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["healthy"] is True
        assert "components" in data
        assert "statistics" in data
        assert "uptime_seconds" in data
    
    def test_detailed_health_check_degraded(self, health_client, mock_dependencies, mock_db_session):
        """Test detailed health check with degraded service"""
        with patch('backend.api.routers.health.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.health.check_database_health') as mock_db_health, \
             patch('backend.api.routers.health.check_background_tasks_health') as mock_bg_health, \
             patch('backend.api.routers.health.check_websocket_health') as mock_ws_health, \
             patch('backend.api.routers.health.check_discovery_health') as mock_discovery_health, \
             patch('backend.api.routers.health.get_system_metrics') as mock_system_metrics, \
             patch('backend.api.routers.health.get_application_statistics') as mock_app_stats:
            
            # Configure mock responses with one unhealthy service
            mock_db_health.return_value = MagicMock(connected=False)  # Database down
            mock_bg_health.return_value = MagicMock(healthy=True)
            mock_ws_health.return_value = MagicMock(healthy=True)
            mock_discovery_health.return_value = MagicMock(healthy=True)
            mock_system_metrics.return_value = MagicMock()
            mock_app_stats.return_value = {}
            
            response = health_client.get("/api/v1/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["healthy"] is False
    
    def test_detailed_health_check_exception(self, health_client, mock_dependencies):
        """Test detailed health check with exception"""
        with patch('backend.api.routers.health.get_db', side_effect=Exception("DB Error")):
            response = health_client.get("/api/v1/health/detailed")
        
        assert response.status_code == 503
        assert "Failed to perform health check" in response.json()["detail"]
    
    def test_readiness_check_success(self, health_client, mock_db_session):
        """Test readiness probe endpoint"""
        with patch('backend.api.routers.health.get_db', return_value=mock_db_session):
            response = health_client.get("/api/v1/health/ready")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "timestamp" in data
    
    def test_readiness_check_failure(self, health_client):
        """Test readiness probe endpoint with database failure"""
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database connection failed")
        
        with patch('backend.api.routers.health.get_db', return_value=mock_db):
            response = health_client.get("/api/v1/health/ready")
        
        assert response.status_code == 503
        assert "Service not ready" in response.json()["detail"]
    
    def test_liveness_check(self, health_client):
        """Test liveness probe endpoint"""
        response = health_client.get("/api/v1/health/live")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"
        assert "timestamp" in data


class TestHealthHelperFunctions:
    """Test health check helper functions"""
    
    def test_check_database_health_success(self, mock_db_session):
        """Test database health check success"""
        from backend.api.routers.health import check_database_health
        
        with patch('backend.api.routers.health.db') as mock_db_module:
            mock_db_module.get_connection_stats = AsyncMock(return_value={
                "pool_size": 20,
                "checked_out": 5
            })
            
            # Run the test
            import asyncio
            result = asyncio.run(check_database_health(mock_db_session))
        
        assert result.connected is True
        assert result.pool_size == 20
        assert result.active_connections == 5
        assert result.response_time_ms > 0
    
    def test_check_database_health_failure(self):
        """Test database health check failure"""
        from backend.api.routers.health import check_database_health
        
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Connection failed")
        
        # Run the test
        import asyncio
        result = asyncio.run(check_database_health(mock_db))
        
        assert result.connected is False
        assert result.pool_size == 0
        assert result.active_connections == 0
        assert result.response_time_ms == -1
    
    def test_check_background_tasks_health_success(self):
        """Test background tasks health check success"""
        from backend.api.routers.health import check_background_tasks_health
        
        with patch('backend.services.background_tasks.background_service') as mock_service:
            mock_service.is_running = True
            mock_service.active_tasks_count.return_value = 5
            
            # Run the test
            import asyncio
            result = asyncio.run(check_background_tasks_health())
        
        assert result.service == "background_tasks"
        assert result.status == "running"
        assert result.healthy is True
        assert result.details["active_tasks"] == 5
    
    def test_check_background_tasks_health_failure(self):
        """Test background tasks health check failure"""
        from backend.api.routers.health import check_background_tasks_health
        
        with patch('backend.services.background_tasks.background_service', side_effect=ImportError("Module not found")):
            # Run the test
            import asyncio
            result = asyncio.run(check_background_tasks_health())
        
        assert result.service == "background_tasks"
        assert result.status == "error"
        assert result.healthy is False
        assert "error" in result.details
    
    def test_check_websocket_health_success(self):
        """Test WebSocket health check success"""
        from backend.api.routers.health import check_websocket_health
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.get_statistics.return_value = {
                "active_connections": 10,
                "authenticated_users": 8,
                "event_subscriptions": {"alerts": 5, "devices": 3}
            }
            
            # Run the test
            import asyncio
            result = asyncio.run(check_websocket_health())
        
        assert result.service == "websocket"
        assert result.status == "running"
        assert result.healthy is True
        assert result.details["active_connections"] == 10
    
    def test_check_websocket_health_failure(self):
        """Test WebSocket health check failure"""
        from backend.api.routers.health import check_websocket_health
        
        with patch('backend.api.websocket_manager.ws_manager', side_effect=ImportError("Module not found")):
            # Run the test
            import asyncio
            result = asyncio.run(check_websocket_health())
        
        assert result.service == "websocket"
        assert result.status == "error"
        assert result.healthy is False
    
    def test_get_system_metrics_with_psutil(self, mock_psutil):
        """Test system metrics with psutil available"""
        from backend.api.routers.health import get_system_metrics
        
        result = get_system_metrics()
        
        assert result.cpu_percent == 45.2
        assert result.memory_percent == 65.3
        assert result.disk_usage_percent == 75.1
        assert result.process_count == 100
        assert result.thread_count == 12
    
    def test_get_system_metrics_without_psutil(self):
        """Test system metrics without psutil"""
        from backend.api.routers.health import get_system_metrics
        
        with patch('backend.api.routers.health.psutil', None):
            result = get_system_metrics()
        
        assert result.cpu_percent == 0
        assert result.memory_percent == 0
        assert result.disk_usage_percent == 0
        assert result.process_count == 0
        assert result.thread_count == 0
    
    def test_get_system_metrics_exception(self, mock_psutil):
        """Test system metrics with exception"""
        from backend.api.routers.health import get_system_metrics
        
        mock_psutil.cpu_percent.side_effect = Exception("CPU error")
        
        result = get_system_metrics()
        
        # Should return zeros on exception
        assert result.cpu_percent == 0
        assert result.memory_percent == 0
    
    def test_get_application_statistics_success(self, mock_db_session):
        """Test application statistics success"""
        from backend.api.routers.health import get_application_statistics
        
        # Configure scalar to return different values for different queries
        mock_db_session.scalar = AsyncMock(side_effect=[100, 80, 15, 5, 200])
        
        # Run the test
        import asyncio
        result = asyncio.run(get_application_statistics(mock_db_session))
        
        assert "devices" in result
        assert result["devices"]["total"] == 100
        assert result["devices"]["active"] == 80
        assert result["devices"]["inactive"] == 20
        assert "alerts" in result
        assert result["alerts"]["active"] == 15
        assert result["alerts"]["critical"] == 5
        assert "metrics" in result
    
    def test_get_application_statistics_failure(self):
        """Test application statistics failure"""
        from backend.api.routers.health import get_application_statistics
        
        mock_db = AsyncMock()
        mock_db.scalar.side_effect = Exception("Database error")
        
        # Run the test
        import asyncio
        result = asyncio.run(get_application_statistics(mock_db))
        
        assert result == {}  # Should return empty dict on error


class TestMetricsEndpoints:
    """Test metrics API endpoints"""
    
    def test_create_metrics_success(self, metrics_client, mock_dependencies, mock_db_session, mock_validation_service):
        """Test successful metrics creation"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.post(
                "/api/v1/metrics/",
                json={
                    "device_id": device_id,
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
            )
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        assert data[0]["metric_type"] == "cpu_usage"
        assert data[0]["value"] == 75.5
        mock_validation_service.validate_metric_name.assert_called()
    
    def test_create_metrics_device_not_found(self, metrics_client, mock_dependencies, mock_validation_service):
        """Test metrics creation when device not found"""
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)  # Device not found
        
        device_id = str(uuid4())
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db):
            response = metrics_client.post(
                "/api/v1/metrics/",
                json={
                    "device_id": device_id,
                    "metrics": [
                        {
                            "metric_type": "cpu_usage",
                            "value": 75.5,
                            "unit": "percent",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    ]
                }
            )
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_create_metrics_validation_error(self, metrics_client, mock_dependencies, mock_db_session):
        """Test metrics creation with validation error"""
        from backend.services.validation_service import ValidationError
        
        device_id = str(uuid4())
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.metrics.ValidationService.validate_metric_name', 
                   side_effect=ValidationError("Invalid metric name")):
            
            response = metrics_client.post(
                "/api/v1/metrics/",
                json={
                    "device_id": device_id,
                    "metrics": [
                        {
                            "metric_type": "invalid-metric",
                            "value": 75.5,
                            "unit": "percent",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    ]
                }
            )
        
        assert response.status_code == 400
        assert "Invalid metric name" in response.json()["detail"]
    
    def test_create_metrics_database_error(self, metrics_client, mock_dependencies, mock_validation_service):
        """Test metrics creation with database error"""
        mock_db = AsyncMock()
        mock_device = MagicMock()
        mock_db.get = AsyncMock(return_value=mock_device)
        mock_db.commit.side_effect = Exception("Database error")
        
        device_id = str(uuid4())
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db):
            response = metrics_client.post(
                "/api/v1/metrics/",
                json={
                    "device_id": device_id,
                    "metrics": [
                        {
                            "metric_type": "cpu_usage",
                            "value": 75.5,
                            "unit": "percent",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    ]
                }
            )
        
        assert response.status_code == 500
        assert "Failed to create metrics" in response.json()["detail"]
    
    def test_get_performance_summary_success(self, metrics_client, mock_dependencies, mock_db_session):
        """Test performance summary endpoint"""
        # Mock database responses for different queries
        mock_db_session.scalar = AsyncMock(side_effect=[
            100,  # total devices
            80,   # active devices
            5,    # devices with issues
            45.2, # cpu average
            60.5, # memory average
            150.3 # response time average
        ])
        
        # Mock result for top devices queries
        mock_top_result = MagicMock()
        mock_top_row = MagicMock()
        mock_top_row.id = uuid4()
        mock_top_row.hostname = "high-cpu-device"
        mock_top_row.avg_cpu = 85.5
        mock_top_row.avg_memory = 70.2
        mock_top_result.__iter__ = lambda x: iter([mock_top_row])
        mock_db_session.execute = AsyncMock(return_value=mock_top_result)
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.get("/api/v1/metrics/performance/summary")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_devices"] == 100
        assert data["active_devices"] == 80
        assert data["devices_with_issues"] == 5
        assert data["average_cpu"] == 45.2
        assert data["average_memory"] == 60.5
        assert data["average_response_time"] == 150.3
        assert len(data["top_cpu_devices"]) > 0
        assert len(data["top_memory_devices"]) > 0
    
    def test_get_performance_summary_custom_hours(self, metrics_client, mock_dependencies, mock_db_session):
        """Test performance summary with custom time range"""
        mock_db_session.scalar = AsyncMock(return_value=50)
        mock_empty_result = MagicMock()
        mock_empty_result.__iter__ = lambda x: iter([])
        mock_db_session.execute = AsyncMock(return_value=mock_empty_result)
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.get("/api/v1/metrics/performance/summary?hours=48")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_devices" in data
        assert "top_cpu_devices" in data
        assert "top_memory_devices" in data
    
    def test_get_performance_summary_invalid_hours(self, metrics_client, mock_dependencies):
        """Test performance summary with invalid hours"""
        response = metrics_client.get("/api/v1/metrics/performance/summary?hours=200")
        
        assert response.status_code == 422  # Validation error
    
    def test_get_performance_summary_database_error(self, metrics_client, mock_dependencies):
        """Test performance summary with database error"""
        mock_db = AsyncMock()
        mock_db.scalar.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db):
            response = metrics_client.get("/api/v1/metrics/performance/summary")
        
        assert response.status_code == 500
        assert "Failed to get performance summary" in response.json()["detail"]
    
    def test_get_device_performance_success(self, metrics_client, mock_dependencies, mock_db_session, mock_device):
        """Test device performance metrics endpoint"""
        device_id = str(uuid4())
        
        # Mock metric statistics query
        mock_stats_result = MagicMock()
        mock_stats_result.one.return_value = MagicMock(
            max_val=100.0,
            min_val=10.0,
            avg_val=55.0,
            last_updated=datetime.utcnow()
        )
        
        # Mock current metric query
        mock_current_result = MagicMock()
        mock_current_result.scalar_one_or_none.return_value = MagicMock(
            value=75.0,
            unit="percent"
        )
        
        mock_db_session.execute = AsyncMock(side_effect=[mock_stats_result, mock_current_result] * 6)  # For 6 metric types
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == str(mock_device.id)
        assert data["hostname"] == "test-device"
        assert "metrics" in data
    
    def test_get_device_performance_not_found(self, metrics_client, mock_dependencies):
        """Test device performance when device not found"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db):
            response = metrics_client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_get_device_performance_database_error(self, metrics_client, mock_dependencies, mock_db_session):
        """Test device performance with database error"""
        device_id = str(uuid4())
        mock_db_session.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.get(f"/api/v1/metrics/performance/{device_id}")
        
        assert response.status_code == 500
        assert "Failed to get device performance" in response.json()["detail"]
    
    def test_get_device_metrics_graph_success(self, metrics_client, mock_dependencies, mock_db_session, 
                                              mock_device, mock_validation_service):
        """Test device metrics graph endpoint"""
        device_id = str(uuid4())
        
        # Mock metrics data for graphing
        mock_graph_result = MagicMock()
        mock_metric_row = MagicMock()
        mock_metric_row.timestamp = datetime.utcnow()
        mock_metric_row.value = 75.5
        mock_metric_row.unit = "percent"
        mock_graph_result.all.return_value = [mock_metric_row]
        mock_db_session.execute = AsyncMock(return_value=mock_graph_result)
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.get(
                f"/api/v1/metrics/performance/{device_id}/graph?metric_type=cpu_usage&hours=24&interval=60"
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == str(mock_device.id)
        assert data["hostname"] == "test-device"
        assert data["metric_type"] == "cpu_usage"
        assert "data_points" in data
        assert "start_time" in data
        assert "end_time" in data
        mock_validation_service.validate_metric_name.assert_called_with("cpu_usage")
    
    def test_get_device_metrics_graph_device_not_found(self, metrics_client, mock_dependencies, mock_validation_service):
        """Test device metrics graph when device not found"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db):
            response = metrics_client.get(
                f"/api/v1/metrics/performance/{device_id}/graph?metric_type=cpu_usage"
            )
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_get_device_metrics_graph_validation_error(self, metrics_client, mock_dependencies, mock_db_session):
        """Test device metrics graph with validation error"""
        from backend.services.validation_service import ValidationError
        
        device_id = str(uuid4())
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.metrics.ValidationService.validate_metric_name', 
                   side_effect=ValidationError("Invalid metric type")):
            
            response = metrics_client.get(
                f"/api/v1/metrics/performance/{device_id}/graph?metric_type=invalid-metric"
            )
        
        assert response.status_code == 400
        assert "Invalid metric type" in response.json()["detail"]
    
    def test_get_device_metrics_graph_database_error(self, metrics_client, mock_dependencies, 
                                                     mock_db_session, mock_validation_service):
        """Test device metrics graph with database error"""
        device_id = str(uuid4())
        mock_db_session.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db_session):
            response = metrics_client.get(
                f"/api/v1/metrics/performance/{device_id}/graph?metric_type=cpu_usage"
            )
        
        assert response.status_code == 500
        assert "Failed to get metrics graph data" in response.json()["detail"]


class TestHealthMetricsIntegration:
    """Integration tests for health and metrics endpoints"""
    
    def test_health_and_metrics_consistency(self, health_client, metrics_client, mock_dependencies):
        """Test that health and metrics endpoints work together"""
        # Test health endpoint first
        response = health_client.get("/api/v1/health")
        assert response.status_code == 200
        
        # Test metrics endpoint
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_device = MagicMock()
        mock_db.get = AsyncMock(return_value=mock_device)
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db), \
             patch('backend.api.routers.metrics.ValidationService.validate_metric_name', side_effect=lambda x: x):
            
            response = metrics_client.post(
                "/api/v1/metrics/",
                json={
                    "device_id": device_id,
                    "metrics": [
                        {
                            "metric_type": "cpu_usage",
                            "value": 75.5,
                            "unit": "percent",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    ]
                }
            )
        
        assert response.status_code == 200
    
    def test_error_handling_consistency(self, health_client, metrics_client, mock_dependencies):
        """Test consistent error handling across endpoints"""
        # Test health endpoints with errors
        with patch('backend.api.routers.health.datetime') as mock_dt:
            mock_dt.utcnow.side_effect = Exception("Time error")
            health_response = health_client.get("/api/v1/health")
        
        assert health_response.status_code == 503
        
        # Test metrics endpoint with error
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.get.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.metrics.get_db', return_value=mock_db):
            metrics_response = metrics_client.post(
                "/api/v1/metrics/",
                json={
                    "device_id": device_id,
                    "metrics": [
                        {
                            "metric_type": "cpu_usage",
                            "value": 75.5,
                            "unit": "percent",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    ]
                }
            )
        
        assert metrics_response.status_code == 500


if __name__ == "__main__":
    pytest.main([__file__, "-v"])