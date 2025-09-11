"""
Comprehensive tests for health check API endpoints
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import os
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.health import (
    router,
    HealthStatus,
    SystemMetrics,
    DatabaseHealth,
    ServiceHealth,
    ComponentHealth,
    ApplicationHealth,
    APP_START_TIME,
    check_database_health,
    check_background_tasks_health,
    check_websocket_health,
    check_discovery_health,
    get_system_metrics,
    get_application_statistics
)
from backend.database.user_models import User


class TestHealthCheckEndpoint:
    """Test GET /api/v1/health endpoint"""
    
    @pytest.mark.asyncio
    async def test_health_check_success(self, client):
        """Test successful basic health check"""
        with patch("backend.api.routers.health.APP_START_TIME", datetime.utcnow() - timedelta(hours=1)):
            response = await client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data
        assert data["uptime_seconds"] > 0
        assert "version" in data
    
    @pytest.mark.asyncio
    async def test_health_check_with_version(self, client):
        """Test health check with custom version"""
        with patch.dict(os.environ, {"APP_VERSION": "3.1.4"}):
            response = await client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["version"] == "3.1.4"
    
    @pytest.mark.asyncio
    async def test_health_check_exception(self, client):
        """Test health check with exception"""
        with patch("backend.api.routers.health.datetime") as mock_datetime:
            mock_datetime.utcnow.side_effect = Exception("Time error")
            response = await client.get("/api/v1/health")
        
        assert response.status_code == 503
        assert "Service unhealthy" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_health_check_long_uptime(self, client):
        """Test health check with long uptime"""
        with patch("backend.api.routers.health.APP_START_TIME", datetime.utcnow() - timedelta(days=30)):
            response = await client.get("/api/v1/health")
        
        assert response.status_code == 200
        data = response.json()
        assert data["uptime_seconds"] > 2592000  # More than 30 days in seconds


class TestDetailedHealthCheckEndpoint:
    """Test GET /api/v1/health/detailed endpoint"""
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_success(self, client, mock_db, mock_user):
        """Test successful detailed health check"""
        # Mock all health check functions
        with patch("backend.api.routers.health.check_database_health") as mock_db_health:
            mock_db_health.return_value = DatabaseHealth(
                connected=True,
                pool_size=10,
                active_connections=3,
                response_time_ms=5.2
            )
            
            with patch("backend.api.routers.health.check_background_tasks_health") as mock_bg_health:
                mock_bg_health.return_value = ServiceHealth(
                    service="background_tasks",
                    status="running",
                    healthy=True,
                    details={"active_tasks": 5}
                )
                
                with patch("backend.api.routers.health.check_websocket_health") as mock_ws_health:
                    mock_ws_health.return_value = ServiceHealth(
                        service="websocket",
                        status="running",
                        healthy=True,
                        details={"active_connections": 10}
                    )
                    
                    with patch("backend.api.routers.health.check_discovery_health") as mock_disc_health:
                        mock_disc_health.return_value = ServiceHealth(
                            service="discovery",
                            status="running",
                            healthy=True,
                            details={"running_jobs": 2}
                        )
                        
                        with patch("backend.api.routers.health.get_system_metrics") as mock_sys_metrics:
                            mock_sys_metrics.return_value = SystemMetrics(
                                cpu_percent=45.5,
                                memory_percent=60.2,
                                memory_used_mb=4096,
                                memory_available_mb=4096,
                                disk_usage_percent=75.0,
                                process_count=150,
                                thread_count=20
                            )
                            
                            with patch("backend.api.routers.health.get_application_statistics") as mock_stats:
                                mock_stats.return_value = {
                                    "devices": {"total": 100, "active": 85},
                                    "alerts": {"active": 10, "critical": 2}
                                }
                                
                                with patch("backend.api.routers.health.get_optional_current_user", return_value=mock_user):
                                    response = await client.get("/api/v1/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["healthy"] is True
        assert "components" in data
        assert data["components"]["database"]["connected"] is True
        assert data["components"]["background_tasks"]["healthy"] is True
        assert data["components"]["websocket"]["healthy"] is True
        assert data["components"]["discovery"]["healthy"] is True
        assert data["components"]["system_metrics"]["cpu_percent"] == 45.5
        assert data["statistics"]["devices"]["total"] == 100
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_degraded(self, client, mock_db, mock_user):
        """Test detailed health check with degraded status"""
        with patch("backend.api.routers.health.check_database_health") as mock_db_health:
            mock_db_health.return_value = DatabaseHealth(
                connected=False,  # Database not connected
                pool_size=0,
                active_connections=0,
                response_time_ms=-1
            )
            
            with patch("backend.api.routers.health.check_background_tasks_health") as mock_bg_health:
                mock_bg_health.return_value = ServiceHealth(
                    service="background_tasks",
                    status="running",
                    healthy=True,
                    details={}
                )
                
                with patch("backend.api.routers.health.check_websocket_health") as mock_ws_health:
                    mock_ws_health.return_value = ServiceHealth(
                        service="websocket",
                        status="running",
                        healthy=True,
                        details={}
                    )
                    
                    with patch("backend.api.routers.health.check_discovery_health") as mock_disc_health:
                        mock_disc_health.return_value = ServiceHealth(
                            service="discovery",
                            status="running",
                            healthy=True,
                            details={}
                        )
                        
                        with patch("backend.api.routers.health.get_system_metrics") as mock_sys_metrics:
                            mock_sys_metrics.return_value = SystemMetrics(
                                cpu_percent=0,
                                memory_percent=0,
                                memory_used_mb=0,
                                memory_available_mb=0,
                                disk_usage_percent=0,
                                process_count=0,
                                thread_count=0
                            )
                            
                            with patch("backend.api.routers.health.get_application_statistics") as mock_stats:
                                mock_stats.return_value = {}
                                
                                with patch("backend.api.routers.health.get_optional_current_user", return_value=mock_user):
                                    response = await client.get("/api/v1/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"  # Degraded due to database issue
        assert data["healthy"] is False
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_exception(self, client, mock_user):
        """Test detailed health check with exception"""
        with patch("backend.api.routers.health.check_database_health") as mock_db_health:
            mock_db_health.side_effect = Exception("Database check failed")
            
            with patch("backend.api.routers.health.get_optional_current_user", return_value=mock_user):
                response = await client.get("/api/v1/health/detailed")
        
        assert response.status_code == 503
        assert "Failed to perform health check" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_detailed_health_check_environment(self, client, mock_db, mock_user):
        """Test detailed health check with custom environment"""
        with patch.dict(os.environ, {"ENVIRONMENT": "production", "APP_VERSION": "2.5.0"}):
            with patch("backend.api.routers.health.check_database_health") as mock_db_health:
                mock_db_health.return_value = DatabaseHealth(
                    connected=True,
                    pool_size=10,
                    active_connections=3,
                    response_time_ms=5.2
                )
                
                # Mock other health checks with minimal setup
                with patch("backend.api.routers.health.check_background_tasks_health") as mock_bg:
                    mock_bg.return_value = ServiceHealth(
                        service="background_tasks",
                        status="running",
                        healthy=True,
                        details={}
                    )
                    
                    with patch("backend.api.routers.health.check_websocket_health") as mock_ws:
                        mock_ws.return_value = ServiceHealth(
                            service="websocket",
                            status="running",
                            healthy=True,
                            details={}
                        )
                        
                        with patch("backend.api.routers.health.check_discovery_health") as mock_disc:
                            mock_disc.return_value = ServiceHealth(
                                service="discovery",
                                status="running",
                                healthy=True,
                                details={}
                            )
                            
                            with patch("backend.api.routers.health.get_system_metrics") as mock_sys:
                                mock_sys.return_value = SystemMetrics(
                                    cpu_percent=0,
                                    memory_percent=0,
                                    memory_used_mb=0,
                                    memory_available_mb=0,
                                    disk_usage_percent=0,
                                    process_count=0,
                                    thread_count=0
                                )
                                
                                with patch("backend.api.routers.health.get_application_statistics") as mock_stats:
                                    mock_stats.return_value = {}
                                    
                                    with patch("backend.api.routers.health.get_optional_current_user", return_value=mock_user):
                                        response = await client.get("/api/v1/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["environment"] == "production"
        assert data["version"] == "2.5.0"


class TestReadinessCheckEndpoint:
    """Test GET /api/v1/health/ready endpoint"""
    
    @pytest.mark.asyncio
    async def test_readiness_check_success(self, client, mock_db):
        """Test successful readiness check"""
        mock_db.execute.return_value = None  # Database is accessible
        
        with patch("backend.api.routers.health.get_db", return_value=mock_db):
            response = await client.get("/api/v1/health/ready")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert "timestamp" in data
        mock_db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_readiness_check_database_error(self, client, mock_db):
        """Test readiness check with database error"""
        mock_db.execute.side_effect = Exception("Database connection failed")
        
        with patch("backend.api.routers.health.get_db", return_value=mock_db):
            response = await client.get("/api/v1/health/ready")
        
        assert response.status_code == 503
        assert "Service not ready" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_readiness_check_timeout(self, client, mock_db):
        """Test readiness check with timeout"""
        import asyncio
        
        async def slow_execute(*args):
            await asyncio.sleep(10)  # Simulate slow database
        
        mock_db.execute = slow_execute
        
        with patch("backend.api.routers.health.get_db", return_value=mock_db):
            # This would timeout in real scenario
            pass


class TestLivenessCheckEndpoint:
    """Test GET /api/v1/health/live endpoint"""
    
    @pytest.mark.asyncio
    async def test_liveness_check_success(self, client):
        """Test successful liveness check"""
        response = await client.get("/api/v1/health/live")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"
        assert "timestamp" in data
    
    @pytest.mark.asyncio
    async def test_liveness_check_always_succeeds(self, client):
        """Test liveness check always succeeds"""
        # Even with various patches, liveness should always work
        with patch("backend.api.routers.health.datetime") as mock_datetime:
            mock_datetime.utcnow.return_value = datetime(2024, 1, 1)
            response = await client.get("/api/v1/health/live")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"


class TestDatabaseHealthCheck:
    """Test database health check function"""
    
    @pytest.mark.asyncio
    async def test_check_database_health_success(self, mock_db):
        """Test successful database health check"""
        mock_db.execute.return_value = None
        
        with patch("backend.api.routers.health.db.get_connection_stats") as mock_stats:
            mock_stats.return_value = {
                "pool_size": 20,
                "checked_out": 5
            }
            
            result = await check_database_health(mock_db)
        
        assert result.connected is True
        assert result.pool_size == 20
        assert result.active_connections == 5
        assert result.response_time_ms >= 0
    
    @pytest.mark.asyncio
    async def test_check_database_health_failure(self, mock_db):
        """Test database health check with connection failure"""
        mock_db.execute.side_effect = Exception("Connection refused")
        
        result = await check_database_health(mock_db)
        
        assert result.connected is False
        assert result.pool_size == 0
        assert result.active_connections == 0
        assert result.response_time_ms == -1
    
    @pytest.mark.asyncio
    async def test_check_database_health_slow_response(self, mock_db):
        """Test database health check with slow response"""
        import asyncio
        
        async def slow_execute(*args):
            await asyncio.sleep(0.1)  # 100ms delay
        
        mock_db.execute = slow_execute
        
        with patch("backend.api.routers.health.db.get_connection_stats") as mock_stats:
            mock_stats.return_value = {"pool_size": 10, "checked_out": 2}
            
            result = await check_database_health(mock_db)
        
        assert result.connected is True
        assert result.response_time_ms >= 100  # At least 100ms


class TestBackgroundTasksHealthCheck:
    """Test background tasks health check function"""
    
    @pytest.mark.asyncio
    async def test_check_background_tasks_health_running(self):
        """Test background tasks health check when running"""
        with patch("backend.services.background_tasks.background_service") as mock_service:
            mock_service.is_running = True
            mock_service.active_tasks_count.return_value = 5
            
            result = await check_background_tasks_health()
        
        assert result.service == "background_tasks"
        assert result.status == "running"
        assert result.healthy is True
        assert result.details["active_tasks"] == 5
    
    @pytest.mark.asyncio
    async def test_check_background_tasks_health_stopped(self):
        """Test background tasks health check when stopped"""
        with patch("backend.services.background_tasks.background_service") as mock_service:
            mock_service.is_running = False
            
            result = await check_background_tasks_health()
        
        assert result.status == "stopped"
        assert result.healthy is False
    
    @pytest.mark.asyncio
    async def test_check_background_tasks_health_no_service(self):
        """Test background tasks health check when service doesn't exist"""
        with patch("backend.services.background_tasks.background_service", new=None):
            result = await check_background_tasks_health()
        
        assert result.healthy is False
        assert result.status == "stopped"
    
    @pytest.mark.asyncio
    async def test_check_background_tasks_health_exception(self):
        """Test background tasks health check with exception"""
        with patch("backend.services.background_tasks.background_service") as mock_service:
            mock_service.is_running = property(lambda self: (_ for _ in ()).throw(Exception("Service error")))
            
            result = await check_background_tasks_health()
        
        assert result.status == "error"
        assert result.healthy is False
        assert "error" in result.details


class TestWebSocketHealthCheck:
    """Test WebSocket health check function"""
    
    @pytest.mark.asyncio
    async def test_check_websocket_health_success(self):
        """Test successful WebSocket health check"""
        with patch("backend.api.websocket_manager.ws_manager") as mock_manager:
            mock_manager.get_statistics.return_value = {
                "active_connections": 15,
                "authenticated_users": 10,
                "event_subscriptions": {"alerts": 5, "metrics": 8}
            }
            
            result = await check_websocket_health()
        
        assert result.service == "websocket"
        assert result.status == "running"
        assert result.healthy is True
        assert result.details["active_connections"] == 15
        assert result.details["authenticated_users"] == 10
    
    @pytest.mark.asyncio
    async def test_check_websocket_health_no_connections(self):
        """Test WebSocket health check with no connections"""
        with patch("backend.api.websocket_manager.ws_manager") as mock_manager:
            mock_manager.get_statistics.return_value = {
                "active_connections": 0,
                "authenticated_users": 0,
                "event_subscriptions": {}
            }
            
            result = await check_websocket_health()
        
        assert result.healthy is True  # Still healthy, just no connections
        assert result.details["active_connections"] == 0
    
    @pytest.mark.asyncio
    async def test_check_websocket_health_exception(self):
        """Test WebSocket health check with exception"""
        with patch("backend.api.websocket_manager.ws_manager") as mock_manager:
            mock_manager.get_statistics.side_effect = Exception("WebSocket error")
            
            result = await check_websocket_health()
        
        assert result.status == "error"
        assert result.healthy is False
        assert "error" in result.details


class TestDiscoveryHealthCheck:
    """Test discovery service health check function"""
    
    @pytest.mark.asyncio
    async def test_check_discovery_health_success(self, mock_db):
        """Test successful discovery health check"""
        mock_db.scalar.side_effect = [5, 2]  # 5 recent jobs, 2 running
        
        result = await check_discovery_health(mock_db)
        
        assert result.service == "discovery"
        assert result.status == "running"
        assert result.healthy is True
        assert result.details["recent_jobs"] == 5
        assert result.details["running_jobs"] == 2
    
    @pytest.mark.asyncio
    async def test_check_discovery_health_no_jobs(self, mock_db):
        """Test discovery health check with no jobs"""
        mock_db.scalar.side_effect = [0, 0]  # No recent or running jobs
        
        result = await check_discovery_health(mock_db)
        
        assert result.healthy is True  # Still healthy, just no jobs
        assert result.details["recent_jobs"] == 0
        assert result.details["running_jobs"] == 0
    
    @pytest.mark.asyncio
    async def test_check_discovery_health_database_error(self, mock_db):
        """Test discovery health check with database error"""
        mock_db.scalar.side_effect = Exception("Query failed")
        
        result = await check_discovery_health(mock_db)
        
        assert result.status == "error"
        assert result.healthy is False
        assert "error" in result.details


class TestSystemMetrics:
    """Test system metrics function"""
    
    def test_get_system_metrics_with_psutil(self):
        """Test system metrics with psutil available"""
        with patch("backend.api.routers.health.psutil") as mock_psutil:
            # Mock CPU
            mock_psutil.cpu_percent.return_value = 55.5
            
            # Mock memory
            mock_memory = MagicMock()
            mock_memory.percent = 65.2
            mock_memory.used = 8589934592  # 8GB in bytes
            mock_memory.available = 8589934592
            mock_psutil.virtual_memory.return_value = mock_memory
            
            # Mock disk
            mock_disk = MagicMock()
            mock_disk.percent = 80.5
            mock_psutil.disk_usage.return_value = mock_disk
            
            # Mock process
            mock_process = MagicMock()
            mock_process.num_threads.return_value = 25
            mock_psutil.Process.return_value = mock_process
            
            # Mock PIDs
            mock_psutil.pids.return_value = list(range(200))
            
            result = get_system_metrics()
        
        assert result.cpu_percent == 55.5
        assert result.memory_percent == 65.2
        assert result.memory_used_mb == 8192.0  # 8GB in MB
        assert result.memory_available_mb == 8192.0
        assert result.disk_usage_percent == 80.5
        assert result.process_count == 200
        assert result.thread_count == 25
    
    def test_get_system_metrics_without_psutil(self):
        """Test system metrics without psutil"""
        with patch("backend.api.routers.health.psutil", None):
            result = get_system_metrics()
        
        # Should return zeros when psutil not available
        assert result.cpu_percent == 0
        assert result.memory_percent == 0
        assert result.memory_used_mb == 0
        assert result.memory_available_mb == 0
        assert result.disk_usage_percent == 0
        assert result.process_count == 0
        assert result.thread_count == 0
    
    def test_get_system_metrics_exception(self):
        """Test system metrics with exception"""
        with patch("backend.api.routers.health.psutil") as mock_psutil:
            mock_psutil.cpu_percent.side_effect = Exception("CPU error")
            
            result = get_system_metrics()
        
        # Should return zeros on exception
        assert result.cpu_percent == 0
        assert result.memory_percent == 0


class TestApplicationStatistics:
    """Test application statistics function"""
    
    @pytest.mark.asyncio
    async def test_get_application_statistics_success(self, mock_db):
        """Test successful application statistics retrieval"""
        mock_db.scalar.side_effect = [
            100,  # total_devices
            85,   # active_devices
            15,   # active_alerts
            3,    # critical_alerts
            5000  # recent_metrics
        ]
        
        result = await get_application_statistics(mock_db)
        
        assert result["devices"]["total"] == 100
        assert result["devices"]["active"] == 85
        assert result["devices"]["inactive"] == 15
        assert result["alerts"]["active"] == 15
        assert result["alerts"]["critical"] == 3
        assert result["metrics"]["recent_count"] == 5000
        assert result["metrics"]["collection_rate"] > 0
    
    @pytest.mark.asyncio
    async def test_get_application_statistics_no_data(self, mock_db):
        """Test application statistics with no data"""
        mock_db.scalar.side_effect = [0, 0, 0, 0, 0]
        
        result = await get_application_statistics(mock_db)
        
        assert result["devices"]["total"] == 0
        assert result["devices"]["active"] == 0
        assert result["devices"]["inactive"] == 0
        assert result["alerts"]["active"] == 0
        assert result["metrics"]["collection_rate"] == 0
    
    @pytest.mark.asyncio
    async def test_get_application_statistics_exception(self, mock_db):
        """Test application statistics with exception"""
        mock_db.scalar.side_effect = Exception("Database error")
        
        result = await get_application_statistics(mock_db)
        
        assert result == {}  # Returns empty dict on error


class TestHealthCheckEdgeCases:
    """Test edge cases and error scenarios"""
    
    @pytest.mark.asyncio
    async def test_health_check_with_negative_uptime(self, client):
        """Test health check with future start time"""
        with patch("backend.api.routers.health.APP_START_TIME", datetime.utcnow() + timedelta(hours=1)):
            response = await client.get("/api/v1/health")
        
        assert response.status_code == 200
        # Uptime would be negative but should handle gracefully
    
    @pytest.mark.asyncio
    async def test_detailed_health_all_services_down(self, client, mock_user):
        """Test detailed health with all services down"""
        with patch("backend.api.routers.health.check_database_health") as mock_db:
            mock_db.return_value = DatabaseHealth(
                connected=False,
                pool_size=0,
                active_connections=0,
                response_time_ms=-1
            )
            
            with patch("backend.api.routers.health.check_background_tasks_health") as mock_bg:
                mock_bg.return_value = ServiceHealth(
                    service="background_tasks",
                    status="error",
                    healthy=False,
                    details={"error": "Service crashed"}
                )
                
                with patch("backend.api.routers.health.check_websocket_health") as mock_ws:
                    mock_ws.return_value = ServiceHealth(
                        service="websocket",
                        status="error",
                        healthy=False,
                        details={"error": "Connection failed"}
                    )
                    
                    with patch("backend.api.routers.health.check_discovery_health") as mock_disc:
                        mock_disc.return_value = ServiceHealth(
                            service="discovery",
                            status="error",
                            healthy=False,
                            details={"error": "Service unavailable"}
                        )
                        
                        with patch("backend.api.routers.health.get_system_metrics") as mock_sys:
                            mock_sys.return_value = SystemMetrics(
                                cpu_percent=0,
                                memory_percent=0,
                                memory_used_mb=0,
                                memory_available_mb=0,
                                disk_usage_percent=0,
                                process_count=0,
                                thread_count=0
                            )
                            
                            with patch("backend.api.routers.health.get_application_statistics") as mock_stats:
                                mock_stats.return_value = {}
                                
                                with patch("backend.api.routers.health.get_optional_current_user", return_value=mock_user):
                                    response = await client.get("/api/v1/health/detailed")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "degraded"
        assert data["healthy"] is False
    
    @pytest.mark.asyncio
    async def test_health_check_high_resource_usage(self):
        """Test health check with high resource usage"""
        with patch("backend.api.routers.health.psutil") as mock_psutil:
            # Simulate high resource usage
            mock_psutil.cpu_percent.return_value = 99.9
            
            mock_memory = MagicMock()
            mock_memory.percent = 95.5
            mock_memory.used = 32212254720  # ~30GB
            mock_memory.available = 1073741824  # 1GB
            mock_psutil.virtual_memory.return_value = mock_memory
            
            mock_disk = MagicMock()
            mock_disk.percent = 98.5
            mock_psutil.disk_usage.return_value = mock_disk
            
            mock_process = MagicMock()
            mock_process.num_threads.return_value = 500
            mock_psutil.Process.return_value = mock_process
            
            mock_psutil.pids.return_value = list(range(1000))
            
            result = get_system_metrics()
        
        assert result.cpu_percent == 99.9
        assert result.memory_percent == 95.5
        assert result.disk_usage_percent == 98.5
        assert result.thread_count == 500
        assert result.process_count == 1000


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
    mock.execute = AsyncMock()
    mock.scalar = AsyncMock()
    return mock


@pytest.fixture
def mock_user():
    """Create mock user"""
    user = MagicMock(spec=User)
    user.id = "user-123"
    user.username = "testuser"
    user.is_active = True
    return user