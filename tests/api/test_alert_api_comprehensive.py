"""
Comprehensive tests for Alert API endpoints
Testing all alert router endpoints for complete coverage
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
    with patch('backend.api.routers.alerts.ValidationService') as mock:
        mock.sanitize_string = MagicMock(side_effect=lambda x: x)
        yield mock


@pytest.fixture
def mock_device():
    """Mock device object"""
    device = MagicMock()
    device.id = uuid4()
    device.hostname = "test-device"
    device.ip_address = "192.168.1.100"
    return device


@pytest.fixture
def mock_alert():
    """Mock alert object"""
    alert = MagicMock()
    alert.id = uuid4()
    alert.device_id = uuid4()
    alert.alert_type = "connectivity"
    alert.severity = "critical"
    alert.status = "active"
    alert.message = "Device unreachable"
    alert.details = {"timeout": 30}
    alert.acknowledged_by = None
    alert.acknowledged_at = None
    alert.resolved_at = None
    alert.created_at = datetime.utcnow()
    alert.updated_at = datetime.utcnow()
    alert.device = mock_device()
    return alert


@pytest.fixture
def mock_db_session(mock_device, mock_alert):
    """Mock database session"""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.delete = AsyncMock()
    mock_session.get = AsyncMock(side_effect=lambda model, id: mock_device if model.__name__ == 'Device' else mock_alert)
    mock_session.scalar = AsyncMock(return_value=10)  # Default count
    
    # Mock query results
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_alert
    mock_result.scalars.return_value.all.return_value = [mock_alert]
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    return mock_session


@pytest.fixture
def test_app():
    """Create test FastAPI app with alert router"""
    from fastapi import FastAPI
    from backend.api.routers.alerts import router
    
    app = FastAPI()
    app.include_router(router)
    
    return app


@pytest.fixture
def client(test_app):
    """Test client for API testing"""
    return TestClient(test_app)


@pytest.fixture
def mock_dependencies():
    """Mock all authentication dependencies"""
    mock_user = MagicMock()
    mock_user.id = uuid4()
    mock_user.username = "testuser"
    mock_user.roles = ["alerts_write", "alerts_read", "alerts_delete"]
    
    with patch('backend.api.routers.alerts.require_alerts_read', return_value=mock_user), \
         patch('backend.api.routers.alerts.require_alerts_write', return_value=mock_user), \
         patch('backend.api.routers.alerts.require_alerts_delete', return_value=mock_user), \
         patch('backend.api.routers.alerts.standard_rate_limit'), \
         patch('backend.api.routers.alerts.get_db', return_value=AsyncMock()):
        yield mock_user


class TestCreateAlertEndpoint:
    """Test alert creation endpoint"""
    
    def test_create_alert_success(self, client, mock_dependencies, mock_db_session, 
                                  mock_validation_service):
        """Test successful alert creation"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/alerts",
                json={
                    "device_id": device_id,
                    "alert_type": "connectivity",
                    "severity": "critical",
                    "message": "Device unreachable",
                    "details": {"timeout": 30}
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["alert_type"] == "connectivity"
        assert data["severity"] == "critical"
        assert data["status"] == "active"
        assert data["message"] == "Device unreachable"
        
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
        mock_validation_service.sanitize_string.assert_called_once()
    
    def test_create_alert_device_not_found(self, client, mock_dependencies, mock_validation_service):
        """Test alert creation when device not found"""
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)  # Device not found
        
        device_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/alerts",
                json={
                    "device_id": device_id,
                    "alert_type": "connectivity",
                    "severity": "critical",
                    "message": "Device unreachable"
                }
            )
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_create_alert_invalid_severity(self, client, mock_dependencies):
        """Test alert creation with invalid severity"""
        device_id = str(uuid4())
        
        response = client.post(
            "/api/v1/alerts",
            json={
                "device_id": device_id,
                "alert_type": "connectivity",
                "severity": "invalid-severity",
                "message": "Device unreachable"
            }
        )
        
        assert response.status_code == 422  # Validation error
    
    def test_create_alert_database_error(self, client, mock_dependencies, mock_validation_service):
        """Test alert creation with database error"""
        mock_db = AsyncMock()
        mock_device = MagicMock()
        mock_db.get = AsyncMock(return_value=mock_device)
        mock_db.commit.side_effect = Exception("Database error")
        
        device_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/alerts",
                json={
                    "device_id": device_id,
                    "alert_type": "connectivity",
                    "severity": "critical",
                    "message": "Device unreachable"
                }
            )
        
        assert response.status_code == 500
        assert "Failed to create alert" in response.json()["detail"]


class TestListAlertsEndpoint:
    """Test alert listing endpoint"""
    
    def test_list_alerts_success(self, client, mock_dependencies, mock_db_session):
        """Test successful alert listing"""
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert "unacknowledged_count" in data
        assert "critical_count" in data
        assert len(data["alerts"]) > 0
        assert data["alerts"][0]["alert_type"] == "connectivity"
    
    def test_list_alerts_with_filters(self, client, mock_dependencies, mock_db_session):
        """Test alert listing with filters"""
        device_id = str(uuid4())
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow()
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.get(
                f"/api/v1/alerts?device_id={device_id}&severity=critical&status=active"
                f"&alert_type=connectivity&start_date={start_date.isoformat()}&end_date={end_date.isoformat()}"
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
    
    def test_list_alerts_with_pagination(self, client, mock_dependencies, mock_db_session):
        """Test alert listing with pagination"""
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/alerts?page=2&per_page=25")
        
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 2
        assert data["per_page"] == 25
    
    def test_list_alerts_invalid_pagination(self, client, mock_dependencies):
        """Test alert listing with invalid pagination"""
        response = client.get("/api/v1/alerts?page=0&per_page=200")
        
        assert response.status_code == 422  # Validation error
    
    def test_list_alerts_database_error(self, client, mock_dependencies):
        """Test alert listing with database error"""
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.get("/api/v1/alerts")
        
        assert response.status_code == 500
        assert "Failed to list alerts" in response.json()["detail"]


class TestGetAlertStatisticsEndpoint:
    """Test alert statistics endpoint"""
    
    def test_get_alert_statistics_success(self, client, mock_dependencies, mock_db_session):
        """Test successful alert statistics retrieval"""
        # Mock statistics query results
        mock_severity_result = MagicMock()
        mock_severity_row = MagicMock()
        mock_severity_row.severity = "critical"
        mock_severity_row.count = 5
        mock_severity_result.__iter__ = lambda x: iter([mock_severity_row])
        
        mock_type_result = MagicMock()
        mock_type_row = MagicMock()
        mock_type_row.alert_type = "connectivity"
        mock_type_row.count = 3
        mock_type_result.__iter__ = lambda x: iter([mock_type_row])
        
        # Configure mock to return different results for different queries
        mock_db_session.execute = AsyncMock(side_effect=[
            mock_severity_result,  # severity counts
            mock_type_result,      # type counts
            mock_db_session.execute.return_value  # recent critical alerts
        ])
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/alerts/statistics")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data
        assert "active_alerts" in data
        assert "acknowledged_alerts" in data
        assert "resolved_alerts" in data
        assert "alerts_by_severity" in data
        assert "alerts_by_type" in data
        assert "recent_critical_alerts" in data
        assert isinstance(data["recent_critical_alerts"], list)
    
    def test_get_alert_statistics_custom_hours(self, client, mock_dependencies, mock_db_session):
        """Test alert statistics with custom time range"""
        # Mock empty results for custom hours
        mock_empty_result = MagicMock()
        mock_empty_result.__iter__ = lambda x: iter([])
        mock_db_session.execute = AsyncMock(return_value=mock_empty_result)
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/alerts/statistics?hours=48")
        
        assert response.status_code == 200
        data = response.json()
        assert "total_alerts" in data
        assert "alerts_by_severity" in data
        assert "alerts_by_type" in data
    
    def test_get_alert_statistics_invalid_hours(self, client, mock_dependencies):
        """Test alert statistics with invalid hours parameter"""
        response = client.get("/api/v1/alerts/statistics?hours=200")
        
        assert response.status_code == 422  # Validation error
    
    def test_get_alert_statistics_database_error(self, client, mock_dependencies):
        """Test alert statistics with database error"""
        mock_db = AsyncMock()
        mock_db.scalar.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.get("/api/v1/alerts/statistics")
        
        assert response.status_code == 500
        assert "Failed to get alert statistics" in response.json()["detail"]


class TestGetAlertEndpoint:
    """Test get alert by ID endpoint"""
    
    def test_get_alert_success(self, client, mock_dependencies, mock_db_session):
        """Test successful alert retrieval"""
        alert_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.get(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["alert_type"] == "connectivity"
        assert data["severity"] == "critical"
        assert data["status"] == "active"
        assert data["message"] == "Device unreachable"
        assert data["device_hostname"] == "test-device"
    
    def test_get_alert_invalid_id(self, client, mock_dependencies):
        """Test alert retrieval with invalid ID format"""
        response = client.get("/api/v1/alerts/invalid-uuid")
        
        assert response.status_code == 400
        assert "Invalid alert ID format" in response.json()["detail"]
    
    def test_get_alert_not_found(self, client, mock_dependencies):
        """Test alert retrieval when alert not found"""
        alert_id = str(uuid4())
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.get(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    def test_get_alert_database_error(self, client, mock_dependencies):
        """Test alert retrieval with database error"""
        alert_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.get(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 500
        assert "Failed to get alert" in response.json()["detail"]


class TestAcknowledgeAlertEndpoint:
    """Test alert acknowledgment endpoint"""
    
    def test_acknowledge_alert_success(self, client, mock_dependencies, mock_db_session, mock_alert):
        """Test successful alert acknowledgment"""
        alert_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "active"  # From mock, would be acknowledged in real implementation
        
        # Verify the alert was modified
        assert mock_alert.status == "acknowledged"
        assert mock_alert.acknowledged_by == "testuser"
        assert mock_alert.acknowledged_at is not None
        
        mock_db_session.commit.assert_called_once()
        mock_db_session.refresh.assert_called()
    
    def test_acknowledge_alert_not_found(self, client, mock_dependencies):
        """Test alert acknowledgment when alert not found"""
        alert_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    def test_acknowledge_alert_database_error(self, client, mock_dependencies, mock_db_session):
        """Test alert acknowledgment with database error"""
        alert_id = str(uuid4())
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert response.status_code == 500
        assert "Failed to acknowledge alert" in response.json()["detail"]


class TestResolveAlertEndpoint:
    """Test alert resolution endpoint"""
    
    def test_resolve_alert_success(self, client, mock_dependencies, mock_db_session, mock_alert):
        """Test successful alert resolution"""
        alert_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/alerts/{alert_id}/resolve")
        
        assert response.status_code == 200
        data = response.json()
        assert data["alert_type"] == "connectivity"
        
        # Verify the alert was modified
        assert mock_alert.status == "resolved"
        assert mock_alert.resolved_at is not None
        
        mock_db_session.commit.assert_called_once()
        mock_db_session.refresh.assert_called()
    
    def test_resolve_alert_with_note(self, client, mock_dependencies, mock_db_session, mock_alert):
        """Test alert resolution with resolution note"""
        alert_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.post(
                f"/api/v1/alerts/{alert_id}/resolve",
                json={"resolution_note": "Fixed network cable"}
            )
        
        assert response.status_code == 200
        
        # Verify resolution note was added to details
        assert mock_alert.details["resolution_note"] == "Fixed network cable"
        assert mock_alert.details["resolved_by"] == "testuser"
    
    def test_resolve_alert_not_found(self, client, mock_dependencies):
        """Test alert resolution when alert not found"""
        alert_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.post(f"/api/v1/alerts/{alert_id}/resolve")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    def test_resolve_alert_database_error(self, client, mock_dependencies, mock_db_session):
        """Test alert resolution with database error"""
        alert_id = str(uuid4())
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/alerts/{alert_id}/resolve")
        
        assert response.status_code == 500
        assert "Failed to resolve alert" in response.json()["detail"]


class TestDeleteAlertEndpoint:
    """Test alert deletion endpoint"""
    
    def test_delete_alert_success(self, client, mock_dependencies, mock_db_session):
        """Test successful alert deletion"""
        alert_id = str(uuid4())
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Alert deleted successfully"
        mock_db_session.delete.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    def test_delete_alert_not_found(self, client, mock_dependencies):
        """Test alert deletion when alert not found"""
        alert_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.get = AsyncMock(return_value=None)
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db):
            response = client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    def test_delete_alert_database_error(self, client, mock_dependencies, mock_db_session):
        """Test alert deletion with database error"""
        alert_id = str(uuid4())
        mock_db_session.delete.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_session):
            response = client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 500
        assert "Failed to delete alert" in response.json()["detail"]


class TestAlertEndpointsIntegration:
    """Integration tests for alert endpoints"""
    
    def test_alert_lifecycle_flow(self, client, mock_dependencies, mock_validation_service):
        """Test complete alert lifecycle: create, acknowledge, resolve, delete"""
        device_id = str(uuid4())
        
        # Mock database for creation
        mock_db_create = AsyncMock()
        mock_device = MagicMock()
        mock_device.id = device_id
        mock_device.hostname = "test-device"
        mock_db_create.get = AsyncMock(return_value=mock_device)
        mock_db_create.add = MagicMock()
        mock_db_create.commit = AsyncMock()
        mock_db_create.refresh = AsyncMock()
        
        # Create alert
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_create):
            create_response = client.post(
                "/api/v1/alerts",
                json={
                    "device_id": device_id,
                    "alert_type": "connectivity",
                    "severity": "critical",
                    "message": "Device unreachable"
                }
            )
        
        assert create_response.status_code == 200
        
        # Mock alert for subsequent operations
        mock_alert = MagicMock()
        mock_alert.id = uuid4()
        mock_alert.device_id = device_id
        mock_alert.alert_type = "connectivity"
        mock_alert.severity = "critical"
        mock_alert.status = "active"
        mock_alert.message = "Device unreachable"
        mock_alert.details = {}
        mock_alert.device = mock_device
        mock_alert.acknowledged_by = None
        mock_alert.acknowledged_at = None
        mock_alert.resolved_at = None
        mock_alert.created_at = datetime.utcnow()
        mock_alert.updated_at = datetime.utcnow()
        
        alert_id = str(mock_alert.id)
        
        # Mock database for acknowledgment
        mock_db_ack = AsyncMock()
        mock_db_ack.get = AsyncMock(return_value=mock_alert)
        mock_db_ack.commit = AsyncMock()
        mock_db_ack.refresh = AsyncMock()
        
        # Acknowledge alert
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_ack):
            ack_response = client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert ack_response.status_code == 200
        
        # Mock database for resolution
        mock_db_resolve = AsyncMock()
        mock_db_resolve.get = AsyncMock(return_value=mock_alert)
        mock_db_resolve.commit = AsyncMock()
        mock_db_resolve.refresh = AsyncMock()
        
        # Resolve alert
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_resolve):
            resolve_response = client.post(f"/api/v1/alerts/{alert_id}/resolve")
        
        assert resolve_response.status_code == 200
        
        # Mock database for deletion
        mock_db_delete = AsyncMock()
        mock_db_delete.get = AsyncMock(return_value=mock_alert)
        mock_db_delete.delete = AsyncMock()
        mock_db_delete.commit = AsyncMock()
        
        # Delete alert
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_delete):
            delete_response = client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert delete_response.status_code == 200
    
    def test_error_handling_consistency(self, client, mock_dependencies):
        """Test consistent error handling across alert endpoints"""
        alert_id = str(uuid4())
        
        # Test database errors
        mock_db_error = AsyncMock()
        mock_db_error.execute.side_effect = Exception("Database connection error")
        mock_db_error.get.side_effect = Exception("Database connection error")
        
        with patch('backend.api.routers.alerts.get_db', return_value=mock_db_error):
            # Test various endpoints that should handle DB errors gracefully
            endpoints = [
                ("GET", f"/api/v1/alerts/{alert_id}"),
                ("GET", "/api/v1/alerts"),
                ("GET", "/api/v1/alerts/statistics"),
                ("POST", f"/api/v1/alerts/{alert_id}/acknowledge"),
                ("POST", f"/api/v1/alerts/{alert_id}/resolve"),
                ("DELETE", f"/api/v1/alerts/{alert_id}"),
            ]
            
            for method, endpoint in endpoints:
                if method == "GET":
                    response = client.get(endpoint)
                elif method == "POST":
                    response = client.post(endpoint)
                elif method == "DELETE":
                    response = client.delete(endpoint)
                
                # Each endpoint should handle errors appropriately
                assert response.status_code in [404, 500]  # Various expected error codes
    
    def test_validation_consistency(self, client, mock_dependencies):
        """Test validation consistency across alert endpoints"""
        # Test invalid UUID formats
        invalid_ids = ["not-a-uuid", "12345", ""]
        
        for invalid_id in invalid_ids:
            if invalid_id != "":  # Empty string will be handled by routing
                response = client.get(f"/api/v1/alerts/{invalid_id}")
                assert response.status_code == 400  # UUID validation
        
        # Test invalid severity values in create
        response = client.post(
            "/api/v1/alerts",
            json={
                "device_id": str(uuid4()),
                "alert_type": "test",
                "severity": "invalid",
                "message": "test"
            }
        )
        assert response.status_code == 422  # Validation error
        
        # Test invalid status values in update
        response = client.put(
            f"/api/v1/alerts/{uuid4()}",
            json={"status": "invalid-status"}
        )
        # This endpoint doesn't exist in the router, so it will return 405 or 404


if __name__ == "__main__":
    pytest.main([__file__, "-v"])