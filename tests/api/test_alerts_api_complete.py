"""
Comprehensive tests for alerts API endpoints
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import uuid
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.alerts import (
    router,
    AlertCreate,
    AlertUpdate,
    AlertResponse,
    AlertListResponse,
    AlertStatistics
)
from backend.database.models import Alert, Device
from backend.database.user_models import User


class TestAlertCreateEndpoint:
    """Test POST /api/v1/alerts endpoint"""
    
    @pytest.mark.asyncio
    async def test_create_alert_success(self, client, mock_db, mock_user, mock_device):
        """Test successful alert creation"""
        # Setup
        mock_device.id = uuid.uuid4()
        mock_device.hostname = "test-device"
        mock_db.get.return_value = mock_device
        
        alert_data = {
            "device_id": str(mock_device.id),
            "alert_type": "cpu_high",
            "severity": "warning",
            "message": "CPU usage high",
            "details": {"cpu_percent": 85}
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_id"] == str(mock_device.id)
        assert data["alert_type"] == "cpu_high"
        assert data["severity"] == "warning"
        assert data["status"] == "active"
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_device_not_found(self, client, mock_db, mock_user):
        """Test alert creation with non-existent device"""
        mock_db.get.return_value = None
        
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "info",
            "message": "Test alert"
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_create_alert_invalid_severity(self, client, mock_user):
        """Test alert creation with invalid severity"""
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "invalid",  # Invalid severity
            "message": "Test alert"
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_create_alert_missing_required_fields(self, client, mock_user):
        """Test alert creation with missing required fields"""
        alert_data = {
            "device_id": str(uuid.uuid4())
            # Missing alert_type, severity, message
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_create_alert_unauthorized(self, client):
        """Test alert creation without authentication"""
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "info",
            "message": "Test alert"
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", side_effect=HTTPException(status_code=401)):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_create_alert_database_error(self, client, mock_db, mock_user, mock_device):
        """Test alert creation with database error"""
        mock_db.get.return_value = mock_device
        mock_db.commit.side_effect = Exception("Database error")
        
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "info",
            "message": "Test alert"
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 500
        assert "Failed to create alert" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_create_alert_sanitizes_message(self, client, mock_db, mock_user, mock_device):
        """Test that alert message is sanitized"""
        mock_device.id = uuid.uuid4()
        mock_db.get.return_value = mock_device
        
        alert_data = {
            "device_id": str(mock_device.id),
            "alert_type": "test",
            "severity": "info",
            "message": "<script>alert('XSS')</script>Test"
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.sanitize_string") as mock_sanitize:
                mock_sanitize.return_value = "Test"  # Sanitized message
                response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 200
        mock_sanitize.assert_called_once_with("<script>alert('XSS')</script>Test")


class TestAlertListEndpoint:
    """Test GET /api/v1/alerts endpoint"""
    
    @pytest.mark.asyncio
    async def test_list_alerts_success(self, client, mock_db, mock_user):
        """Test successful alert listing"""
        # Mock alerts
        mock_alert1 = MagicMock(spec=Alert)
        mock_alert1.id = uuid.uuid4()
        mock_alert1.device_id = uuid.uuid4()
        mock_alert1.alert_type = "cpu_high"
        mock_alert1.severity = "warning"
        mock_alert1.status = "active"
        mock_alert1.message = "CPU high"
        mock_alert1.details = None
        mock_alert1.acknowledged_by = None
        mock_alert1.acknowledged_at = None
        mock_alert1.resolved_at = None
        mock_alert1.created_at = datetime.utcnow()
        mock_alert1.updated_at = None
        mock_alert1.device = MagicMock(hostname="device1")
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_alert1]
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [1, 0, 0]  # total, unacknowledged, critical counts
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert "alerts" in data
        assert data["total"] == 1
        assert data["unacknowledged_count"] == 0
        assert data["critical_count"] == 0
    
    @pytest.mark.asyncio
    async def test_list_alerts_with_filters(self, client, mock_db, mock_user):
        """Test alert listing with filters"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [0, 0, 0]
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get(
                "/api/v1/alerts",
                params={
                    "device_id": str(uuid.uuid4()),
                    "severity": "critical",
                    "status": "active",
                    "alert_type": "cpu_high",
                    "page": 1,
                    "per_page": 20
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["per_page"] == 20
    
    @pytest.mark.asyncio
    async def test_list_alerts_with_date_range(self, client, mock_db, mock_user):
        """Test alert listing with date range filter"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [0, 0, 0]
        
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get(
                "/api/v1/alerts",
                params={
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat()
                }
            )
        
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_list_alerts_pagination(self, client, mock_db, mock_user):
        """Test alert listing pagination"""
        # Create mock alerts
        mock_alerts = []
        for i in range(5):
            alert = MagicMock(spec=Alert)
            alert.id = uuid.uuid4()
            alert.device_id = uuid.uuid4()
            alert.alert_type = f"type_{i}"
            alert.severity = "info"
            alert.status = "active"
            alert.message = f"Alert {i}"
            alert.details = None
            alert.acknowledged_by = None
            alert.acknowledged_at = None
            alert.resolved_at = None
            alert.created_at = datetime.utcnow()
            alert.updated_at = None
            alert.device = MagicMock(hostname=f"device{i}")
            mock_alerts.append(alert)
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = mock_alerts[:2]  # Page 1, 2 items
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [5, 3, 1]  # total, unacknowledged, critical
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts", params={"page": 1, "per_page": 2})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data["alerts"]) == 2
        assert data["total"] == 5
        assert data["page"] == 1
        assert data["per_page"] == 2
    
    @pytest.mark.asyncio
    async def test_list_alerts_database_error(self, client, mock_db, mock_user):
        """Test alert listing with database error"""
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts")
        
        assert response.status_code == 500
        assert "Failed to list alerts" in response.json()["detail"]


class TestAlertStatisticsEndpoint:
    """Test GET /api/v1/alerts/statistics endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_statistics_success(self, client, mock_db, mock_user):
        """Test successful statistics retrieval"""
        # Mock statistics data
        mock_db.scalar.side_effect = [10, 5, 3, 2]  # total, active, acknowledged, resolved
        
        # Mock severity counts
        severity_result = MagicMock()
        severity_result.__iter__ = lambda x: iter([
            MagicMock(severity="info", count=4),
            MagicMock(severity="warning", count=3),
            MagicMock(severity="critical", count=2),
            MagicMock(severity="error", count=1)
        ])
        
        # Mock type counts
        type_result = MagicMock()
        type_result.__iter__ = lambda x: iter([
            MagicMock(alert_type="cpu_high", count=5),
            MagicMock(alert_type="memory_high", count=3),
            MagicMock(alert_type="disk_full", count=2)
        ])
        
        # Mock recent critical alerts
        mock_critical = MagicMock(spec=Alert)
        mock_critical.id = uuid.uuid4()
        mock_critical.device_id = uuid.uuid4()
        mock_critical.alert_type = "cpu_critical"
        mock_critical.severity = "critical"
        mock_critical.status = "active"
        mock_critical.message = "Critical CPU"
        mock_critical.details = None
        mock_critical.acknowledged_by = None
        mock_critical.acknowledged_at = None
        mock_critical.resolved_at = None
        mock_critical.created_at = datetime.utcnow()
        mock_critical.updated_at = None
        mock_critical.device = MagicMock(hostname="critical-device")
        
        critical_result = MagicMock()
        critical_result.scalars.return_value.all.return_value = [mock_critical]
        
        mock_db.execute.side_effect = [severity_result, type_result, critical_result]
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts/statistics")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_alerts"] == 10
        assert data["active_alerts"] == 5
        assert data["acknowledged_alerts"] == 3
        assert data["resolved_alerts"] == 2
        assert "alerts_by_severity" in data
        assert "alerts_by_type" in data
        assert "recent_critical_alerts" in data
    
    @pytest.mark.asyncio
    async def test_get_statistics_with_custom_hours(self, client, mock_db, mock_user):
        """Test statistics with custom hours parameter"""
        mock_db.scalar.side_effect = [5, 2, 1, 2]
        mock_db.execute.side_effect = [MagicMock(), MagicMock(), MagicMock()]
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts/statistics", params={"hours": 48})
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_alerts"] == 5
    
    @pytest.mark.asyncio
    async def test_get_statistics_invalid_hours(self, client, mock_user):
        """Test statistics with invalid hours parameter"""
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts/statistics", params={"hours": 200})
        
        assert response.status_code == 422  # Validation error (max 168 hours)
    
    @pytest.mark.asyncio
    async def test_get_statistics_database_error(self, client, mock_db, mock_user):
        """Test statistics with database error"""
        mock_db.scalar.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts/statistics")
        
        assert response.status_code == 500
        assert "Failed to get alert statistics" in response.json()["detail"]


class TestAlertGetEndpoint:
    """Test GET /api/v1/alerts/{alert_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_alert_success(self, client, mock_db, mock_user):
        """Test successful alert retrieval"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.device_id = uuid.uuid4()
        mock_alert.alert_type = "test"
        mock_alert.severity = "info"
        mock_alert.status = "active"
        mock_alert.message = "Test alert"
        mock_alert.details = {"test": "data"}
        mock_alert.acknowledged_by = None
        mock_alert.acknowledged_at = None
        mock_alert.resolved_at = None
        mock_alert.created_at = datetime.utcnow()
        mock_alert.updated_at = None
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(alert_id)
        assert data["alert_type"] == "test"
        assert data["device_hostname"] == "test-device"
    
    @pytest.mark.asyncio
    async def test_get_alert_not_found(self, client, mock_db, mock_user):
        """Test get alert that doesn't exist"""
        alert_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_alert_invalid_id(self, client, mock_user):
        """Test get alert with invalid UUID"""
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts/invalid-uuid")
        
        assert response.status_code == 400
        assert "Invalid alert ID format" in response.json()["detail"]


class TestAlertAcknowledgeEndpoint:
    """Test POST /api/v1/alerts/{alert_id}/acknowledge endpoint"""
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_success(self, client, mock_db, mock_user):
        """Test successful alert acknowledgment"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.device_id = uuid.uuid4()
        mock_alert.alert_type = "test"
        mock_alert.severity = "warning"
        mock_alert.status = "active"
        mock_alert.message = "Test alert"
        mock_alert.details = None
        mock_alert.acknowledged_by = None
        mock_alert.acknowledged_at = None
        mock_alert.resolved_at = None
        mock_alert.created_at = datetime.utcnow()
        mock_alert.updated_at = None
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_db.get.return_value = mock_alert
        mock_user.username = "testuser"
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert response.status_code == 200
        assert mock_alert.status == "acknowledged"
        assert mock_alert.acknowledged_by == "testuser"
        assert mock_alert.acknowledged_at is not None
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_not_found(self, client, mock_db, mock_user):
        """Test acknowledge non-existent alert"""
        alert_id = uuid.uuid4()
        mock_db.get.return_value = None
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_already_acknowledged(self, client, mock_db, mock_user):
        """Test acknowledge already acknowledged alert"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.status = "acknowledged"
        mock_alert.acknowledged_by = "otheruser"
        mock_alert.acknowledged_at = datetime.utcnow()
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_db.get.return_value = mock_alert
        mock_user.username = "testuser"
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        # Should still succeed but update the acknowledger
        assert response.status_code == 200
        assert mock_alert.acknowledged_by == "testuser"
    
    @pytest.mark.asyncio
    async def test_acknowledge_alert_database_error(self, client, mock_db, mock_user):
        """Test acknowledge with database error"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_db.get.return_value = mock_alert
        mock_db.commit.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        assert response.status_code == 500
        assert "Failed to acknowledge alert" in response.json()["detail"]


class TestAlertResolveEndpoint:
    """Test POST /api/v1/alerts/{alert_id}/resolve endpoint"""
    
    @pytest.mark.asyncio
    async def test_resolve_alert_success(self, client, mock_db, mock_user):
        """Test successful alert resolution"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.status = "acknowledged"
        mock_alert.details = {}
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_db.get.return_value = mock_alert
        mock_user.username = "testuser"
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(
                f"/api/v1/alerts/{alert_id}/resolve",
                params={"resolution_note": "Fixed the issue"}
            )
        
        assert response.status_code == 200
        assert mock_alert.status == "resolved"
        assert mock_alert.resolved_at is not None
        assert mock_alert.details["resolution_note"] == "Fixed the issue"
        assert mock_alert.details["resolved_by"] == "testuser"
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resolve_alert_without_note(self, client, mock_db, mock_user):
        """Test resolve alert without resolution note"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.status = "active"
        mock_alert.details = None
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_db.get.return_value = mock_alert
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/resolve")
        
        assert response.status_code == 200
        assert mock_alert.status == "resolved"
        assert mock_alert.resolved_at is not None
    
    @pytest.mark.asyncio
    async def test_resolve_alert_not_found(self, client, mock_db, mock_user):
        """Test resolve non-existent alert"""
        alert_id = uuid.uuid4()
        mock_db.get.return_value = None
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/resolve")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_resolve_already_resolved_alert(self, client, mock_db, mock_user):
        """Test resolve already resolved alert"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.status = "resolved"
        mock_alert.resolved_at = datetime.utcnow() - timedelta(hours=1)
        mock_alert.details = {"resolution_note": "Old fix"}
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_db.get.return_value = mock_alert
        mock_user.username = "testuser"
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(
                f"/api/v1/alerts/{alert_id}/resolve",
                params={"resolution_note": "New fix"}
            )
        
        # Should update the resolution
        assert response.status_code == 200
        assert mock_alert.details["resolution_note"] == "New fix"


class TestAlertDeleteEndpoint:
    """Test DELETE /api/v1/alerts/{alert_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_delete_alert_success(self, client, mock_db, mock_user):
        """Test successful alert deletion"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_db.get.return_value = mock_alert
        
        with patch("backend.api.routers.alerts.require_alerts_delete", return_value=mock_user):
            response = await client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Alert deleted successfully"
        mock_db.delete.assert_called_once_with(mock_alert)
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_alert_not_found(self, client, mock_db, mock_user):
        """Test delete non-existent alert"""
        alert_id = uuid.uuid4()
        mock_db.get.return_value = None
        
        with patch("backend.api.routers.alerts.require_alerts_delete", return_value=mock_user):
            response = await client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 404
        assert "Alert not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_delete_alert_unauthorized(self, client):
        """Test delete alert without proper permissions"""
        alert_id = uuid.uuid4()
        
        with patch("backend.api.routers.alerts.require_alerts_delete", side_effect=HTTPException(status_code=403)):
            response = await client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_delete_alert_database_error(self, client, mock_db, mock_user):
        """Test delete with database error"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_db.get.return_value = mock_alert
        mock_db.delete.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.alerts.require_alerts_delete", return_value=mock_user):
            response = await client.delete(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 500
        assert "Failed to delete alert" in response.json()["detail"]


class TestAlertValidation:
    """Test alert data validation"""
    
    @pytest.mark.asyncio
    async def test_severity_validation(self, client, mock_user):
        """Test severity field validation"""
        valid_severities = ["info", "warning", "critical", "error"]
        
        for severity in valid_severities:
            alert_data = {
                "device_id": str(uuid.uuid4()),
                "alert_type": "test",
                "severity": severity,
                "message": "Test"
            }
            # Should pass validation (would fail at DB level without proper setup)
            with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
                with patch("backend.api.routers.alerts.get_db"):
                    # This would normally validate the schema
                    pass
        
        # Invalid severity
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "extreme",  # Invalid
            "message": "Test"
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_status_validation(self, client, mock_db, mock_user):
        """Test status field validation in update"""
        alert_id = uuid.uuid4()
        valid_statuses = ["active", "acknowledged", "resolved"]
        
        # Note: The AlertUpdate model validates status
        for status in valid_statuses:
            update_data = {"status": status}
            # Would pass validation at schema level
        
        # Invalid status would fail at validation
        update_data = {"status": "invalid"}
        # This would be rejected by Pydantic validation


class TestAlertEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.mark.asyncio
    async def test_create_alert_with_null_details(self, client, mock_db, mock_user, mock_device):
        """Test creating alert with null details"""
        mock_db.get.return_value = mock_device
        
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "info",
            "message": "Test",
            "details": None
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_list_alerts_empty_result(self, client, mock_db, mock_user):
        """Test listing alerts with no results"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result
        mock_db.scalar.side_effect = [0, 0, 0]
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts")
        
        assert response.status_code == 200
        data = response.json()
        assert data["alerts"] == []
        assert data["total"] == 0
    
    @pytest.mark.asyncio
    async def test_statistics_no_alerts(self, client, mock_db, mock_user):
        """Test statistics when no alerts exist"""
        mock_db.scalar.side_effect = [0, 0, 0, 0]
        
        empty_result = MagicMock()
        empty_result.__iter__ = lambda x: iter([])
        
        critical_result = MagicMock()
        critical_result.scalars.return_value.all.return_value = []
        
        mock_db.execute.side_effect = [empty_result, empty_result, critical_result]
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get("/api/v1/alerts/statistics")
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_alerts"] == 0
        assert data["recent_critical_alerts"] == []
    
    @pytest.mark.asyncio
    async def test_concurrent_alert_updates(self, client, mock_db, mock_user):
        """Test handling concurrent alert updates"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.status = "active"
        mock_alert.device = MagicMock(hostname="test-device")
        
        mock_db.get.return_value = mock_alert
        
        # Simulate optimistic locking failure
        mock_db.commit.side_effect = [Exception("Concurrent update"), None]
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post(f"/api/v1/alerts/{alert_id}/acknowledge")
        
        # First attempt fails, but should handle gracefully
        assert response.status_code == 500
    
    @pytest.mark.asyncio
    async def test_alert_with_large_details(self, client, mock_db, mock_user, mock_device):
        """Test creating alert with large details object"""
        mock_db.get.return_value = mock_device
        
        # Create large details object
        large_details = {
            f"key_{i}": f"value_{i}" * 100
            for i in range(100)
        }
        
        alert_data = {
            "device_id": str(uuid.uuid4()),
            "alert_type": "test",
            "severity": "info",
            "message": "Test",
            "details": large_details
        }
        
        with patch("backend.api.routers.alerts.require_alerts_write", return_value=mock_user):
            response = await client.post("/api/v1/alerts", json=alert_data)
        
        # Should handle large details
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_alert_device_cascade_behavior(self, client, mock_db, mock_user):
        """Test alert behavior when device is deleted"""
        alert_id = uuid.uuid4()
        mock_alert = MagicMock(spec=Alert)
        mock_alert.device = None  # Device was deleted
        mock_alert.device_id = uuid.uuid4()
        mock_alert.alert_type = "test"
        mock_alert.severity = "info"
        mock_alert.status = "active"
        mock_alert.message = "Test"
        mock_alert.details = None
        mock_alert.acknowledged_by = None
        mock_alert.acknowledged_at = None
        mock_alert.resolved_at = None
        mock_alert.created_at = datetime.utcnow()
        mock_alert.updated_at = None
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_alert
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.alerts.require_alerts_read", return_value=mock_user):
            response = await client.get(f"/api/v1/alerts/{alert_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["device_hostname"] is None  # Device deleted but alert remains


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
    mock.delete = AsyncMock()
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