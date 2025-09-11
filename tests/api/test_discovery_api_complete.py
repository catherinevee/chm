"""
Comprehensive tests for discovery API endpoints
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import uuid
from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.discovery import (
    router,
    DiscoveryRequest,
    DiscoveryJobResponse,
    DiscoveryResult,
    run_discovery_job,
    update_job_progress
)
from backend.database.models import DiscoveryJob, Device
from backend.database.user_models import User
from backend.services.validation_service import ValidationError


class TestStartDiscoveryEndpoint:
    """Test POST /api/v1/discovery/start endpoint"""
    
    @pytest.mark.asyncio
    async def test_start_discovery_success(self, client, mock_db, mock_user):
        """Test successful discovery job start"""
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp",
            "snmp_community": "public",
            "snmp_version": "2c",
            "ports": [22, 161],
            "timeout": 5,
            "parallel_scans": 10
        }
        
        mock_background = MagicMock(spec=BackgroundTasks)
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.return_value = "192.168.1.0/24"
                with patch("backend.api.routers.discovery.BackgroundTasks", return_value=mock_background):
                    response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "pending"
        assert data["ip_range"] == "192.168.1.0/24"
        assert data["scan_type"] == "snmp"
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
        mock_background.add_task.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_start_discovery_invalid_ip_range(self, client, mock_user):
        """Test discovery with invalid IP range"""
        discovery_request = {
            "ip_range": "invalid-range",
            "scan_type": "snmp"
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.side_effect = ValidationError("Invalid IP range format")
                response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 400
        assert "Invalid IP range format" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_start_discovery_invalid_scan_type(self, client, mock_user):
        """Test discovery with invalid scan type"""
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "invalid"  # Invalid scan type
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_start_discovery_ssh_scan(self, client, mock_db, mock_user):
        """Test starting SSH discovery scan"""
        discovery_request = {
            "ip_range": "10.0.0.0/8",
            "scan_type": "ssh",
            "ssh_username": "admin",
            "ssh_password": "password123",
            "ports": [22, 2222],
            "timeout": 10
        }
        
        mock_background = MagicMock(spec=BackgroundTasks)
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.return_value = "10.0.0.0/8"
                with patch("backend.api.routers.discovery.BackgroundTasks", return_value=mock_background):
                    response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["scan_type"] == "ssh"
    
    @pytest.mark.asyncio
    async def test_start_discovery_auto_scan(self, client, mock_db, mock_user):
        """Test starting auto discovery scan"""
        discovery_request = {
            "ip_range": "172.16.0.0/12",
            "scan_type": "auto",
            "snmp_community": "public",
            "ssh_username": "admin",
            "ssh_password": "password"
        }
        
        mock_background = MagicMock(spec=BackgroundTasks)
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.return_value = "172.16.0.0/12"
                with patch("backend.api.routers.discovery.BackgroundTasks", return_value=mock_background):
                    response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 200
        data = response.json()
        assert data["scan_type"] == "auto"
    
    @pytest.mark.asyncio
    async def test_start_discovery_unauthorized(self, client):
        """Test starting discovery without authentication"""
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp"
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", side_effect=HTTPException(status_code=401)):
            response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_start_discovery_database_error(self, client, mock_db, mock_user):
        """Test discovery start with database error"""
        mock_db.commit.side_effect = Exception("Database error")
        
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp"
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.return_value = "192.168.1.0/24"
                response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 500
        assert "Failed to start discovery job" in response.json()["detail"]


class TestListDiscoveryJobsEndpoint:
    """Test GET /api/v1/discovery endpoint"""
    
    @pytest.mark.asyncio
    async def test_list_discovery_jobs_success(self, client, mock_db, mock_user):
        """Test successful listing of discovery jobs"""
        # Mock discovery jobs
        mock_job1 = MagicMock(spec=DiscoveryJob)
        mock_job1.id = uuid.uuid4()
        mock_job1.job_type = "network_scan"
        mock_job1.status = "completed"
        mock_job1.ip_range = "192.168.1.0/24"
        mock_job1.scan_type = "snmp"
        mock_job1.progress = 100
        mock_job1.total_targets = 254
        mock_job1.discovered_count = 10
        mock_job1.error_count = 0
        mock_job1.started_at = datetime.utcnow() - timedelta(hours=1)
        mock_job1.completed_at = datetime.utcnow()
        mock_job1.created_at = datetime.utcnow() - timedelta(hours=2)
        
        mock_job2 = MagicMock(spec=DiscoveryJob)
        mock_job2.id = uuid.uuid4()
        mock_job2.job_type = "network_scan"
        mock_job2.status = "running"
        mock_job2.ip_range = "10.0.0.0/16"
        mock_job2.scan_type = "ssh"
        mock_job2.progress = 45
        mock_job2.total_targets = 65536
        mock_job2.discovered_count = 100
        mock_job2.error_count = 5
        mock_job2.started_at = datetime.utcnow() - timedelta(minutes=30)
        mock_job2.completed_at = None
        mock_job2.created_at = datetime.utcnow() - timedelta(hours=1)
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_job1, mock_job2]
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get("/api/v1/discovery")
        
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["status"] == "completed"
        assert data[0]["progress"] == 100
        assert data[1]["status"] == "running"
        assert data[1]["progress"] == 45
    
    @pytest.mark.asyncio
    async def test_list_discovery_jobs_with_filter(self, client, mock_db, mock_user):
        """Test listing discovery jobs with status filter"""
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = uuid.uuid4()
        mock_job.status = "running"
        mock_job.job_type = "network_scan"
        mock_job.ip_range = "192.168.1.0/24"
        mock_job.scan_type = "snmp"
        mock_job.progress = 50
        mock_job.total_targets = 254
        mock_job.discovered_count = 5
        mock_job.error_count = 0
        mock_job.started_at = datetime.utcnow()
        mock_job.completed_at = None
        mock_job.created_at = datetime.utcnow()
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_job]
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get("/api/v1/discovery", params={"status_filter": "running"})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["status"] == "running"
    
    @pytest.mark.asyncio
    async def test_list_discovery_jobs_empty(self, client, mock_db, mock_user):
        """Test listing discovery jobs when none exist"""
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get("/api/v1/discovery")
        
        assert response.status_code == 200
        assert response.json() == []
    
    @pytest.mark.asyncio
    async def test_list_discovery_jobs_with_limit(self, client, mock_db, mock_user):
        """Test listing discovery jobs with limit"""
        # Create multiple jobs
        jobs = []
        for i in range(10):
            job = MagicMock(spec=DiscoveryJob)
            job.id = uuid.uuid4()
            job.status = "completed"
            job.job_type = "network_scan"
            job.ip_range = f"192.168.{i}.0/24"
            job.scan_type = "snmp"
            job.progress = 100
            job.total_targets = 254
            job.discovered_count = i
            job.error_count = 0
            job.started_at = datetime.utcnow() - timedelta(hours=i)
            job.completed_at = datetime.utcnow() - timedelta(hours=i-1)
            job.created_at = datetime.utcnow() - timedelta(hours=i+1)
            jobs.append(job)
        
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = jobs[:5]  # Return only 5
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get("/api/v1/discovery", params={"limit": 5})
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 5
    
    @pytest.mark.asyncio
    async def test_list_discovery_jobs_database_error(self, client, mock_db, mock_user):
        """Test listing jobs with database error"""
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get("/api/v1/discovery")
        
        assert response.status_code == 500
        assert "Failed to list discovery jobs" in response.json()["detail"]


class TestGetDiscoveryJobEndpoint:
    """Test GET /api/v1/discovery/{job_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_discovery_job_success(self, client, mock_db, mock_user):
        """Test successful retrieval of discovery job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = job_id
        mock_job.job_type = "network_scan"
        mock_job.status = "completed"
        mock_job.ip_range = "192.168.1.0/24"
        mock_job.scan_type = "snmp"
        mock_job.progress = 100
        mock_job.total_targets = 254
        mock_job.discovered_count = 15
        mock_job.error_count = 2
        mock_job.started_at = datetime.utcnow() - timedelta(hours=1)
        mock_job.completed_at = datetime.utcnow()
        mock_job.created_at = datetime.utcnow() - timedelta(hours=2)
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == str(job_id)
        assert data["status"] == "completed"
        assert data["discovered_count"] == 15
    
    @pytest.mark.asyncio
    async def test_get_discovery_job_not_found(self, client, mock_db, mock_user):
        """Test getting non-existent discovery job"""
        job_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}")
        
        assert response.status_code == 404
        assert "Discovery job not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_discovery_job_invalid_id(self, client, mock_user):
        """Test getting discovery job with invalid UUID"""
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get("/api/v1/discovery/invalid-uuid")
        
        assert response.status_code == 400
        assert "Invalid job ID format" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_discovery_job_database_error(self, client, mock_db, mock_user):
        """Test getting job with database error"""
        job_id = uuid.uuid4()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}")
        
        assert response.status_code == 500
        assert "Failed to get discovery job" in response.json()["detail"]


class TestCancelDiscoveryJobEndpoint:
    """Test POST /api/v1/discovery/{job_id}/cancel endpoint"""
    
    @pytest.mark.asyncio
    async def test_cancel_running_job_success(self, client, mock_db, mock_user):
        """Test successful cancellation of running job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.status = "running"
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post(f"/api/v1/discovery/{job_id}/cancel")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Discovery job cancelled successfully"
        assert mock_job.status == "cancelled"
        assert mock_job.completed_at is not None
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cancel_pending_job_success(self, client, mock_db, mock_user):
        """Test cancellation of pending job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.status = "pending"
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post(f"/api/v1/discovery/{job_id}/cancel")
        
        assert response.status_code == 200
        assert mock_job.status == "cancelled"
    
    @pytest.mark.asyncio
    async def test_cancel_completed_job_failure(self, client, mock_db, mock_user):
        """Test cannot cancel completed job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.status = "completed"
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post(f"/api/v1/discovery/{job_id}/cancel")
        
        assert response.status_code == 400
        assert "Cannot cancel job with status: completed" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_cancel_job_not_found(self, client, mock_db, mock_user):
        """Test cancelling non-existent job"""
        job_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post(f"/api/v1/discovery/{job_id}/cancel")
        
        assert response.status_code == 404
        assert "Discovery job not found" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_cancel_job_unauthorized(self, client):
        """Test cancelling job without authorization"""
        job_id = uuid.uuid4()
        
        with patch("backend.api.routers.discovery.require_discovery_write", side_effect=HTTPException(status_code=403)):
            response = await client.post(f"/api/v1/discovery/{job_id}/cancel")
        
        assert response.status_code == 403


class TestGetDiscoveryResultsEndpoint:
    """Test GET /api/v1/discovery/{job_id}/results endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_results_completed_job(self, client, mock_db, mock_user):
        """Test getting results of completed job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = job_id
        mock_job.status = "completed"
        mock_job.total_targets = 254
        mock_job.discovered_count = 10
        mock_job.error_count = 2
        mock_job.started_at = datetime.utcnow() - timedelta(hours=1)
        mock_job.completed_at = datetime.utcnow()
        
        # Mock discovered devices
        mock_device = MagicMock(spec=Device)
        mock_device.id = uuid.uuid4()
        mock_device.hostname = "device1"
        mock_device.ip_address = "192.168.1.10"
        mock_device.device_type = "router"
        mock_device.manufacturer = "Cisco"
        mock_device.model = "ISR4321"
        mock_device.discovery_protocol = "snmp"
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = mock_job
        
        devices_result = MagicMock()
        devices_result.scalars.return_value.all.return_value = [mock_device]
        
        mock_db.execute.side_effect = [job_result, devices_result]
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}/results")
        
        assert response.status_code == 200
        data = response.json()
        assert data["job_id"] == str(job_id)
        assert len(data["discovered_devices"]) == 1
        assert data["discovered_devices"][0]["hostname"] == "device1"
        assert data["summary"]["discovered"] == 10
        assert data["summary"]["failed"] == 2
    
    @pytest.mark.asyncio
    async def test_get_results_running_job(self, client, mock_db, mock_user):
        """Test cannot get results of running job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.status = "running"
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}/results")
        
        assert response.status_code == 400
        assert "Job not completed" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_get_results_failed_job(self, client, mock_db, mock_user):
        """Test getting results of failed job"""
        job_id = uuid.uuid4()
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = job_id
        mock_job.status = "failed"
        mock_job.total_targets = 254
        mock_job.discovered_count = 0
        mock_job.error_count = 254
        mock_job.started_at = datetime.utcnow() - timedelta(hours=1)
        mock_job.completed_at = datetime.utcnow()
        
        job_result = MagicMock()
        job_result.scalar_one_or_none.return_value = mock_job
        
        devices_result = MagicMock()
        devices_result.scalars.return_value.all.return_value = []
        
        mock_db.execute.side_effect = [job_result, devices_result]
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}/results")
        
        assert response.status_code == 200
        data = response.json()
        assert data["discovered_devices"] == []
        assert data["summary"]["failed"] == 254
    
    @pytest.mark.asyncio
    async def test_get_results_job_not_found(self, client, mock_db, mock_user):
        """Test getting results of non-existent job"""
        job_id = uuid.uuid4()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_read", return_value=mock_user):
            response = await client.get(f"/api/v1/discovery/{job_id}/results")
        
        assert response.status_code == 404
        assert "Discovery job not found" in response.json()["detail"]


class TestDiscoveryValidation:
    """Test discovery request validation"""
    
    @pytest.mark.asyncio
    async def test_ip_range_validation(self, client, mock_user):
        """Test IP range validation"""
        # Valid IP ranges
        valid_ranges = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.1.1-192.168.1.254"
        ]
        
        for ip_range in valid_ranges:
            discovery_request = {
                "ip_range": ip_range,
                "scan_type": "snmp"
            }
            # Would validate at service level
        
        # Invalid IP range
        discovery_request = {
            "ip_range": "256.256.256.256/24",  # Invalid IP
            "scan_type": "snmp"
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.side_effect = ValidationError("Invalid IP address")
                response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 400
    
    @pytest.mark.asyncio
    async def test_snmp_version_validation(self, client, mock_user):
        """Test SNMP version validation"""
        # Valid versions
        for version in ["1", "2c", "3"]:
            discovery_request = {
                "ip_range": "192.168.1.0/24",
                "scan_type": "snmp",
                "snmp_version": version
            }
            # Would pass validation
        
        # Invalid version
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp",
            "snmp_version": "4"  # Invalid version
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_timeout_validation(self, client, mock_user):
        """Test timeout validation"""
        # Valid timeout
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp",
            "timeout": 15
        }
        
        # Invalid timeout (too high)
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp",
            "timeout": 60  # Above max of 30
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_parallel_scans_validation(self, client, mock_user):
        """Test parallel scans validation"""
        # Too many parallel scans
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp",
            "parallel_scans": 100  # Above max of 50
        }
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        assert response.status_code == 422


class TestDiscoveryEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.mark.asyncio
    async def test_large_ip_range(self, client, mock_db, mock_user):
        """Test discovery with very large IP range"""
        discovery_request = {
            "ip_range": "0.0.0.0/0",  # Entire IPv4 space
            "scan_type": "snmp",
            "parallel_scans": 50
        }
        
        mock_background = MagicMock(spec=BackgroundTasks)
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.return_value = "0.0.0.0/0"
                with patch("backend.api.routers.discovery.BackgroundTasks", return_value=mock_background):
                    response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        # Should accept but handle appropriately
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_concurrent_job_starts(self, client, mock_db, mock_user):
        """Test starting multiple discovery jobs concurrently"""
        discovery_requests = [
            {"ip_range": "192.168.1.0/24", "scan_type": "snmp"},
            {"ip_range": "10.0.0.0/24", "scan_type": "ssh"},
            {"ip_range": "172.16.0.0/24", "scan_type": "auto"}
        ]
        
        mock_background = MagicMock(spec=BackgroundTasks)
        
        for request in discovery_requests:
            with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
                with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                    mock_validate.return_value = request["ip_range"]
                    with patch("backend.api.routers.discovery.BackgroundTasks", return_value=mock_background):
                        response = await client.post("/api/v1/discovery/start", json=request)
            
            assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_job_state_transitions(self, client, mock_db, mock_user):
        """Test job state transitions"""
        job_id = uuid.uuid4()
        
        # Test cancelling already cancelled job
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.status = "cancelled"
        
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_db.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            response = await client.post(f"/api/v1/discovery/{job_id}/cancel")
        
        assert response.status_code == 400
        assert "Cannot cancel job with status: cancelled" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_discovery_with_no_credentials(self, client, mock_db, mock_user):
        """Test discovery without any credentials"""
        discovery_request = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "auto"
            # No SNMP community or SSH credentials
        }
        
        mock_background = MagicMock(spec=BackgroundTasks)
        
        with patch("backend.api.routers.discovery.require_discovery_write", return_value=mock_user):
            with patch("backend.services.validation_service.ValidationService.validate_ip_range") as mock_validate:
                mock_validate.return_value = "192.168.1.0/24"
                with patch("backend.api.routers.discovery.BackgroundTasks", return_value=mock_background):
                    response = await client.post("/api/v1/discovery/start", json=discovery_request)
        
        # Should use defaults
        assert response.status_code == 200


class TestBackgroundDiscoveryJob:
    """Test background discovery job execution"""
    
    @pytest.mark.asyncio
    async def test_run_discovery_job_success(self):
        """Test successful background discovery job execution"""
        job_id = str(uuid.uuid4())
        config = {
            "ip_range": "192.168.1.0/24",
            "scan_type": "snmp",
            "snmp_community": "public",
            "snmp_version": "2c",
            "timeout": 5,
            "parallel_scans": 10
        }
        user_id = str(uuid.uuid4())
        
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = job_id
        mock_job.status = "pending"
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.db.get_async_session") as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session
            with patch("backend.discovery.service.DiscoveryService") as mock_service_class:
                mock_service = MagicMock()
                mock_service.discover_network = AsyncMock(return_value={
                    "discovered": ["192.168.1.1", "192.168.1.2"],
                    "failed": ["192.168.1.3"]
                })
                mock_service_class.return_value = mock_service
                
                await run_discovery_job(job_id, config, user_id)
        
        assert mock_job.status == "completed"
        assert mock_job.discovered_count == 2
        assert mock_job.error_count == 1
        assert mock_job.progress == 100
        mock_session.commit.assert_called()
    
    @pytest.mark.asyncio
    async def test_run_discovery_job_failure(self):
        """Test background discovery job failure"""
        job_id = str(uuid.uuid4())
        config = {"ip_range": "192.168.1.0/24", "scan_type": "snmp"}
        user_id = str(uuid.uuid4())
        
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = job_id
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.db.get_async_session") as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session
            with patch("backend.discovery.service.DiscoveryService") as mock_service_class:
                mock_service = MagicMock()
                mock_service.discover_network = AsyncMock(side_effect=Exception("Discovery failed"))
                mock_service_class.return_value = mock_service
                
                await run_discovery_job(job_id, config, user_id)
        
        # Job should be marked as failed
        # Check in second session context
        assert mock_session.execute.call_count >= 2  # At least 2 calls for status updates
    
    @pytest.mark.asyncio
    async def test_update_job_progress(self):
        """Test job progress update"""
        job_id = str(uuid.uuid4())
        progress = 50
        
        mock_job = MagicMock(spec=DiscoveryJob)
        mock_job.id = job_id
        
        mock_session = AsyncMock(spec=AsyncSession)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_job
        mock_session.execute.return_value = mock_result
        
        with patch("backend.api.routers.discovery.db.get_async_session") as mock_get_session:
            mock_get_session.return_value.__aenter__.return_value = mock_session
            
            await update_job_progress(job_id, progress)
        
        assert mock_job.progress == 50
        assert mock_job.updated_at is not None
        mock_session.commit.assert_called_once()


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
    mock.add = MagicMock()
    mock.commit = AsyncMock()
    mock.refresh = AsyncMock()
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