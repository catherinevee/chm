"""
Comprehensive tests for Device API endpoints
Testing all device router endpoints for complete coverage
"""

import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime
import json
from uuid import uuid4, UUID

# Mock modules that might not be available during testing
@pytest.fixture
def mock_validation_service():
    """Mock ValidationService"""
    with patch('backend.api.routers.devices.ValidationService') as mock:
        mock.validate_ip_address = MagicMock(side_effect=lambda x: x)
        mock.validate_device_type = MagicMock(side_effect=lambda x: x)
        mock.validate_hostname = MagicMock(side_effect=lambda x: x)
        mock.validate_pagination = MagicMock(return_value=(1, 50))
        yield mock


@pytest.fixture
def mock_secure_credential_store():
    """Mock SecureCredentialStore"""
    with patch('backend.api.routers.devices.SecureCredentialStore') as mock:
        mock.store_device_credential = AsyncMock(return_value=True)
        yield mock


@pytest.fixture
def mock_device():
    """Mock device object"""
    device_id = uuid4()
    device = MagicMock()
    device.id = device_id
    device.hostname = "test-device"
    device.ip_address = "192.168.1.100"
    device.device_type = "router"
    device.current_state = "active"
    device.manufacturer = "Cisco"
    device.model = "2901"
    device.location = "Datacenter-1"
    device.department = "IT"
    device.is_active = True
    device.last_poll_time = datetime.utcnow()
    device.discovery_status = "discovered"
    device.created_at = datetime.utcnow()
    device.updated_at = datetime.utcnow()
    device.ssh_username = "admin"
    return device


@pytest.fixture
def mock_db_session(mock_device):
    """Mock database session"""
    mock_session = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.flush = AsyncMock()
    mock_session.commit = AsyncMock()
    mock_session.refresh = AsyncMock()
    mock_session.delete = AsyncMock()
    mock_session.scalar = AsyncMock(return_value=10)  # Default count
    
    # Mock query results
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = mock_device
    mock_result.scalars.return_value.all.return_value = [mock_device]
    mock_session.execute = AsyncMock(return_value=mock_result)
    
    return mock_session


@pytest.fixture
def test_app():
    """Create test FastAPI app with device router"""
    from fastapi import FastAPI
    from backend.api.routers.devices import router
    
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
    mock_user.roles = ["device_write", "device_read", "device_delete"]
    
    with patch('backend.api.routers.devices.require_device_read', return_value=mock_user), \
         patch('backend.api.routers.devices.require_device_write', return_value=mock_user), \
         patch('backend.api.routers.devices.require_device_delete', return_value=mock_user), \
         patch('backend.api.routers.devices.standard_rate_limit'), \
         patch('backend.api.routers.devices.get_db', return_value=AsyncMock()):
        yield mock_user


class TestCreateDeviceEndpoint:
    """Test device creation endpoint"""
    
    def test_create_device_success(self, client, mock_dependencies, mock_db_session, 
                                   mock_validation_service, mock_secure_credential_store):
        """Test successful device creation"""
        # Mock no existing device
        mock_result_empty = MagicMock()
        mock_result_empty.scalar_one_or_none.return_value = None
        mock_db_session.execute = AsyncMock(side_effect=[mock_result_empty, mock_result_empty])
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "test-device",
                    "ip_address": "192.168.1.100",
                    "device_type": "router",
                    "manufacturer": "Cisco",
                    "model": "2901",
                    "location": "Datacenter-1",
                    "department": "IT",
                    "snmp_community": "public",
                    "ssh_password": "secret"
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == "test-device"
        assert data["ip_address"] == "192.168.1.100"
        assert data["device_type"] == "router"
        
        mock_db_session.add.assert_called_once()
        mock_db_session.commit.assert_called_once()
        mock_secure_credential_store.store_device_credential.assert_called()
    
    def test_create_device_already_exists(self, client, mock_dependencies, mock_db_session, 
                                          mock_validation_service, mock_device):
        """Test device creation when device already exists"""
        # Mock existing device found
        mock_result_existing = MagicMock()
        mock_result_existing.scalar_one_or_none.return_value = mock_device
        mock_db_session.execute = AsyncMock(return_value=mock_result_existing)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "test-device",
                    "ip_address": "192.168.1.100",
                    "device_type": "router"
                }
            )
        
        assert response.status_code == 409
        assert "already exists" in response.json()["detail"]
    
    def test_create_device_invalid_ip(self, client, mock_dependencies):
        """Test device creation with invalid IP address"""
        with patch('backend.api.routers.devices.ValidationService.validate_ip_address', 
                   side_effect=ValueError("Invalid IP address")):
            response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "test-device",
                    "ip_address": "invalid-ip",
                    "device_type": "router"
                }
            )
        
        assert response.status_code == 422  # Validation error
    
    def test_create_device_invalid_hostname(self, client, mock_dependencies):
        """Test device creation with invalid hostname"""
        with patch('backend.api.routers.devices.ValidationService.validate_hostname', 
                   side_effect=ValueError("Invalid hostname")):
            response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "",
                    "ip_address": "192.168.1.100",
                    "device_type": "router"
                }
            )
        
        assert response.status_code == 422  # Validation error
    
    def test_create_device_invalid_type(self, client, mock_dependencies):
        """Test device creation with invalid device type"""
        with patch('backend.api.routers.devices.ValidationService.validate_device_type', 
                   side_effect=ValueError("Invalid device type")):
            response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "test-device",
                    "ip_address": "192.168.1.100",
                    "device_type": "invalid-type"
                }
            )
        
        assert response.status_code == 422  # Validation error
    
    def test_create_device_database_error(self, client, mock_dependencies, mock_validation_service):
        """Test device creation with database error"""
        mock_db = AsyncMock()
        mock_result_empty = MagicMock()
        mock_result_empty.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result_empty)
        mock_db.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "test-device",
                    "ip_address": "192.168.1.100",
                    "device_type": "router"
                }
            )
        
        assert response.status_code == 500
        assert "Failed to create device" in response.json()["detail"]


class TestListDevicesEndpoint:
    """Test device listing endpoint"""
    
    def test_list_devices_success(self, client, mock_dependencies, mock_db_session, 
                                  mock_validation_service):
        """Test successful device listing"""
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/devices")
        
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert len(data["devices"]) > 0
        assert data["devices"][0]["hostname"] == "test-device"
    
    def test_list_devices_with_filters(self, client, mock_dependencies, mock_db_session, 
                                       mock_validation_service):
        """Test device listing with filters"""
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.get(
                "/api/v1/devices?device_type=router&state=active&location=Datacenter-1&department=IT&search=test"
            )
        
        assert response.status_code == 200
        data = response.json()
        assert "devices" in data
    
    def test_list_devices_with_pagination(self, client, mock_dependencies, mock_db_session, 
                                          mock_validation_service):
        """Test device listing with pagination"""
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.get("/api/v1/devices?page=2&per_page=25")
        
        assert response.status_code == 200
        data = response.json()
        assert data["page"] == 2
        assert data["per_page"] == 25
    
    def test_list_devices_invalid_pagination(self, client, mock_dependencies):
        """Test device listing with invalid pagination"""
        response = client.get("/api/v1/devices?page=0&per_page=200")
        
        assert response.status_code == 422  # Validation error
    
    def test_list_devices_database_error(self, client, mock_dependencies):
        """Test device listing with database error"""
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db), \
             patch('backend.api.routers.devices.ValidationService.validate_pagination', return_value=(1, 50)):
            response = client.get("/api/v1/devices")
        
        assert response.status_code == 500
        assert "Failed to list devices" in response.json()["detail"]


class TestGetDeviceEndpoint:
    """Test get device by ID endpoint"""
    
    def test_get_device_success(self, client, mock_dependencies, mock_db_session):
        """Test successful device retrieval"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.get(f"/api/v1/devices/{device_id}")
        
        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == "test-device"
        assert data["ip_address"] == "192.168.1.100"
        assert "interface_count" in data
        assert "active_alerts" in data
    
    def test_get_device_invalid_id(self, client, mock_dependencies):
        """Test device retrieval with invalid ID format"""
        response = client.get("/api/v1/devices/invalid-uuid")
        
        assert response.status_code == 400
        assert "Invalid device ID format" in response.json()["detail"]
    
    def test_get_device_not_found(self, client, mock_dependencies):
        """Test device retrieval when device not found"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            response = client.get(f"/api/v1/devices/{device_id}")
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_get_device_database_error(self, client, mock_dependencies):
        """Test device retrieval with database error"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_db.execute.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            response = client.get(f"/api/v1/devices/{device_id}")
        
        assert response.status_code == 500
        assert "Failed to get device" in response.json()["detail"]


class TestUpdateDeviceEndpoint:
    """Test device update endpoint"""
    
    def test_update_device_success(self, client, mock_dependencies, mock_db_session, 
                                   mock_validation_service):
        """Test successful device update"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.put(
                f"/api/v1/devices/{device_id}",
                json={
                    "hostname": "updated-device",
                    "manufacturer": "Updated Cisco",
                    "location": "Updated Location"
                }
            )
        
        assert response.status_code == 200
        data = response.json()
        assert data["hostname"] == "test-device"  # From mock device
        mock_db_session.commit.assert_called_once()
    
    def test_update_device_not_found(self, client, mock_dependencies):
        """Test device update when device not found"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            response = client.put(
                f"/api/v1/devices/{device_id}",
                json={"hostname": "updated-device"}
            )
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_update_device_validation_error(self, client, mock_dependencies, mock_db_session):
        """Test device update with validation error"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session), \
             patch('backend.api.routers.devices.ValidationService.validate_hostname', 
                   side_effect=Exception("Invalid hostname")):
            response = client.put(
                f"/api/v1/devices/{device_id}",
                json={"hostname": ""}
            )
        
        assert response.status_code == 400
        assert "Invalid hostname" in response.json()["detail"]
    
    def test_update_device_database_error(self, client, mock_dependencies, mock_db_session, 
                                          mock_validation_service):
        """Test device update with database error"""
        device_id = str(uuid4())
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.put(
                f"/api/v1/devices/{device_id}",
                json={"hostname": "updated-device"}
            )
        
        assert response.status_code == 500
        assert "Failed to update device" in response.json()["detail"]


class TestDeleteDeviceEndpoint:
    """Test device deletion endpoint"""
    
    def test_delete_device_success(self, client, mock_dependencies, mock_db_session):
        """Test successful device deletion"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.delete(f"/api/v1/devices/{device_id}")
        
        assert response.status_code == 200
        assert response.json()["message"] == "Device deleted successfully"
        mock_db_session.delete.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    def test_delete_device_not_found(self, client, mock_dependencies):
        """Test device deletion when device not found"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            response = client.delete(f"/api/v1/devices/{device_id}")
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_delete_device_database_error(self, client, mock_dependencies, mock_db_session):
        """Test device deletion with database error"""
        device_id = str(uuid4())
        mock_db_session.delete.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.delete(f"/api/v1/devices/{device_id}")
        
        assert response.status_code == 500
        assert "Failed to delete device" in response.json()["detail"]


class TestPollDeviceEndpoint:
    """Test device polling endpoint"""
    
    def test_poll_device_success(self, client, mock_dependencies, mock_db_session):
        """Test successful device polling"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/devices/{device_id}/poll")
        
        assert response.status_code == 200
        assert "Polling triggered" in response.json()["message"]
        mock_db_session.commit.assert_called_once()
    
    def test_poll_device_not_found(self, client, mock_dependencies):
        """Test device polling when device not found"""
        device_id = str(uuid4())
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db.execute = AsyncMock(return_value=mock_result)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            response = client.post(f"/api/v1/devices/{device_id}/poll")
        
        assert response.status_code == 404
        assert "Device not found" in response.json()["detail"]
    
    def test_poll_device_inactive(self, client, mock_dependencies, mock_db_session, mock_device):
        """Test polling inactive device"""
        device_id = str(uuid4())
        mock_device.is_active = False
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/devices/{device_id}/poll")
        
        assert response.status_code == 400
        assert "Device is not active" in response.json()["detail"]
    
    def test_poll_device_database_error(self, client, mock_dependencies, mock_db_session):
        """Test device polling with database error"""
        device_id = str(uuid4())
        mock_db_session.commit.side_effect = Exception("Database error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_session):
            response = client.post(f"/api/v1/devices/{device_id}/poll")
        
        assert response.status_code == 500
        assert "Failed to poll device" in response.json()["detail"]


class TestDeviceEndpointsIntegration:
    """Integration tests for device endpoints"""
    
    def test_device_crud_flow(self, client, mock_dependencies, mock_validation_service, 
                              mock_secure_credential_store):
        """Test complete CRUD flow for devices"""
        # Mock database for creation
        mock_db_create = AsyncMock()
        mock_result_empty = MagicMock()
        mock_result_empty.scalar_one_or_none.return_value = None
        mock_db_create.execute = AsyncMock(side_effect=[mock_result_empty, mock_result_empty])
        mock_db_create.add = MagicMock()
        mock_db_create.flush = AsyncMock()
        mock_db_create.commit = AsyncMock()
        mock_db_create.refresh = AsyncMock()
        
        # Create device
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_create):
            create_response = client.post(
                "/api/v1/devices",
                json={
                    "hostname": "integration-test",
                    "ip_address": "192.168.1.200",
                    "device_type": "switch"
                }
            )
        
        assert create_response.status_code == 200
        
        # Mock database for reading
        mock_db_read = AsyncMock()
        mock_device = MagicMock()
        mock_device.id = uuid4()
        mock_device.hostname = "integration-test"
        mock_device.ip_address = "192.168.1.200"
        mock_device.device_type = "switch"
        mock_device.current_state = "active"
        mock_device.is_active = True
        mock_device.created_at = datetime.utcnow()
        mock_device.updated_at = datetime.utcnow()
        
        mock_result_found = MagicMock()
        mock_result_found.scalar_one_or_none.return_value = mock_device
        mock_result_found.scalars.return_value.all.return_value = [mock_device]
        mock_db_read.execute = AsyncMock(return_value=mock_result_found)
        mock_db_read.scalar = AsyncMock(return_value=5)
        
        device_id = str(mock_device.id)
        
        # Read device
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_read):
            read_response = client.get(f"/api/v1/devices/{device_id}")
        
        assert read_response.status_code == 200
        
        # List devices
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_read):
            list_response = client.get("/api/v1/devices")
        
        assert list_response.status_code == 200
        
        # Mock database for updating
        mock_db_update = AsyncMock()
        mock_db_update.execute = AsyncMock(return_value=mock_result_found)
        mock_db_update.commit = AsyncMock()
        mock_db_update.refresh = AsyncMock()
        
        # Update device
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_update):
            update_response = client.put(
                f"/api/v1/devices/{device_id}",
                json={"location": "Updated Location"}
            )
        
        assert update_response.status_code == 200
        
        # Mock database for deletion
        mock_db_delete = AsyncMock()
        mock_db_delete.execute = AsyncMock(return_value=mock_result_found)
        mock_db_delete.delete = AsyncMock()
        mock_db_delete.commit = AsyncMock()
        
        # Delete device
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_delete):
            delete_response = client.delete(f"/api/v1/devices/{device_id}")
        
        assert delete_response.status_code == 200
    
    def test_error_handling_consistency(self, client, mock_dependencies):
        """Test consistent error handling across device endpoints"""
        device_id = str(uuid4())
        
        # Test database errors
        mock_db_error = AsyncMock()
        mock_db_error.execute.side_effect = Exception("Database connection error")
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db_error):
            # Test various endpoints that should handle DB errors gracefully
            endpoints = [
                ("GET", f"/api/v1/devices/{device_id}"),
                ("GET", "/api/v1/devices"),
                ("PUT", f"/api/v1/devices/{device_id}"),
                ("DELETE", f"/api/v1/devices/{device_id}"),
                ("POST", f"/api/v1/devices/{device_id}/poll"),
            ]
            
            for method, endpoint in endpoints:
                if method == "GET":
                    response = client.get(endpoint)
                elif method == "PUT":
                    response = client.put(endpoint, json={"hostname": "test"})
                elif method == "DELETE":
                    response = client.delete(endpoint)
                elif method == "POST":
                    response = client.post(endpoint)
                
                # Each endpoint should handle errors appropriately
                assert response.status_code in [404, 500]  # Various expected error codes
    
    def test_validation_consistency(self, client, mock_dependencies):
        """Test validation consistency across device endpoints"""
        # Test invalid UUID format
        invalid_ids = ["not-a-uuid", "12345", ""]
        
        for invalid_id in invalid_ids:
            response = client.get(f"/api/v1/devices/{invalid_id}")
            if invalid_id == "":
                assert response.status_code == 404  # FastAPI routing
            else:
                assert response.status_code == 400  # UUID validation


if __name__ == "__main__":
    pytest.main([__file__, "-v"])