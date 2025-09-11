"""
Comprehensive tests for Device API endpoints
"""
import pytest
import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient
from fastapi import status

from main import app
from backend.services.device_service import DeviceService
from backend.services.auth_service import TokenData
from backend.common.exceptions import (
    ResourceNotFoundException, ValidationException, DuplicateResourceException
)
from backend.models.device import Device, DeviceType, DeviceStatus
from backend.models.device_credentials import DeviceCredentials
from backend.models.user import UserRole


class TestDevicesAPI:
    """Test Device API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        return TestClient(app)
    
    @pytest.fixture
    def device_service_mock(self):
        """Mock device service"""
        return AsyncMock(spec=DeviceService)
    
    @pytest.fixture
    def admin_token_data(self):
        """Admin user token data"""
        return TokenData(
            user_id=1,
            username="admin",
            email="admin@example.com",
            role=UserRole.ADMIN.value,
            permissions=["read", "write", "delete", "admin"],
            exp=datetime.now(),
            iat=datetime.now()
        )
    
    @pytest.fixture
    def user_token_data(self):
        """Regular user token data"""
        return TokenData(
            user_id=2,
            username="user",
            email="user@example.com",
            role=UserRole.USER.value,
            permissions=["read"],
            exp=datetime.now(),
            iat=datetime.now()
        )
    
    @pytest.fixture
    def sample_device(self):
        """Sample device for testing"""
        return Device(
            id=1,
            name="Test Router",
            ip_address="192.168.1.1",
            device_type=DeviceType.ROUTER,
            status=DeviceStatus.ACTIVE,
            manufacturer="Cisco",
            model="ISR4321",
            location="Data Center 1",
            description="Test network router",
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
    
    @pytest.fixture
    def sample_credentials(self):
        """Sample device credentials"""
        return DeviceCredentials(
            id=1,
            device_id=1,
            username="admin",
            password_hash="hashed_password",
            snmp_community="private",
            ssh_key="ssh_key_content"
        )

    def test_create_device_success_admin(self, client, admin_token_data, sample_device):
        """Test successful device creation as admin"""
        device_data = {
            "name": "New Router",
            "ip_address": "192.168.1.2",
            "device_type": "router",
            "manufacturer": "Cisco",
            "model": "ISR4331",
            "location": "Data Center 2",
            "description": "New network router"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.create_device', return_value=sample_device):
                response = client.post(
                    "/api/v1/devices/",
                    json=device_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_201_CREATED
                data = response.json()
                assert data["name"] == "Test Router"
                assert data["ip_address"] == "192.168.1.1"

    def test_create_device_forbidden_user(self, client, user_token_data):
        """Test device creation forbidden for regular user"""
        device_data = {
            "name": "New Router",
            "ip_address": "192.168.1.2",
            "device_type": "router"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            response = client.post(
                "/api/v1/devices/",
                json=device_data,
                headers={"Authorization": "Bearer user_token"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_create_device_duplicate_ip(self, client, admin_token_data):
        """Test device creation with duplicate IP address"""
        device_data = {
            "name": "Duplicate Router",
            "ip_address": "192.168.1.1",  # Existing IP
            "device_type": "router"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.create_device') as mock_create:
                mock_create.side_effect = DuplicateResourceException("Device with this IP already exists")
                
                response = client.post(
                    "/api/v1/devices/",
                    json=device_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_409_CONFLICT
                assert "already exists" in response.json()["detail"]

    def test_create_device_invalid_data(self, client, admin_token_data):
        """Test device creation with invalid data"""
        invalid_data = {
            "name": "",  # Empty name
            "ip_address": "invalid-ip",  # Invalid IP
            "device_type": "invalid_type"  # Invalid device type
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            response = client.post(
                "/api/v1/devices/",
                json=invalid_data,
                headers={"Authorization": "Bearer admin_token"}
            )
            
            assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_device_by_id_success(self, client, user_token_data, sample_device):
        """Test getting device by ID"""
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=sample_device):
                response = client.get(
                    "/api/v1/devices/1",
                    headers={"Authorization": "Bearer user_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["id"] == 1
                assert data["name"] == "Test Router"

    def test_get_device_by_id_not_found(self, client, user_token_data):
        """Test getting non-existent device"""
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=None):
                response = client.get(
                    "/api/v1/devices/999",
                    headers={"Authorization": "Bearer user_token"}
                )
                
                assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_devices_list_success(self, client, user_token_data):
        """Test getting devices list with pagination"""
        devices = [
            Device(id=i, name=f"Router {i}", ip_address=f"192.168.1.{i}")
            for i in range(1, 6)
        ]
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_all_devices', return_value=devices[:3]):
                response = client.get(
                    "/api/v1/devices/?page=1&page_size=3",
                    headers={"Authorization": "Bearer user_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data["items"]) == 3
                assert data["page"] == 1
                assert data["page_size"] == 3

    def test_get_devices_by_type_success(self, client, user_token_data):
        """Test getting devices by type"""
        routers = [
            Device(id=i, name=f"Router {i}", device_type=DeviceType.ROUTER)
            for i in range(1, 4)
        ]
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_devices_by_type', return_value=routers):
                response = client.get(
                    "/api/v1/devices/type/router",
                    headers={"Authorization": "Bearer user_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data) == 3

    def test_get_devices_by_status_success(self, client, user_token_data):
        """Test getting devices by status"""
        active_devices = [
            Device(id=i, name=f"Device {i}", status=DeviceStatus.ACTIVE)
            for i in range(1, 3)
        ]
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_devices_by_status', return_value=active_devices):
                response = client.get(
                    "/api/v1/devices/status/active",
                    headers={"Authorization": "Bearer user_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data) == 2

    def test_update_device_success_admin(self, client, admin_token_data, sample_device):
        """Test successful device update as admin"""
        update_data = {
            "name": "Updated Router",
            "location": "Updated Location",
            "description": "Updated description"
        }
        
        updated_device = sample_device.copy()
        updated_device.name = "Updated Router"
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.update_device', return_value=updated_device):
                response = client.put(
                    "/api/v1/devices/1",
                    json=update_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["name"] == "Updated Router"

    def test_update_device_forbidden_user(self, client, user_token_data):
        """Test device update forbidden for regular user"""
        update_data = {
            "name": "Updated Router"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            response = client.put(
                "/api/v1/devices/1",
                json=update_data,
                headers={"Authorization": "Bearer user_token"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_update_device_not_found(self, client, admin_token_data):
        """Test updating non-existent device"""
        update_data = {
            "name": "Updated Router"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.update_device') as mock_update:
                mock_update.side_effect = ResourceNotFoundException("Device not found")
                
                response = client.put(
                    "/api/v1/devices/999",
                    json=update_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_delete_device_success_admin(self, client, admin_token_data):
        """Test successful device deletion as admin"""
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.delete_device', return_value=True):
                response = client.delete(
                    "/api/v1/devices/1",
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert "deleted successfully" in response.json()["message"]

    def test_delete_device_forbidden_user(self, client, user_token_data):
        """Test device deletion forbidden for regular user"""
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            response = client.delete(
                "/api/v1/devices/1",
                headers={"Authorization": "Bearer user_token"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_device_not_found(self, client, admin_token_data):
        """Test deleting non-existent device"""
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.delete_device') as mock_delete:
                mock_delete.side_effect = ResourceNotFoundException("Device not found")
                
                response = client.delete(
                    "/api/v1/devices/999",
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_ping_device_success(self, client, user_token_data, sample_device):
        """Test device ping functionality"""
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=sample_device):
                with patch('api.v1.devices.device_service.ping_device', return_value=True):
                    response = client.post(
                        "/api/v1/devices/1/ping",
                        headers={"Authorization": "Bearer user_token"}
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["success"] is True
                    assert "reachable" in data["message"]

    def test_ping_device_failure(self, client, user_token_data, sample_device):
        """Test device ping failure"""
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=sample_device):
                with patch('api.v1.devices.device_service.ping_device', return_value=False):
                    response = client.post(
                        "/api/v1/devices/1/ping",
                        headers={"Authorization": "Bearer user_token"}
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["success"] is False
                    assert "not reachable" in data["message"]

    def test_check_connectivity_success(self, client, user_token_data, sample_device):
        """Test device connectivity check"""
        connectivity_result = {
            "ping": True,
            "snmp": True,
            "ssh": True,
            "overall": True
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=sample_device):
                with patch('api.v1.devices.device_service.check_device_connectivity', return_value=connectivity_result):
                    response = client.get(
                        "/api/v1/devices/1/connectivity",
                        headers={"Authorization": "Bearer user_token"}
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["ping"] is True
                    assert data["snmp"] is True
                    assert data["ssh"] is True
                    assert data["overall"] is True

    def test_get_device_credentials_success_admin(self, client, admin_token_data, sample_credentials):
        """Test getting device credentials as admin"""
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.get_device_credentials', return_value=sample_credentials):
                response = client.get(
                    "/api/v1/devices/1/credentials",
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["username"] == "admin"
                assert "password_hash" not in data  # Sensitive data should not be exposed

    def test_get_device_credentials_forbidden_user(self, client, user_token_data):
        """Test getting device credentials forbidden for regular user"""
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            response = client.get(
                "/api/v1/devices/1/credentials",
                headers={"Authorization": "Bearer user_token"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_set_device_credentials_success_admin(self, client, admin_token_data):
        """Test setting device credentials as admin"""
        credentials_data = {
            "username": "admin",
            "password": "secret123",
            "snmp_community": "private",
            "ssh_key": "ssh_key_content"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.set_device_credentials'):
                response = client.put(
                    "/api/v1/devices/1/credentials",
                    json=credentials_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert "updated successfully" in response.json()["message"]

    def test_get_device_info_success(self, client, user_token_data, sample_device):
        """Test getting device information via SNMP"""
        device_info = {
            "sysDescr": "Cisco IOS Software",
            "sysName": "Router1",
            "sysContact": "admin@company.com",
            "sysLocation": "Data Center 1",
            "sysUpTime": "12345600"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=sample_device):
                with patch('api.v1.devices.device_service.get_device_info_snmp', return_value=device_info):
                    response = client.get(
                        "/api/v1/devices/1/info",
                        headers={"Authorization": "Bearer user_token"}
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert data["sysName"] == "Router1"
                    assert "sysDescr" in data

    def test_get_device_uptime_success(self, client, user_token_data, sample_device):
        """Test getting device uptime"""
        from datetime import timedelta
        uptime = timedelta(days=30, hours=12, minutes=45)
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.get_device_by_id', return_value=sample_device):
                with patch('api.v1.devices.device_service.get_device_uptime', return_value=uptime):
                    response = client.get(
                        "/api/v1/devices/1/uptime",
                        headers={"Authorization": "Bearer user_token"}
                    )
                    
                    assert response.status_code == status.HTTP_200_OK
                    data = response.json()
                    assert "days" in data
                    assert "hours" in data
                    assert "minutes" in data

    def test_discover_devices_success_admin(self, client, admin_token_data):
        """Test network device discovery as admin"""
        discovery_data = {
            "subnet": "192.168.1.0/24"
        }
        
        discovered_devices = [
            {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "vendor": "Cisco"},
            {"ip": "192.168.1.2", "mac": "00:11:22:33:44:66", "vendor": "HP"}
        ]
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.discover_devices_subnet', return_value=discovered_devices):
                response = client.post(
                    "/api/v1/devices/discover",
                    json=discovery_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data["devices"]) == 2
                assert data["devices"][0]["ip"] == "192.168.1.1"

    def test_discover_devices_forbidden_user(self, client, user_token_data):
        """Test device discovery forbidden for regular user"""
        discovery_data = {
            "subnet": "192.168.1.0/24"
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            response = client.post(
                "/api/v1/devices/discover",
                json=discovery_data,
                headers={"Authorization": "Bearer user_token"}
            )
            
            assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_update_device_status_success_admin(self, client, admin_token_data, sample_device):
        """Test updating device status as admin"""
        status_data = {
            "status": "inactive"
        }
        
        updated_device = sample_device.copy()
        updated_device.status = DeviceStatus.INACTIVE
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.update_device_status', return_value=updated_device):
                response = client.patch(
                    "/api/v1/devices/1/status",
                    json=status_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["status"] == "inactive"

    def test_bulk_update_devices_success_admin(self, client, admin_token_data):
        """Test bulk device updates as admin"""
        bulk_data = {
            "device_ids": [1, 2, 3],
            "updates": {
                "location": "New Data Center"
            }
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.bulk_update_devices') as mock_bulk:
                mock_bulk.return_value = {"updated": 3, "failed": 0}
                
                response = client.patch(
                    "/api/v1/devices/bulk",
                    json=bulk_data,
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["updated"] == 3
                assert data["failed"] == 0

    def test_export_devices_success_admin(self, client, admin_token_data):
        """Test device data export as admin"""
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.export_devices_csv') as mock_export:
                mock_export.return_value = "csv_content"
                
                response = client.get(
                    "/api/v1/devices/export?format=csv",
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                assert response.headers["content-type"] == "text/csv"

    def test_unauthorized_access(self, client):
        """Test unauthorized access to device endpoints"""
        endpoints = [
            ("GET", "/api/v1/devices/"),
            ("POST", "/api/v1/devices/"),
            ("GET", "/api/v1/devices/1"),
            ("PUT", "/api/v1/devices/1"),
            ("DELETE", "/api/v1/devices/1")
        ]
        
        for method, endpoint in endpoints:
            response = getattr(client, method.lower())(endpoint)
            assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_search_devices_success(self, client, user_token_data):
        """Test device search functionality"""
        search_results = [
            Device(id=1, name="Router1", ip_address="192.168.1.1"),
            Device(id=2, name="Router2", ip_address="192.168.1.2")
        ]
        
        with patch('api.v1.devices.get_current_token_data', return_value=user_token_data):
            with patch('api.v1.devices.device_service.search_devices', return_value=search_results):
                response = client.get(
                    "/api/v1/devices/search?q=Router",
                    headers={"Authorization": "Bearer user_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert len(data) == 2
                assert "Router" in data[0]["name"]

    def test_device_statistics_success_admin(self, client, admin_token_data):
        """Test getting device statistics as admin"""
        stats = {
            "total_devices": 100,
            "active_devices": 85,
            "inactive_devices": 10,
            "offline_devices": 5,
            "by_type": {
                "router": 30,
                "switch": 40,
                "server": 20,
                "other": 10
            }
        }
        
        with patch('api.v1.devices.get_current_token_data', return_value=admin_token_data):
            with patch('api.v1.devices.device_service.get_device_statistics', return_value=stats):
                response = client.get(
                    "/api/v1/devices/statistics",
                    headers={"Authorization": "Bearer admin_token"}
                )
                
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert data["total_devices"] == 100
                assert data["active_devices"] == 85
                assert "by_type" in data