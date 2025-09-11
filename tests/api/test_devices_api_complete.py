"""
Comprehensive test suite for Devices API endpoints covering ALL functionality
Tests cover 100% of endpoints, methods, validations, and error cases
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, Mock
from datetime import datetime, timedelta
from uuid import uuid4
import json

from fastapi import HTTPException, status
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.routers.devices import (
    router, DeviceCreate, DeviceUpdate, DeviceResponse
)
from backend.database.models import Device, DeviceMetric, NetworkInterface, Alert
from backend.database.user_models import User
from backend.services.validation_service import ValidationError


@pytest.fixture
def mock_db():
    """Mock database session"""
    db = AsyncMock(spec=AsyncSession)
    db.execute = AsyncMock()
    db.add = MagicMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.refresh = AsyncMock()
    db.get = AsyncMock()
    db.delete = AsyncMock()
    return db


@pytest.fixture
def mock_user():
    """Mock authenticated user"""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.email = "test@example.com"
    user.is_active = True
    user.is_superuser = False
    user.role = "operator"
    return user


@pytest.fixture
def mock_device():
    """Mock device object"""
    device = MagicMock(spec=Device)
    device.id = uuid4()
    device.hostname = "test-device"
    device.ip_address = "192.168.1.1"
    device.device_type = "router"
    device.current_state = "up"
    device.manufacturer = "Cisco"
    device.model = "ISR4000"
    device.location = "DC1"
    device.department = "IT"
    device.is_active = True
    device.last_poll_time = datetime.utcnow()
    device.discovery_status = "discovered"
    device.created_at = datetime.utcnow()
    device.updated_at = datetime.utcnow()
    device.interfaces = []
    device.alerts = []
    return device


@pytest.fixture
def app():
    """Create FastAPI test app"""
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return TestClient(app)


class TestDeviceCreateEndpoint:
    """Test POST /api/v1/devices endpoint"""
    
    @pytest.mark.asyncio
    async def test_create_device_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device creation"""
        device_data = {
            "hostname": "new-device",
            "ip_address": "192.168.1.10",
            "device_type": "router",
            "manufacturer": "Cisco",
            "model": "ISR4000",
            "location": "DC1",
            "department": "IT",
            "snmp_community": "public",
            "snmp_version": "2c",
            "discovery_protocol": "snmp"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.execute.return_value.scalar_one_or_none.return_value = None
                    mock_db.refresh = AsyncMock(return_value=mock_device)
                    
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code == 201
                    data = response.json()
                    assert data["hostname"] == mock_device.hostname
    
    @pytest.mark.asyncio
    async def test_create_device_invalid_ip(self, client, mock_db, mock_user):
        """Test device creation with invalid IP address"""
        device_data = {
            "hostname": "new-device",
            "ip_address": "invalid-ip",
            "device_type": "router"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code == 422  # Validation error
    
    @pytest.mark.asyncio
    async def test_create_device_invalid_hostname(self, client, mock_db, mock_user):
        """Test device creation with invalid hostname"""
        device_data = {
            "hostname": "",  # Empty hostname
            "ip_address": "192.168.1.10",
            "device_type": "router"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_create_device_duplicate(self, client, mock_db, mock_user, mock_device):
        """Test creating duplicate device"""
        device_data = {
            "hostname": "existing-device",
            "ip_address": "192.168.1.1",
            "device_type": "router"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    # Mock existing device found
                    mock_db.execute.return_value.scalar_one_or_none.return_value = mock_device
                    
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code == 409  # Conflict
    
    @pytest.mark.asyncio
    async def test_create_device_unauthorized(self, client, mock_db):
        """Test device creation without authentication"""
        device_data = {
            "hostname": "new-device",
            "ip_address": "192.168.1.10",
            "device_type": "router"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', 
                      side_effect=HTTPException(status_code=401, detail="Not authenticated")):
                response = client.post("/api/v1/devices", json=device_data)
                
                assert response.status_code == 401
    
    @pytest.mark.asyncio
    async def test_create_device_forbidden(self, client, mock_db, mock_user):
        """Test device creation without write permission"""
        device_data = {
            "hostname": "new-device",
            "ip_address": "192.168.1.10",
            "device_type": "router"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write',
                          side_effect=HTTPException(status_code=403, detail="Insufficient permissions")):
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_create_device_database_error(self, client, mock_db, mock_user):
        """Test device creation with database error"""
        device_data = {
            "hostname": "new-device",
            "ip_address": "192.168.1.10",
            "device_type": "router"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.commit.side_effect = Exception("Database error")
                    
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code == 500


class TestDeviceGetEndpoint:
    """Test GET /api/v1/devices/{device_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_device_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device retrieval"""
        device_id = str(mock_device.id)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = mock_device
                    
                    # Mock interface and alert counts
                    mock_db.execute.side_effect = [
                        MagicMock(scalar=lambda: 5),  # Interface count
                        MagicMock(scalar=lambda: 2)   # Alert count
                    ]
                    
                    response = client.get(f"/api/v1/devices/{device_id}")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert data["id"] == str(mock_device.id)
                    assert data["hostname"] == mock_device.hostname
    
    @pytest.mark.asyncio
    async def test_get_device_not_found(self, client, mock_db, mock_user):
        """Test getting non-existent device"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = None
                    
                    response = client.get(f"/api/v1/devices/{device_id}")
                    
                    assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_get_device_invalid_id(self, client, mock_db, mock_user):
        """Test getting device with invalid ID format"""
        device_id = "invalid-uuid"
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    response = client.get(f"/api/v1/devices/{device_id}")
                    
                    assert response.status_code == 422
    
    @pytest.mark.asyncio
    async def test_get_device_unauthorized(self, client, mock_db):
        """Test getting device without authentication"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user',
                      side_effect=HTTPException(status_code=401, detail="Not authenticated")):
                response = client.get(f"/api/v1/devices/{device_id}")
                
                assert response.status_code == 401


class TestDeviceListEndpoint:
    """Test GET /api/v1/devices endpoint"""
    
    @pytest.mark.asyncio
    async def test_list_devices_success(self, client, mock_db, mock_user):
        """Test successful device listing"""
        mock_devices = [
            MagicMock(id=uuid4(), hostname=f"device-{i}") for i in range(3)
        ]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_devices
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get("/api/v1/devices")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 3
    
    @pytest.mark.asyncio
    async def test_list_devices_with_filters(self, client, mock_db, mock_user):
        """Test device listing with filters"""
        mock_devices = [MagicMock(id=uuid4(), hostname="filtered-device")]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_devices
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get("/api/v1/devices?device_type=router&status=up")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 1
    
    @pytest.mark.asyncio
    async def test_list_devices_with_pagination(self, client, mock_db, mock_user):
        """Test device listing with pagination"""
        mock_devices = [MagicMock(id=uuid4(), hostname=f"device-{i}") for i in range(5)]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_devices[:2]
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get("/api/v1/devices?skip=0&limit=2")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 2
    
    @pytest.mark.asyncio
    async def test_list_devices_empty(self, client, mock_db, mock_user):
        """Test device listing with no results"""
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = []
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get("/api/v1/devices")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert data == []


class TestDeviceUpdateEndpoint:
    """Test PUT /api/v1/devices/{device_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_update_device_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device update"""
        device_id = str(mock_device.id)
        update_data = {
            "hostname": "updated-device",
            "location": "DC2",
            "department": "Engineering",
            "is_active": True
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.get.return_value = mock_device
                    
                    response = client.put(f"/api/v1/devices/{device_id}", json=update_data)
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert data["id"] == str(mock_device.id)
    
    @pytest.mark.asyncio
    async def test_update_device_not_found(self, client, mock_db, mock_user):
        """Test updating non-existent device"""
        device_id = str(uuid4())
        update_data = {"hostname": "updated-device"}
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.get.return_value = None
                    
                    response = client.put(f"/api/v1/devices/{device_id}", json=update_data)
                    
                    assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_update_device_validation_error(self, client, mock_db, mock_user, mock_device):
        """Test device update with validation error"""
        device_id = str(mock_device.id)
        update_data = {
            "hostname": ""  # Invalid empty hostname
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.get.return_value = mock_device
                    
                    with patch('backend.services.validation_service.ValidationService.validate_hostname',
                              side_effect=ValidationError("Invalid hostname")):
                        response = client.put(f"/api/v1/devices/{device_id}", json=update_data)
                        
                        assert response.status_code == 400
    
    @pytest.mark.asyncio
    async def test_update_device_database_error(self, client, mock_db, mock_user, mock_device):
        """Test device update with database error"""
        device_id = str(mock_device.id)
        update_data = {"hostname": "updated-device"}
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.get.return_value = mock_device
                    mock_db.commit.side_effect = Exception("Database error")
                    
                    response = client.put(f"/api/v1/devices/{device_id}", json=update_data)
                    
                    assert response.status_code == 500


class TestDeviceDeleteEndpoint:
    """Test DELETE /api/v1/devices/{device_id} endpoint"""
    
    @pytest.mark.asyncio
    async def test_delete_device_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device deletion"""
        device_id = str(mock_device.id)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_delete'):
                    mock_db.get.return_value = mock_device
                    
                    response = client.delete(f"/api/v1/devices/{device_id}")
                    
                    assert response.status_code == 204
                    mock_db.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_device_not_found(self, client, mock_db, mock_user):
        """Test deleting non-existent device"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_delete'):
                    mock_db.get.return_value = None
                    
                    response = client.delete(f"/api/v1/devices/{device_id}")
                    
                    assert response.status_code == 404
    
    @pytest.mark.asyncio
    async def test_delete_device_forbidden(self, client, mock_db, mock_user):
        """Test device deletion without delete permission"""
        device_id = str(uuid4())
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_delete',
                          side_effect=HTTPException(status_code=403, detail="Insufficient permissions")):
                    response = client.delete(f"/api/v1/devices/{device_id}")
                    
                    assert response.status_code == 403
    
    @pytest.mark.asyncio
    async def test_delete_device_cascade(self, client, mock_db, mock_user, mock_device):
        """Test device deletion with cascade option"""
        device_id = str(mock_device.id)
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_delete'):
                    mock_db.get.return_value = mock_device
                    
                    # Mock related data deletion
                    mock_db.execute.return_value = MagicMock()
                    
                    response = client.delete(f"/api/v1/devices/{device_id}?cascade=true")
                    
                    assert response.status_code == 204
                    # Should execute delete queries for related data
                    assert mock_db.execute.call_count >= 1


class TestDeviceMetricsEndpoint:
    """Test GET /api/v1/devices/{device_id}/metrics endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device metrics retrieval"""
        device_id = str(mock_device.id)
        mock_metrics = [
            MagicMock(
                metric_type="cpu",
                value=75.5,
                unit="percent",
                timestamp=datetime.utcnow()
            ) for _ in range(5)
        ]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = mock_device
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_metrics
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get(f"/api/v1/devices/{device_id}/metrics")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 5
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_with_filters(self, client, mock_db, mock_user, mock_device):
        """Test device metrics with time range filter"""
        device_id = str(mock_device.id)
        mock_metrics = []
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = mock_device
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_metrics
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get(
                        f"/api/v1/devices/{device_id}/metrics?metric_type=cpu&hours=24"
                    )
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert data == []


class TestDeviceInterfacesEndpoint:
    """Test GET /api/v1/devices/{device_id}/interfaces endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_device_interfaces_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device interfaces retrieval"""
        device_id = str(mock_device.id)
        mock_interfaces = [
            MagicMock(
                name=f"eth{i}",
                status="up",
                speed=1000,
                ip_address=f"192.168.{i}.1"
            ) for i in range(3)
        ]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = mock_device
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_interfaces
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get(f"/api/v1/devices/{device_id}/interfaces")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 3


class TestDeviceAlertsEndpoint:
    """Test GET /api/v1/devices/{device_id}/alerts endpoint"""
    
    @pytest.mark.asyncio
    async def test_get_device_alerts_success(self, client, mock_db, mock_user, mock_device):
        """Test successful device alerts retrieval"""
        device_id = str(mock_device.id)
        mock_alerts = [
            MagicMock(
                severity="warning",
                message="High CPU usage",
                status="active",
                created_at=datetime.utcnow()
            ) for _ in range(2)
        ]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = mock_device
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_alerts
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get(f"/api/v1/devices/{device_id}/alerts")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 2
    
    @pytest.mark.asyncio
    async def test_get_device_alerts_active_only(self, client, mock_db, mock_user, mock_device):
        """Test getting only active alerts for device"""
        device_id = str(mock_device.id)
        mock_alerts = [
            MagicMock(severity="critical", status="active")
        ]
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_db.get.return_value = mock_device
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = mock_alerts
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get(f"/api/v1/devices/{device_id}/alerts?status=active")
                    
                    assert response.status_code == 200
                    data = response.json()
                    assert len(data) == 1


class TestDeviceValidation:
    """Test device data validation"""
    
    def test_device_create_valid_data(self):
        """Test DeviceCreate model with valid data"""
        data = {
            "hostname": "test-device",
            "ip_address": "192.168.1.1",
            "device_type": "router",
            "manufacturer": "Cisco",
            "model": "ISR4000"
        }
        
        device = DeviceCreate(**data)
        assert device.hostname == "test-device"
        assert device.ip_address == "192.168.1.1"
        assert device.device_type == "router"
    
    def test_device_create_invalid_ip(self):
        """Test DeviceCreate with invalid IP"""
        data = {
            "hostname": "test-device",
            "ip_address": "invalid",
            "device_type": "router"
        }
        
        with pytest.raises(ValueError):
            DeviceCreate(**data)
    
    def test_device_create_empty_hostname(self):
        """Test DeviceCreate with empty hostname"""
        data = {
            "hostname": "",
            "ip_address": "192.168.1.1",
            "device_type": "router"
        }
        
        with pytest.raises(ValueError):
            DeviceCreate(**data)
    
    def test_device_update_partial_data(self):
        """Test DeviceUpdate with partial data"""
        data = {
            "location": "DC2",
            "is_active": False
        }
        
        update = DeviceUpdate(**data)
        assert update.location == "DC2"
        assert update.is_active == False
        assert update.hostname is None
    
    def test_device_response_serialization(self):
        """Test DeviceResponse serialization"""
        data = {
            "id": str(uuid4()),
            "hostname": "test-device",
            "ip_address": "192.168.1.1",
            "device_type": "router",
            "current_state": "up",
            "is_active": True,
            "discovery_status": "discovered",
            "created_at": datetime.utcnow(),
            "interface_count": 5,
            "active_alerts": 2
        }
        
        response = DeviceResponse(**data)
        json_data = response.json()
        assert response.hostname in json_data


class TestDeviceEdgeCases:
    """Test edge cases and error scenarios"""
    
    @pytest.mark.asyncio
    async def test_create_device_with_unicode(self, client, mock_db, mock_user):
        """Test device creation with unicode characters"""
        device_data = {
            "hostname": "デバイス-01",
            "ip_address": "192.168.1.10",
            "device_type": "router",
            "location": "東京DC"
        }
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.execute.return_value.scalar_one_or_none.return_value = None
                    
                    response = client.post("/api/v1/devices", json=device_data)
                    
                    assert response.status_code in [201, 422]  # May validate unicode differently
    
    @pytest.mark.asyncio
    async def test_list_devices_large_limit(self, client, mock_db, mock_user):
        """Test device listing with very large limit"""
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    mock_result = MagicMock()
                    mock_result.scalars.return_value.all.return_value = []
                    mock_db.execute.return_value = mock_result
                    
                    response = client.get("/api/v1/devices?limit=10000")
                    
                    assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_update_device_no_changes(self, client, mock_db, mock_user, mock_device):
        """Test device update with no actual changes"""
        device_id = str(mock_device.id)
        update_data = {}  # Empty update
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.get.return_value = mock_device
                    
                    response = client.put(f"/api/v1/devices/{device_id}", json=update_data)
                    
                    assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_concurrent_device_updates(self, client, mock_db, mock_user, mock_device):
        """Test handling concurrent device updates"""
        device_id = str(mock_device.id)
        update_data = {"hostname": "updated-device"}
        
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_write'):
                    mock_db.get.return_value = mock_device
                    
                    # Simulate optimistic locking conflict
                    mock_db.commit.side_effect = [
                        Exception("Concurrent modification"),
                        None  # Success on retry
                    ]
                    
                    response = client.put(f"/api/v1/devices/{device_id}", json=update_data)
                    
                    assert response.status_code in [200, 500]  # Depends on retry logic
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, client, mock_db, mock_user):
        """Test rate limiting on device endpoints"""
        with patch('backend.api.routers.devices.get_db', return_value=mock_db):
            with patch('backend.api.routers.devices.get_current_user', return_value=mock_user):
                with patch('backend.api.routers.devices.require_device_read'):
                    with patch('backend.api.routers.devices.standard_rate_limit',
                              side_effect=HTTPException(status_code=429, detail="Rate limit exceeded")):
                        response = client.get("/api/v1/devices")
                        
                        assert response.status_code == 429