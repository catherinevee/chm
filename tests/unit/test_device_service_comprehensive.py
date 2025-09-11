"""
Comprehensive Device Service Tests
Tests all actual methods in backend/services/device_service.py
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
from typing import List, Optional, Dict, Any, Tuple

# Mock the models and dependencies that DeviceService expects
from dataclasses import dataclass


@dataclass
class MockDevice:
    """Mock Device model for testing"""
    id: UUID
    hostname: str
    ip_address: str
    device_type: str
    current_state: str = "unknown"
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial_number: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    discovery_protocol: str = "snmp"
    device_group: Optional[str] = None
    ssh_username: Optional[str] = None
    is_active: bool = True
    created_at: datetime = None
    updated_at: Optional[datetime] = None
    last_poll_time: Optional[datetime] = None
    discovery_status: Optional[str] = None
    consecutive_failures: int = 0
    circuit_breaker_trips: int = 0
    snmp_community_encrypted: Optional[str] = None
    ssh_password_encrypted: Optional[str] = None
    api_key_encrypted: Optional[str] = None
    
    # Mock relationships
    interfaces: List = None
    alerts: List = None
    metrics: List = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.interfaces is None:
            self.interfaces = []
        if self.alerts is None:
            self.alerts = []
        if self.metrics is None:
            self.metrics = []


@dataclass
class MockDeviceMetric:
    """Mock DeviceMetric model for testing"""
    id: UUID
    device_id: UUID
    metric_type: str
    value: float
    unit: str
    timestamp: datetime


@dataclass
class MockAlert:
    """Mock Alert model for testing"""
    id: UUID
    device_id: UUID
    status: str
    message: str


@dataclass
class MockNetworkInterface:
    """Mock NetworkInterface model for testing"""
    id: UUID
    device_id: UUID
    name: str


class TestDeviceServiceComprehensive:
    """Comprehensive test coverage for DeviceService"""
    
    @pytest.fixture
    def mock_session(self):
        """Create mock database session"""
        return AsyncMock()
    
    @pytest.fixture
    def mock_validator(self):
        """Create mock ValidationService"""
        validator = MagicMock()
        validator.validate_hostname.return_value = "test-device"
        validator.validate_ip_address.return_value = "192.168.1.1"
        validator.validate_device_type.return_value = "router"
        validator.sanitize_string.side_effect = lambda x, _: x
        validator.validate_snmp_community.return_value = "public"
        validator.validate_snmp_version.return_value = "2c"
        return validator
    
    @pytest.fixture
    def device_service(self, mock_session, mock_validator):
        """Create DeviceService instance for testing"""
        # Mock the dependencies
        with patch('backend.services.device_service.Device', MockDevice), \
             patch('backend.services.device_service.DeviceMetric', MockDeviceMetric), \
             patch('backend.services.device_service.Alert', MockAlert), \
             patch('backend.services.device_service.NetworkInterface', MockNetworkInterface), \
             patch('backend.services.device_service.ValidationService', return_value=mock_validator), \
             patch('backend.services.device_service.credential_encryption') as mock_encryption:
            
            mock_encryption.encrypt_snmp_credential.return_value = "encrypted_snmp"
            mock_encryption.encrypt_credential.return_value = "encrypted_cred"
            
            from backend.services.device_service import DeviceService
            service = DeviceService(mock_session)
            service.validator = mock_validator  # Override with our mock
            return service
    
    @pytest.fixture
    def sample_device(self):
        """Create sample device for testing"""
        return MockDevice(
            id=uuid4(),
            hostname="test-device",
            ip_address="192.168.1.1",
            device_type="router",
            manufacturer="Cisco",
            model="ISR4331",
            location="Data Center 1",
            department="IT",
            is_active=True,
            created_at=datetime.utcnow()
        )
    
    @pytest.fixture
    def device_data(self):
        """Sample device creation data"""
        return {
            "hostname": "test-device",
            "ip_address": "192.168.1.1",
            "device_type": "router",
            "manufacturer": "Cisco",
            "model": "ISR4331",
            "location": "Data Center 1",
            "department": "IT",
            "snmp_community": "public",
            "snmp_version": "2c",
            "ssh_username": "admin",
            "ssh_password": "password123",
            "api_key": "api-key-123"
        }
    
    # Test create_device method
    @pytest.mark.asyncio
    async def test_create_device_success(self, device_service, mock_session, device_data):
        """Test successful device creation"""
        # Mock validation methods
        with patch.object(device_service, '_validate_device_data', return_value=device_data), \
             patch.object(device_service, '_check_device_exists', return_value=None), \
             patch.object(device_service, '_trigger_device_discovery', return_value=None), \
             patch('backend.services.device_service.ws_manager') as mock_ws:
            
            # Mock session operations
            mock_session.add = MagicMock()
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            mock_ws.broadcast_device_update = AsyncMock()
            
            # Mock datetime
            with patch('backend.services.device_service.datetime') as mock_dt:
                mock_dt.utcnow.return_value = datetime(2024, 1, 1, 12, 0, 0)
                
                result = await device_service.create_device(device_data, user_id="user123")
                
                assert isinstance(result, MockDevice)
                assert result.hostname == "test-device"
                assert result.ip_address == "192.168.1.1"
                mock_session.add.assert_called_once()
                mock_session.commit.assert_called_once()
                mock_ws.broadcast_device_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_device_already_exists(self, device_service, mock_session, device_data, sample_device):
        """Test device creation when device already exists"""
        with patch.object(device_service, '_validate_device_data', return_value=device_data), \
             patch.object(device_service, '_check_device_exists', return_value=sample_device):
            
            from backend.common.exceptions import DeviceAlreadyExistsException
            
            with pytest.raises(DeviceAlreadyExistsException):
                await device_service.create_device(device_data)
    
    @pytest.mark.asyncio
    async def test_create_device_validation_error(self, device_service, mock_session, device_data):
        """Test device creation with validation error"""
        from backend.common.exceptions import ValidationException
        
        with patch.object(device_service, '_validate_device_data', 
                         side_effect=ValidationException("Invalid hostname")):
            
            with pytest.raises(ValidationException):
                await device_service.create_device(device_data)
    
    @pytest.mark.asyncio
    async def test_create_device_database_error(self, device_service, mock_session, device_data):
        """Test device creation with database error"""
        with patch.object(device_service, '_validate_device_data', return_value=device_data), \
             patch.object(device_service, '_check_device_exists', return_value=None):
            
            # Mock session to raise exception
            mock_session.add.side_effect = Exception("Database error")
            mock_session.rollback = AsyncMock()
            
            with pytest.raises(Exception):
                await device_service.create_device(device_data)
            
            mock_session.rollback.assert_called_once()
    
    # Test get_device method
    @pytest.mark.asyncio
    async def test_get_device_success(self, device_service, mock_session, sample_device):
        """Test successful device retrieval"""
        device_id = str(sample_device.id)
        
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result
        
        result = await device_service.get_device(device_id)
        
        assert result == sample_device
        mock_session.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_device_not_found(self, device_service, mock_session):
        """Test device retrieval when device not found"""
        device_id = str(uuid4())
        
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        from backend.common.exceptions import DeviceNotFoundException
        
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device(device_id)
    
    @pytest.mark.asyncio
    async def test_get_device_invalid_id(self, device_service, mock_session):
        """Test device retrieval with invalid ID format"""
        from backend.common.exceptions import ValidationException
        
        with pytest.raises(ValidationException):
            await device_service.get_device("invalid-uuid")
    
    # Test list_devices method
    @pytest.mark.asyncio
    async def test_list_devices_success(self, device_service, mock_session, sample_device):
        """Test successful device listing"""
        devices = [sample_device]
        
        # Mock database queries
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = devices
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1  # Total count
        
        result_devices, total = await device_service.list_devices()
        
        assert result_devices == devices
        assert total == 1
    
    @pytest.mark.asyncio
    async def test_list_devices_with_filters(self, device_service, mock_session, sample_device):
        """Test device listing with filters"""
        devices = [sample_device]
        
        # Mock database queries
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = devices
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 1
        
        filters = {
            "device_type": "router",
            "state": "up",
            "location": "Data Center 1",
            "department": "IT",
            "is_active": True,
            "search": "test"
        }
        
        result_devices, total = await device_service.list_devices(
            filters=filters,
            page=1,
            per_page=10,
            sort_by="hostname",
            sort_order="asc"
        )
        
        assert result_devices == devices
        assert total == 1
    
    @pytest.mark.asyncio
    async def test_list_devices_pagination(self, device_service, mock_session, sample_device):
        """Test device listing with pagination"""
        devices = [sample_device]
        
        # Mock database queries
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = devices
        mock_session.execute.return_value = mock_result
        mock_session.scalar.return_value = 100  # Total count
        
        result_devices, total = await device_service.list_devices(
            page=2,
            per_page=20,
            sort_by="created_at",
            sort_order="desc"
        )
        
        assert result_devices == devices
        assert total == 100
    
    # Test update_device method
    @pytest.mark.asyncio
    async def test_update_device_success(self, device_service, mock_session, sample_device):
        """Test successful device update"""
        device_id = str(sample_device.id)
        update_data = {
            "hostname": "updated-device",
            "location": "Data Center 2",
            "manufacturer": "Juniper"
        }
        
        with patch.object(device_service, 'get_device', return_value=sample_device), \
             patch.object(device_service, '_validate_device_update_data', return_value=update_data), \
             patch('backend.services.device_service.ws_manager') as mock_ws:
            
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            mock_ws.broadcast_device_update = AsyncMock()
            
            # Mock datetime
            with patch('backend.services.device_service.datetime') as mock_dt:
                mock_dt.utcnow.return_value = datetime(2024, 1, 2, 12, 0, 0)
                
                result = await device_service.update_device(device_id, update_data, user_id="user123")
                
                assert result == sample_device
                mock_session.commit.assert_called_once()
                mock_ws.broadcast_device_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_device_with_credentials(self, device_service, mock_session, sample_device):
        """Test device update with credential fields"""
        device_id = str(sample_device.id)
        update_data = {
            "snmp_community": "private",
            "ssh_password": "newpassword",
            "api_key": "new-api-key"
        }
        
        with patch.object(device_service, 'get_device', return_value=sample_device), \
             patch.object(device_service, '_validate_device_update_data', return_value=update_data), \
             patch('backend.services.device_service.ws_manager') as mock_ws:
            
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            mock_ws.broadcast_device_update = AsyncMock()
            
            result = await device_service.update_device(device_id, update_data)
            
            assert result == sample_device
            assert sample_device.snmp_community_encrypted == "encrypted_snmp"
            assert sample_device.ssh_password_encrypted == "encrypted_cred"
            assert sample_device.api_key_encrypted == "encrypted_cred"
    
    @pytest.mark.asyncio
    async def test_update_device_not_found(self, device_service, mock_session):
        """Test update device when device not found"""
        device_id = str(uuid4())
        update_data = {"hostname": "updated"}
        
        from backend.common.exceptions import DeviceNotFoundException
        
        with patch.object(device_service, 'get_device', side_effect=DeviceNotFoundException("Device not found")):
            
            with pytest.raises(DeviceNotFoundException):
                await device_service.update_device(device_id, update_data)
    
    # Test delete_device method
    @pytest.mark.asyncio
    async def test_delete_device_success(self, device_service, mock_session, sample_device):
        """Test successful device deletion"""
        device_id = str(sample_device.id)
        
        with patch.object(device_service, 'get_device', return_value=sample_device):
            mock_session.execute = AsyncMock()
            mock_session.delete = AsyncMock()
            mock_session.commit = AsyncMock()
            
            result = await device_service.delete_device(device_id, user_id="user123", cascade=True)
            
            assert result is True
            # Should delete related data first (3 calls for metrics, interfaces, alerts)
            assert mock_session.execute.call_count == 3
            mock_session.delete.assert_called_once_with(sample_device)
            mock_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_device_no_cascade(self, device_service, mock_session, sample_device):
        """Test device deletion without cascade"""
        device_id = str(sample_device.id)
        
        with patch.object(device_service, 'get_device', return_value=sample_device):
            mock_session.execute = AsyncMock()
            mock_session.delete = AsyncMock()
            mock_session.commit = AsyncMock()
            
            result = await device_service.delete_device(device_id, cascade=False)
            
            assert result is True
            # Should not delete related data
            mock_session.execute.assert_not_called()
            mock_session.delete.assert_called_once_with(sample_device)
    
    @pytest.mark.asyncio
    async def test_delete_device_not_found(self, device_service, mock_session):
        """Test delete device when device not found"""
        device_id = str(uuid4())
        
        from backend.common.exceptions import DeviceNotFoundException
        
        with patch.object(device_service, 'get_device', side_effect=DeviceNotFoundException("Device not found")):
            
            with pytest.raises(DeviceNotFoundException):
                await device_service.delete_device(device_id)
    
    @pytest.mark.asyncio
    async def test_delete_device_database_error(self, device_service, mock_session, sample_device):
        """Test delete device with database error"""
        device_id = str(sample_device.id)
        
        with patch.object(device_service, 'get_device', return_value=sample_device):
            mock_session.execute = AsyncMock()
            mock_session.delete.side_effect = Exception("Database error")
            mock_session.rollback = AsyncMock()
            
            with pytest.raises(Exception):
                await device_service.delete_device(device_id)
            
            mock_session.rollback.assert_called_once()
    
    # Test get_device_metrics method
    @pytest.mark.asyncio
    async def test_get_device_metrics_success(self, device_service, mock_session, sample_device):
        """Test successful device metrics retrieval"""
        device_id = str(sample_device.id)
        metrics = [
            MockDeviceMetric(uuid4(), sample_device.id, "cpu", 75.5, "%", datetime.utcnow()),
            MockDeviceMetric(uuid4(), sample_device.id, "memory", 65.2, "%", datetime.utcnow())
        ]
        
        with patch.object(device_service, 'get_device', return_value=sample_device):
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = metrics
            mock_session.execute.return_value = mock_result
            
            result = await device_service.get_device_metrics(device_id)
            
            assert result == metrics
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_with_filters(self, device_service, mock_session, sample_device):
        """Test device metrics retrieval with filters"""
        device_id = str(sample_device.id)
        start_time = datetime.utcnow() - timedelta(hours=1)
        end_time = datetime.utcnow()
        
        with patch.object(device_service, 'get_device', return_value=sample_device):
            mock_result = MagicMock()
            mock_result.scalars.return_value.all.return_value = []
            mock_session.execute.return_value = mock_result
            
            result = await device_service.get_device_metrics(
                device_id,
                metric_type="cpu",
                start_time=start_time,
                end_time=end_time,
                aggregation="avg"
            )
            
            assert result == []
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_device_not_found(self, device_service, mock_session):
        """Test metrics retrieval when device not found"""
        device_id = str(uuid4())
        
        from backend.common.exceptions import DeviceNotFoundException
        
        with patch.object(device_service, 'get_device', side_effect=DeviceNotFoundException("Device not found")):
            
            with pytest.raises(DeviceNotFoundException):
                await device_service.get_device_metrics(device_id)
    
    # Test get_device_status method
    @pytest.mark.asyncio
    async def test_get_device_status_success(self, device_service, mock_session, sample_device):
        """Test successful device status retrieval"""
        device_id = str(sample_device.id)
        sample_device.last_poll_time = datetime.utcnow()
        sample_device.discovery_status = "discovered"
        
        # Mock metrics query
        mock_metrics_result = MagicMock()
        mock_metrics_result.scalars.return_value = [
            MockDeviceMetric(uuid4(), sample_device.id, "cpu", 75.5, "%", datetime.utcnow())
        ]
        
        with patch.object(device_service, 'get_device', return_value=sample_device), \
             patch.object(device_service, '_calculate_health_score', return_value=85.0):
            
            # Mock multiple database calls
            mock_session.execute.return_value = mock_metrics_result
            mock_session.scalar.side_effect = [5, 2]  # alerts count, interface count
            
            result = await device_service.get_device_status(device_id)
            
            assert result["device_id"] == str(sample_device.id)
            assert result["hostname"] == sample_device.hostname
            assert result["ip_address"] == sample_device.ip_address
            assert result["current_state"] == sample_device.current_state
            assert result["active_alerts"] == 5
            assert result["interface_count"] == 2
            assert result["health_score"] == 85.0
            assert "latest_metrics" in result
    
    @pytest.mark.asyncio
    async def test_get_device_status_device_not_found(self, device_service, mock_session):
        """Test status retrieval when device not found"""
        device_id = str(uuid4())
        
        from backend.common.exceptions import DeviceNotFoundException
        
        with patch.object(device_service, 'get_device', side_effect=DeviceNotFoundException("Device not found")):
            
            with pytest.raises(DeviceNotFoundException):
                await device_service.get_device_status(device_id)
    
    # Test private helper methods
    @pytest.mark.asyncio
    async def test_validate_device_data(self, device_service, device_data):
        """Test device data validation"""
        result = await device_service._validate_device_data(device_data)
        
        assert result["hostname"] == "test-device"
        assert result["ip_address"] == "192.168.1.1"
        assert result["device_type"] == "router"
        assert "manufacturer" in result
        assert "model" in result
        assert "location" in result
    
    @pytest.mark.asyncio
    async def test_validate_device_update_data(self, device_service):
        """Test device update data validation"""
        update_data = {
            "hostname": "updated-device",
            "manufacturer": "Updated Manufacturer",
            "is_active": False
        }
        
        result = await device_service._validate_device_update_data(update_data)
        
        assert result["hostname"] == "updated-device"
        assert result["manufacturer"] == "Updated Manufacturer"
        assert result["is_active"] is False
    
    @pytest.mark.asyncio
    async def test_check_device_exists_found(self, device_service, mock_session, sample_device):
        """Test check device exists when device found"""
        # Mock database query
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_session.execute.return_value = mock_result
        
        result = await device_service._check_device_exists("192.168.1.1", "test-device")
        
        assert result == sample_device
    
    @pytest.mark.asyncio
    async def test_check_device_exists_not_found(self, device_service, mock_session):
        """Test check device exists when device not found"""
        # Mock database query to return None
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_session.execute.return_value = mock_result
        
        result = await device_service._check_device_exists("192.168.1.100", "nonexistent")
        
        assert result is None
    
    @pytest.mark.asyncio
    async def test_trigger_device_discovery(self, device_service, sample_device):
        """Test trigger device discovery"""
        # Should not raise exception (placeholder implementation)
        await device_service._trigger_device_discovery(sample_device)
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_healthy(self, device_service, sample_device):
        """Test health score calculation for healthy device"""
        sample_device.current_state = "up"
        sample_device.consecutive_failures = 0
        sample_device.circuit_breaker_trips = 0
        
        score = await device_service._calculate_health_score(sample_device)
        
        assert score == 100.0
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_down(self, device_service, sample_device):
        """Test health score calculation for down device"""
        sample_device.current_state = "down"
        sample_device.consecutive_failures = 3
        sample_device.circuit_breaker_trips = 1
        
        score = await device_service._calculate_health_score(sample_device)
        
        # 100 - 50 (down) - 15 (3 failures * 5) - 10 (1 trip * 10) = 25
        assert score == 25.0
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_critical(self, device_service, sample_device):
        """Test health score calculation for critical device"""
        sample_device.current_state = "critical"
        sample_device.consecutive_failures = 2
        sample_device.circuit_breaker_trips = 0
        
        score = await device_service._calculate_health_score(sample_device)
        
        # 100 - 30 (critical) - 10 (2 failures * 5) = 60
        assert score == 60.0
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_warning(self, device_service, sample_device):
        """Test health score calculation for warning device"""
        sample_device.current_state = "warning"
        sample_device.consecutive_failures = 1
        sample_device.circuit_breaker_trips = 0
        
        score = await device_service._calculate_health_score(sample_device)
        
        # 100 - 15 (warning) - 5 (1 failure * 5) = 80
        assert score == 80.0
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_min_zero(self, device_service, sample_device):
        """Test health score never goes below zero"""
        sample_device.current_state = "down"
        sample_device.consecutive_failures = 10  # Would be -50 points
        sample_device.circuit_breaker_trips = 5   # Would be -50 points
        
        score = await device_service._calculate_health_score(sample_device)
        
        # Should not go below 0
        assert score == 0.0
    
    # Error handling tests
    @pytest.mark.asyncio
    async def test_create_device_unknown_exception(self, device_service, mock_session, device_data):
        """Test device creation with unknown exception"""
        with patch.object(device_service, '_validate_device_data', return_value=device_data), \
             patch.object(device_service, '_check_device_exists', return_value=None):
            
            # Mock session to raise unknown exception
            mock_session.add.side_effect = RuntimeError("Unknown error")
            mock_session.rollback = AsyncMock()
            
            with pytest.raises(RuntimeError):
                await device_service.create_device(device_data)
            
            mock_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_device_unknown_exception(self, device_service, mock_session):
        """Test device retrieval with unknown exception"""
        device_id = str(uuid4())
        
        # Mock session to raise exception
        mock_session.execute.side_effect = RuntimeError("Database connection error")
        
        with pytest.raises(RuntimeError):
            await device_service.get_device(device_id)
    
    @pytest.mark.asyncio
    async def test_list_devices_exception(self, device_service, mock_session):
        """Test device listing with exception"""
        # Mock session to raise exception
        mock_session.execute.side_effect = RuntimeError("Query error")
        
        with pytest.raises(RuntimeError):
            await device_service.list_devices()
    
    @pytest.mark.asyncio
    async def test_update_device_database_error(self, device_service, mock_session, sample_device):
        """Test device update with database error"""
        device_id = str(sample_device.id)
        update_data = {"hostname": "updated"}
        
        with patch.object(device_service, 'get_device', return_value=sample_device), \
             patch.object(device_service, '_validate_device_update_data', return_value=update_data):
            
            mock_session.commit.side_effect = Exception("Database error")
            mock_session.rollback = AsyncMock()
            
            with pytest.raises(Exception):
                await device_service.update_device(device_id, update_data)
            
            mock_session.rollback.assert_called_once()
    
    # Integration-style tests
    @pytest.mark.asyncio
    async def test_device_lifecycle_complete(self, device_service, mock_session, device_data):
        """Test complete device lifecycle: create -> get -> update -> delete"""
        device_id = str(uuid4())
        created_device = MockDevice(
            id=UUID(device_id),
            hostname="lifecycle-device",
            ip_address="192.168.1.100",
            device_type="switch",
            is_active=True
        )
        
        # Mock all dependencies for lifecycle test
        with patch.object(device_service, '_validate_device_data', return_value=device_data), \
             patch.object(device_service, '_check_device_exists', return_value=None), \
             patch.object(device_service, '_trigger_device_discovery', return_value=None), \
             patch.object(device_service, '_validate_device_update_data', return_value={"hostname": "updated"}), \
             patch('backend.services.device_service.ws_manager') as mock_ws:
            
            # Setup session mocks
            mock_session.add = MagicMock()
            mock_session.commit = AsyncMock()
            mock_session.refresh = AsyncMock()
            mock_session.execute = AsyncMock()
            mock_session.delete = AsyncMock()
            mock_ws.broadcast_device_update = AsyncMock()
            
            # Mock database queries for get operations
            mock_result = MagicMock()
            mock_result.scalar_one_or_none.return_value = created_device
            mock_session.execute.return_value = mock_result
            
            # 1. Create device
            create_result = await device_service.create_device(device_data)
            assert isinstance(create_result, MockDevice)
            
            # 2. Get device
            get_result = await device_service.get_device(device_id)
            assert get_result == created_device
            
            # 3. Update device
            update_result = await device_service.update_device(device_id, {"hostname": "updated"})
            assert update_result == created_device
            
            # 4. Delete device
            delete_result = await device_service.delete_device(device_id, cascade=True)
            assert delete_result is True
    
    @pytest.mark.asyncio
    async def test_device_metrics_and_status_integration(self, device_service, mock_session, sample_device):
        """Test device metrics and status integration"""
        device_id = str(sample_device.id)
        
        # Create mock metrics
        metrics = [
            MockDeviceMetric(uuid4(), sample_device.id, "cpu", 75.5, "%", datetime.utcnow()),
            MockDeviceMetric(uuid4(), sample_device.id, "memory", 65.2, "%", datetime.utcnow())
        ]
        
        with patch.object(device_service, 'get_device', return_value=sample_device), \
             patch.object(device_service, '_calculate_health_score', return_value=90.0):
            
            # Mock metrics query
            mock_metrics_result = MagicMock()
            mock_metrics_result.scalars.return_value.all.return_value = metrics
            mock_metrics_result.scalars.return_value = metrics  # For status query
            
            mock_session.execute.return_value = mock_metrics_result
            mock_session.scalar.side_effect = [3, 4]  # alerts, interfaces
            
            # 1. Get metrics
            metrics_result = await device_service.get_device_metrics(device_id, metric_type="cpu")
            assert metrics_result == metrics
            
            # 2. Get status (includes metrics)
            status_result = await device_service.get_device_status(device_id)
            assert status_result["device_id"] == device_id
            assert status_result["active_alerts"] == 3
            assert status_result["interface_count"] == 4
            assert status_result["health_score"] == 90.0