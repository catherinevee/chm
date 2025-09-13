"""
Comprehensive tests for Device Service to boost coverage to 65%
"""
import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession

# Mock ValidationService before importing
class MockValidationService:
    def __init__(self):
        pass
    
    def validate_hostname(self, hostname):
        if not hostname or len(hostname) < 3:
            raise ValueError("Invalid hostname")
        return hostname
    
    def validate_ip_address(self, ip):
        if not ip or "." not in ip:
            raise ValueError("Invalid IP address")
        return ip
    
    def validate_device_type(self, device_type):
        valid_types = ["router", "switch", "firewall", "server"]
        if device_type not in valid_types:
            raise ValueError("Invalid device type")
        return device_type
    
    def sanitize_string(self, value, max_length):
        if not value:
            return value
        return str(value)[:max_length]
    
    def validate_snmp_community(self, community):
        return community
    
    def validate_snmp_version(self, version):
        return version

# Apply the mock
import sys
sys.modules['backend.services.validation_service'] = MagicMock()
sys.modules['backend.services.validation_service'].ValidationService = MockValidationService

# Mock credential encryption
class MockCredentialEncryption:
    @staticmethod
    def encrypt_snmp_credential(credential, version):
        return f"encrypted_{credential}_{version}"
    
    @staticmethod
    def encrypt_credential(credential, metadata=None):
        return f"encrypted_{credential}"

sys.modules['backend.common.security'] = MagicMock()
sys.modules['backend.common.security'].credential_encryption = MockCredentialEncryption()

from backend.services.device_service import DeviceService
from backend.common.exceptions import (
    DeviceNotFoundException,
    DeviceAlreadyExistsException,
    InvalidIPAddressException,
    ValidationException
)


class TestDeviceService:
    """Comprehensive test cases for DeviceService"""
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        session = AsyncMock(spec=AsyncSession)
        session.commit = AsyncMock()
        session.rollback = AsyncMock()
        session.refresh = AsyncMock()
        session.add = MagicMock()
        session.get = AsyncMock()
        session.execute = AsyncMock()
        session.scalar = AsyncMock()
        session.delete = AsyncMock()
        return session
    
    @pytest.fixture
    def device_service(self, mock_db_session):
        """Create DeviceService instance"""
        return DeviceService(mock_db_session)
    
    @pytest.fixture
    def mock_device(self):
        """Mock device object"""
        device = MagicMock()
        device.id = str(uuid4())
        device.hostname = "test-device"
        device.ip_address = "192.168.1.1"
        device.device_type = "router"
        device.manufacturer = "Cisco"
        device.model = "ISR4321"
        device.current_state = "active"
        device.is_active = True
        device.created_at = datetime.utcnow()
        device.updated_at = datetime.utcnow()
        device.last_poll_time = None
        device.discovery_status = "pending"
        device.consecutive_failures = 0
        device.circuit_breaker_trips = 0
        device.configuration = {}
        return device
    
    @pytest.fixture
    def device_data(self):
        """Sample device data for creation"""
        return {
            "hostname": "test-router-01",
            "ip_address": "192.168.1.100",
            "device_type": "router",
            "manufacturer": "Cisco",
            "model": "ISR4321",
            "location": "Data Center",
            "department": "IT",
            "snmp_community": "public",
            "snmp_version": "2c",
            "ssh_username": "admin",
            "ssh_password": "password123",
            "api_key": "api_key_123"
        }
    
    # Test create_device method
    @pytest.mark.asyncio
    async def test_create_device_success(self, device_service, device_data):
        """Test successful device creation"""
        # Setup mocks
        device_service.db.execute.return_value.scalar_one_or_none.return_value = None  # No existing device
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_device_update = AsyncMock()
            
            with patch.object(device_service, '_trigger_device_discovery', new=AsyncMock()):
                # Execute
                result = await device_service.create_device(device_data, user_id="test_user")
                
                # Verify
                device_service.db.add.assert_called_once()
                device_service.db.commit.assert_called_once()
                device_service.db.refresh.assert_called_once()
                mock_ws.broadcast_device_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_device_already_exists(self, device_service, device_data, mock_device):
        """Test device creation when device already exists"""
        # Setup mocks
        device_service.db.execute.return_value.scalar_one_or_none.return_value = mock_device
        
        # Execute and verify
        with pytest.raises(DeviceAlreadyExistsException):
            await device_service.create_device(device_data)
    
    @pytest.mark.asyncio
    async def test_create_device_validation_error(self, device_service):
        """Test device creation with validation error"""
        invalid_data = {
            "hostname": "ab",  # Too short
            "ip_address": "invalid_ip",
            "device_type": "invalid_type"
        }
        
        # Execute and verify
        with pytest.raises(ValidationException):
            await device_service.create_device(invalid_data)
    
    @pytest.mark.asyncio
    async def test_create_device_database_error(self, device_service, device_data):
        """Test device creation with database error"""
        # Setup mocks
        device_service.db.execute.return_value.scalar_one_or_none.return_value = None
        device_service.db.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(Exception):
            await device_service.create_device(device_data)
        
        device_service.db.rollback.assert_called_once()
    
    # Test get_device method
    @pytest.mark.asyncio
    async def test_get_device_success(self, device_service, mock_device):
        """Test successful device retrieval"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        # Execute
        result = await device_service.get_device(mock_device.id)
        
        # Verify
        assert result == mock_device
        device_service.db.execute.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_device_not_found(self, device_service):
        """Test device retrieval when device not found"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        device_service.db.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device(str(uuid4()))
    
    @pytest.mark.asyncio
    async def test_get_device_invalid_uuid(self, device_service):
        """Test device retrieval with invalid UUID"""
        # Execute and verify
        with pytest.raises(ValidationException):
            await device_service.get_device("invalid_uuid")
    
    @pytest.mark.asyncio
    async def test_get_device_database_error(self, device_service):
        """Test device retrieval with database error"""
        # Setup mocks
        device_service.db.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(Exception):
            await device_service.get_device(str(uuid4()))
    
    # Test list_devices method
    @pytest.mark.asyncio
    async def test_list_devices_success(self, device_service, mock_device):
        """Test successful device listing"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_device]
        device_service.db.execute.return_value = mock_result
        device_service.db.scalar.return_value = 1
        
        # Execute
        devices, total = await device_service.list_devices()
        
        # Verify
        assert len(devices) == 1
        assert total == 1
        assert devices[0] == mock_device
    
    @pytest.mark.asyncio
    async def test_list_devices_with_filters(self, device_service, mock_device):
        """Test device listing with filters"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = [mock_device]
        device_service.db.execute.return_value = mock_result
        device_service.db.scalar.return_value = 1
        
        filters = {
            "device_type": "router",
            "state": "active",
            "location": "Data Center",
            "department": "IT",
            "is_active": True,
            "search": "test"
        }
        
        # Execute
        devices, total = await device_service.list_devices(
            filters=filters,
            page=2,
            per_page=10,
            sort_by="hostname",
            sort_order="asc"
        )
        
        # Verify
        assert len(devices) == 1
        assert total == 1
        device_service.db.execute.assert_called()
    
    @pytest.mark.asyncio
    async def test_list_devices_database_error(self, device_service):
        """Test device listing with database error"""
        # Setup mocks
        device_service.db.execute.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(Exception):
            await device_service.list_devices()
    
    # Test update_device method
    @pytest.mark.asyncio
    async def test_update_device_success(self, device_service, mock_device):
        """Test successful device update"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        update_data = {
            "hostname": "updated-device",
            "manufacturer": "Updated Cisco",
            "snmp_community": "private",
            "ssh_password": "newpassword",
            "api_key": "new_api_key"
        }
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_device_update = AsyncMock()
            
            # Execute
            result = await device_service.update_device(
                mock_device.id,
                update_data,
                user_id="test_user"
            )
            
            # Verify
            device_service.db.commit.assert_called_once()
            device_service.db.refresh.assert_called_once()
            mock_ws.broadcast_device_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_device_not_found(self, device_service):
        """Test updating non-existent device"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        device_service.db.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(DeviceNotFoundException):
            await device_service.update_device(str(uuid4()), {"hostname": "new"})
    
    @pytest.mark.asyncio
    async def test_update_device_validation_error(self, device_service, mock_device):
        """Test device update with validation error"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        invalid_data = {"hostname": "ab"}  # Too short
        
        # Execute and verify
        with pytest.raises(ValidationException):
            await device_service.update_device(mock_device.id, invalid_data)
    
    @pytest.mark.asyncio
    async def test_update_device_database_error(self, device_service, mock_device):
        """Test device update with database error"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        device_service.db.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(Exception):
            await device_service.update_device(mock_device.id, {"hostname": "new"})
        
        device_service.db.rollback.assert_called_once()
    
    # Test delete_device method
    @pytest.mark.asyncio
    async def test_delete_device_success(self, device_service, mock_device):
        """Test successful device deletion"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        # Execute
        result = await device_service.delete_device(mock_device.id, user_id="test_user")
        
        # Verify
        assert result is True
        device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_device_with_cascade(self, device_service, mock_device):
        """Test device deletion with cascade"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        # Execute
        result = await device_service.delete_device(
            mock_device.id,
            user_id="test_user",
            cascade=True
        )
        
        # Verify
        assert result is True
        # Should have 4 execute calls: get device + 3 cascade deletes
        assert device_service.db.execute.call_count >= 3
        device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_device_not_found(self, device_service):
        """Test deleting non-existent device"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        device_service.db.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(DeviceNotFoundException):
            await device_service.delete_device(str(uuid4()))
    
    @pytest.mark.asyncio
    async def test_delete_device_database_error(self, device_service, mock_device):
        """Test device deletion with database error"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        device_service.db.commit.side_effect = Exception("Database error")
        
        # Execute and verify
        with pytest.raises(Exception):
            await device_service.delete_device(mock_device.id)
        
        device_service.db.rollback.assert_called_once()
    
    # Test get_device_metrics method
    @pytest.mark.asyncio
    async def test_get_device_metrics_success(self, device_service, mock_device):
        """Test successful device metrics retrieval"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        
        mock_metrics_result = AsyncMock()
        mock_metric = MagicMock()
        mock_metric.device_id = mock_device.id
        mock_metric.metric_type = "cpu_usage"
        mock_metric.value = 75.0
        mock_metric.timestamp = datetime.utcnow()
        mock_metrics_result.scalars.return_value.all.return_value = [mock_metric]
        
        device_service.db.execute.side_effect = [mock_result, mock_metrics_result]
        
        # Execute
        metrics = await device_service.get_device_metrics(
            mock_device.id,
            metric_type="cpu_usage",
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow(),
            aggregation="avg"
        )
        
        # Verify
        assert len(metrics) == 1
        assert metrics[0] == mock_metric
        assert device_service.db.execute.call_count == 2
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_device_not_found(self, device_service):
        """Test metrics retrieval for non-existent device"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        device_service.db.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device_metrics(str(uuid4()))
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_database_error(self, device_service, mock_device):
        """Test metrics retrieval with database error"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.side_effect = [mock_result, Exception("Database error")]
        
        # Execute and verify
        with pytest.raises(Exception):
            await device_service.get_device_metrics(mock_device.id)
    
    # Test get_device_status method
    @pytest.mark.asyncio
    async def test_get_device_status_success(self, device_service, mock_device):
        """Test successful device status retrieval"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        
        mock_metrics_result = AsyncMock()
        mock_metric = MagicMock()
        mock_metric.metric_type = "cpu_usage"
        mock_metric.value = 75.0
        mock_metric.unit = "percent"
        mock_metric.timestamp = datetime.utcnow()
        mock_metrics_result.scalars.return_value = [mock_metric]
        
        device_service.db.execute.side_effect = [mock_result, mock_metrics_result]
        device_service.db.scalar.side_effect = [2, 3]  # active alerts, interface count
        
        with patch.object(device_service, '_calculate_health_score', return_value=85.0):
            # Execute
            status = await device_service.get_device_status(mock_device.id)
            
            # Verify
            assert status["device_id"] == mock_device.id
            assert status["hostname"] == mock_device.hostname
            assert status["active_alerts"] == 2
            assert status["interface_count"] == 3
            assert status["health_score"] == 85.0
            assert len(status["latest_metrics"]) == 1
    
    @pytest.mark.asyncio
    async def test_get_device_status_device_not_found(self, device_service):
        """Test status retrieval for non-existent device"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        device_service.db.execute.return_value = mock_result
        
        # Execute and verify
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device_status(str(uuid4()))
    
    # Test private methods
    @pytest.mark.asyncio
    async def test_validate_device_data_success(self, device_service, device_data):
        """Test successful device data validation"""
        # Execute
        validated = await device_service._validate_device_data(device_data)
        
        # Verify
        assert validated["hostname"] == device_data["hostname"]
        assert validated["ip_address"] == device_data["ip_address"]
        assert validated["device_type"] == device_data["device_type"]
        assert "snmp_community" in validated
    
    @pytest.mark.asyncio
    async def test_validate_device_update_data_success(self, device_service):
        """Test successful device update data validation"""
        update_data = {
            "hostname": "updated-device",
            "manufacturer": "Updated Cisco",
            "is_active": True
        }
        
        # Execute
        validated = await device_service._validate_device_update_data(update_data)
        
        # Verify
        assert validated["hostname"] == update_data["hostname"]
        assert validated["manufacturer"] == update_data["manufacturer"]
        assert validated["is_active"] == update_data["is_active"]
    
    @pytest.mark.asyncio
    async def test_check_device_exists_found(self, device_service, mock_device):
        """Test device existence check when device exists"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        # Execute
        result = await device_service._check_device_exists("192.168.1.1", "test-device")
        
        # Verify
        assert result == mock_device
    
    @pytest.mark.asyncio
    async def test_check_device_exists_not_found(self, device_service):
        """Test device existence check when device doesn't exist"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = None
        device_service.db.execute.return_value = mock_result
        
        # Execute
        result = await device_service._check_device_exists("192.168.1.1")
        
        # Verify
        assert result is None
    
    @pytest.mark.asyncio
    async def test_trigger_device_discovery(self, device_service, mock_device):
        """Test device discovery trigger"""
        # Execute - should not raise exception
        await device_service._trigger_device_discovery(mock_device)
        
        # Verify it completes without error
        assert True
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_active(self, device_service, mock_device):
        """Test health score calculation for active device"""
        mock_device.current_state = "active"
        mock_device.consecutive_failures = 0
        mock_device.circuit_breaker_trips = 0
        
        # Execute
        score = await device_service._calculate_health_score(mock_device)
        
        # Verify
        assert score == 100.0
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_down(self, device_service, mock_device):
        """Test health score calculation for down device"""
        mock_device.current_state = "down"
        mock_device.consecutive_failures = 3
        mock_device.circuit_breaker_trips = 1
        
        # Execute
        score = await device_service._calculate_health_score(mock_device)
        
        # Verify
        assert score == 25.0  # 100 - 50 (down) - 15 (failures) - 10 (trips)
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_critical(self, device_service, mock_device):
        """Test health score calculation for critical device"""
        mock_device.current_state = "critical"
        mock_device.consecutive_failures = 2
        mock_device.circuit_breaker_trips = 0
        
        # Execute
        score = await device_service._calculate_health_score(mock_device)
        
        # Verify
        assert score == 60.0  # 100 - 30 (critical) - 10 (failures)
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_warning(self, device_service, mock_device):
        """Test health score calculation for warning device"""
        mock_device.current_state = "warning"
        mock_device.consecutive_failures = 1
        mock_device.circuit_breaker_trips = 2
        
        # Execute
        score = await device_service._calculate_health_score(mock_device)
        
        # Verify
        assert score == 60.0  # 100 - 15 (warning) - 5 (failures) - 20 (trips)
    
    @pytest.mark.asyncio
    async def test_calculate_health_score_minimum(self, device_service, mock_device):
        """Test health score calculation minimum value"""
        mock_device.current_state = "down"
        mock_device.consecutive_failures = 10  # Would be -50
        mock_device.circuit_breaker_trips = 5   # Would be -50
        
        # Execute
        score = await device_service._calculate_health_score(mock_device)
        
        # Verify minimum score is 0
        assert score == 0.0
    
    # Test instance methods
    @pytest.mark.asyncio
    async def test_get_monitored_device_count(self, device_service):
        """Test getting monitored device count"""
        count = await device_service.get_monitored_device_count()
        
        # Should return sample data
        assert isinstance(count, int)
        assert count >= 0
    
    # Test edge cases and error conditions
    @pytest.mark.asyncio
    async def test_create_device_minimal_data(self, device_service):
        """Test device creation with minimal required data"""
        minimal_data = {
            "hostname": "minimal-device",
            "ip_address": "192.168.1.200",
            "device_type": "router"
        }
        
        # Setup mocks
        device_service.db.execute.return_value.scalar_one_or_none.return_value = None
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_device_update = AsyncMock()
            
            with patch.object(device_service, '_trigger_device_discovery', new=AsyncMock()):
                # Execute
                result = await device_service.create_device(minimal_data)
                
                # Verify
                device_service.db.add.assert_called_once()
                device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_device_partial_data(self, device_service, mock_device):
        """Test device update with partial data"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        device_service.db.execute.return_value = mock_result
        
        partial_data = {"location": "New Location"}
        
        with patch('backend.api.websocket_manager.ws_manager') as mock_ws:
            mock_ws.broadcast_device_update = AsyncMock()
            
            # Execute
            result = await device_service.update_device(mock_device.id, partial_data)
            
            # Verify
            device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_list_devices_empty_filters(self, device_service):
        """Test device listing with empty filters"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalars.return_value.all.return_value = []
        device_service.db.execute.return_value = mock_result
        device_service.db.scalar.return_value = 0
        
        # Execute
        devices, total = await device_service.list_devices(filters={})
        
        # Verify
        assert len(devices) == 0
        assert total == 0
    
    @pytest.mark.asyncio
    async def test_get_device_metrics_no_filters(self, device_service, mock_device):
        """Test metrics retrieval without filters"""
        # Setup mocks
        mock_result = AsyncMock()
        mock_result.scalar_one_or_none.return_value = mock_device
        
        mock_metrics_result = AsyncMock()
        mock_metrics_result.scalars.return_value.all.return_value = []
        
        device_service.db.execute.side_effect = [mock_result, mock_metrics_result]
        
        # Execute
        metrics = await device_service.get_device_metrics(mock_device.id)
        
        # Verify
        assert len(metrics) == 0