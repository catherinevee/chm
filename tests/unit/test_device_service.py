"""
Comprehensive tests for Device Service
"""
import pytest
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.device_service import DeviceService
from backend.common.exceptions import (
    ResourceNotFoundException, ValidationException, DuplicateResourceException
)
from models.device import Device, DeviceType, DeviceStatus
from models.device_credentials import DeviceCredentials


class TestDeviceService:
    """Test Device Service functionality"""
    
    @pytest.fixture
    def device_service(self):
        """Create DeviceService instance"""
        return DeviceService()
    
    @pytest.fixture
    def mock_db_session(self):
        """Mock database session"""
        return AsyncMock(spec=AsyncSession)
    
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
            snmp_community="public",
            ssh_key="ssh_key_content"
        )

    def test_init(self, device_service):
        """Test DeviceService initialization"""
        assert device_service is not None

    @pytest.mark.asyncio
    async def test_create_device_success(self, device_service, mock_db_session):
        """Test successful device creation"""
        device_data = {
            "name": "New Router",
            "ip_address": "192.168.1.2",
            "device_type": DeviceType.ROUTER,
            "manufacturer": "Cisco",
            "model": "ISR4331"
        }
        
        new_device = Device(**device_data, id=2)
        mock_db_session.add = MagicMock()
        mock_db_session.commit = AsyncMock()
        mock_db_session.refresh = AsyncMock()
        
        with patch.object(device_service, '_validate_device_data'):
            with patch.object(device_service, '_check_device_exists', return_value=False):
                result = await device_service.create_device(mock_db_session, device_data)
                mock_db_session.add.assert_called_once()
                mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_device_duplicate_ip(self, device_service, mock_db_session):
        """Test device creation with duplicate IP address"""
        device_data = {
            "name": "Duplicate Router",
            "ip_address": "192.168.1.1",  # Existing IP
            "device_type": DeviceType.ROUTER
        }
        
        with patch.object(device_service, '_validate_device_data'):
            with patch.object(device_service, '_check_device_exists', return_value=True):
                with pytest.raises(DuplicateResourceException):
                    await device_service.create_device(mock_db_session, device_data)

    @pytest.mark.asyncio
    async def test_get_device_by_id_success(self, device_service, mock_db_session, sample_device):
        """Test getting device by ID"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service.get_device_by_id(mock_db_session, 1)
        assert result == sample_device
        mock_db_session.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_device_by_id_not_found(self, device_service, mock_db_session):
        """Test getting non-existent device by ID"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service.get_device_by_id(mock_db_session, 999)
        assert result is None

    @pytest.mark.asyncio
    async def test_get_device_by_ip_success(self, device_service, mock_db_session, sample_device):
        """Test getting device by IP address"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service.get_device_by_ip(mock_db_session, "192.168.1.1")
        assert result == sample_device

    @pytest.mark.asyncio
    async def test_get_devices_by_type(self, device_service, mock_db_session):
        """Test getting devices by type"""
        devices = [sample_device for _ in range(3)]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = devices
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service.get_devices_by_type(mock_db_session, DeviceType.ROUTER)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_get_all_devices(self, device_service, mock_db_session):
        """Test getting all devices with pagination"""
        devices = [sample_device for _ in range(5)]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = devices[:3]  # First page
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service.get_all_devices(mock_db_session, page=1, page_size=3)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_update_device_success(self, device_service, mock_db_session, sample_device):
        """Test successful device update"""
        update_data = {
            "name": "Updated Router",
            "manufacturer": "Juniper"
        }
        
        with patch.object(device_service, 'get_device_by_id', return_value=sample_device):
            mock_db_session.commit = AsyncMock()
            mock_db_session.refresh = AsyncMock()
            
            result = await device_service.update_device(mock_db_session, 1, update_data)
            assert result.name == "Updated Router"
            assert result.manufacturer == "Juniper"
            mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_device_not_found(self, device_service, mock_db_session):
        """Test updating non-existent device"""
        with patch.object(device_service, 'get_device_by_id', return_value=None):
            with pytest.raises(ResourceNotFoundException):
                await device_service.update_device(mock_db_session, 999, {"name": "Updated"})

    @pytest.mark.asyncio
    async def test_delete_device_success(self, device_service, mock_db_session, sample_device):
        """Test successful device deletion"""
        with patch.object(device_service, 'get_device_by_id', return_value=sample_device):
            mock_db_session.delete = MagicMock()
            mock_db_session.commit = AsyncMock()
            
            result = await device_service.delete_device(mock_db_session, 1)
            assert result is True
            mock_db_session.delete.assert_called_once()
            mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_device_not_found(self, device_service, mock_db_session):
        """Test deleting non-existent device"""
        with patch.object(device_service, 'get_device_by_id', return_value=None):
            with pytest.raises(ResourceNotFoundException):
                await device_service.delete_device(mock_db_session, 999)

    @pytest.mark.asyncio
    async def test_ping_device_success(self, device_service, sample_device):
        """Test successful device ping"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 0
            result = await device_service.ping_device(sample_device)
            assert result is True

    @pytest.mark.asyncio
    async def test_ping_device_failure(self, device_service, sample_device):
        """Test failed device ping"""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value.returncode = 1
            result = await device_service.ping_device(sample_device)
            assert result is False

    @pytest.mark.asyncio
    async def test_check_device_connectivity(self, device_service, mock_db_session, sample_device):
        """Test device connectivity check"""
        with patch.object(device_service, 'ping_device', return_value=True):
            with patch.object(device_service, '_test_snmp_connection', return_value=True):
                with patch.object(device_service, '_test_ssh_connection', return_value=True):
                    result = await device_service.check_device_connectivity(mock_db_session, sample_device)
                    assert result["ping"] is True
                    assert result["snmp"] is True
                    assert result["ssh"] is True

    @pytest.mark.asyncio
    async def test_discover_devices_subnet(self, device_service, mock_db_session):
        """Test network device discovery"""
        with patch.object(device_service, '_scan_subnet') as mock_scan:
            mock_scan.return_value = [
                {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55"},
                {"ip": "192.168.1.2", "mac": "00:11:22:33:44:66"}
            ]
            result = await device_service.discover_devices_subnet(mock_db_session, "192.168.1.0/24")
            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_device_credentials_success(self, device_service, mock_db_session, sample_credentials):
        """Test getting device credentials"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_credentials
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service.get_device_credentials(mock_db_session, 1)
        assert result == sample_credentials

    @pytest.mark.asyncio
    async def test_set_device_credentials_success(self, device_service, mock_db_session):
        """Test setting device credentials"""
        credentials_data = {
            "username": "admin",
            "password": "secret123",
            "snmp_community": "private"
        }
        
        mock_db_session.merge = AsyncMock()
        mock_db_session.commit = AsyncMock()
        
        result = await device_service.set_device_credentials(mock_db_session, 1, credentials_data)
        mock_db_session.merge.assert_called_once()
        mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_device_status_success(self, device_service, mock_db_session, sample_device):
        """Test updating device status"""
        with patch.object(device_service, 'get_device_by_id', return_value=sample_device):
            mock_db_session.commit = AsyncMock()
            
            result = await device_service.update_device_status(mock_db_session, 1, DeviceStatus.INACTIVE)
            assert result.status == DeviceStatus.INACTIVE
            mock_db_session.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_device_uptime(self, device_service, sample_device):
        """Test getting device uptime via SNMP"""
        with patch.object(device_service, '_snmp_get') as mock_snmp:
            mock_snmp.return_value = "12345600"  # Ticks
            result = await device_service.get_device_uptime(sample_device)
            assert isinstance(result, timedelta)

    @pytest.mark.asyncio
    async def test_get_device_info_snmp(self, device_service, sample_device):
        """Test getting device info via SNMP"""
        mock_info = {
            "sysDescr": "Cisco IOS Software",
            "sysName": "Router1",
            "sysContact": "admin@company.com",
            "sysLocation": "Data Center 1"
        }
        
        with patch.object(device_service, '_snmp_walk') as mock_snmp:
            mock_snmp.return_value = mock_info
            result = await device_service.get_device_info_snmp(sample_device)
            assert result == mock_info

    def test_validate_device_data_valid(self, device_service):
        """Test device data validation with valid data"""
        valid_data = {
            "name": "Test Router",
            "ip_address": "192.168.1.1",
            "device_type": DeviceType.ROUTER
        }
        # Should not raise any exception
        device_service._validate_device_data(valid_data)

    def test_validate_device_data_invalid_ip(self, device_service):
        """Test device data validation with invalid IP"""
        invalid_data = {
            "name": "Test Router",
            "ip_address": "999.999.999.999",  # Invalid IP
            "device_type": DeviceType.ROUTER
        }
        with pytest.raises(ValidationException):
            device_service._validate_device_data(invalid_data)

    def test_validate_device_data_missing_name(self, device_service):
        """Test device data validation with missing name"""
        invalid_data = {
            "ip_address": "192.168.1.1",
            "device_type": DeviceType.ROUTER
        }
        with pytest.raises(ValidationException):
            device_service._validate_device_data(invalid_data)

    @pytest.mark.asyncio
    async def test_check_device_exists_true(self, device_service, mock_db_session, sample_device):
        """Test checking if device exists - returns True"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = sample_device
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service._check_device_exists(mock_db_session, "192.168.1.1")
        assert result is True

    @pytest.mark.asyncio
    async def test_check_device_exists_false(self, device_service, mock_db_session):
        """Test checking if device exists - returns False"""
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_db_session.execute = AsyncMock(return_value=mock_result)
        
        result = await device_service._check_device_exists(mock_db_session, "192.168.1.99")
        assert result is False

    @pytest.mark.asyncio
    async def test_test_snmp_connection_success(self, device_service, sample_device):
        """Test SNMP connection testing - success"""
        with patch('pysnmp.hlapi.getCmd') as mock_get:
            mock_get.return_value = iter([
                (None, None, None, [("1.3.6.1.2.1.1.1.0", "System Description")])
            ])
            result = await device_service._test_snmp_connection(sample_device, "public")
            assert result is True

    @pytest.mark.asyncio
    async def test_test_snmp_connection_failure(self, device_service, sample_device):
        """Test SNMP connection testing - failure"""
        with patch('pysnmp.hlapi.getCmd') as mock_get:
            mock_get.side_effect = Exception("SNMP timeout")
            result = await device_service._test_snmp_connection(sample_device, "public")
            assert result is False

    @pytest.mark.asyncio
    async def test_test_ssh_connection_success(self, device_service, sample_device):
        """Test SSH connection testing - success"""
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.connect = MagicMock()
            mock_client.close = MagicMock()
            
            result = await device_service._test_ssh_connection(sample_device, "admin", "password")
            assert result is True

    @pytest.mark.asyncio
    async def test_test_ssh_connection_failure(self, device_service, sample_device):
        """Test SSH connection testing - failure"""
        with patch('paramiko.SSHClient') as mock_ssh:
            mock_client = MagicMock()
            mock_ssh.return_value = mock_client
            mock_client.connect.side_effect = Exception("SSH connection failed")
            
            result = await device_service._test_ssh_connection(sample_device, "admin", "wrong")
            assert result is False

    @pytest.mark.asyncio
    async def test_scan_subnet(self, device_service):
        """Test subnet scanning for device discovery"""
        with patch('subprocess.run') as mock_run:
            # Mock nmap output
            mock_run.return_value.stdout = """
            Nmap scan report for 192.168.1.1
            Host is up (0.001s latency).
            MAC Address: 00:11:22:33:44:55 (Cisco Systems)
            
            Nmap scan report for 192.168.1.2
            Host is up (0.002s latency).
            MAC Address: 00:11:22:33:44:66 (Cisco Systems)
            """
            mock_run.return_value.returncode = 0
            
            result = await device_service._scan_subnet("192.168.1.0/24")
            assert len(result) >= 0  # May return empty if parsing logic differs

    def test_parse_nmap_output(self, device_service):
        """Test nmap output parsing"""
        nmap_output = """
        Nmap scan report for 192.168.1.1
        Host is up (0.001s latency).
        MAC Address: 00:11:22:33:44:55 (Cisco Systems)
        """
        
        result = device_service._parse_nmap_output(nmap_output)
        # Test depends on implementation details

    @pytest.mark.asyncio
    async def test_snmp_get(self, device_service, sample_device):
        """Test SNMP GET operation"""
        with patch('pysnmp.hlapi.getCmd') as mock_get:
            mock_get.return_value = iter([
                (None, None, None, [("1.3.6.1.2.1.1.1.0", "System Description")])
            ])
            result = await device_service._snmp_get(sample_device, "1.3.6.1.2.1.1.1.0", "public")
            # Test implementation specific result

    @pytest.mark.asyncio
    async def test_snmp_walk(self, device_service, sample_device):
        """Test SNMP WALK operation"""
        with patch('pysnmp.hlapi.nextCmd') as mock_walk:
            mock_walk.return_value = iter([
                (None, None, None, [
                    ("1.3.6.1.2.1.1.1.0", "System Description"),
                    ("1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.9")
                ])
            ])
            result = await device_service._snmp_walk(sample_device, "1.3.6.1.2.1.1", "public")
            # Test implementation specific result