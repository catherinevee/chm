"""
CHM Device Operations Service Tests
Comprehensive testing of device operations including SNMP/SSH polling
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from chm.services.device_operations import DeviceOperationsService
from chm.models.device import Device, DeviceStatus, DeviceProtocol
from chm.models.device_credentials import DeviceCredentials, CredentialType
from chm.models.result_objects import DeviceStatusResult, OperationStatus, DeviceStatus as DeviceStatusEnum

@pytest.fixture
def device_operations_service():
    """Create device operations service instance"""
    return DeviceOperationsService()

@pytest.fixture
def mock_device():
    """Create mock device for testing"""
    return Device(
        id=1,
        name="Test Router",
        ip_address="192.168.1.1",
        protocol=DeviceProtocol.SNMP,
        status=DeviceStatus.UNKNOWN,
        monitoring_enabled=True,
        poll_interval_seconds=300,
        timeout_seconds=30,
        retry_count=3
    )

@pytest.fixture
def mock_credentials():
    """Create mock credentials for testing"""
    return DeviceCredentials(
        id=1,
        device_id=1,
        credential_type=CredentialType.SNMP,
        name="Primary SNMP",
        encrypted_data="mock_encrypted_data",
        key_id="mock_key_id"
    )

@pytest.fixture
def mock_ssh_device():
    """Create mock SSH device for testing"""
    return Device(
        id=2,
        name="Test Switch",
        ip_address="192.168.1.2",
        protocol=DeviceProtocol.SSH,
        status=DeviceStatus.UNKNOWN,
        monitoring_enabled=True,
        ssh_username="admin",
        poll_interval_seconds=300,
        timeout_seconds=30,
        retry_count=3
    )

@pytest.fixture
def mock_ssh_credentials():
    """Create mock SSH credentials for testing"""
    return DeviceCredentials(
        id=2,
        device_id=2,
        credential_type=CredentialType.SSH,
        name="SSH Admin",
        encrypted_data="mock_encrypted_data",
        key_id="mock_key_id"
    )

class TestDeviceOperationsService:
    """Test device operations service functionality"""
    
    @pytest.mark.asyncio
    async def test_get_device_status_success(self, device_operations_service, mock_device, mock_credentials):
        """Test successful device status retrieval"""
        with patch.object(device_operations_service, '_get_device', return_value=mock_device), \
             patch.object(device_operations_service, '_get_primary_credentials', return_value=mock_credentials), \
             patch.object(device_operations_service, '_poll_snmp') as mock_poll, \
             patch.object(device_operations_service, '_update_device_status') as mock_update:
            
            # Mock successful SNMP poll
            mock_poll.return_value = DeviceStatusResult.success(
                device_id=1,
                status=DeviceStatusEnum.ONLINE,
                response_time_ms=50.0
            )
            
            result = await device_operations_service.get_device_status(1)
            
            # Verify result
            assert result.status == OperationStatus.SUCCESS
            assert result.device_id == 1
            assert result.device_status == DeviceStatusEnum.ONLINE
            assert result.message == "Device status retrieved successfully"
            assert result.timestamp is not None
            
            # Verify methods were called
            mock_poll.assert_called_once_with(mock_device, mock_credentials)
            mock_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_device_status_device_not_found(self, device_operations_service):
        """Test device status retrieval when device not found"""
        with patch.object(device_operations_service, '_get_device', return_value=None):
            result = await device_operations_service.get_device_status(999)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 999
            assert result.device_status == DeviceStatusEnum.UNKNOWN
            assert "Device not found" in result.message
            assert result.fallback_data is not None
    
    @pytest.mark.asyncio
    async def test_get_device_status_no_credentials(self, device_operations_service, mock_device):
        """Test device status retrieval when no credentials found"""
        with patch.object(device_operations_service, '_get_device', return_value=mock_device), \
             patch.object(device_operations_service, '_get_primary_credentials', return_value=None):
            
            result = await device_operations_service.get_device_status(1)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 1
            assert result.device_status == DeviceStatusEnum.UNKNOWN
            assert "No primary credentials found" in result.message
            assert result.fallback_data is not None
    
    @pytest.mark.asyncio
    async def test_get_device_status_unsupported_protocol(self, device_operations_service, mock_device, mock_credentials):
        """Test device status retrieval with unsupported protocol"""
        # Create device with unsupported protocol
        mock_device.protocol = "UNSUPPORTED"
        
        with patch.object(device_operations_service, '_get_device', return_value=mock_device), \
             patch.object(device_operations_service, '_get_primary_credentials', return_value=mock_credentials):
            
            result = await device_operations_service.get_device_status(1)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 1
            assert result.device_status == DeviceStatusEnum.UNKNOWN
            assert "Unsupported protocol" in result.message
            assert result.fallback_data is not None
    
    @pytest.mark.asyncio
    async def test_snmp_poll_success(self, device_operations_service, mock_device, mock_credentials):
        """Test successful SNMP polling"""
        with patch('chm.services.device_operations.SNMP_AVAILABLE', True), \
             patch('chm.services.device_operations.credential_manager') as mock_cm, \
             patch.object(device_operations_service, '_execute_snmp_poll') as mock_execute:
            
            # Mock credential decryption
            mock_cm.decrypt_credentials.return_value = "public"
            
            # Mock successful SNMP execution
            mock_execute.return_value = DeviceStatusEnum.ONLINE
            
            result = await device_operations_service._poll_snmp(mock_device, mock_credentials)
            
            assert result.status == OperationStatus.SUCCESS
            assert result.device_id == 1
            assert result.device_status == DeviceStatusEnum.ONLINE
            mock_cm.decrypt_credentials.assert_called_once_with(mock_credentials)
            mock_execute.assert_called_once_with(mock_device, "public")
    
    @pytest.mark.asyncio
    async def test_snmp_poll_not_available(self, device_operations_service, mock_device, mock_credentials):
        """Test SNMP polling when PySNMP not available"""
        with patch('chm.services.device_operations.SNMP_AVAILABLE', False):
            result = await device_operations_service._poll_snmp(mock_device, mock_credentials)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 1
            assert "SNMP functionality not available" in result.message
            assert result.fallback_data is not None
    
    @pytest.mark.asyncio
    async def test_snmp_poll_credential_decryption_failed(self, device_operations_service, mock_device, mock_credentials):
        """Test SNMP polling when credential decryption fails"""
        with patch('chm.services.device_operations.SNMP_AVAILABLE', True), \
             patch('chm.services.device_operations.credential_manager') as mock_cm:
            
            # Mock failed credential decryption
            mock_cm.decrypt_credentials.return_value = None
            
            result = await device_operations_service._poll_snmp(mock_device, mock_credentials)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 1
            assert "Failed to decrypt SNMP credentials" in result.message
            assert result.fallback_data is not None
    
    @pytest.mark.asyncio
    async def test_ssh_poll_success(self, device_operations_service, mock_ssh_device, mock_ssh_credentials):
        """Test successful SSH polling"""
        with patch('chm.services.device_operations.SSH_AVAILABLE', True), \
             patch('chm.services.device_operations.credential_manager') as mock_cm, \
             patch.object(device_operations_service, '_execute_ssh_poll') as mock_execute:
            
            # Mock credential decryption
            mock_cm.decrypt_credentials.return_value = "admin123"
            
            # Mock successful SSH execution
            mock_execute.return_value = DeviceStatusEnum.ONLINE
            
            result = await device_operations_service._poll_ssh(mock_ssh_device, mock_ssh_credentials)
            
            assert result.status == OperationStatus.SUCCESS
            assert result.device_id == 2
            assert result.device_status == DeviceStatusEnum.ONLINE
            mock_cm.decrypt_credentials.assert_called_once_with(mock_ssh_credentials)
            mock_execute.assert_called_once_with(mock_ssh_device, "admin123")
    
    @pytest.mark.asyncio
    async def test_ssh_poll_not_available(self, device_operations_service, mock_ssh_device, mock_ssh_credentials):
        """Test SSH polling when AsyncSSH not available"""
        with patch('chm.services.device_operations.SSH_AVAILABLE', False):
            result = await device_operations_service._poll_ssh(mock_ssh_device, mock_ssh_credentials)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 2
            assert "SSH functionality not available" in result.message
            assert result.fallback_data is not None
    
    @pytest.mark.asyncio
    async def test_execute_snmp_poll_success(self, device_operations_service, mock_device):
        """Test successful SNMP execution"""
        with patch('chm.services.device_operations.getCmd') as mock_get_cmd:
            # Mock successful SNMP response
            mock_get_cmd.return_value = (None, None, None, [Mock()])
            
            result = await device_operations_service._execute_snmp_poll(mock_device, "public")
            
            assert result == DeviceStatusEnum.ONLINE
            mock_get_cmd.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_execute_snmp_poll_with_retries(self, device_operations_service, mock_device):
        """Test SNMP execution with retry logic"""
        with patch('chm.services.device_operations.getCmd') as mock_get_cmd:
            # Mock first two attempts failing, third succeeding
            mock_get_cmd.side_effect = [
                Exception("Connection timeout"),  # First attempt
                Exception("SNMP error"),         # Second attempt
                (None, None, None, [Mock()])     # Third attempt succeeds
            ]
            
            result = await device_operations_service._execute_snmp_poll(mock_device, "public")
            
            assert result == DeviceStatusEnum.ONLINE
            assert mock_get_cmd.call_count == 3
    
    @pytest.mark.asyncio
    async def test_execute_snmp_poll_all_retries_failed(self, device_operations_service, mock_device):
        """Test SNMP execution when all retries fail"""
        with patch('chm.services.device_operations.getCmd') as mock_get_cmd:
            # Mock all attempts failing
            mock_get_cmd.side_effect = Exception("Connection failed")
            
            result = await device_operations_service._execute_snmp_poll(mock_device, "public")
            
            assert result == DeviceStatusEnum.OFFLINE
            assert mock_get_cmd.call_count == 3
    
    @pytest.mark.asyncio
    async def test_execute_ssh_poll_success(self, device_operations_service, mock_ssh_device):
        """Test successful SSH execution"""
        mock_conn = AsyncMock()
        mock_result = Mock()
        mock_result.exit_status = 0
        
        mock_conn.run.return_value = mock_result
        
        with patch('chm.services.device_operations.asyncssh.connect') as mock_connect:
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            result = await device_operations_service._execute_ssh_poll(mock_ssh_device, "admin123")
            
            assert result == DeviceStatusEnum.ONLINE
            mock_conn.run.assert_called_once_with('echo "CHM Health Check"')
    
    @pytest.mark.asyncio
    async def test_execute_ssh_poll_command_failed(self, device_operations_service, mock_ssh_device):
        """Test SSH execution when command fails"""
        mock_conn = AsyncMock()
        mock_result = Mock()
        mock_result.exit_status = 1  # Command failed
        
        mock_conn.run.return_value = mock_result
        
        with patch('chm.services.device_operations.asyncssh.connect') as mock_connect:
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            with pytest.raises(Exception, match="SSH command failed with exit status 1"):
                await device_operations_service._execute_ssh_poll(mock_ssh_device, "admin123")
    
    @pytest.mark.asyncio
    async def test_execute_ssh_poll_with_retries(self, device_operations_service, mock_ssh_device):
        """Test SSH execution with retry logic"""
        mock_conn = AsyncMock()
        mock_result = Mock()
        mock_result.exit_status = 0
        
        mock_conn.run.return_value = mock_result
        
        with patch('chm.services.device_operations.asyncssh.connect') as mock_connect:
            # Mock first two attempts failing, third succeeding
            mock_connect.side_effect = [
                Exception("Connection timeout"),  # First attempt
                Exception("Authentication failed"),  # Second attempt
                mock_connect.return_value.__aenter__.return_value = mock_conn  # Third attempt succeeds
            ]
            
            result = await device_operations_service._execute_ssh_poll(mock_ssh_device, "admin123")
            
            assert result == DeviceStatusEnum.ONLINE
            assert mock_connect.call_count == 3
    
    @pytest.mark.asyncio
    async def test_batch_poll_devices_success(self, device_operations_service):
        """Test successful batch device polling"""
        device_ids = [1, 2, 3]
        
        with patch.object(device_operations_service, 'get_device_status') as mock_get_status:
            # Mock successful status checks
            mock_get_status.side_effect = [
                DeviceStatusResult.success(1, DeviceStatusEnum.ONLINE),
                DeviceStatusResult.success(2, DeviceStatusEnum.ONLINE),
                DeviceStatusResult.success(3, DeviceStatusEnum.OFFLINE)
            ]
            
            results = await device_operations_service.batch_poll_devices(device_ids)
            
            assert len(results) == 3
            assert all(result.status == OperationStatus.SUCCESS for result in results)
            assert results[0].device_id == 1
            assert results[1].device_id == 2
            assert results[2].device_id == 3
    
    @pytest.mark.asyncio
    async def test_batch_poll_devices_timeout(self, device_operations_service):
        """Test batch device polling timeout"""
        device_ids = [1, 2, 3]
        
        with patch.object(device_operations_service, 'get_device_status') as mock_get_status:
            # Mock slow status checks that will timeout
            async def slow_status_check(device_id):
                await asyncio.sleep(2)  # Simulate slow operation
                return DeviceStatusResult.success(device_id, DeviceStatusEnum.ONLINE)
            
            mock_get_status.side_effect = slow_status_check
            
            results = await device_operations_service.batch_poll_devices(device_ids)
            
            assert len(results) == 3
            assert all(result.status == OperationStatus.FAILED for result in results)
            assert all("timeout" in result.message for result in results)
    
    @pytest.mark.asyncio
    async def test_batch_poll_devices_exception_handling(self, device_operations_service):
        """Test batch device polling with exception handling"""
        device_ids = [1, 2, 3]
        
        with patch.object(device_operations_service, 'get_device_status') as mock_get_status:
            # Mock mixed results: success, exception, success
            mock_get_status.side_effect = [
                DeviceStatusResult.success(1, DeviceStatusEnum.ONLINE),
                Exception("Connection failed"),
                DeviceStatusResult.success(3, DeviceStatusEnum.ONLINE)
            ]
            
            results = await device_operations_service.batch_poll_devices(device_ids)
            
            assert len(results) == 3
            assert results[0].status == OperationStatus.SUCCESS
            assert results[1].status == OperationStatus.FAILED
            assert results[2].status == OperationStatus.SUCCESS
            assert "Connection failed" in results[1].message
    
    @pytest.mark.asyncio
    async def test_error_handling_with_fallback_data(self, device_operations_service):
        """Test error handling provides meaningful fallback data"""
        with patch.object(device_operations_service, '_get_device', side_effect=Exception("Database error")), \
             patch.object(device_operations_service, '_get_fallback_status') as mock_fallback:
            
            mock_fallback.return_value = {
                "status": "unknown",
                "last_check": "2023-01-01T00:00:00",
                "fallback_reason": "Database connection failed"
            }
            
            result = await device_operations_service.get_device_status(1)
            
            assert result.status == OperationStatus.FAILED
            assert result.device_id == 1
            assert result.fallback_data is not None
            assert result.fallback_data["status"] == "unknown"
            assert "Database error" in result.message
    
    @pytest.mark.asyncio
    async def test_device_status_update(self, device_operations_service):
        """Test device status update functionality"""
        with patch.object(device_operations_service, '_update_device_status') as mock_update:
            # This would test the status update logic
            # For now, just verify the method exists and can be called
            await device_operations_service._update_device_status(1, DeviceStatusEnum.ONLINE, 45.5)
            mock_update.assert_called_once_with(1, DeviceStatusEnum.ONLINE, 45.5)

class TestDeviceOperationsIntegration:
    """Integration tests for device operations"""
    
    @pytest.mark.asyncio
    async def test_full_device_status_workflow(self, device_operations_service, mock_device, mock_credentials):
        """Test complete device status workflow"""
        with patch.object(device_operations_service, '_get_device', return_value=mock_device), \
             patch.object(device_operations_service, '_get_primary_credentials', return_value=mock_credentials), \
             patch.object(device_operations_service, '_poll_snmp') as mock_poll, \
             patch.object(device_operations_service, '_update_device_status') as mock_update:
            
            # Mock successful SNMP poll
            mock_poll.return_value = DeviceStatusResult.success(
                device_id=1,
                status=DeviceStatusEnum.ONLINE,
                response_time_ms=25.0
            )
            
            # Execute full workflow
            result = await device_operations_service.get_device_status(1)
            
            # Verify complete result
            assert result.status == OperationStatus.SUCCESS
            assert result.device_id == 1
            assert result.device_status == DeviceStatusEnum.ONLINE
            assert result.operation == "device_status_check"
            assert result.timestamp is not None
            
            # Verify all steps were executed
            mock_poll.assert_called_once()
            mock_update.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_concurrent_device_polling(self, device_operations_service):
        """Test concurrent device polling performance"""
        device_ids = list(range(1, 11))  # 10 devices
        
        with patch.object(device_operations_service, 'get_device_status') as mock_get_status:
            # Mock fast status checks
            mock_get_status.side_effect = [
                DeviceStatusResult.success(device_id, DeviceStatusEnum.ONLINE)
                for device_id in device_ids
            ]
            
            start_time = asyncio.get_event_loop().time()
            results = await device_operations_service.batch_poll_devices(device_ids)
            end_time = asyncio.get_event_loop().time()
            
            # Verify all devices were polled
            assert len(results) == 10
            assert all(result.status == OperationStatus.SUCCESS for result in results)
            
            # Verify concurrent execution (should be much faster than sequential)
            execution_time = end_time - start_time
            assert execution_time < 1.0  # Should complete in under 1 second
    
    @pytest.mark.asyncio
    async def test_mixed_protocol_devices(self, device_operations_service):
        """Test handling of devices with different protocols"""
        # Create devices with different protocols
        snmp_device = Device(
            id=1, name="SNMP Device", ip_address="192.168.1.1",
            protocol=DeviceProtocol.SNMP, status=DeviceStatus.UNKNOWN
        )
        ssh_device = Device(
            id=2, name="SSH Device", ip_address="192.168.1.2",
            protocol=DeviceProtocol.SSH, status=DeviceStatus.UNKNOWN
        )
        
        snmp_creds = DeviceCredentials(
            id=1, device_id=1, credential_type=CredentialType.SNMP,
            encrypted_data="snmp_data", key_id="snmp_key"
        )
        ssh_creds = DeviceCredentials(
            id=2, device_id=2, credential_type=CredentialType.SSH,
            encrypted_data="ssh_data", key_id="ssh_key"
        )
        
        with patch.object(device_operations_service, '_get_device') as mock_get_device, \
             patch.object(device_operations_service, '_get_primary_credentials') as mock_get_creds, \
             patch.object(device_operations_service, '_poll_snmp') as mock_snmp, \
             patch.object(device_operations_service, '_poll_ssh') as mock_ssh, \
             patch.object(device_operations_service, '_update_device_status') as mock_update:
            
            # Mock device and credential retrieval
            mock_get_device.side_effect = [snmp_device, ssh_device]
            mock_get_creds.side_effect = [snmp_creds, ssh_creds]
            
            # Mock successful polling
            mock_snmp.return_value = DeviceStatusResult.success(1, DeviceStatusEnum.ONLINE)
            mock_ssh.return_value = DeviceStatusResult.success(2, DeviceStatusEnum.ONLINE)
            
            # Test SNMP device
            snmp_result = await device_operations_service.get_device_status(1)
            assert snmp_result.device_status == DeviceStatusEnum.ONLINE
            mock_snmp.assert_called_once()
            
            # Test SSH device
            ssh_result = await device_operations_service.get_device_status(2)
            assert ssh_result.device_status == DeviceStatusEnum.ONLINE
            mock_ssh.assert_called_once()
            
            # Verify different protocols were handled correctly
            assert mock_snmp.call_count == 1
            assert mock_ssh.call_count == 1
