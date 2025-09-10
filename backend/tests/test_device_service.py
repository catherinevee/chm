"""
Tests for Device Service
Comprehensive testing of device management functionality
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from uuid import uuid4

from backend.services.device_service import DeviceService
from backend.storage.models import Device, DeviceType, DeviceState, DeviceGroup
from backend.common.exceptions import (
    DeviceNotFoundException,
    DeviceAlreadyExistsException,
    InvalidIPAddressException,
    ValidationException
)


class TestDeviceService:
    """Test cases for DeviceService"""
    
    @pytest.fixture
    def device_service(self, test_session):
        """Create DeviceService instance for testing"""
        return DeviceService(test_session)
    
    @pytest.fixture
    def sample_device_data(self):
        """Sample device data for testing"""
        return {
            "hostname": "test-router-01",
            "ip_address": "192.168.1.1",
            "device_type": DeviceType.ROUTER,
            "manufacturer": "Cisco",
            "model": "ISR4321",
            "location": "Data Center A",
            "department": "Network Engineering",
            "discovery_protocol": "snmp",
            "device_group": DeviceGroup.PRODUCTION,
            "snmp_community": "test-community",
            "snmp_version": "2c",
            "ssh_username": "admin",
            "ssh_password": "test-password"
        }
    
    @pytest.fixture
    def sample_device(self, sample_device_data):
        """Create a sample device instance"""
        return Device(
            id=uuid4(),
            hostname=sample_device_data["hostname"],
            ip_address=sample_device_data["ip_address"],
            device_type=sample_device_data["device_type"],
            manufacturer=sample_device_data["manufacturer"],
            model=sample_device_data["model"],
            location=sample_device_data["location"],
            department=sample_device_data["department"],
            discovery_protocol=sample_device_data["discovery_protocol"],
            device_group=sample_device_data["device_group"],
            current_state=DeviceState.ONLINE,
            is_active=True,
            created_at=datetime.utcnow()
        )
    
    @pytest.mark.asyncio
    async def test_create_device_success(self, device_service, sample_device_data, test_session):
        """Test successful device creation"""
        # Mock validation service
        with patch.object(device_service, 'validator') as mock_validator:
            mock_validator.validate_device_data.return_value = sample_device_data
            
            # Mock credential encryption
            with patch('backend.services.device_service.credential_encryption') as mock_encryption:
                mock_encryption.encrypt_snmp_credential.return_value = "encrypted-snmp"
                mock_encryption.encrypt_credential.return_value = "encrypted-ssh"
                
                # Create device
                device = await device_service.create_device(sample_device_data, "test-user")
                
                # Verify device was created
                assert device.hostname == sample_device_data["hostname"]
                assert device.ip_address == sample_device_data["ip_address"]
                assert device.device_type == sample_device_data["device_type"]
                assert device.is_active is True
                
                # Verify credentials were encrypted
                assert device.snmp_community_encrypted == "encrypted-snmp"
                assert device.ssh_password_encrypted == "encrypted-ssh"
    
    @pytest.mark.asyncio
    async def test_create_device_duplicate_ip(self, device_service, sample_device_data, test_session):
        """Test device creation with duplicate IP address"""
        # Mock validation service
        with patch.object(device_service, 'validator') as mock_validator:
            mock_validator.validate_device_data.return_value = sample_device_data
            
            # Mock existing device check
            with patch.object(device_service, '_check_device_exists') as mock_check:
                mock_check.return_value = True  # Device already exists
                
                # Attempt to create device
                with pytest.raises(DeviceAlreadyExistsException):
                    await device_service.create_device(sample_device_data, "test-user")
    
    @pytest.mark.asyncio
    async def test_create_device_duplicate_hostname(self, device_service, sample_device_data, test_session):
        """Test device creation with duplicate hostname"""
        # Mock validation service
        with patch.object(device_service, 'validator') as mock_validator:
            mock_validator.validate_device_data.return_value = sample_device_data
            
            # Mock existing device check
            with patch.object(device_service, '_check_device_exists') as mock_check:
                mock_check.return_value = True  # Device already exists
                
                # Attempt to create device
                with pytest.raises(DeviceAlreadyExistsException):
                    await device_service.create_device(sample_device_data, "test-user")
    
    @pytest.mark.asyncio
    async def test_create_device_invalid_data(self, device_service, sample_device_data, test_session):
        """Test device creation with invalid data"""
        # Mock validation service to raise exception
        with patch.object(device_service, 'validator') as mock_validator:
            mock_validator.validate_device_data.side_effect = ValidationException("Invalid data")
            
            # Attempt to create device
            with pytest.raises(ValidationException):
                await device_service.create_device(sample_device_data, "test-user")
    
    @pytest.mark.asyncio
    async def test_get_device_by_id_success(self, device_service, sample_device, test_session):
        """Test successful device retrieval by ID"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Retrieve device
        device = await device_service.get_device_by_id(str(sample_device.id))
        
        # Verify device was retrieved
        assert device is not None
        assert device.id == sample_device.id
        assert device.hostname == sample_device.hostname
    
    @pytest.mark.asyncio
    async def test_get_device_by_id_not_found(self, device_service, test_session):
        """Test device retrieval with non-existent ID"""
        # Attempt to retrieve non-existent device
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device_by_id(str(uuid4()))
    
    @pytest.mark.asyncio
    async def test_get_device_by_ip_success(self, device_service, sample_device, test_session):
        """Test successful device retrieval by IP address"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Retrieve device
        device = await device_service.get_device_by_ip(sample_device.ip_address)
        
        # Verify device was retrieved
        assert device is not None
        assert device.ip_address == sample_device.ip_address
    
    @pytest.mark.asyncio
    async def test_get_device_by_ip_not_found(self, device_service, test_session):
        """Test device retrieval with non-existent IP"""
        # Attempt to retrieve device with non-existent IP
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device_by_ip("192.168.1.999")
    
    @pytest.mark.asyncio
    async def test_update_device_success(self, device_service, sample_device, test_session):
        """Test successful device update"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Update data
        update_data = {
            "hostname": "updated-router-01",
            "location": "Data Center B",
            "department": "Infrastructure"
        }
        
        # Update device
        updated_device = await device_service.update_device(str(sample_device.id), update_data, "test-user")
        
        # Verify device was updated
        assert updated_device.hostname == update_data["hostname"]
        assert updated_device.location == update_data["location"]
        assert updated_device.department == update_data["department"]
    
    @pytest.mark.asyncio
    async def test_update_device_not_found(self, device_service, test_session):
        """Test device update with non-existent ID"""
        # Attempt to update non-existent device
        with pytest.raises(DeviceNotFoundException):
            await device_service.update_device(str(uuid4()), {"hostname": "test"}, "test-user")
    
    @pytest.mark.asyncio
    async def test_delete_device_success(self, device_service, sample_device, test_session):
        """Test successful device deletion"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Delete device
        await device_service.delete_device(str(sample_device.id), "test-user")
        
        # Verify device was deleted
        with pytest.raises(DeviceNotFoundException):
            await device_service.get_device_by_id(str(sample_device.id))
    
    @pytest.mark.asyncio
    async def test_delete_device_not_found(self, device_service, test_session):
        """Test device deletion with non-existent ID"""
        # Attempt to delete non-existent device
        with pytest.raises(DeviceNotFoundException):
            await device_service.delete_device(str(uuid4()), "test-user")
    
    @pytest.mark.asyncio
    async def test_list_devices_pagination(self, device_service, test_session):
        """Test device listing with pagination"""
        # Create multiple devices
        devices = []
        for i in range(15):
            device = Device(
                id=uuid4(),
                hostname=f"test-device-{i:02d}",
                ip_address=f"192.168.1.{i+1}",
                device_type=DeviceType.SWITCH,
                current_state=DeviceState.ONLINE,
                is_active=True,
                created_at=datetime.utcnow()
            )
            devices.append(device)
            test_session.add(device)
        
        await test_session.commit()
        
        # Test first page
        result = await device_service.list_devices(skip=0, limit=10)
        assert len(result['devices']) == 10
        assert result['total'] == 15
        assert result['page'] == 1
        assert result['pages'] == 2
        
        # Test second page
        result = await device_service.list_devices(skip=10, limit=10)
        assert len(result['devices']) == 5
        assert result['page'] == 2
    
    @pytest.mark.asyncio
    async def test_list_devices_filtering(self, device_service, test_session):
        """Test device listing with filters"""
        # Create devices with different types
        router = Device(
            id=uuid4(),
            hostname="test-router",
            ip_address="192.168.1.1",
            device_type=DeviceType.ROUTER,
            current_state=DeviceState.ONLINE,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        switch = Device(
            id=uuid4(),
            hostname="test-switch",
            ip_address="192.168.1.2",
            device_type=DeviceType.SWITCH,
            current_state=DeviceState.ONLINE,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        test_session.add(router)
        test_session.add(switch)
        await test_session.commit()
        
        # Filter by device type
        result = await device_service.list_devices(device_type=DeviceType.ROUTER)
        assert len(result['devices']) == 1
        assert result['devices'][0].device_type == DeviceType.ROUTER
        
        # Filter by state
        result = await device_service.list_devices(state=DeviceState.ONLINE)
        assert len(result['devices']) == 2
        
        # Filter by location
        result = await device_service.list_devices(location="Data Center A")
        assert len(result['devices']) == 0  # No devices with this location
    
    @pytest.mark.asyncio
    async def test_search_devices(self, device_service, test_session):
        """Test device search functionality"""
        # Create devices with searchable content
        device1 = Device(
            id=uuid4(),
            hostname="core-router-01",
            ip_address="10.0.0.1",
            device_type=DeviceType.ROUTER,
            manufacturer="Cisco",
            model="ASR9000",
            location="Core Data Center",
            current_state=DeviceState.ONLINE,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        device2 = Device(
            id=uuid4(),
            hostname="edge-switch-01",
            ip_address="10.0.1.1",
            device_type=DeviceType.SWITCH,
            manufacturer="Juniper",
            model="EX4300",
            location="Edge Location",
            current_state=DeviceState.ONLINE,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        test_session.add(device1)
        test_session.add(device2)
        await test_session.commit()
        
        # Search by hostname
        result = await device_service.search_devices("core-router")
        assert len(result['devices']) == 1
        assert result['devices'][0].hostname == "core-router-01"
        
        # Search by manufacturer
        result = await device_service.search_devices("Cisco")
        assert len(result['devices']) == 1
        assert result['devices'][0].manufacturer == "Cisco"
        
        # Search by location
        result = await device_service.search_devices("Core Data")
        assert len(result['devices']) == 1
        assert result['devices'][0].location == "Core Data Center"
        
        # Search with no results
        result = await device_service.search_devices("nonexistent")
        assert len(result['devices']) == 0
    
    @pytest.mark.asyncio
    async def test_get_device_statistics(self, device_service, test_session):
        """Test device statistics generation"""
        # Create devices with different states and types
        devices = [
            Device(
                id=uuid4(),
                hostname=f"device-{i}",
                ip_address=f"192.168.1.{i+1}",
                device_type=DeviceType.ROUTER if i % 2 == 0 else DeviceType.SWITCH,
                current_state=DeviceState.ONLINE if i < 8 else DeviceState.OFFLINE,
                is_active=True,
                created_at=datetime.utcnow()
            )
            for i in range(10)
        ]
        
        for device in devices:
            test_session.add(device)
        
        await test_session.commit()
        
        # Get statistics
        stats = await device_service.get_device_statistics()
        
        # Verify statistics
        assert stats['total_devices'] == 10
        assert stats['online_devices'] == 8
        assert stats['offline_devices'] == 2
        assert stats['routers'] == 5
        assert stats['switches'] == 5
        assert stats['active_devices'] == 10
    
    @pytest.mark.asyncio
    async def test_bulk_device_operations(self, device_service, test_session):
        """Test bulk device operations"""
        # Create multiple devices
        devices_data = [
            {
                "hostname": f"bulk-device-{i:02d}",
                "ip_address": f"192.168.2.{i+1}",
                "device_type": DeviceType.SWITCH,
                "manufacturer": "HP",
                "model": "ProCurve 5406",
                "location": "Distribution Layer",
                "department": "Network Engineering",
                "discovery_protocol": "snmp",
                "device_group": DeviceGroup.PRODUCTION,
                "snmp_community": "bulk-community",
                "snmp_version": "2c"
            }
            for i in range(5)
        ]
        
        # Mock validation and encryption
        with patch.object(device_service, 'validator') as mock_validator:
            mock_validator.validate_device_data.side_effect = lambda x: x
            
            with patch('backend.services.device_service.credential_encryption') as mock_encryption:
                mock_encryption.encrypt_snmp_credential.return_value = "encrypted-bulk"
                
                # Bulk create devices
                created_devices = await device_service.bulk_create_devices(devices_data, "test-user")
                
                # Verify devices were created
                assert len(created_devices) == 5
                for device in created_devices:
                    assert device.is_active is True
                    assert device.created_at is not None
        
        # Test bulk update
        update_data = {"location": "Updated Distribution Layer"}
        updated_count = await device_service.bulk_update_devices(
            [str(device.id) for device in created_devices],
            update_data,
            "test-user"
        )
        assert updated_count == 5
        
        # Test bulk delete
        deleted_count = await device_service.bulk_delete_devices(
            [str(device.id) for device in created_devices],
            "test-user"
        )
        assert deleted_count == 5
    
    @pytest.mark.asyncio
    async def test_device_health_check(self, device_service, sample_device, test_session):
        """Test device health check functionality"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Mock health check
        with patch.object(device_service, '_perform_health_check') as mock_health_check:
            mock_health_check.return_value = {
                'status': 'healthy',
                'response_time': 50,
                'last_check': datetime.utcnow()
            }
            
            # Perform health check
            health_status = await device_service.check_device_health(str(sample_device.id))
            
            # Verify health check
            assert health_status['status'] == 'healthy'
            assert health_status['response_time'] == 50
            assert 'last_check' in health_status
    
    @pytest.mark.asyncio
    async def test_device_credential_rotation(self, device_service, sample_device, test_session):
        """Test device credential rotation"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Mock credential encryption
        with patch('backend.services.device_service.credential_encryption') as mock_encryption:
            mock_encryption.encrypt_snmp_credential.return_value = "new-encrypted-snmp"
            mock_encryption.encrypt_credential.return_value = "new-encrypted-ssh"
            
            # Rotate credentials
            new_credentials = {
                "snmp_community": "new-community",
                "snmp_version": "3",
                "ssh_password": "new-password"
            }
            
            updated_device = await device_service.rotate_credentials(
                str(sample_device.id),
                new_credentials,
                "test-user"
            )
            
            # Verify credentials were updated
            assert updated_device.snmp_community_encrypted == "new-encrypted-snmp"
            assert updated_device.ssh_password_encrypted == "new-encrypted-ssh"
    
    @pytest.mark.asyncio
    async def test_device_maintenance_mode(self, device_service, sample_device, test_session):
        """Test device maintenance mode functionality"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Enable maintenance mode
        await device_service.enable_maintenance_mode(str(sample_device.id), "test-user")
        
        # Verify maintenance mode is enabled
        device = await device_service.get_device_by_id(str(sample_device.id))
        assert device.current_state == DeviceState.MAINTENANCE
        
        # Disable maintenance mode
        await device_service.disable_maintenance_mode(str(sample_device.id), "test-user")
        
        # Verify maintenance mode is disabled
        device = await device_service.get_device_by_id(str(sample_device.id))
        assert device.current_state == DeviceState.ONLINE
    
    @pytest.mark.asyncio
    async def test_device_audit_logging(self, device_service, sample_device, test_session):
        """Test device audit logging"""
        # Add device to session
        test_session.add(sample_device)
        await test_session.commit()
        
        # Mock audit logger
        with patch('backend.services.device_service.logger') as mock_logger:
            # Perform an operation that should be logged
            await device_service.update_device(
                str(sample_device.id),
                {"hostname": "audited-device"},
                "audit-user"
            )
            
            # Verify logging occurred
            mock_logger.info.assert_called()
            log_call = mock_logger.info.call_args[0][0]
            assert "audit-user" in log_call
            assert "updated" in log_call
    
    @pytest.mark.asyncio
    async def test_device_validation_edge_cases(self, device_service, test_session):
        """Test device validation edge cases"""
        # Test invalid IP address
        invalid_data = {
            "hostname": "test-device",
            "ip_address": "invalid-ip",
            "device_type": DeviceType.ROUTER
        }
        
        with pytest.raises(InvalidIPAddressException):
            await device_service.create_device(invalid_data, "test-user")
        
        # Test empty hostname
        invalid_data = {
            "hostname": "",
            "ip_address": "192.168.1.1",
            "device_type": DeviceType.ROUTER
        }
        
        with pytest.raises(ValidationException):
            await device_service.create_device(invalid_data, "test-user")
        
        # Test invalid device type
        invalid_data = {
            "hostname": "test-device",
            "ip_address": "192.168.1.1",
            "device_type": "INVALID_TYPE"
        }
        
        with pytest.raises(ValidationException):
            await device_service.create_device(invalid_data, "test-user")
    
    @pytest.mark.asyncio
    async def test_device_service_error_handling(self, device_service, test_session):
        """Test device service error handling"""
        # Test database connection error
        with patch.object(test_session, 'commit') as mock_commit:
            mock_commit.side_effect = Exception("Database connection failed")
            
            with pytest.raises(Exception):
                await device_service.create_device({
                    "hostname": "test-device",
                    "ip_address": "192.168.1.1",
                    "device_type": DeviceType.ROUTER
                }, "test-user")
        
        # Test rollback on error
        with patch.object(test_session, 'rollback') as mock_rollback:
            with patch.object(test_session, 'commit') as mock_commit:
                mock_commit.side_effect = Exception("Commit failed")
                
                try:
                    await device_service.create_device({
                        "hostname": "test-device",
                        "ip_address": "192.168.1.1",
                        "device_type": DeviceType.ROUTER
                    }, "test-user")
                except Exception:
                    pass
                
                # Verify rollback was called
                mock_rollback.assert_called_once()


# Performance tests
class TestDeviceServicePerformance:
    """Performance tests for DeviceService"""
    
    @pytest.mark.asyncio
    async def test_bulk_operations_performance(self, device_service, test_session):
        """Test performance of bulk operations"""
        import time
        
        # Create large dataset
        devices_data = [
            {
                "hostname": f"perf-device-{i:04d}",
                "ip_address": f"192.168.3.{i+1}",
                "device_type": DeviceType.SWITCH,
                "manufacturer": "HP",
                "model": "ProCurve 5406",
                "location": "Performance Test",
                "department": "Testing",
                "discovery_protocol": "snmp",
                "device_group": DeviceGroup.TESTING,
                "snmp_community": "perf-community",
                "snmp_version": "2c"
            }
            for i in range(100)
        ]
        
        # Mock validation and encryption
        with patch.object(device_service, 'validator') as mock_validator:
            mock_validator.validate_device_data.side_effect = lambda x: x
            
            with patch('backend.services.device_service.credential_encryption') as mock_encryption:
                mock_encryption.encrypt_snmp_credential.return_value = "encrypted-perf"
                
                # Measure bulk create performance
                start_time = time.time()
                created_devices = await device_service.bulk_create_devices(devices_data, "perf-user")
                create_time = time.time() - start_time
                
                # Verify performance (should complete within reasonable time)
                assert create_time < 5.0  # 5 seconds for 100 devices
                assert len(created_devices) == 100
                
                # Measure bulk update performance
                start_time = time.time()
                updated_count = await device_service.bulk_update_devices(
                    [str(device.id) for device in created_devices],
                    {"location": "Updated Performance Test"},
                    "perf-user"
                )
                update_time = time.time() - start_time
                
                # Verify performance
                assert update_time < 3.0  # 3 seconds for 100 devices
                assert updated_count == 100
    
    @pytest.mark.asyncio
    async def test_search_performance(self, device_service, test_session):
        """Test search performance with large dataset"""
        import time
        
        # Create large dataset
        devices = []
        for i in range(1000):
            device = Device(
                id=uuid4(),
                hostname=f"search-device-{i:04d}",
                ip_address=f"192.168.4.{i+1}",
                device_type=DeviceType.SWITCH if i % 2 == 0 else DeviceType.ROUTER,
                manufacturer="HP" if i % 3 == 0 else "Cisco" if i % 3 == 1 else "Juniper",
                model=f"Model-{i % 10}",
                location=f"Location-{i % 5}",
                current_state=DeviceState.ONLINE,
                is_active=True,
                created_at=datetime.utcnow()
            )
            devices.append(device)
            test_session.add(device)
        
        await test_session.commit()
        
        # Measure search performance
        start_time = time.time()
        result = await device_service.search_devices("search-device")
        search_time = time.time() - start_time
        
        # Verify performance and results
        assert search_time < 1.0  # 1 second for 1000 devices
        assert len(result['devices']) == 1000
        
        # Measure filtered search performance
        start_time = time.time()
        result = await device_service.search_devices("Cisco")
        filtered_search_time = time.time() - start_time
        
        # Verify performance
        assert filtered_search_time < 0.5  # 0.5 seconds for filtered search
        assert len(result['devices']) > 0
