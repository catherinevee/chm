"""
Comprehensive tests for Device Service
Testing device management, monitoring, SNMP/SSH integration, and network operations
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, Mock, call
import uuid
import json
from typing import List, Dict, Any

# Test infrastructure imports
from tests.test_infrastructure.test_fixtures_comprehensive import (
    TestInfrastructureManager,
    TestDataFactory
)

# Service and model imports
from backend.services.device_service import DeviceService
from backend.database.models import Device, NetworkInterface, DeviceMetric, DeviceConfiguration
from backend.services.snmp_service import SNMPService
from backend.services.ssh_service import SSHService


class TestDeviceServiceCore:
    """Core device service functionality tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance with mocked dependencies"""
        service = DeviceService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        service.snmp_service = AsyncMock(spec=SNMPService)
        service.ssh_service = AsyncMock(spec=SSHService)
        service.notification_service = AsyncMock()
        return service
    
    @pytest.fixture
    def sample_device_data(self):
        """Sample device data for testing"""
        return {
            "name": "test-router-01",
            "ip_address": "192.168.1.1",
            "device_type": "router",
            "vendor": "cisco",
            "model": "ISR4321",
            "os_version": "IOS XE 17.3.1",
            "serial_number": "FCZ1234567",
            "location": "Data Center 1",
            "snmp_community": "public",
            "snmp_version": "2c",
            "ssh_username": "admin",
            "ssh_password": "encrypted_password",
            "status": "active"
        }
    
    @pytest.mark.asyncio
    async def test_create_device(self, device_service, sample_device_data):
        """Test device creation"""
        # Mock device creation
        device_service.db.add = AsyncMock()
        device_service.db.commit = AsyncMock()
        device_service.db.refresh = AsyncMock()
        
        # Create device
        device = await device_service.create_device(sample_device_data)
        
        # Verify device created
        device_service.db.add.assert_called_once()
        device_service.db.commit.assert_called_once()
        assert device is not None
    
    @pytest.mark.asyncio
    async def test_get_device_by_id(self, device_service):
        """Test getting device by ID"""
        device_id = uuid.uuid4()
        
        mock_device = MagicMock(spec=Device)
        mock_device.id = device_id
        mock_device.name = "test-device"
        
        device_service.db.query.return_value.filter.return_value.first.return_value = mock_device
        
        # Get device
        device = await device_service.get_device(device_id)
        
        assert device == mock_device
        device_service.db.query.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_device_by_ip(self, device_service):
        """Test getting device by IP address"""
        ip_address = "192.168.1.100"
        
        mock_device = MagicMock(spec=Device)
        mock_device.ip_address = ip_address
        
        device_service.db.query.return_value.filter.return_value.first.return_value = mock_device
        
        # Get device by IP
        device = await device_service.get_device_by_ip(ip_address)
        
        assert device == mock_device
        assert device.ip_address == ip_address
    
    @pytest.mark.asyncio
    async def test_update_device(self, device_service):
        """Test device update"""
        device_id = uuid.uuid4()
        update_data = {
            "name": "updated-device",
            "location": "New Location",
            "status": "maintenance"
        }
        
        mock_device = MagicMock(spec=Device)
        mock_device.id = device_id
        
        device_service.db.query.return_value.filter.return_value.first.return_value = mock_device
        
        # Update device
        updated = await device_service.update_device(device_id, update_data)
        
        assert updated is True
        assert mock_device.name == "updated-device"
        assert mock_device.location == "New Location"
        assert mock_device.status == "maintenance"
        device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_delete_device(self, device_service):
        """Test device deletion"""
        device_id = uuid.uuid4()
        
        mock_device = MagicMock(spec=Device)
        mock_device.id = device_id
        mock_device.deleted_at = None
        
        device_service.db.query.return_value.filter.return_value.first.return_value = mock_device
        
        # Delete device (soft delete)
        result = await device_service.delete_device(device_id)
        
        assert result is True
        assert mock_device.deleted_at is not None
        device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_list_devices_with_filters(self, device_service):
        """Test listing devices with filters"""
        filters = {
            "device_type": "router",
            "vendor": "cisco",
            "status": "active"
        }
        
        mock_devices = [
            MagicMock(spec=Device, name="router1"),
            MagicMock(spec=Device, name="router2")
        ]
        
        query_mock = MagicMock()
        query_mock.filter.return_value = query_mock
        query_mock.offset.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.all.return_value = mock_devices
        
        device_service.db.query.return_value = query_mock
        
        # List devices
        devices = await device_service.list_devices(filters=filters, offset=0, limit=10)
        
        assert len(devices) == 2
        assert query_mock.filter.called


class TestDeviceMonitoring:
    """Device monitoring and health check tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.db = AsyncMock()
        service.snmp_service = AsyncMock(spec=SNMPService)
        service.ssh_service = AsyncMock(spec=SSHService)
        service.alert_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_check_device_connectivity_success(self, device_service):
        """Test successful device connectivity check"""
        device = MagicMock(spec=Device)
        device.ip_address = "192.168.1.1"
        
        with patch('backend.services.device_service.ping') as mock_ping:
            mock_ping.return_value = True
            
            # Check connectivity
            result = await device_service.check_device_connectivity(device)
            
            assert result is True
            mock_ping.assert_called_once_with(device.ip_address)
    
    @pytest.mark.asyncio
    async def test_check_device_connectivity_failure(self, device_service):
        """Test failed device connectivity check"""
        device = MagicMock(spec=Device)
        device.ip_address = "192.168.1.1"
        device.name = "test-device"
        
        with patch('backend.services.device_service.ping') as mock_ping:
            mock_ping.return_value = False
            
            # Check connectivity
            result = await device_service.check_device_connectivity(device)
            
            assert result is False
            
            # Verify alert created
            device_service.alert_service.create_alert.assert_called_once()
            alert_call = device_service.alert_service.create_alert.call_args[0][0]
            assert alert_call["device_id"] == device.id
            assert alert_call["alert_type"] == "connectivity"
    
    @pytest.mark.asyncio
    async def test_monitor_device_health(self, device_service):
        """Test device health monitoring"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        device.ip_address = "192.168.1.1"
        device.snmp_community = "public"
        
        # Mock SNMP responses
        snmp_data = {
            "cpu_usage": 45.5,
            "memory_usage": 62.3,
            "uptime": 1234567,
            "interface_count": 4,
            "temperature": 35.2
        }
        device_service.snmp_service.get_device_health.return_value = snmp_data
        
        # Monitor health
        health_data = await device_service.monitor_device_health(device)
        
        assert health_data == snmp_data
        device_service.snmp_service.get_device_health.assert_called_once_with(device)
        
        # Verify metrics stored
        device_service.db.add.assert_called()
    
    @pytest.mark.asyncio
    async def test_collect_device_metrics(self, device_service):
        """Test device metrics collection"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        
        # Mock SNMP metrics
        metrics = {
            "interfaces": [
                {"name": "GigabitEthernet0/0", "in_octets": 1000000, "out_octets": 500000},
                {"name": "GigabitEthernet0/1", "in_octets": 2000000, "out_octets": 1500000}
            ],
            "cpu_usage": 35.0,
            "memory_free": 1024000,
            "memory_used": 512000
        }
        device_service.snmp_service.collect_metrics.return_value = metrics
        
        # Collect metrics
        collected = await device_service.collect_device_metrics(device)
        
        assert collected == metrics
        
        # Verify metrics stored in database
        assert device_service.db.add.call_count > 0
    
    @pytest.mark.asyncio
    async def test_monitor_device_interfaces(self, device_service):
        """Test device interface monitoring"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        
        # Mock interface data
        interfaces = [
            {
                "index": 1,
                "name": "GigabitEthernet0/0",
                "status": "up",
                "speed": 1000000000,
                "mtu": 1500,
                "mac_address": "00:1A:2B:3C:4D:5E"
            },
            {
                "index": 2,
                "name": "GigabitEthernet0/1",
                "status": "down",
                "speed": 1000000000,
                "mtu": 1500,
                "mac_address": "00:1A:2B:3C:4D:5F"
            }
        ]
        device_service.snmp_service.get_interfaces.return_value = interfaces
        
        # Monitor interfaces
        result = await device_service.monitor_interfaces(device)
        
        assert len(result) == 2
        device_service.snmp_service.get_interfaces.assert_called_once_with(device)
        
        # Verify interface status alerts
        down_interfaces = [i for i in interfaces if i["status"] == "down"]
        if down_interfaces:
            device_service.alert_service.create_alert.assert_called()


class TestDeviceConfiguration:
    """Device configuration management tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.db = AsyncMock()
        service.ssh_service = AsyncMock(spec=SSHService)
        return service
    
    @pytest.mark.asyncio
    async def test_backup_device_configuration(self, device_service):
        """Test device configuration backup"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        device.ip_address = "192.168.1.1"
        device.ssh_username = "admin"
        
        # Mock SSH configuration retrieval
        config_text = """
        hostname test-router
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
        !
        router ospf 1
         network 192.168.1.0 0.0.0.255 area 0
        """
        device_service.ssh_service.get_configuration.return_value = config_text
        
        # Backup configuration
        backup = await device_service.backup_configuration(device)
        
        assert backup is not None
        device_service.ssh_service.get_configuration.assert_called_once_with(device)
        
        # Verify backup stored
        device_service.db.add.assert_called_once()
        config_backup = device_service.db.add.call_args[0][0]
        assert config_backup.device_id == device.id
        assert config_backup.configuration == config_text
    
    @pytest.mark.asyncio
    async def test_restore_device_configuration(self, device_service):
        """Test device configuration restoration"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        backup_id = uuid.uuid4()
        
        # Mock configuration backup
        mock_backup = MagicMock(spec=DeviceConfiguration)
        mock_backup.configuration = "backup config text"
        
        device_service.db.query.return_value.filter.return_value.first.return_value = mock_backup
        device_service.ssh_service.apply_configuration.return_value = True
        
        # Restore configuration
        result = await device_service.restore_configuration(device, backup_id)
        
        assert result is True
        device_service.ssh_service.apply_configuration.assert_called_once_with(
            device, mock_backup.configuration
        )
    
    @pytest.mark.asyncio
    async def test_compare_configurations(self, device_service):
        """Test configuration comparison"""
        device = MagicMock(spec=Device)
        
        config1 = """
        hostname router1
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
        """
        
        config2 = """
        hostname router1
        interface GigabitEthernet0/0
         ip address 192.168.1.2 255.255.255.0
        """
        
        # Compare configurations
        diff = await device_service.compare_configurations(config1, config2)
        
        assert diff is not None
        assert "192.168.1.1" in diff
        assert "192.168.1.2" in diff
    
    @pytest.mark.asyncio
    async def test_validate_configuration(self, device_service):
        """Test configuration validation"""
        device = MagicMock(spec=Device)
        device.vendor = "cisco"
        
        valid_config = """
        hostname test-router
        interface GigabitEthernet0/0
         ip address 192.168.1.1 255.255.255.0
        !
        """
        
        invalid_config = """
        hostname test-router
        interface InvalidInterface
         ip address 999.999.999.999 255.255.255.0
        """
        
        # Validate configurations
        assert await device_service.validate_configuration(device, valid_config) is True
        assert await device_service.validate_configuration(device, invalid_config) is False


class TestSNMPIntegration:
    """SNMP integration tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.snmp_service = AsyncMock(spec=SNMPService)
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_snmp_discovery(self, device_service):
        """Test SNMP device discovery"""
        network = "192.168.1.0/24"
        community = "public"
        
        # Mock discovered devices
        discovered = [
            {"ip": "192.168.1.1", "sysName": "router1", "sysDescr": "Cisco IOS"},
            {"ip": "192.168.1.2", "sysName": "switch1", "sysDescr": "Cisco Catalyst"}
        ]
        device_service.snmp_service.discover_devices.return_value = discovered
        
        # Run discovery
        devices = await device_service.discover_devices_snmp(network, community)
        
        assert len(devices) == 2
        device_service.snmp_service.discover_devices.assert_called_once_with(network, community)
    
    @pytest.mark.asyncio
    async def test_snmp_trap_handling(self, device_service):
        """Test SNMP trap handling"""
        trap_data = {
            "source": "192.168.1.1",
            "oid": "1.3.6.1.6.3.1.1.5.3",  # Link down trap
            "value": "GigabitEthernet0/0",
            "timestamp": datetime.utcnow()
        }
        
        # Handle trap
        await device_service.handle_snmp_trap(trap_data)
        
        # Verify alert created
        device_service.db.add.assert_called()
    
    @pytest.mark.asyncio
    async def test_snmp_bulk_walk(self, device_service):
        """Test SNMP bulk walk operation"""
        device = MagicMock(spec=Device)
        device.snmp_community = "public"
        device.snmp_version = "2c"
        
        oid = "1.3.6.1.2.1.2.2"  # Interface table OID
        
        # Mock walk results
        walk_results = [
            ("1.3.6.1.2.1.2.2.1.1.1", 1),
            ("1.3.6.1.2.1.2.2.1.1.2", 2),
            ("1.3.6.1.2.1.2.2.1.2.1", "GigabitEthernet0/0"),
            ("1.3.6.1.2.1.2.2.1.2.2", "GigabitEthernet0/1")
        ]
        device_service.snmp_service.bulk_walk.return_value = walk_results
        
        # Perform bulk walk
        results = await device_service.snmp_bulk_walk(device, oid)
        
        assert len(results) == 4
        device_service.snmp_service.bulk_walk.assert_called_once()


class TestSSHIntegration:
    """SSH integration tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.ssh_service = AsyncMock(spec=SSHService)
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_execute_ssh_command(self, device_service):
        """Test SSH command execution"""
        device = MagicMock(spec=Device)
        device.ip_address = "192.168.1.1"
        device.ssh_username = "admin"
        
        command = "show version"
        output = "Cisco IOS XE Software, Version 17.3.1"
        
        device_service.ssh_service.execute_command.return_value = output
        
        # Execute command
        result = await device_service.execute_command(device, command)
        
        assert result == output
        device_service.ssh_service.execute_command.assert_called_once_with(device, command)
    
    @pytest.mark.asyncio
    async def test_execute_ssh_commands_batch(self, device_service):
        """Test batch SSH command execution"""
        device = MagicMock(spec=Device)
        
        commands = [
            "show version",
            "show interfaces brief",
            "show ip route"
        ]
        
        outputs = [
            "Version output",
            "Interface output",
            "Route output"
        ]
        
        device_service.ssh_service.execute_commands.return_value = outputs
        
        # Execute batch commands
        results = await device_service.execute_commands_batch(device, commands)
        
        assert len(results) == 3
        assert results == outputs
    
    @pytest.mark.asyncio
    async def test_ssh_file_transfer(self, device_service):
        """Test SSH file transfer"""
        device = MagicMock(spec=Device)
        
        local_file = "/tmp/config.txt"
        remote_file = "flash:/config.txt"
        
        device_service.ssh_service.transfer_file.return_value = True
        
        # Transfer file
        result = await device_service.transfer_file(device, local_file, remote_file)
        
        assert result is True
        device_service.ssh_service.transfer_file.assert_called_once_with(
            device, local_file, remote_file
        )


class TestDevicePolling:
    """Device polling and scheduling tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        service.scheduler = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_schedule_device_polling(self, device_service):
        """Test device polling scheduling"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        device.polling_interval = 300  # 5 minutes
        
        # Schedule polling
        job_id = await device_service.schedule_polling(device)
        
        assert job_id is not None
        device_service.scheduler.add_job.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_poll_device(self, device_service):
        """Test single device polling"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        device.status = "active"
        
        # Mock polling operations
        device_service.check_device_connectivity = AsyncMock(return_value=True)
        device_service.collect_device_metrics = AsyncMock(return_value={"cpu": 30})
        device_service.monitor_interfaces = AsyncMock(return_value=[])
        
        # Poll device
        result = await device_service.poll_device(device)
        
        assert result["connectivity"] is True
        assert result["metrics"]["cpu"] == 30
        device_service.check_device_connectivity.assert_called_once()
        device_service.collect_device_metrics.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_bulk_device_polling(self, device_service):
        """Test bulk device polling"""
        devices = [
            MagicMock(spec=Device, id=uuid.uuid4(), status="active"),
            MagicMock(spec=Device, id=uuid.uuid4(), status="active"),
            MagicMock(spec=Device, id=uuid.uuid4(), status="maintenance")
        ]
        
        device_service.db.query.return_value.filter.return_value.all.return_value = devices
        device_service.poll_device = AsyncMock(return_value={"status": "ok"})
        
        # Bulk poll
        results = await device_service.bulk_poll_devices()
        
        # Only active devices should be polled
        assert device_service.poll_device.call_count == 2
    
    @pytest.mark.asyncio
    async def test_polling_with_rate_limiting(self, device_service):
        """Test polling with rate limiting"""
        devices = [MagicMock(spec=Device) for _ in range(10)]
        
        device_service.db.query.return_value.filter.return_value.all.return_value = devices
        device_service.poll_device = AsyncMock()
        
        # Set rate limit
        device_service.polling_rate_limit = 5  # 5 devices per batch
        
        # Poll with rate limiting
        await device_service.bulk_poll_devices_with_rate_limit()
        
        # Verify rate limiting applied
        assert device_service.poll_device.call_count == 10


class TestDeviceGroups:
    """Device grouping and organization tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_create_device_group(self, device_service):
        """Test device group creation"""
        group_data = {
            "name": "Core Routers",
            "description": "Core network routers",
            "tags": ["critical", "core"]
        }
        
        # Create group
        group = await device_service.create_device_group(group_data)
        
        assert group is not None
        device_service.db.add.assert_called_once()
        device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_add_device_to_group(self, device_service):
        """Test adding device to group"""
        device_id = uuid.uuid4()
        group_id = uuid.uuid4()
        
        mock_device = MagicMock(spec=Device)
        mock_group = MagicMock()
        mock_group.devices = []
        
        device_service.db.query.return_value.filter.return_value.first.side_effect = [
            mock_device, mock_group
        ]
        
        # Add device to group
        result = await device_service.add_device_to_group(device_id, group_id)
        
        assert result is True
        assert mock_device in mock_group.devices
        device_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_devices_by_group(self, device_service):
        """Test getting devices by group"""
        group_id = uuid.uuid4()
        
        mock_devices = [
            MagicMock(spec=Device, name="device1"),
            MagicMock(spec=Device, name="device2")
        ]
        
        mock_group = MagicMock()
        mock_group.devices = mock_devices
        
        device_service.db.query.return_value.filter.return_value.first.return_value = mock_group
        
        # Get devices by group
        devices = await device_service.get_devices_by_group(group_id)
        
        assert len(devices) == 2
        assert devices == mock_devices


class TestDeviceAlerts:
    """Device alert integration tests"""
    
    @pytest.fixture
    def device_service(self):
        """Create device service instance"""
        service = DeviceService()
        service.db = AsyncMock()
        service.alert_service = AsyncMock()
        service.notification_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_create_device_alert(self, device_service):
        """Test device alert creation"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        device.name = "test-device"
        
        alert_data = {
            "alert_type": "cpu_high",
            "severity": "warning",
            "message": "CPU usage above 80%",
            "details": {"cpu_usage": 85}
        }
        
        # Create alert
        alert = await device_service.create_device_alert(device, alert_data)
        
        device_service.alert_service.create_alert.assert_called_once()
        call_args = device_service.alert_service.create_alert.call_args[0][0]
        assert call_args["device_id"] == device.id
    
    @pytest.mark.asyncio
    async def test_auto_resolve_alerts(self, device_service):
        """Test automatic alert resolution"""
        device = MagicMock(spec=Device)
        device.id = uuid.uuid4()
        
        # Mock open alerts
        open_alerts = [
            MagicMock(id=uuid.uuid4(), alert_type="connectivity"),
            MagicMock(id=uuid.uuid4(), alert_type="interface_down")
        ]
        
        device_service.alert_service.get_open_alerts.return_value = open_alerts
        device_service.alert_service.resolve_alert = AsyncMock()
        
        # Auto resolve connectivity alerts (device is now reachable)
        await device_service.auto_resolve_alerts(device, ["connectivity"])
        
        # Verify only connectivity alert resolved
        assert device_service.alert_service.resolve_alert.call_count == 1
        resolved_alert_id = device_service.alert_service.resolve_alert.call_args[0][0]
        assert resolved_alert_id == open_alerts[0].id