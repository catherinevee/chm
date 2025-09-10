"""
Integration tests for Device Service
"""

import pytest
import asyncio
from uuid import uuid4
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.device_service import DeviceService
from backend.database.models import Device, DeviceMetric, Alert
from backend.common.exceptions import (
    DeviceNotFoundException,
    DeviceAlreadyExistsException,
    ValidationException
)


@pytest.mark.asyncio
class TestDeviceServiceIntegration:
    """Integration tests for device service"""
    
    async def test_create_device_success(self, test_session):
        """Test successful device creation"""
        service = DeviceService(test_session)
        
        device_data = {
            'hostname': 'test-router-01',
            'ip_address': '192.168.1.1',
            'device_type': 'router',
            'manufacturer': 'Cisco',
            'model': 'ISR4451',
            'location': 'Data Center 1',
            'snmp_community': 'public',
            'snmp_version': '2c'
        }
        
        device = await service.create_device(device_data)
        
        assert device is not None
        assert device.hostname == 'test-router-01'
        assert device.ip_address == '192.168.1.1'
        assert device.device_type == 'router'
        assert device.snmp_community_encrypted is not None
        assert device.is_active is True
        assert device.current_state == 'unknown'
    
    async def test_create_duplicate_device_fails(self, test_session):
        """Test that creating duplicate device fails"""
        service = DeviceService(test_session)
        
        device_data = {
            'hostname': 'test-switch-01',
            'ip_address': '192.168.1.2',
            'device_type': 'switch'
        }
        
        # Create first device
        await service.create_device(device_data)
        
        # Try to create duplicate
        with pytest.raises(DeviceAlreadyExistsException):
            await service.create_device(device_data)
    
    async def test_get_device_by_id(self, test_session):
        """Test getting device by ID"""
        service = DeviceService(test_session)
        
        # Create device
        device_data = {
            'hostname': 'test-firewall-01',
            'ip_address': '192.168.1.3',
            'device_type': 'firewall'
        }
        created_device = await service.create_device(device_data)
        
        # Get device by ID
        retrieved_device = await service.get_device(str(created_device.id))
        
        assert retrieved_device is not None
        assert retrieved_device.id == created_device.id
        assert retrieved_device.hostname == 'test-firewall-01'
    
    async def test_get_nonexistent_device_fails(self, test_session):
        """Test that getting non-existent device fails"""
        service = DeviceService(test_session)
        
        fake_id = str(uuid4())
        
        with pytest.raises(DeviceNotFoundException):
            await service.get_device(fake_id)
    
    async def test_list_devices_with_filters(self, test_session):
        """Test listing devices with filters"""
        service = DeviceService(test_session)
        
        # Create multiple devices
        devices_data = [
            {'hostname': 'router-01', 'ip_address': '10.0.0.1', 'device_type': 'router'},
            {'hostname': 'router-02', 'ip_address': '10.0.0.2', 'device_type': 'router'},
            {'hostname': 'switch-01', 'ip_address': '10.0.0.3', 'device_type': 'switch'},
            {'hostname': 'firewall-01', 'ip_address': '10.0.0.4', 'device_type': 'firewall'}
        ]
        
        for data in devices_data:
            await service.create_device(data)
        
        # List all devices
        all_devices, total = await service.list_devices()
        assert total >= 4
        
        # Filter by device type
        routers, router_count = await service.list_devices(
            filters={'device_type': 'router'}
        )
        assert router_count >= 2
        assert all(d.device_type == 'router' for d in routers)
        
        # Search by hostname
        search_results, search_count = await service.list_devices(
            filters={'search': 'switch'}
        )
        assert search_count >= 1
        assert any('switch' in d.hostname.lower() for d in search_results)
    
    async def test_update_device(self, test_session):
        """Test updating device information"""
        service = DeviceService(test_session)
        
        # Create device
        device_data = {
            'hostname': 'test-device',
            'ip_address': '192.168.10.1',
            'device_type': 'router'
        }
        device = await service.create_device(device_data)
        
        # Update device
        update_data = {
            'location': 'New Location',
            'department': 'IT',
            'is_active': False
        }
        
        updated_device = await service.update_device(
            str(device.id),
            update_data
        )
        
        assert updated_device.location == 'New Location'
        assert updated_device.department == 'IT'
        assert updated_device.is_active is False
        assert updated_device.updated_at > device.created_at
    
    async def test_delete_device_cascade(self, test_session):
        """Test deleting device with cascade"""
        service = DeviceService(test_session)
        
        # Create device
        device_data = {
            'hostname': 'delete-test',
            'ip_address': '192.168.20.1',
            'device_type': 'switch'
        }
        device = await service.create_device(device_data)
        device_id = str(device.id)
        
        # Add some metrics
        metric = DeviceMetric(
            device_id=device.id,
            metric_type='cpu_usage',
            value=45.5,
            unit='percent',
            timestamp=datetime.utcnow()
        )
        test_session.add(metric)
        await test_session.commit()
        
        # Delete device
        result = await service.delete_device(device_id, cascade=True)
        assert result is True
        
        # Verify device is deleted
        with pytest.raises(DeviceNotFoundException):
            await service.get_device(device_id)
        
        # Verify metrics are deleted
        metrics = await test_session.execute(
            f"SELECT * FROM device_metrics WHERE device_id = '{device_id}'"
        )
        assert len(metrics.fetchall()) == 0
    
    async def test_get_device_metrics(self, test_session):
        """Test getting device metrics"""
        service = DeviceService(test_session)
        
        # Create device
        device_data = {
            'hostname': 'metric-test',
            'ip_address': '192.168.30.1',
            'device_type': 'router'
        }
        device = await service.create_device(device_data)
        
        # Add metrics
        metrics_data = [
            {'metric_type': 'cpu_usage', 'value': 30.5, 'unit': 'percent'},
            {'metric_type': 'cpu_usage', 'value': 35.2, 'unit': 'percent'},
            {'metric_type': 'memory_usage', 'value': 65.8, 'unit': 'percent'}
        ]
        
        for data in metrics_data:
            metric = DeviceMetric(
                device_id=device.id,
                timestamp=datetime.utcnow(),
                **data
            )
            test_session.add(metric)
        
        await test_session.commit()
        
        # Get all metrics
        all_metrics = await service.get_device_metrics(str(device.id))
        assert len(all_metrics) == 3
        
        # Get CPU metrics only
        cpu_metrics = await service.get_device_metrics(
            str(device.id),
            metric_type='cpu_usage'
        )
        assert len(cpu_metrics) == 2
        assert all(m.metric_type == 'cpu_usage' for m in cpu_metrics)
    
    async def test_get_device_status(self, test_session):
        """Test getting comprehensive device status"""
        service = DeviceService(test_session)
        
        # Create device
        device_data = {
            'hostname': 'status-test',
            'ip_address': '192.168.40.1',
            'device_type': 'switch'
        }
        device = await service.create_device(device_data)
        
        # Get status
        status = await service.get_device_status(str(device.id))
        
        assert status is not None
        assert status['device_id'] == str(device.id)
        assert status['hostname'] == 'status-test'
        assert status['current_state'] == 'unknown'
        assert status['is_active'] is True
        assert 'health_score' in status
        assert status['health_score'] >= 0
        assert status['health_score'] <= 100
    
    async def test_credential_encryption(self, test_session):
        """Test that credentials are properly encrypted"""
        service = DeviceService(test_session)
        
        device_data = {
            'hostname': 'crypto-test',
            'ip_address': '192.168.50.1',
            'device_type': 'router',
            'snmp_community': 'secret_community',
            'ssh_password': 'secret_password',
            'api_key': 'secret_api_key'
        }
        
        device = await service.create_device(device_data)
        
        # Verify credentials are encrypted
        assert device.snmp_community_encrypted is not None
        assert device.snmp_community_encrypted != 'secret_community'
        assert device.ssh_password_encrypted is not None
        assert device.ssh_password_encrypted != 'secret_password'
        assert device.api_key_encrypted is not None
        assert device.api_key_encrypted != 'secret_api_key'
        
        # Original values should not be stored
        assert not hasattr(device, 'snmp_community')
        assert not hasattr(device, 'ssh_password')
        assert not hasattr(device, 'api_key')
    
    async def test_invalid_ip_address_validation(self, test_session):
        """Test that invalid IP addresses are rejected"""
        service = DeviceService(test_session)
        
        device_data = {
            'hostname': 'invalid-ip-test',
            'ip_address': '999.999.999.999',  # Invalid IP
            'device_type': 'router'
        }
        
        with pytest.raises(ValidationException):
            await service.create_device(device_data)
    
    async def test_device_state_transitions(self, test_session):
        """Test device state transitions"""
        service = DeviceService(test_session)
        
        # Create device
        device_data = {
            'hostname': 'state-test',
            'ip_address': '192.168.60.1',
            'device_type': 'switch'
        }
        device = await service.create_device(device_data)
        
        # Initial state should be unknown
        assert device.current_state == 'unknown'
        
        # Update to up state
        device.current_state = 'up'
        device.consecutive_failures = 0
        await test_session.commit()
        
        # Update to down state
        device.current_state = 'down'
        device.consecutive_failures = 1
        await test_session.commit()
        
        # Verify circuit breaker
        device.consecutive_failures = 5
        device.circuit_breaker_trips = 1
        await test_session.commit()
        
        status = await service.get_device_status(str(device.id))
        assert status['health_score'] < 100  # Health should be degraded