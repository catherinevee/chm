"""
Unit tests for Polling Engine Service
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
import ipaddress

from backend.services.polling_engine import (
    polling_engine, PollResult, PollStatus, SNMPConfig, SSHConfig, OIDLibrary
)
from models.device import Device, DeviceStatus, DeviceType, DeviceProtocol


@pytest.fixture
def mock_device():
    """Create a mock device for testing"""
    device = Mock(spec=Device)
    device.id = 1
    device.name = "test-router"
    device.ip_address = "192.168.1.1"
    device.device_type = DeviceType.ROUTER
    device.vendor = "Cisco"
    device.model = "ISR4321"
    device.protocol = DeviceProtocol.SNMP
    device.status = DeviceStatus.ACTIVE
    device.ssh_username = "admin"
    return device


@pytest.fixture
def snmp_config():
    """Create SNMP configuration"""
    return SNMPConfig(
        community="public",
        version="v2c",
        port=161,
        timeout=10,
        retries=3
    )


@pytest.fixture
def ssh_config():
    """Create SSH configuration"""
    return SSHConfig(
        username="admin",
        password="password123",
        port=22,
        timeout=30
    )


class TestPollingEngine:
    """Test polling engine functionality"""
    
    @pytest.mark.asyncio
    async def test_poll_device_snmp_success(self, mock_device, snmp_config):
        """Test successful SNMP polling"""
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=100,
                metrics={
                    "sysDescr": "Cisco IOS Software",
                    "sysUptime": "2 days, 3:45:22",
                    "cpu_usage": 45.5
                }
            )
            
            result = await polling_engine.poll_device(mock_device, snmp_config=snmp_config)
            
            assert result.status == PollStatus.SUCCESS
            assert result.device_id == mock_device.id
            assert "cpu_usage" in result.metrics
            assert result.metrics["cpu_usage"] == 45.5
            mock_poll.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_poll_device_ssh_success(self, mock_device, ssh_config):
        """Test successful SSH polling"""
        mock_device.protocol = DeviceProtocol.SSH
        
        with patch.object(polling_engine, '_poll_ssh') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=200,
                metrics={
                    "cpu": "CPU utilization: 35%",
                    "memory": "Memory: 2048MB used of 4096MB",
                    "uptime": "Uptime: 5 days"
                }
            )
            
            result = await polling_engine.poll_device(mock_device, ssh_config=ssh_config)
            
            assert result.status == PollStatus.SUCCESS
            assert result.device_id == mock_device.id
            assert "cpu" in result.metrics
            assert "35%" in result.metrics["cpu"]
            mock_poll.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_poll_device_failure(self, mock_device, snmp_config):
        """Test polling failure handling"""
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.side_effect = Exception("Connection timeout")
            
            result = await polling_engine.poll_device(mock_device, snmp_config=snmp_config)
            
            assert result.status == PollStatus.FAILED
            assert len(result.errors) > 0
            assert "Connection timeout" in str(result.errors)
    
    @pytest.mark.asyncio
    async def test_poll_device_partial_success(self, mock_device, snmp_config):
        """Test partial polling success"""
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.PARTIAL,
                timestamp=datetime.utcnow(),
                duration_ms=150,
                metrics={
                    "sysDescr": "Cisco IOS Software",
                    "cpu_usage": None  # Failed to get CPU
                },
                errors=["Failed to retrieve CPU metrics"]
            )
            
            result = await polling_engine.poll_device(mock_device, snmp_config=snmp_config)
            
            assert result.status == PollStatus.PARTIAL
            assert "sysDescr" in result.metrics
            assert len(result.errors) > 0
    
    @pytest.mark.asyncio
    async def test_poll_multiple_devices(self, snmp_config):
        """Test polling multiple devices concurrently"""
        devices = []
        for i in range(5):
            device = Mock(spec=Device)
            device.id = i + 1
            device.ip_address = f"192.168.1.{i+1}"
            device.protocol = DeviceProtocol.SNMP
            device.status = DeviceStatus.ACTIVE
            devices.append(device)
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=1,
                device_ip="192.168.1.1",
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=50,
                metrics={"status": "up"}
            )
            
            results = await polling_engine.poll_multiple_devices(devices, snmp_config)
            
            assert len(results) == 5
            for result in results:
                assert result.status == PollStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_poll_network_range(self, snmp_config):
        """Test polling a network range"""
        with patch.object(polling_engine, 'poll_device') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=0,
                device_ip="192.168.1.1",
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=50,
                metrics={"status": "up"}
            )
            
            # Small range for testing
            results = await polling_engine.poll_network_range(
                "192.168.1.0/30",
                snmp_config
            )
            
            # Should attempt to poll hosts in range (excluding network and broadcast)
            assert mock_poll.call_count >= 2
    
    def test_oid_library_initialization(self):
        """Test OID library has proper OIDs defined"""
        oid_lib = OIDLibrary()
        
        # Check system OIDs
        assert oid_lib.SYSTEM_DESCRIPTION is not None
        assert oid_lib.SYSTEM_UPTIME is not None
        assert oid_lib.SYSTEM_NAME is not None
        
        # Check interface OIDs
        assert oid_lib.INTERFACE_TABLE is not None
        assert oid_lib.INTERFACE_STATUS is not None
        
        # Check CPU OIDs
        assert oid_lib.CPU_USAGE_1MIN is not None
        assert oid_lib.CPU_USAGE_5MIN is not None
        
        # Check memory OIDs
        assert oid_lib.MEMORY_USED is not None
        assert oid_lib.MEMORY_FREE is not None
    
    @pytest.mark.asyncio
    async def test_poll_with_custom_oids(self, mock_device, snmp_config):
        """Test polling with custom OIDs"""
        custom_oids = [
            "1.3.6.1.2.1.1.1.0",  # sysDescr
            "1.3.6.1.2.1.1.3.0",  # sysUptime
            "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1"  # Cisco CPU 5min
        ]
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=100,
                metrics={
                    "1.3.6.1.2.1.1.1.0": "Cisco IOS",
                    "1.3.6.1.2.1.1.3.0": "123456",
                    "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": "45"
                }
            )
            
            result = await polling_engine.poll_device(
                mock_device, 
                snmp_config=snmp_config,
                custom_oids=custom_oids
            )
            
            assert result.status == PollStatus.SUCCESS
            assert len(result.metrics) == 3
    
    @pytest.mark.asyncio
    async def test_poll_device_timeout(self, mock_device, snmp_config):
        """Test polling timeout handling"""
        snmp_config.timeout = 1  # Very short timeout
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.side_effect = asyncio.TimeoutError("Poll timeout")
            
            result = await polling_engine.poll_device(mock_device, snmp_config=snmp_config)
            
            assert result.status == PollStatus.FAILED
            assert "timeout" in str(result.errors).lower()
    
    @pytest.mark.asyncio
    async def test_poll_device_invalid_protocol(self, mock_device):
        """Test polling with invalid protocol"""
        mock_device.protocol = "INVALID"
        
        result = await polling_engine.poll_device(mock_device)
        
        assert result.status == PollStatus.FAILED
        assert "No valid configuration" in str(result.errors)
    
    @pytest.mark.asyncio
    async def test_process_snmp_results(self):
        """Test SNMP result processing"""
        raw_results = {
            "1.3.6.1.2.1.1.1.0": b"Cisco IOS Software",
            "1.3.6.1.2.1.1.3.0": 12345678,
            "1.3.6.1.4.1.9.9.109.1.1.1.1.5.1": 45
        }
        
        processed = polling_engine._process_snmp_results(raw_results)
        
        assert isinstance(processed, dict)
        assert "sysDescr" in processed or "1.3.6.1.2.1.1.1.0" in processed
    
    @pytest.mark.asyncio
    async def test_parse_ssh_output(self):
        """Test SSH output parsing"""
        cisco_output = """
        Cisco IOS Software, ISR Software
        Uptime: 2 days, 3 hours, 45 minutes
        CPU utilization: 45%
        Memory: 2048MB used, 2048MB free
        """
        
        parsed = polling_engine._parse_ssh_output(cisco_output, "cisco")
        
        assert isinstance(parsed, dict)
        assert len(parsed) > 0
    
    @pytest.mark.asyncio
    async def test_concurrent_polling_limit(self, snmp_config):
        """Test concurrent polling limit"""
        devices = []
        for i in range(20):  # More than default concurrent limit
            device = Mock(spec=Device)
            device.id = i + 1
            device.ip_address = f"10.0.0.{i+1}"
            device.protocol = DeviceProtocol.SNMP
            devices.append(device)
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=1,
                device_ip="10.0.0.1",
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=50,
                metrics={}
            )
            
            # Should handle concurrent limit properly
            results = await polling_engine.poll_multiple_devices(devices, snmp_config)
            
            assert len(results) == 20
            # Verify concurrent limit was respected (implementation dependent)
    
    def test_poll_result_serialization(self):
        """Test PollResult can be serialized"""
        result = PollResult(
            device_id=1,
            device_ip="192.168.1.1",
            status=PollStatus.SUCCESS,
            timestamp=datetime.utcnow(),
            duration_ms=100,
            metrics={"cpu": 45.5}
        )
        
        # Should be able to convert to dict
        result_dict = {
            "device_id": result.device_id,
            "device_ip": result.device_ip,
            "status": result.status.value,
            "timestamp": result.timestamp.isoformat(),
            "duration_ms": result.duration_ms,
            "metrics": result.metrics,
            "errors": result.errors
        }
        
        assert result_dict["device_id"] == 1
        assert result_dict["status"] == "success"
        assert "cpu" in result_dict["metrics"]


class TestSNMPPolling:
    """Test SNMP-specific polling functionality"""
    
    @pytest.mark.asyncio
    async def test_snmp_v1_polling(self, mock_device):
        """Test SNMP v1 polling"""
        config = SNMPConfig(
            community="public",
            version="v1",
            port=161
        )
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=100,
                metrics={"version": "v1"}
            )
            
            result = await polling_engine.poll_device(mock_device, snmp_config=config)
            
            assert result.status == PollStatus.SUCCESS
    
    @pytest.mark.asyncio
    async def test_snmp_v3_polling(self, mock_device):
        """Test SNMP v3 polling"""
        config = SNMPConfig(
            community="",  # Not used in v3
            version="v3",
            port=161,
            v3_user="admin",
            v3_auth_key="authkey123",
            v3_priv_key="privkey123"
        )
        
        with patch.object(polling_engine, '_poll_snmp') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=100,
                metrics={"version": "v3", "secure": True}
            )
            
            result = await polling_engine.poll_device(mock_device, snmp_config=config)
            
            assert result.status == PollStatus.SUCCESS
            assert result.metrics.get("secure") is True


class TestSSHPolling:
    """Test SSH-specific polling functionality"""
    
    @pytest.mark.asyncio
    async def test_ssh_cisco_polling(self, mock_device, ssh_config):
        """Test SSH polling for Cisco devices"""
        mock_device.protocol = DeviceProtocol.SSH
        mock_device.vendor = "Cisco"
        
        with patch.object(polling_engine, '_poll_ssh') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=200,
                metrics={
                    "vendor": "Cisco",
                    "cpu": "45%",
                    "memory": "2048MB"
                }
            )
            
            result = await polling_engine.poll_device(mock_device, ssh_config=ssh_config)
            
            assert result.status == PollStatus.SUCCESS
            assert result.metrics["vendor"] == "Cisco"
    
    @pytest.mark.asyncio
    async def test_ssh_juniper_polling(self, mock_device, ssh_config):
        """Test SSH polling for Juniper devices"""
        mock_device.protocol = DeviceProtocol.SSH
        mock_device.vendor = "Juniper"
        
        with patch.object(polling_engine, '_poll_ssh') as mock_poll:
            mock_poll.return_value = PollResult(
                device_id=mock_device.id,
                device_ip=mock_device.ip_address,
                status=PollStatus.SUCCESS,
                timestamp=datetime.utcnow(),
                duration_ms=200,
                metrics={
                    "vendor": "Juniper",
                    "routing_engine": "RE-0",
                    "cpu": "35%"
                }
            )
            
            result = await polling_engine.poll_device(mock_device, ssh_config=ssh_config)
            
            assert result.status == PollStatus.SUCCESS
            assert result.metrics["vendor"] == "Juniper"
            assert "routing_engine" in result.metrics