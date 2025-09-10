"""
Tests for CHM Network Discovery Service
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime
import ipaddress

# Check SNMP availability
try:
    import pysnmp
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False

from backend.services.discovery_service import (
    NetworkDiscoveryService,
    DiscoveredDevice,
    discovery_service
)
from models.discovery_job import DiscoveryStatus, DiscoveryMethod
from models.device import DeviceType, DeviceStatus


@pytest.fixture
def discovery():
    """Create discovery service instance"""
    return NetworkDiscoveryService()


@pytest.fixture
def mock_db():
    """Create mock database session"""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.add = Mock()
    return db


@pytest.fixture
def sample_device():
    """Create sample discovered device"""
    return DiscoveredDevice(
        ip_address="192.168.1.1",
        mac_address="00:11:22:33:44:55",
        hostname="router-01",
        device_type=DeviceType.ROUTER,
        vendor="Cisco",
        model="ISR 4331",
        discovery_method=DiscoveryMethod.SNMP
    )


class TestDiscoveredDevice:
    """Test DiscoveredDevice dataclass"""
    
    def test_device_creation(self):
        """Test creating a discovered device"""
        device = DiscoveredDevice(
            ip_address="10.0.0.1",
            hostname="switch-01"
        )
        
        assert device.ip_address == "10.0.0.1"
        assert device.hostname == "switch-01"
        assert device.discovery_time is not None
        assert isinstance(device.neighbors, list)
        assert isinstance(device.capabilities, list)
        assert isinstance(device.interfaces, list)
    
    def test_device_with_full_details(self, sample_device):
        """Test device with full details"""
        assert sample_device.ip_address == "192.168.1.1"
        assert sample_device.mac_address == "00:11:22:33:44:55"
        assert sample_device.hostname == "router-01"
        assert sample_device.device_type == DeviceType.ROUTER
        assert sample_device.vendor == "Cisco"
        assert sample_device.model == "ISR 4331"
        assert sample_device.discovery_method == DiscoveryMethod.SNMP


class TestNetworkDiscoveryService:
    """Test NetworkDiscoveryService class"""
    
    def test_service_initialization(self, discovery):
        """Test service initialization"""
        assert discovery is not None
        assert isinstance(discovery.discovered_devices, dict)
        assert isinstance(discovery.discovery_tasks, list)
        assert len(discovery.discovered_devices) == 0
    
    @pytest.mark.asyncio
    async def test_ping_host(self, discovery):
        """Test ping host functionality"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock successful ping
            mock_proc = AsyncMock()
            mock_proc.wait = AsyncMock(return_value=0)
            mock_subprocess.return_value = mock_proc
            
            ip, result = await discovery._ping_host("192.168.1.1")
            
            assert ip == "192.168.1.1"
            assert result is True
            mock_subprocess.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_ping_host_failure(self, discovery):
        """Test ping host failure"""
        with patch('asyncio.create_subprocess_exec') as mock_subprocess:
            # Mock failed ping
            mock_proc = AsyncMock()
            mock_proc.wait = AsyncMock(return_value=1)
            mock_subprocess.return_value = mock_proc
            
            ip, result = await discovery._ping_host("192.168.1.2")
            
            assert ip == "192.168.1.2"
            assert result is False
    
    @pytest.mark.asyncio
    async def test_discover_icmp(self, discovery):
        """Test ICMP discovery"""
        network = ipaddress.ip_network("192.168.1.0/30")
        
        with patch.object(discovery, '_ping_host') as mock_ping:
            # Mock successful pings for some hosts
            async def ping_side_effect(ip):
                return (ip, ip in ["192.168.1.1", "192.168.1.2"])
            
            mock_ping.side_effect = ping_side_effect
            
            await discovery._discover_icmp(network)
            
            # Should have discovered 2 hosts
            assert len(discovery.discovered_devices) == 2
            assert "192.168.1.1" in discovery.discovered_devices
            assert "192.168.1.2" in discovery.discovered_devices
            
            device = discovery.discovered_devices["192.168.1.1"]
            assert device.discovery_method == DiscoveryMethod.ICMP
    
    def test_determine_device_type(self, discovery):
        """Test device type determination"""
        test_cases = [
            ("Cisco IOS Software, C3750 Software", DeviceType.ROUTER),
            ("Catalyst 2960 Switch", DeviceType.SWITCH),
            ("ASA Version 9.14", DeviceType.FIREWALL),
            ("Cisco AP Software", DeviceType.ACCESS_POINT),
            ("Linux Server", DeviceType.SERVER),
            ("Microsoft Windows", DeviceType.WORKSTATION),
            ("Unknown Device", DeviceType.UNKNOWN)
        ]
        
        for description, expected_type in test_cases:
            device_type = discovery._determine_device_type(description)
            assert device_type == expected_type
    
    def test_determine_vendor_from_oid(self, discovery):
        """Test vendor determination from OID"""
        test_cases = [
            ("1.3.6.1.4.1.9.1.1234", "Cisco"),
            ("1.3.6.1.4.1.2636.1.1", "Juniper"),
            ("1.3.6.1.4.1.30065.1", "Arista"),
            ("1.3.6.1.4.1.11.2.3", "HP"),
            ("1.3.6.1.4.1.311.1.1", "Microsoft"),
            ("1.3.6.1.4.1.99999", None)
        ]
        
        for oid, expected_vendor in test_cases:
            vendor = discovery._determine_vendor_from_oid(oid)
            assert vendor == expected_vendor
    
    def test_determine_capabilities(self, discovery):
        """Test capability determination from ports"""
        open_ports = [22, 80, 443, 161, 3389]
        capabilities = discovery._determine_capabilities(open_ports)
        
        assert "SSH" in capabilities
        assert "HTTP" in capabilities
        assert "HTTPS" in capabilities
        assert "SNMP" in capabilities
        assert "RDP" in capabilities
    
    @pytest.mark.asyncio
    async def test_save_device_new(self, discovery, mock_db, sample_device):
        """Test saving a new device"""
        # Mock no existing device
        mock_result = Mock()
        mock_result.scalar_one_or_none = Mock(return_value=None)
        mock_db.execute.return_value = mock_result
        
        await discovery._save_device(mock_db, sample_device)
        
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_save_device_existing(self, discovery, mock_db, sample_device):
        """Test updating an existing device"""
        # Mock existing device
        existing_device = Mock()
        existing_device.ip_address = sample_device.ip_address
        
        mock_result = Mock()
        mock_result.scalar_one_or_none = Mock(return_value=existing_device)
        mock_db.execute.return_value = mock_result
        
        await discovery._save_device(mock_db, sample_device)
        
        assert existing_device.hostname == sample_device.hostname
        assert existing_device.device_type == sample_device.device_type
        assert existing_device.vendor == sample_device.vendor
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_job_status(self, discovery, mock_db):
        """Test updating discovery job status"""
        # Mock existing job
        mock_job = Mock()
        mock_job.id = 1
        mock_job.status = DiscoveryStatus.RUNNING
        
        mock_result = Mock()
        mock_result.scalar_one_or_none = Mock(return_value=mock_job)
        mock_db.execute.return_value = mock_result
        
        await discovery._update_job_status(
            mock_db,
            job_id=1,
            status=DiscoveryStatus.COMPLETED,
            devices_found=5
        )
        
        assert mock_job.status == DiscoveryStatus.COMPLETED
        assert mock_job.devices_found == 5
        assert mock_job.completed_at is not None
        mock_db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_discover_network_full(self, discovery, mock_db):
        """Test full network discovery"""
        with patch.object(discovery, '_discover_icmp') as mock_icmp, \
             patch.object(discovery, '_discover_arp') as mock_arp, \
             patch.object(discovery, '_discover_snmp') as mock_snmp, \
             patch.object(discovery, '_save_device') as mock_save:
            
            # Add some discovered devices
            discovery.discovered_devices = {
                "192.168.1.1": DiscoveredDevice(ip_address="192.168.1.1"),
                "192.168.1.2": DiscoveredDevice(ip_address="192.168.1.2")
            }
            
            result = await discovery.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.ICMP, DiscoveryMethod.ARP]
            )
            
            assert len(result) == 2
            mock_icmp.assert_called_once()
            mock_arp.assert_called_once()
            assert mock_save.call_count == 2
    
    @pytest.mark.asyncio
    async def test_discover_network_with_job(self, discovery, mock_db):
        """Test network discovery with job tracking"""
        # Mock job
        mock_job = Mock()
        mock_job.id = 1
        mock_result = Mock()
        mock_result.scalar_one_or_none = Mock(return_value=mock_job)
        mock_db.execute.return_value = mock_result
        
        with patch.object(discovery, '_discover_icmp') as mock_icmp, \
             patch.object(discovery, '_save_device') as mock_save:
            
            discovery.discovered_devices = {
                "10.0.0.1": DiscoveredDevice(ip_address="10.0.0.1")
            }
            
            result = await discovery.discover_network(
                mock_db,
                "10.0.0.0/24",
                methods=[DiscoveryMethod.ICMP],
                job_id=1
            )
            
            assert len(result) == 1
            # Job status should be updated twice (running and completed)
            assert mock_db.commit.call_count >= 2


class TestDiscoveryServiceIntegration:
    """Integration tests for discovery service"""
    
    @pytest.mark.asyncio
    async def test_singleton_instance(self):
        """Test that discovery_service is a singleton"""
        from backend.services.discovery_service import discovery_service
        
        assert discovery_service is not None
        assert isinstance(discovery_service, NetworkDiscoveryService)
    
    @pytest.mark.asyncio
    @pytest.mark.skipif(not SNMP_AVAILABLE, reason="PySNMP not available")
    async def test_snmp_discovery(self, discovery, mock_db):
        """Test SNMP discovery (requires PySNMP)"""
        with patch('pysnmp.hlapi.asyncio.getCmd') as mock_get:
            # Mock SNMP response
            mock_get.return_value = (None, None, None, [
                ('sysDescr', 'Cisco IOS Software'),
                ('sysName', 'router-01'),
                ('sysObjectID', '1.3.6.1.4.1.9.1.1234')
            ])
            
            discovery.discovered_devices["192.168.1.1"] = DiscoveredDevice(
                ip_address="192.168.1.1"
            )
            
            await discovery._discover_snmp(["192.168.1.1"])
            
            device = discovery.discovered_devices["192.168.1.1"]
            assert device.snmp_community is not None
            assert device.hostname == "router-01"
            assert device.vendor == "Cisco"


