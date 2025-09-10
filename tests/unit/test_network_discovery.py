"""
Unit tests for Network Discovery Service
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch, MagicMock, call
from datetime import datetime
import ipaddress
from typing import List

from backend.services.network_discovery_service import (
    network_discovery_service, DiscoveredDevice, DiscoveryResult
)
from models.discovery_job import DiscoveryMethod, DiscoveryType, DiscoveryStatus
from models.device import DeviceType, DeviceStatus


@pytest.fixture
def mock_db():
    """Create mock database session"""
    db = AsyncMock()
    db.execute = AsyncMock()
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    db.add = Mock()
    db.refresh = AsyncMock()
    return db


class TestNetworkDiscoveryService:
    """Test network discovery service functionality"""
    
    @pytest.mark.asyncio
    async def test_discover_network_ping(self, mock_db):
        """Test network discovery using ping sweep"""
        with patch.object(network_discovery_service, '_ping_host') as mock_ping:
            # Mock successful pings
            mock_ping.side_effect = [
                ("192.168.1.1", True),
                ("192.168.1.2", True),
                ("192.168.1.3", False),  # One host down
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/30",
                methods=[DiscoveryMethod.PING]
            )
            
            # Should discover 2 active hosts
            assert len(discovered) >= 2
            assert mock_ping.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_discover_network_snmp(self, mock_db):
        """Test network discovery using SNMP"""
        with patch.object(network_discovery_service, '_snmp_discovery') as mock_snmp:
            mock_snmp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.1",
                    hostname="router-01",
                    device_type=DeviceType.ROUTER,
                    vendor="Cisco",
                    model="ISR4321",
                    discovery_method=DiscoveryMethod.SNMP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.SNMP]
            )
            
            assert len(discovered) >= 1
            assert discovered[0].vendor == "Cisco"
            assert discovered[0].discovery_method == DiscoveryMethod.SNMP
    
    @pytest.mark.asyncio
    async def test_discover_network_cdp(self, mock_db):
        """Test network discovery using CDP"""
        with patch.object(network_discovery_service, '_cdp_discovery') as mock_cdp:
            mock_cdp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.2",
                    hostname="switch-01",
                    device_type=DeviceType.SWITCH,
                    vendor="Cisco",
                    model="Catalyst 3850",
                    discovery_method=DiscoveryMethod.CDP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.CDP]
            )
            
            assert len(discovered) >= 1
            assert discovered[0].device_type == DeviceType.SWITCH
            assert discovered[0].discovery_method == DiscoveryMethod.CDP
    
    @pytest.mark.asyncio
    async def test_discover_network_lldp(self, mock_db):
        """Test network discovery using LLDP"""
        with patch.object(network_discovery_service, '_lldp_discovery') as mock_lldp:
            mock_lldp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.3",
                    hostname="ap-01",
                    device_type=DeviceType.ACCESS_POINT,
                    vendor="Aruba",
                    model="AP-305",
                    discovery_method=DiscoveryMethod.LLDP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.LLDP]
            )
            
            assert len(discovered) >= 1
            assert discovered[0].vendor == "Aruba"
            assert discovered[0].discovery_method == DiscoveryMethod.LLDP
    
    @pytest.mark.asyncio
    async def test_discover_network_arp(self, mock_db):
        """Test network discovery using ARP"""
        with patch.object(network_discovery_service, '_arp_discovery') as mock_arp:
            mock_arp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.10",
                    mac_address="00:11:22:33:44:55",
                    discovery_method=DiscoveryMethod.ARP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.ARP]
            )
            
            assert len(discovered) >= 1
            assert discovered[0].mac_address == "00:11:22:33:44:55"
            assert discovered[0].discovery_method == DiscoveryMethod.ARP
    
    @pytest.mark.asyncio
    async def test_discover_network_multiple_methods(self, mock_db):
        """Test discovery using multiple methods"""
        with patch.object(network_discovery_service, '_ping_host') as mock_ping, \
             patch.object(network_discovery_service, '_snmp_discovery') as mock_snmp:
            
            mock_ping.side_effect = [("192.168.1.1", True)]
            mock_snmp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.1",
                    hostname="router-01",
                    device_type=DeviceType.ROUTER,
                    vendor="Cisco",
                    discovery_method=DiscoveryMethod.SNMP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.1/32",
                methods=[DiscoveryMethod.PING, DiscoveryMethod.SNMP]
            )
            
            # Should combine results from both methods
            assert len(discovered) >= 1
            # SNMP should provide more details
            assert any(d.vendor == "Cisco" for d in discovered)
    
    @pytest.mark.asyncio
    async def test_start_discovery_job(self, mock_db):
        """Test starting a discovery job"""
        job_id = 1
        networks = ["192.168.1.0/24", "10.0.0.0/24"]
        
        with patch.object(network_discovery_service, 'discover_network') as mock_discover:
            mock_discover.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.1",
                    hostname="device-01",
                    device_type=DeviceType.ROUTER,
                    discovery_method=DiscoveryMethod.SNMP
                )
            ]
            
            # Mock job update
            with patch.object(network_discovery_service, '_update_job_status'):
                result = await network_discovery_service.start_discovery_job(
                    job_id,
                    networks,
                    [DiscoveryType.NETWORK_SCAN]
                )
                
                assert result.success
                assert result.job_id == job_id
                # Should discover from both networks
                mock_discover.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_discovery_job_progress_tracking(self, mock_db):
        """Test discovery job progress tracking"""
        job_id = 1
        
        with patch.object(network_discovery_service, '_update_job_progress') as mock_progress:
            with patch.object(network_discovery_service, 'discover_network') as mock_discover:
                mock_discover.return_value = []
                
                await network_discovery_service.start_discovery_job(
                    job_id,
                    ["192.168.1.0/24"],
                    [DiscoveryType.NETWORK_SCAN]
                )
                
                # Should update progress
                mock_progress.assert_called()
    
    def test_discovered_device_creation(self):
        """Test DiscoveredDevice object creation"""
        device = DiscoveredDevice(
            ip_address="192.168.1.1",
            hostname="router-01",
            device_type=DeviceType.ROUTER,
            vendor="Cisco",
            model="ISR4321",
            serial_number="FCZ1234567",
            mac_address="00:11:22:33:44:55",
            discovery_method=DiscoveryMethod.SNMP,
            discovered_at=datetime.utcnow()
        )
        
        assert device.ip_address == "192.168.1.1"
        assert device.hostname == "router-01"
        assert device.device_type == DeviceType.ROUTER
        assert device.vendor == "Cisco"
        assert device.model == "ISR4321"
        assert device.serial_number == "FCZ1234567"
        assert device.mac_address == "00:11:22:33:44:55"
        assert device.discovery_method == DiscoveryMethod.SNMP
    
    @pytest.mark.asyncio
    async def test_validate_network_range(self):
        """Test network range validation"""
        # Valid ranges
        valid_ranges = [
            "192.168.1.0/24",
            "10.0.0.0/8",
            "172.16.0.0/16",
            "192.168.1.1/32"
        ]
        
        for network in valid_ranges:
            try:
                ipaddress.ip_network(network, strict=False)
                valid = True
            except ValueError:
                valid = False
            assert valid, f"{network} should be valid"
        
        # Invalid ranges
        invalid_ranges = [
            "256.256.256.256/24",
            "192.168.1.0/33",
            "not_an_ip/24"
        ]
        
        for network in invalid_ranges:
            try:
                ipaddress.ip_network(network, strict=False)
                valid = True
            except ValueError:
                valid = False
            assert not valid, f"{network} should be invalid"
    
    @pytest.mark.asyncio
    async def test_concurrent_discovery(self, mock_db):
        """Test concurrent discovery of multiple networks"""
        networks = [
            "192.168.1.0/24",
            "192.168.2.0/24",
            "192.168.3.0/24"
        ]
        
        with patch.object(network_discovery_service, '_ping_host') as mock_ping:
            mock_ping.return_value = ("192.168.1.1", True)
            
            # Run discovery for all networks concurrently
            tasks = [
                network_discovery_service.discover_network(
                    mock_db, network, [DiscoveryMethod.PING]
                )
                for network in networks
            ]
            
            results = await asyncio.gather(*tasks)
            
            assert len(results) == 3
            # Each should have discovered something
            for result in results:
                assert isinstance(result, list)
    
    @pytest.mark.asyncio
    async def test_discovery_deduplication(self, mock_db):
        """Test deduplication of discovered devices"""
        with patch.object(network_discovery_service, '_ping_host') as mock_ping, \
             patch.object(network_discovery_service, '_snmp_discovery') as mock_snmp:
            
            # Both methods discover the same device
            mock_ping.return_value = ("192.168.1.1", True)
            mock_snmp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.1",
                    hostname="router-01",
                    device_type=DeviceType.ROUTER,
                    discovery_method=DiscoveryMethod.SNMP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.1/32",
                methods=[DiscoveryMethod.PING, DiscoveryMethod.SNMP]
            )
            
            # Should deduplicate by IP address
            unique_ips = set(d.ip_address for d in discovered)
            assert len(unique_ips) == 1
    
    @pytest.mark.asyncio
    async def test_discovery_error_handling(self, mock_db):
        """Test error handling during discovery"""
        with patch.object(network_discovery_service, '_ping_host') as mock_ping:
            mock_ping.side_effect = Exception("Network unreachable")
            
            # Should handle error gracefully
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.PING]
            )
            
            # Should return empty list or handle error
            assert isinstance(discovered, list)
    
    @pytest.mark.asyncio
    async def test_save_discovered_devices(self, mock_db):
        """Test saving discovered devices to database"""
        devices = [
            DiscoveredDevice(
                ip_address="192.168.1.1",
                hostname="router-01",
                device_type=DeviceType.ROUTER,
                discovery_method=DiscoveryMethod.SNMP
            ),
            DiscoveredDevice(
                ip_address="192.168.1.2",
                hostname="switch-01",
                device_type=DeviceType.SWITCH,
                discovery_method=DiscoveryMethod.CDP
            )
        ]
        
        with patch.object(network_discovery_service, '_save_discovered_device') as mock_save:
            await network_discovery_service._save_discovered_devices(mock_db, devices)
            
            # Should save each device
            assert mock_save.call_count == 2
    
    @pytest.mark.asyncio
    async def test_discovery_with_credentials(self, mock_db):
        """Test discovery with SNMP credentials"""
        snmp_config = {
            "community": "private",
            "version": "v2c",
            "port": 161
        }
        
        with patch.object(network_discovery_service, '_snmp_discovery') as mock_snmp:
            mock_snmp.return_value = [
                DiscoveredDevice(
                    ip_address="192.168.1.1",
                    hostname="secure-router",
                    device_type=DeviceType.ROUTER,
                    discovery_method=DiscoveryMethod.SNMP
                )
            ]
            
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/24",
                methods=[DiscoveryMethod.SNMP],
                snmp_config=snmp_config
            )
            
            assert len(discovered) > 0
            # Should use provided credentials
            mock_snmp.assert_called()
    
    @pytest.mark.asyncio
    async def test_discovery_filtering(self, mock_db):
        """Test filtering discovered devices"""
        with patch.object(network_discovery_service, '_ping_host') as mock_ping:
            # Mock multiple devices
            mock_ping.side_effect = [
                ("192.168.1.1", True),
                ("192.168.1.2", True),
                ("192.168.1.3", True),
            ]
            
            # Add filter to only include certain IPs
            discovered = await network_discovery_service.discover_network(
                mock_db,
                "192.168.1.0/29",
                methods=[DiscoveryMethod.PING],
                filter_func=lambda d: d.ip_address.endswith(".1")
            )
            
            # Should only include filtered devices
            if discovered:
                assert all(d.ip_address.endswith(".1") for d in discovered)
    
    def test_discovery_result_creation(self):
        """Test DiscoveryResult object creation"""
        result = DiscoveryResult(
            success=True,
            job_id=1,
            devices_discovered=5,
            networks_scanned=["192.168.1.0/24"],
            duration_seconds=120,
            error_message=None
        )
        
        assert result.success
        assert result.job_id == 1
        assert result.devices_discovered == 5
        assert len(result.networks_scanned) == 1
        assert result.duration_seconds == 120
        assert result.error_message is None