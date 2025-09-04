"""
Tests for Network Topology Models and Services

This module tests the network topology functionality including models,
discovery service, analysis service, and device classification.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession

from ..models.network_topology import (
    NetworkTopology, NetworkInterface, NetworkPath, DeviceRelationship,
    TopologyType, InterfaceType, InterfaceStatus, PathStatus
)
from ..models.device import Device, DeviceStatus, DeviceProtocol
from ..models.metric import Metric, MetricType, MetricCategory
from ..services.network_discovery import NetworkDiscoveryService, DiscoveryConfig
from ..services.topology_analysis import TopologyAnalysisService
from ..services.device_classification import DeviceClassificationService, DeviceCapability, DeviceClassification


class TestNetworkTopologyModels:
    """Test network topology models"""
    
    def test_network_topology_creation(self):
        """Test NetworkTopology model creation"""
        topology = NetworkTopology(
            name="Test Topology",
            description="Test network topology",
            topology_type="layer3"
        )
        
        assert topology.name == "Test Topology"
        assert topology.description == "Test network topology"
        assert topology.topology_type == "layer3"
        assert topology.discovery_enabled is True
        assert topology.auto_update is True
        assert topology.update_interval == 3600
        assert topology.discovery_status == "pending"
    
    def test_network_interface_creation(self):
        """Test NetworkInterface model creation"""
        interface = NetworkInterface(
            device_id=1,
            name="GigabitEthernet0/1",
            description="Management interface",
            interface_type="ethernet",
            status="up",
            ip_address="192.168.1.1",
            subnet_mask="255.255.255.0",
            bandwidth_mbps=1000
        )
        
        assert interface.device_id == 1
        assert interface.name == "GigabitEthernet0/1"
        assert interface.interface_type == "ethernet"
        assert interface.status == "up"
        assert interface.ip_address == "192.168.1.1"
        assert interface.bandwidth_mbps == 1000
    
    def test_network_path_creation(self):
        """Test NetworkPath model creation"""
        path = NetworkPath(
            topology_id=1,
            name="Primary Path",
            description="Primary network path",
            source_device_id=1,
            destination_device_id=2,
            path_type="primary",
            protocol="OSPF",
            status="active"
        )
        
        assert path.topology_id == 1
        assert path.name == "Primary Path"
        assert path.source_device_id == 1
        assert path.destination_device_id == 2
        assert path.path_type == "primary"
        assert path.protocol == "OSPF"
        assert path.status == "active"
        assert path.is_active is True
    
    def test_device_relationship_creation(self):
        """Test DeviceRelationship model creation"""
        relationship = DeviceRelationship(
            topology_id=1,
            source_device_id=1,
            target_device_id=2,
            relationship_type="connected",
            connection_protocol="SNMP",
            connection_quality=95.0
        )
        
        assert relationship.topology_id == 1
        assert relationship.source_device_id == 1
        assert relationship.target_device_id == 2
        assert relationship.relationship_type == "connected"
        assert relationship.connection_protocol == "SNMP"
        assert relationship.connection_quality == 95.0
        assert relationship.is_active is True


class TestNetworkDiscoveryService:
    """Test NetworkDiscoveryService functionality"""
    
    @pytest.fixture
    def discovery_service(self, db_session):
        return NetworkDiscoveryService(db_session)
    
    @pytest.fixture
    def sample_topology(self):
        return NetworkTopology(
            id=1,
            name="Test Topology",
            topology_type="layer3"
        )
    
    @pytest.fixture
    def sample_credentials(self):
        return [
            {
                "type": "snmp",
                "data": {"community": "public"},
                "ip_range": "192.168.1.0/24",
                "default": True
            }
        ]
    
    @pytest.mark.asyncio
    async def test_discovery_service_initialization(self, discovery_service):
        """Test discovery service initialization"""
        assert discovery_service.config.max_concurrent_discoveries == 10
        assert discovery_service.config.discovery_timeout == 30
        assert discovery_service.config.max_hop_depth == 3
        assert discovery_service.config.use_snmp is True
        assert discovery_service.config.use_ssh is True
    
    @pytest.mark.asyncio
    async def test_create_discovery_targets(self, discovery_service, sample_credentials):
        """Test creation of discovery targets"""
        seed_devices = ["192.168.1.1", "192.168.1.2"]
        targets = await discovery_service._create_discovery_targets(seed_devices, sample_credentials)
        
        assert len(targets) == 2
        assert targets[0].ip_address == "192.168.1.1"
        assert targets[0].credential_type == "snmp"
        assert "snmp" in targets[0].discovery_protocols
        assert targets[0].max_depth == 3
    
    def test_ip_in_range_check(self, discovery_service):
        """Test IP range checking functionality"""
        # CIDR notation
        assert discovery_service._ip_in_range("192.168.1.100", "192.168.1.0/24") is True
        assert discovery_service._ip_in_range("192.168.2.100", "192.168.1.0/24") is False
        
        # Single IP
        assert discovery_service._ip_in_range("192.168.1.100", "192.168.1.100") is True
        assert discovery_service._ip_in_range("192.168.1.100", "192.168.1.101") is False
    
    def test_get_available_protocols(self, discovery_service):
        """Test protocol availability based on credential type"""
        # SNMP credentials
        protocols = discovery_service._get_available_protocols("snmp")
        assert "snmp" in protocols
        assert "ping" in protocols
        
        # SSH credentials
        protocols = discovery_service._get_available_protocols("ssh")
        assert "ssh" in protocols
        assert "ping" in protocols
    
    @pytest.mark.asyncio
    async def test_discover_device_info_snmp(self, discovery_service):
        """Test device discovery via SNMP"""
        target = MagicMock()
        target.ip_address = "192.168.1.1"
        target.discovery_protocols = ["snmp"]
        
        with patch.object(discovery_service, '_discover_via_snmp') as mock_snmp:
            mock_snmp.return_value = {
                "hostname": "test-device",
                "device_type": "switch",
                "vendor": "Cisco",
                "model": "WS-C3560",
                "os_version": "15.2",
                "capabilities": ["snmp_support"]
            }
            
            device_info = await discovery_service._discover_device_info(target)
            
            assert device_info["hostname"] == "test-device"
            assert device_info["device_type"] == "switch"
            assert device_info["vendor"] == "Cisco"
            assert device_info["discovery_protocol"] == "snmp"
    
    @pytest.mark.asyncio
    async def test_discover_device_info_ssh_fallback(self, discovery_service):
        """Test device discovery fallback to SSH"""
        target = MagicMock()
        target.ip_address = "192.168.1.1"
        target.discovery_protocols = ["snmp", "ssh"]
        
        with patch.object(discovery_service, '_discover_via_snmp') as mock_snmp:
            with patch.object(discovery_service, '_discover_via_ssh') as mock_ssh:
                mock_snmp.return_value = None  # SNMP fails
                mock_ssh.return_value = {
                    "hostname": "test-device",
                    "device_type": "router",
                    "vendor": "Cisco",
                    "capabilities": ["ssh_access"]
                }
                
                device_info = await discovery_service._discover_device_info(target)
                
                assert device_info["hostname"] == "test-device"
                assert device_info["device_type"] == "router"
                assert device_info["discovery_protocol"] == "ssh"
    
    def test_parse_sysdescr(self, discovery_service):
        """Test SNMP sysDescr parsing"""
        sysdescr = "Cisco IOS Software, C3560 Software (C3560-IPBASEK9-M), Version 12.2(53)SEY2"
        
        device_type, vendor, model = discovery_service._parse_sysdescr(sysdescr)
        
        assert device_type == "switch"
        assert vendor == "Cisco"
        assert model is None  # Model extraction not implemented in simplified version
    
    def test_extract_os_version(self, discovery_service):
        """Test OS version extraction"""
        sysdescr = "Cisco IOS Software, Version 15.2(4)S7"
        version = discovery_service._extract_os_version(sysdescr)
        assert version == "15.2(4)S7"
        
        # No version pattern
        sysdescr_no_version = "Cisco IOS Software"
        version = discovery_service._extract_os_version(sysdescr_no_version)
        assert version is None
    
    def test_infer_capabilities(self, discovery_service):
        """Test capability inference from SNMP results"""
        snmp_results = {
            "sysObjectID": "1.3.6.1.4.1.9.1.516",
            "sysUpTime": "123456",
            "sysLocation": "Data Center"
        }
        
        capabilities = discovery_service._infer_capabilities(snmp_results)
        
        assert "snmp_support" in capabilities
        assert "uptime_monitoring" in capabilities
        assert "location_tracking" in capabilities


class TestTopologyAnalysisService:
    """Test TopologyAnalysisService functionality"""
    
    @pytest.fixture
    def analysis_service(self, db_session):
        return TopologyAnalysisService(db_session)
    
    @pytest.fixture
    def sample_device(self):
        return Device(
            id=1,
            ip_address="192.168.1.1",
            hostname="test-device",
            status=DeviceStatus.ONLINE
        )
    
    @pytest.mark.asyncio
    async def test_analysis_service_initialization(self, analysis_service):
        """Test analysis service initialization"""
        assert analysis_service._topology_graphs == {}
        assert analysis_service._analysis_cache == {}
        assert analysis_service._cache_ttl == timedelta(minutes=15)
    
    @pytest.mark.asyncio
    async def test_build_topology_graph(self, analysis_service, db_session):
        """Test topology graph building"""
        # Mock database query results
        mock_relationship = MagicMock()
        mock_relationship.source_device_id = 1
        mock_relationship.target_device_id = 2
        mock_relationship.id = 1
        mock_relationship.relationship_type = "connected"
        mock_relationship.latency = 5.0
        mock_relationship.bandwidth = 1000.0
        mock_relationship.reliability = 95.0
        mock_relationship.connection_quality = 90.0
        
        mock_source_device = MagicMock()
        mock_source_device.id = 1
        mock_target_device = MagicMock()
        mock_target_device.id = 2
        
        mock_relationship.source_device = mock_source_device
        mock_relationship.target_device = mock_target_device
        
        with patch.object(analysis_service.db_session, 'execute') as mock_execute:
            mock_result = MagicMock()
            mock_result.scalars.return_value = [mock_relationship]
            mock_execute.return_value = mock_result
            
            graph = await analysis_service._build_topology_graph(1)
            
            assert graph is not None
            assert len(graph.nodes) == 2
            assert len(graph.edges) == 1
            assert graph.has_edge(1, 2)
    
    @pytest.mark.asyncio
    async def test_analyze_path_characteristics(self, analysis_service):
        """Test path characteristics analysis"""
        path = [1, 2, 3]  # 3 devices, 2 hops
        graph = MagicMock()
        
        # Mock edge data
        edge_data_1 = {
            'latency': 5.0,
            'bandwidth': 1000.0,
            'reliability': 95.0
        }
        edge_data_2 = {
            'latency': 3.0,
            'bandwidth': 500.0,
            'reliability': 90.0
        }
        
        graph.get_edge_data.side_effect = [edge_data_1, edge_data_2]
        
        result = await analysis_service._analyze_path_characteristics(1, path, graph)
        
        assert result["total_latency"] == 8.0
        assert result["total_bandwidth"] == 500.0  # Minimum bandwidth
        assert result["path_quality"] == 20.0  # 100 - (8 * 10)
        assert len(result["hop_details"]) == 2
    
    @pytest.mark.asyncio
    async def test_calculate_topology_efficiency(self, analysis_service):
        """Test topology efficiency calculation"""
        with patch.object(analysis_service, 'assess_topology_health') as mock_health:
            mock_health.return_value = MagicMock(overall_health_score=85.0)
            
            with patch.object(analysis_service.db_session, 'execute') as mock_execute:
                mock_result = MagicMock()
                mock_result.scalar.return_value = 10  # 10 devices
                mock_execute.return_value = mock_result
                
                efficiency = await analysis_service._calculate_topology_efficiency(1)
                
                # Base efficiency 80 - 10 (for 10 devices) + 85 (health) / 2 = 77.5
                assert efficiency == 77.5
    
    def test_calculate_overall_health_score(self, analysis_service):
        """Test overall health score calculation"""
        device_health = {1: 90.0, 2: 80.0}
        interface_health = {1: 85.0, 2: 75.0}
        path_health = {1: 95.0}
        
        score = analysis_service._calculate_overall_health_score(
            device_health, interface_health, path_health
        )
        
        # (90*0.4 + 80*0.4) + (85*0.35 + 75*0.35) + (95*0.25) / (0.4 + 0.35 + 0.25)
        # = (68 + 56 + 23.75) / 1.0 = 147.75 / 1.0 = 147.75
        # But this should be capped at 100
        assert score == 100.0
    
    @pytest.mark.asyncio
    async def test_identify_health_issues(self, analysis_service):
        """Test health issue identification"""
        device_health = {1: 25.0, 2: 55.0}  # Critical and warning
        interface_health = {1: 85.0}  # Good
        path_health = {1: 70.0}  # Good
        
        critical_issues, warnings = await analysis_service._identify_health_issues(
            1, device_health, interface_health, path_health
        )
        
        assert len(critical_issues) == 1
        assert len(warnings) == 1
        
        assert critical_issues[0]["type"] == "device_health"
        assert critical_issues[0]["severity"] == "critical"
        assert warnings[0]["type"] == "device_health"
        assert warnings[0]["severity"] == "warning"


class TestDeviceClassificationService:
    """Test DeviceClassificationService functionality"""
    
    @pytest.fixture
    def classification_service(self, db_session):
        return DeviceClassificationService(db_session)
    
    @pytest.fixture
    def sample_device(self):
        return Device(
            id=1,
            ip_address="192.168.1.1",
            hostname="router-01",
            protocol=DeviceProtocol.SNMP,
            status=DeviceStatus.ONLINE
        )
    
    @pytest.mark.asyncio
    async def test_classification_service_initialization(self, classification_service):
        """Test classification service initialization"""
        assert classification_service._classification_cache == {}
        assert len(classification_service._classification_rules) > 0
        assert len(classification_service._vendor_patterns) > 0
        assert len(classification_service._os_patterns) > 0
    
    @pytest.mark.asyncio
    async def test_classify_device(self, classification_service, sample_device):
        """Test device classification"""
        with patch.object(classification_service, '_get_device') as mock_get_device:
            with patch.object(classification_service, '_perform_device_classification') as mock_classify:
                mock_get_device.return_value = sample_device
                
                mock_classification = DeviceClassification(
                    device_id=1,
                    primary_type="router",
                    secondary_types=[],
                    vendor="Cisco",
                    model="ISR4331",
                    os_family="Cisco IOS XE",
                    os_version="16.09.04",
                    capabilities=[],
                    classification_confidence=0.9,
                    classification_method="snmp",
                    last_updated=datetime.now(),
                    metadata={}
                )
                mock_classify.return_value = mock_classification
                
                with patch.object(classification_service, '_update_device_classification'):
                    result = await classification_service.classify_device(1)
                    
                    assert result is not None
                    assert result.primary_type == "router"
                    assert result.vendor == "Cisco"
                    assert result.classification_confidence == 0.9
    
    @pytest.mark.asyncio
    async def test_detect_device_capabilities(self, classification_service, sample_device):
        """Test device capability detection"""
        with patch.object(classification_service, '_get_device') as mock_get_device:
            mock_get_device.return_value = sample_device
            
            with patch.object(classification_service, '_detect_capabilities_via_snmp') as mock_snmp:
                with patch.object(classification_service, '_detect_capabilities_via_interfaces') as mock_interfaces:
                    mock_snmp.return_value = [
                        DeviceCapability(
                            name="snmp_v2c",
                            description="SNMP version 2c support",
                            category="management",
                            confidence=0.9,
                            detection_method="snmp",
                            parameters={"version": "v2c"}
                        )
                    ]
                    
                    mock_interfaces.return_value = [
                        DeviceCapability(
                            name="multi_interface",
                            description="Multiple interfaces",
                            category="connectivity",
                            confidence=0.9,
                            detection_method="interface_analysis",
                            parameters={"interface_count": 2}
                        )
                    ]
                    
                    capabilities = await classification_service.detect_device_capabilities(1)
                    
                    assert len(capabilities) == 2
                    assert any(cap.name == "snmp_v2c" for cap in capabilities)
                    assert any(cap.name == "multi_interface" for cap in capabilities)
    
    def test_parse_snmp_sysdescr(self, classification_service):
        """Test SNMP sysDescr parsing"""
        sysdescr = "Cisco IOS Software, C3560 Software, Version 12.2(53)SEY2"
        
        result = classification_service._parse_snmp_sysdescr(sysdescr)
        
        assert result["primary_type"] == "switch"
        assert result["vendor"] == "Cisco"
        assert result["os_family"] == "Cisco IOS"
        assert result["os_version"] == "12.2(53)SEY2"
    
    def test_parse_ssh_output(self, classification_service):
        """Test SSH output parsing"""
        ssh_data = {
            "show version": "Cisco IOS XE Software, Version 16.09.04",
            "show inventory": "NAME: \"Chassis\", DESCR: \"Cisco ISR4331/K9\""
        }
        
        result = classification_service._parse_ssh_output(ssh_data)
        
        assert result["vendor"] == "Cisco"
        assert result["os_family"] == "Cisco IOS XE"
        assert result["os_version"] == "16.09.04"
        assert result["primary_type"] == "router"
        assert result["model"] == "ISR4331"
    
    def test_evaluate_rule_conditions(self, classification_service, sample_device):
        """Test rule condition evaluation"""
        # Hostname pattern condition
        conditions = [
            {"type": "hostname_pattern", "pattern": r"router-.*"}
        ]
        
        result = classification_service._evaluate_rule_conditions(sample_device, conditions)
        assert result is True
        
        # IP range condition
        conditions = [
            {"type": "ip_range", "range": "192.168.1.0/24"}
        ]
        
        result = classification_service._evaluate_rule_conditions(sample_device, conditions)
        assert result is True
        
        # Protocol condition
        conditions = [
            {"type": "protocol", "protocol": "snmp"}
        ]
        
        result = classification_service._evaluate_rule_conditions(sample_device, conditions)
        assert result is True
    
    def test_calculate_final_confidence(self, classification_service):
        """Test final confidence calculation"""
        classification_data = {
            "confidence": 0.7,
            "vendor": "Cisco",
            "model": "ISR4331",
            "os_family": "Cisco IOS XE"
        }
        
        capabilities = [
            DeviceCapability(
                name="test_cap",
                description="Test capability",
                category="test",
                confidence=0.8,
                detection_method="test",
                parameters={}
            )
        ]
        
        confidence = classification_service._calculate_final_confidence(
            classification_data, capabilities
        )
        
        # Base: 0.7 + Capability boost: 0.02 + Completeness boost: 0.3 = 1.02 (capped at 1.0)
        assert confidence == 1.0
    
    @pytest.mark.asyncio
    async def test_get_device_recommendations(self, classification_service):
        """Test device recommendation generation"""
        with patch.object(classification_service, 'classify_device') as mock_classify:
            mock_classification = DeviceClassification(
                device_id=1,
                primary_type="router",
                secondary_types=[],
                vendor="Cisco",
                model="ISR4331",
                os_family="Cisco IOS XE",
                os_version="16.09.04",
                capabilities=[],
                classification_confidence=0.9,
                classification_method="snmp",
                last_updated=datetime.now(),
                metadata={}
            )
            mock_classify.return_value = mock_classification
            
            with patch.object(classification_service, '_get_performance_recommendations') as mock_perf:
                with patch.object(classification_service, '_get_security_recommendations') as mock_sec:
                    mock_perf.return_value = [
                        {"type": "performance", "title": "Performance Issue"}
                    ]
                    mock_sec.return_value = [
                        {"type": "security", "title": "Security Issue"}
                    ]
                    
                    recommendations = await classification_service.get_device_recommendations(1)
                    
                    assert len(recommendations) == 2
                    assert any(rec["type"] == "performance" for rec in recommendations)
                    assert any(rec["type"] == "security" for rec in recommendations)


@pytest.mark.asyncio
async def test_integration_workflow(db_session):
    """Test integration workflow between topology services"""
    # This test demonstrates how the services work together
    
    # Create discovery service
    discovery_service = NetworkDiscoveryService(db_session)
    
    # Create analysis service
    analysis_service = TopologyAnalysisService(db_session)
    
    # Create classification service
    classification_service = DeviceClassificationService(db_session)
    
    # Test that services can be initialized together
    assert discovery_service is not None
    assert analysis_service is not None
    assert classification_service is not None
    
    # Test that they share the same database session
    assert discovery_service.db_session == db_session
    assert analysis_service.db_session == db_session
    assert classification_service.db_session == db_session
