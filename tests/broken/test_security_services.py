"""
Tests for CHM Security Services

This module contains comprehensive tests for the advanced security services including:
- Advanced threat detection with ML and behavioral analysis
- Vulnerability management and scanning
- Incident response and forensics
- Security orchestration and automation
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from typing import List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from models.security import SecurityAuditLog, SecurityIncident, ThreatLevel, IncidentStatus
from models.result_objects import CollectionResult, OperationStatus
from backend.services.advanced_threat_detection import (
    AdvancedThreatDetectionService, ThreatIndicator, BehavioralProfile, ThreatDetection,
    ThreatType, DetectionMethod, ConfidenceLevel
)
from backend.services.vulnerability_management import (
    VulnerabilityManagementService, ScanTarget, VulnerabilityScan, VulnerabilityRisk
)
from backend.services.incident_response import (
    IncidentResponseService, IncidentResponsePlan, ResponseAction, ForensicEvidence
)
from backend.services.security_orchestration import (
    SecurityOrchestrationService, SecurityPlaybook, WorkflowExecution, AutomationAction
)


class TestAdvancedThreatDetectionService:
    """Test Advanced Threat Detection Service functionality"""

    @pytest.fixture
    def threat_detection_service(self, db_session):
        return AdvancedThreatDetectionService(db_session)

    @pytest.mark.asyncio
    async def test_detect_threats_advanced(self, threat_detection_service):
        """Test advanced threat detection"""
        result = await threat_detection_service.detect_threats_advanced(time_window_hours=24)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "detections" in result.data
        assert "created_incidents" in result.data
        assert "total_events_analyzed" in result.data

    @pytest.mark.asyncio
    async def test_analyze_behavioral_anomalies(self, threat_detection_service):
        """Test behavioral anomaly analysis"""
        result = await threat_detection_service.analyze_behavioral_anomalies(
            entity_id="1",
            entity_type="user",
            time_window_hours=168
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "entity_id" in result.data
        assert "anomalies" in result.data
        assert "risk_score" in result.data

    @pytest.mark.asyncio
    async def test_hunt_threats(self, threat_detection_service):
        """Test threat hunting"""
        from backend.services.advanced_threat_detection import ThreatHuntingQuery
        
        hunting_query = ThreatHuntingQuery(
            query_id="THQ-TEST-001",
            name="Test Threat Hunt",
            description="Test threat hunting query",
            query_type="ioc",
            query_parameters={"indicator": "192.168.1.100"},
            time_range=(datetime.now() - timedelta(days=7), datetime.now()),
            created_by=1,
            created_at=datetime.now()
        )
        
        result = await threat_detection_service.hunt_threats(hunting_query)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "query_id" in result.data
        assert "results" in result.data
        assert "threats" in result.data

    @pytest.mark.asyncio
    async def test_create_threat_hunting_query(self, threat_detection_service):
        """Test creating threat hunting query"""
        query_data = {
            "name": "Test Query",
            "description": "Test threat hunting query",
            "query_type": "behavioral",
            "parameters": {"user_id": 1, "time_window": "24h"}
        }
        
        result = await threat_detection_service.create_threat_hunting_query(query_data, created_by=1)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "query_id" in result.data

    @pytest.mark.asyncio
    async def test_get_threat_intelligence(self, threat_detection_service):
        """Test getting threat intelligence"""
        result = await threat_detection_service.get_threat_intelligence(
            indicator_type="ip",
            indicator_value="192.168.1.100"
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "local_intelligence" in result.data
        assert "external_intelligence" in result.data

    @pytest.mark.asyncio
    async def test_update_threat_intelligence(self, threat_detection_service):
        """Test updating threat intelligence"""
        indicators = [
            ThreatIndicator(
                indicator_id="TI-TEST-001",
                indicator_type="ip",
                indicator_value="192.168.1.100",
                threat_type=ThreatType.MALWARE,
                confidence=0.9,
                severity=ThreatLevel.HIGH,
                source="threat_feed",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                tags=["malware", "botnet"],
                metadata={"reputation": "malicious"}
            )
        ]
        
        result = await threat_detection_service.update_threat_intelligence(indicators)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "updated_indicators" in result.data

    @pytest.mark.asyncio
    async def test_get_threat_detection_metrics(self, threat_detection_service):
        """Test getting threat detection metrics"""
        result = await threat_detection_service.get_threat_detection_metrics(time_window_hours=24)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "detection_summary" in result.data
        assert "threat_types" in result.data
        assert "detection_methods" in result.data


class TestVulnerabilityManagementService:
    """Test Vulnerability Management Service functionality"""

    @pytest.fixture
    def vulnerability_management_service(self, db_session):
        return VulnerabilityManagementService(db_session)

    @pytest.mark.asyncio
    async def test_schedule_vulnerability_scan(self, vulnerability_management_service):
        """Test scheduling vulnerability scan"""
        scan_config = {
            "name": "Network Vulnerability Scan",
            "scan_type": "network",
            "targets": [
                {
                    "type": "device",
                    "address": "192.168.1.0/24",
                    "name": "Network Segment",
                    "parameters": {"ports": "1-1000"}
                }
            ],
            "scan_engine": "nmap"
        }
        
        result = await vulnerability_management_service.schedule_vulnerability_scan(
            scan_config, scheduled_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "scan_id" in result.data

    @pytest.mark.asyncio
    async def test_execute_vulnerability_scan(self, vulnerability_management_service):
        """Test executing vulnerability scan"""
        # First schedule a scan
        scan_config = {
            "name": "Test Scan",
            "scan_type": "network",
            "targets": [{"type": "device", "address": "192.168.1.1", "name": "Test Device"}]
        }
        
        schedule_result = await vulnerability_management_service.schedule_vulnerability_scan(
            scan_config, scheduled_by=1
        )
        scan_id = schedule_result.data["scan_id"]
        
        # Execute the scan
        result = await vulnerability_management_service.execute_vulnerability_scan(scan_id)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "vulnerabilities" in result.data
        assert "scan_results" in result.data

    @pytest.mark.asyncio
    async def test_assess_vulnerability_risk(self, vulnerability_management_service):
        """Test assessing vulnerability risk"""
        # This would require a vulnerability to exist in the database
        result = await vulnerability_management_service.assess_vulnerability_risk("VULN-TEST-001")
        
        # Should fail if vulnerability doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_get_vulnerability_dashboard(self, vulnerability_management_service):
        """Test getting vulnerability dashboard"""
        result = await vulnerability_management_service.get_vulnerability_dashboard()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "statistics" in result.data
        assert "recent_scans" in result.data
        assert "high_risk_vulnerabilities" in result.data

    @pytest.mark.asyncio
    async def test_create_remediation_plan(self, vulnerability_management_service):
        """Test creating remediation plan"""
        vulnerability_ids = ["VULN-001", "VULN-002", "VULN-003"]
        
        result = await vulnerability_management_service.create_remediation_plan(
            vulnerability_ids, created_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "plan_id" in result.data
        assert "vulnerabilities" in result.data


class TestIncidentResponseService:
    """Test Incident Response Service functionality"""

    @pytest.fixture
    def incident_response_service(self, db_session):
        return IncidentResponseService(db_session)

    @pytest.mark.asyncio
    async def test_initiate_incident_response(self, incident_response_service):
        """Test initiating incident response"""
        # This would require an incident to exist
        result = await incident_response_service.initiate_incident_response("INC-TEST-001")
        
        # Should fail if incident doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_execute_response_action(self, incident_response_service):
        """Test executing response action"""
        result = await incident_response_service.execute_response_action(
            action_id="ACTION-TEST-001",
            executed_by=1,
            evidence={"log_file": "/var/log/security.log"},
            notes="Action executed successfully"
        )
        
        # Should fail if action doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_collect_forensic_evidence(self, incident_response_service):
        """Test collecting forensic evidence"""
        result = await incident_response_service.collect_forensic_evidence(
            incident_id="INC-TEST-001",
            evidence_type="log",
            source="/var/log/security.log",
            collected_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "evidence_id" in result.data
        assert "evidence" in result.data

    @pytest.mark.asyncio
    async def test_contain_incident(self, incident_response_service):
        """Test containing incident"""
        result = await incident_response_service.contain_incident(
            incident_id="INC-TEST-001",
            containment_method="network_isolation",
            executed_by=1
        )
        
        # Should fail if incident doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_eradicate_threat(self, incident_response_service):
        """Test eradicating threat"""
        result = await incident_response_service.eradicate_threat(
            incident_id="INC-TEST-001",
            eradication_method="malware_removal",
            executed_by=1
        )
        
        # Should fail if incident doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_recover_systems(self, incident_response_service):
        """Test recovering systems"""
        recovery_plan = {
            "systems": ["web-server-01", "db-server-01"],
            "backup_restore": True,
            "verification": True
        }
        
        result = await incident_response_service.recover_systems(
            incident_id="INC-TEST-001",
            recovery_plan=recovery_plan,
            executed_by=1
        )
        
        # Should fail if incident doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_generate_incident_report(self, incident_response_service):
        """Test generating incident report"""
        result = await incident_response_service.generate_incident_report(
            incident_id="INC-TEST-001",
            report_type="final"
        )
        
        # Should fail if incident doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False


class TestSecurityOrchestrationService:
    """Test Security Orchestration Service functionality"""

    @pytest.fixture
    def security_orchestration_service(self, db_session):
        return SecurityOrchestrationService(db_session)

    @pytest.mark.asyncio
    async def test_execute_playbook(self, security_orchestration_service):
        """Test executing security playbook"""
        trigger_event = {
            "event_type": "threat_detection",
            "threat_type": "malware",
            "severity": "high"
        }
        
        result = await security_orchestration_service.execute_playbook(
            playbook_id="malware_containment",
            trigger_event=trigger_event,
            execution_mode="automatic"
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "execution_id" in result.data
        assert "execution" in result.data

    @pytest.mark.asyncio
    async def test_create_playbook(self, security_orchestration_service):
        """Test creating security playbook"""
        playbook_data = {
            "name": "Test Playbook",
            "description": "Test security playbook",
            "trigger_conditions": [
                {"event_type": "threat_detection", "severity": "high"}
            ],
            "workflow_steps": [
                {"step": 1, "action": "notify_team", "description": "Notify security team"},
                {"step": 2, "action": "isolate_system", "description": "Isolate affected system"}
            ],
            "execution_mode": "automatic"
        }
        
        result = await security_orchestration_service.create_playbook(playbook_data, created_by=1)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "playbook_id" in result.data

    @pytest.mark.asyncio
    async def test_execute_automation_action(self, security_orchestration_service):
        """Test executing automation action"""
        parameters = {"system_id": "SYS-001", "isolation_level": "full"}
        execution_context = {"incident_id": "INC-001", "user_id": 1}
        
        result = await security_orchestration_service.execute_automation_action(
            action_id="isolate_system",
            parameters=parameters,
            execution_context=execution_context
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "action_type" in result.data

    @pytest.mark.asyncio
    async def test_get_workflow_execution_status(self, security_orchestration_service):
        """Test getting workflow execution status"""
        result = await security_orchestration_service.get_workflow_execution_status("EXEC-TEST-001")
        
        # Should fail if execution doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_pause_workflow_execution(self, security_orchestration_service):
        """Test pausing workflow execution"""
        result = await security_orchestration_service.pause_workflow_execution(
            execution_id="EXEC-TEST-001",
            paused_by=1
        )
        
        # Should fail if execution doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_resume_workflow_execution(self, security_orchestration_service):
        """Test resuming workflow execution"""
        result = await security_orchestration_service.resume_workflow_execution(
            execution_id="EXEC-TEST-001",
            resumed_by=1
        )
        
        # Should fail if execution doesn't exist
        assert isinstance(result, CollectionResult)
        assert result.success is False

    @pytest.mark.asyncio
    async def test_get_orchestration_dashboard(self, security_orchestration_service):
        """Test getting orchestration dashboard"""
        result = await security_orchestration_service.get_orchestration_dashboard()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "playbooks" in result.data
        assert "automation_actions" in result.data
        assert "workflow_executions" in result.data


class TestSecurityDataStructures:
    """Test security data structures"""

    def test_threat_indicator_creation(self):
        """Test creating threat indicator"""
        indicator = ThreatIndicator(
            indicator_id="TI-TEST-001",
            indicator_type="ip",
            indicator_value="192.168.1.100",
            threat_type=ThreatType.MALWARE,
            confidence=0.9,
            severity=ThreatLevel.HIGH,
            source="threat_feed",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            tags=["malware", "botnet"],
            metadata={"reputation": "malicious"}
        )
        
        assert indicator.indicator_id == "TI-TEST-001"
        assert indicator.indicator_type == "ip"
        assert indicator.threat_type == ThreatType.MALWARE
        assert indicator.confidence == 0.9

    def test_behavioral_profile_creation(self):
        """Test creating behavioral profile"""
        profile = BehavioralProfile(
            entity_id="user_001",
            entity_type="user",
            profile_period=(datetime.now() - timedelta(days=30), datetime.now()),
            baseline_metrics={"login_frequency": 0.8, "access_pattern": 0.6},
            anomaly_thresholds={"login_frequency": 0.2, "access_pattern": 0.3},
            risk_score=0.3,
            last_updated=datetime.now(),
            profile_data={"total_sessions": 150, "avg_session_duration": 45}
        )
        
        assert profile.entity_id == "user_001"
        assert profile.entity_type == "user"
        assert profile.risk_score == 0.3

    def test_threat_detection_creation(self):
        """Test creating threat detection"""
        detection = ThreatDetection(
            detection_id="DET-TEST-001",
            threat_type=ThreatType.MALWARE,
            detection_method=DetectionMethod.BEHAVIORAL_ANALYSIS,
            confidence=ConfidenceLevel.HIGH,
            severity=ThreatLevel.HIGH,
            description="Malware detected through behavioral analysis",
            detected_at=datetime.now(),
            affected_entities=["user_001", "system_001"],
            indicators=[],
            evidence={"analysis_results": "malware_signature_detected"},
            recommended_actions=["Isolate system", "Run antivirus scan"],
            false_positive_probability=0.1
        )
        
        assert detection.detection_id == "DET-TEST-001"
        assert detection.threat_type == ThreatType.MALWARE
        assert detection.confidence == ConfidenceLevel.HIGH

    def test_scan_target_creation(self):
        """Test creating scan target"""
        target = ScanTarget(
            target_id="TGT-TEST-001",
            target_type="device",
            target_address="192.168.1.100",
            target_name="Test Device",
            scan_parameters={"ports": "1-1000", "timeout": 30},
            credentials={"username": "admin", "password": "secret"}
        )
        
        assert target.target_id == "TGT-TEST-001"
        assert target.target_type == "device"
        assert target.target_address == "192.168.1.100"

    def test_vulnerability_scan_creation(self):
        """Test creating vulnerability scan"""
        targets = [
            ScanTarget(
                target_id="TGT-001",
                target_type="device",
                target_address="192.168.1.1",
                target_name="Device 1",
                scan_parameters={}
            )
        ]
        
        scan = VulnerabilityScan(
            scan_id="SCAN-TEST-001",
            name="Test Vulnerability Scan",
            scan_type="network",
            targets=targets,
            scan_engine="nmap",
            scan_parameters={"aggressive": True},
            status="scheduled"
        )
        
        assert scan.scan_id == "SCAN-TEST-001"
        assert scan.scan_type == "network"
        assert len(scan.targets) == 1

    def test_response_action_creation(self):
        """Test creating response action"""
        action = ResponseAction(
            action_id="ACTION-TEST-001",
            incident_id="INC-TEST-001",
            action_type="contain",
            description="Isolate affected system",
            assigned_to=1,
            status="pending"
        )
        
        assert action.action_id == "ACTION-TEST-001"
        assert action.incident_id == "INC-TEST-001"
        assert action.action_type == "contain"

    def test_forensic_evidence_creation(self):
        """Test creating forensic evidence"""
        evidence = ForensicEvidence(
            evidence_id="EVIDENCE-TEST-001",
            incident_id="INC-TEST-001",
            evidence_type="log",
            source="/var/log/security.log",
            collection_method="automated_log_collection",
            collected_at=datetime.now(),
            collected_by=1,
            hash_value="sha256:abc123",
            chain_of_custody=[{
                "action": "collected",
                "timestamp": datetime.now(),
                "performed_by": 1,
                "location": "/var/log/security.log"
            }]
        )
        
        assert evidence.evidence_id == "EVIDENCE-TEST-001"
        assert evidence.evidence_type == "log"
        assert evidence.hash_value == "sha256:abc123"

    def test_security_playbook_creation(self):
        """Test creating security playbook"""
        playbook = SecurityPlaybook(
            playbook_id="PB-TEST-001",
            name="Test Security Playbook",
            description="Test playbook for security orchestration",
            trigger_conditions=[
                {"event_type": "threat_detection", "severity": "high"}
            ],
            workflow_steps=[
                {"step": 1, "action": "notify_team", "description": "Notify security team"},
                {"step": 2, "action": "isolate_system", "description": "Isolate affected system"}
            ],
            execution_mode="automatic",
            is_active=True,
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        assert playbook.playbook_id == "PB-TEST-001"
        assert playbook.name == "Test Security Playbook"
        assert playbook.execution_mode == "automatic"

    def test_workflow_execution_creation(self):
        """Test creating workflow execution"""
        execution = WorkflowExecution(
            execution_id="EXEC-TEST-001",
            playbook_id="PB-TEST-001",
            trigger_event={"event_type": "threat_detection", "severity": "high"},
            status="running",
            started_at=datetime.now(),
            current_step=0,
            execution_log=[]
        )
        
        assert execution.execution_id == "EXEC-TEST-001"
        assert execution.playbook_id == "PB-TEST-001"
        assert execution.status == "running"

    def test_automation_action_creation(self):
        """Test creating automation action"""
        action = AutomationAction(
            action_id="ACTION-TEST-001",
            name="Test Automation Action",
            action_type="api_call",
            parameters={"endpoint": "/api/test", "method": "POST"},
            timeout_seconds=300,
            retry_count=3,
            is_active=True
        )
        
        assert action.action_id == "ACTION-TEST-001"
        assert action.name == "Test Automation Action"
        assert action.action_type == "api_call"


@pytest.mark.asyncio
async def test_integration_workflow(db_session):
    """Test integration workflow between security services"""
    # Initialize services
    threat_detection = AdvancedThreatDetectionService(db_session)
    vulnerability_management = VulnerabilityManagementService(db_session)
    incident_response = IncidentResponseService(db_session)
    security_orchestration = SecurityOrchestrationService(db_session)
    
    # Test that services can be initialized and share the database session
    assert threat_detection.db_session == db_session
    assert vulnerability_management.db_session == db_session
    assert incident_response.db_session == db_session
    assert security_orchestration.db_session == db_session
    
    # Test basic functionality
    threat_result = await threat_detection.detect_threats_advanced(time_window_hours=24)
    assert threat_result.success is True
    
    # Test vulnerability management
    scan_config = {
        "name": "Integration Test Scan",
        "scan_type": "network",
        "targets": [{"type": "device", "address": "192.168.1.1", "name": "Test Device"}]
    }
    scan_result = await vulnerability_management.schedule_vulnerability_scan(scan_config, scheduled_by=1)
    assert scan_result.success is True
    
    # Test incident response
    evidence_result = await incident_response.collect_forensic_evidence(
        incident_id="INC-INTEGRATION-TEST",
        evidence_type="log",
        source="/var/log/test.log",
        collected_by=1
    )
    assert evidence_result.success is True
    
    # Test security orchestration
    dashboard_result = await security_orchestration.get_orchestration_dashboard()
    assert dashboard_result.success is True
