"""
Tests for CHM Security & Compliance System

This module contains comprehensive tests for the security models and services including:
- Access control and RBAC functionality
- Audit logging and compliance tracking
- Threat detection and incident response
- Vulnerability assessment and management
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from typing import List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from models.security import (
    SecurityRole, SecurityPermission, RolePermission, UserRole,
    SecurityPolicy, SecurityAuditLog, SecurityIncident, VulnerabilityAssessment,
    Vulnerability, ComplianceFramework, ComplianceRequirement,
    SecurityLevel, ThreatLevel, IncidentStatus, VulnerabilitySeverity, ComplianceStatus
)
from models.user import User, UserRole as UserRoleEnum, UserStatus
from models.result_objects import AccessResult, CollectionResult, OperationStatus
from backend.services.access_control import AccessControlService, AccessRequest, PermissionCheck
from backend.services.audit_logging import AuditLoggingService, AuditEvent, AuditQuery, AuditStats
from backend.services.threat_detection import ThreatDetectionService, ThreatIndicator, IncidentContext, DetectionRule


class TestSecurityModels:
    """Test security model functionality"""

    @pytest.mark.asyncio
    async def test_security_role_creation(self, db_session):
        """Test creating security roles"""
        role = SecurityRole(
            name="Network Administrator",
            description="Full network administration privileges",
            security_level=SecurityLevel.CONFIDENTIAL,
            is_system_role=False,
            requires_mfa=True,
            max_session_duration=28800  # 8 hours
        )
        
        db_session.add(role)
        await db_session.commit()
        await db_session.refresh(role)
        
        assert role.id is not None
        assert role.name == "Network Administrator"
        assert role.security_level == SecurityLevel.CONFIDENTIAL
        assert role.requires_mfa is True
        assert role.is_active is True

    @pytest.mark.asyncio
    async def test_security_permission_creation(self, db_session):
        """Test creating security permissions"""
        permission = SecurityPermission(
            name="device:read",
            description="Read access to device information",
            resource_type="device",
            action="read",
            resource_pattern="*",
            is_system_permission=True
        )
        
        db_session.add(permission)
        await db_session.commit()
        await db_session.refresh(permission)
        
        assert permission.id is not None
        assert permission.name == "device:read"
        assert permission.resource_type == "device"
        assert permission.action == "read"
        assert permission.is_active is True

    @pytest.mark.asyncio
    async def test_role_permission_assignment(self, db_session):
        """Test assigning permissions to roles"""
        # Create role and permission
        role = SecurityRole(
            name="Test Role",
            description="Test role for permissions",
            security_level=SecurityLevel.INTERNAL
        )
        
        permission = SecurityPermission(
            name="test:permission",
            description="Test permission",
            resource_type="test",
            action="read"
        )
        
        db_session.add(role)
        db_session.add(permission)
        await db_session.commit()
        await db_session.refresh(role)
        await db_session.refresh(permission)
        
        # Create role-permission assignment
        role_permission = RolePermission(
            role_id=role.id,
            permission_id=permission.id,
            granted_by=1,
            is_active=True
        )
        
        db_session.add(role_permission)
        await db_session.commit()
        
        assert role_permission.id is not None
        assert role_permission.role_id == role.id
        assert role_permission.permission_id == permission.id
        assert role_permission.is_active is True

    @pytest.mark.asyncio
    async def test_security_policy_creation(self, db_session):
        """Test creating security policies"""
        policy = SecurityPolicy(
            name="Network Access Policy",
            description="Policy for network device access",
            policy_type="access",
            policy_rules={
                "rules": [
                    {
                        "type": "time_restriction",
                        "allowed_hours": [8, 9, 10, 11, 12, 13, 14, 15, 16, 17],
                        "message": "Access only allowed during business hours"
                    }
                ]
            },
            enforcement_level="enforce",
            priority=100,
            target_roles=["Network Administrator"],
            compliance_framework="SOX"
        )
        
        db_session.add(policy)
        await db_session.commit()
        await db_session.refresh(policy)
        
        assert policy.id is not None
        assert policy.name == "Network Access Policy"
        assert policy.policy_type == "access"
        assert policy.enforcement_level == "enforce"
        assert policy.is_active is True

    @pytest.mark.asyncio
    async def test_security_audit_log_creation(self, db_session):
        """Test creating security audit logs"""
        audit_log = SecurityAuditLog(
            event_type="authentication",
            event_category="authentication",
            event_action="login",
            user_id=1,
            username="testuser",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
            resource_type="user",
            resource_id="1",
            success=True,
            risk_score=2.5,
            event_data={"login_method": "password"},
            tags=["authentication", "login"]
        )
        
        db_session.add(audit_log)
        await db_session.commit()
        await db_session.refresh(audit_log)
        
        assert audit_log.id is not None
        assert audit_log.event_type == "authentication"
        assert audit_log.user_id == 1
        assert audit_log.success is True
        assert audit_log.risk_score == 2.5

    @pytest.mark.asyncio
    async def test_security_incident_creation(self, db_session):
        """Test creating security incidents"""
        incident = SecurityIncident(
            incident_id="INC-20240101-001",
            title="Suspicious Login Attempts",
            description="Multiple failed login attempts detected",
            incident_type="authentication_attack",
            threat_level=ThreatLevel.HIGH,
            status=IncidentStatus.OPEN,
            category="security",
            affected_systems=["web_server", "database"],
            business_impact="medium",
            source_ip="192.168.1.200",
            attack_vector="brute_force",
            indicators_of_compromise={
                "failed_attempts": 15,
                "time_window": "5 minutes",
                "source_ip": "192.168.1.200"
            },
            detected_at=datetime.now(),
            created_by=1
        )
        
        db_session.add(incident)
        await db_session.commit()
        await db_session.refresh(incident)
        
        assert incident.id is not None
        assert incident.incident_id == "INC-20240101-001"
        assert incident.threat_level == ThreatLevel.HIGH
        assert incident.status == IncidentStatus.OPEN
        assert incident.business_impact == "medium"

    @pytest.mark.asyncio
    async def test_vulnerability_assessment_creation(self, db_session):
        """Test creating vulnerability assessments"""
        assessment = VulnerabilityAssessment(
            assessment_id="VULN-20240101-001",
            name="Network Vulnerability Scan",
            description="Comprehensive network vulnerability assessment",
            assessment_type="automated",
            target_scope={
                "networks": ["192.168.1.0/24"],
                "devices": ["router", "switch", "firewall"],
                "max_vulnerabilities": 50
            },
            status="completed",
            progress_percentage=100.0,
            total_vulnerabilities=25,
            critical_count=3,
            high_count=7,
            medium_count=10,
            low_count=5,
            completed_at=datetime.now(),
            created_by=1
        )
        
        db_session.add(assessment)
        await db_session.commit()
        await db_session.refresh(assessment)
        
        assert assessment.id is not None
        assert assessment.assessment_id == "VULN-20240101-001"
        assert assessment.status == "completed"
        assert assessment.total_vulnerabilities == 25
        assert assessment.critical_count == 3

    @pytest.mark.asyncio
    async def test_vulnerability_creation(self, db_session, vulnerability_assessment):
        """Test creating vulnerability records"""
        vulnerability = Vulnerability(
            vulnerability_id="VULN-000001",
            cve_id="CVE-2023-1234",
            title="SQL Injection Vulnerability",
            description="Application vulnerable to SQL injection attacks",
            severity=VulnerabilitySeverity.HIGH,
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            exploit_available=True,
            assessment_id=vulnerability_assessment.id,
            device_id=1,
            service_name="web_server",
            port=80,
            protocol="http",
            status="open",
            remediation_status="not_started",
            discovered_at=datetime.now()
        )
        
        db_session.add(vulnerability)
        await db_session.commit()
        await db_session.refresh(vulnerability)
        
        assert vulnerability.id is not None
        assert vulnerability.vulnerability_id == "VULN-000001"
        assert vulnerability.cve_id == "CVE-2023-1234"
        assert vulnerability.severity == VulnerabilitySeverity.HIGH
        assert vulnerability.cvss_score == 8.5

    @pytest.mark.asyncio
    async def test_compliance_framework_creation(self, db_session):
        """Test creating compliance frameworks"""
        framework = ComplianceFramework(
            name="SOX Compliance",
            description="Sarbanes-Oxley Act compliance framework",
            framework_type="regulatory",
            version="2023",
            jurisdiction="United States",
            applicable_industries=["financial", "public"],
            total_requirements=50,
            implemented_requirements=45,
            compliance_percentage=90.0,
            assessment_frequency="annual",
            is_active=True
        )
        
        db_session.add(framework)
        await db_session.commit()
        await db_session.refresh(framework)
        
        assert framework.id is not None
        assert framework.name == "SOX Compliance"
        assert framework.framework_type == "regulatory"
        assert framework.compliance_percentage == 90.0

    @pytest.mark.asyncio
    async def test_compliance_requirement_creation(self, db_session, compliance_framework):
        """Test creating compliance requirements"""
        requirement = ComplianceRequirement(
            requirement_id="SOX-001",
            title="Access Control Requirements",
            description="Implement proper access controls for financial systems",
            framework_id=compliance_framework.id,
            category="access_control",
            priority="high",
            implementation_status="implemented",
            implementation_notes="RBAC system implemented with MFA",
            responsible_party="IT Security Team",
            implementation_date=datetime.now(),
            is_automated=True,
            monitoring_enabled=True
        )
        
        db_session.add(requirement)
        await db_session.commit()
        await db_session.refresh(requirement)
        
        assert requirement.id is not None
        assert requirement.requirement_id == "SOX-001"
        assert requirement.framework_id == compliance_framework.id
        assert requirement.implementation_status == "implemented"
        assert requirement.is_automated is True


class TestAccessControlService:
    """Test Access Control Service functionality"""

    @pytest.fixture
    def access_control_service(self, db_session):
        return AccessControlService(db_session)

    @pytest.mark.asyncio
    async def test_check_access_success(self, access_control_service, test_user, test_device):
        """Test successful access check"""
        # Mock user with roles and permissions
        with patch.object(access_control_service, '_get_user_with_roles') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch.object(access_control_service, '_get_user_permissions') as mock_get_permissions:
                mock_get_permissions.return_value = ["device:read", "device:write"]
                
                with patch.object(access_control_service, '_check_security_policies') as mock_check_policies:
                    mock_check_policies.return_value = []
                    
                    request = AccessRequest(
                        user_id=test_user.id,
                        resource_type="device",
                        resource_id=str(test_device.id),
                        action="read",
                        ip_address="192.168.1.100"
                    )
                    
                    result = await access_control_service.check_access(request)
                    
                    assert isinstance(result, PermissionCheck)
                    assert result.granted is True
                    assert result.user_permissions == ["device:read", "device:write"]

    @pytest.mark.asyncio
    async def test_check_access_insufficient_permissions(self, access_control_service, test_user):
        """Test access check with insufficient permissions"""
        with patch.object(access_control_service, '_get_user_with_roles') as mock_get_user:
            mock_get_user.return_value = test_user
            
            with patch.object(access_control_service, '_get_user_permissions') as mock_get_permissions:
                mock_get_permissions.return_value = ["device:read"]  # Missing write permission
                
                request = AccessRequest(
                    user_id=test_user.id,
                    resource_type="device",
                    resource_id="1",
                    action="write"
                )
                
                result = await access_control_service.check_access(request)
                
                assert isinstance(result, PermissionCheck)
                assert result.granted is False
                assert "Missing required permission" in result.reason

    @pytest.mark.asyncio
    async def test_grant_role(self, access_control_service, test_user):
        """Test granting a role to a user"""
        # Create a test role
        role = SecurityRole(
            name="Test Role",
            description="Test role for granting",
            security_level=SecurityLevel.INTERNAL
        )
        access_control_service.db_session.add(role)
        await access_control_service.db_session.commit()
        await access_control_service.db_session.refresh(role)
        
        result = await access_control_service.grant_role(
            user_id=test_user.id,
            role_id=role.id,
            granted_by=1
        )
        
        assert isinstance(result, AccessResult)
        assert result.success is True
        assert f"Role '{role.name}' granted" in result.message

    @pytest.mark.asyncio
    async def test_revoke_role(self, access_control_service, test_user):
        """Test revoking a role from a user"""
        # Create and grant a role first
        role = SecurityRole(
            name="Test Role",
            description="Test role for revoking",
            security_level=SecurityLevel.INTERNAL
        )
        access_control_service.db_session.add(role)
        await access_control_service.db_session.commit()
        await access_control_service.db_session.refresh(role)
        
        # Grant the role
        await access_control_service.grant_role(test_user.id, role.id, 1)
        
        # Now revoke it
        result = await access_control_service.revoke_role(
            user_id=test_user.id,
            role_id=role.id,
            revoked_by=1
        )
        
        assert isinstance(result, AccessResult)
        assert result.success is True
        assert f"Role '{role.name}' revoked" in result.message

    @pytest.mark.asyncio
    async def test_create_role(self, access_control_service):
        """Test creating a new security role"""
        result = await access_control_service.create_role(
            name="Network Operator",
            description="Network operations role",
            security_level=SecurityLevel.INTERNAL,
            created_by=1,
            permissions=[1, 2, 3]  # Mock permission IDs
        )
        
        assert isinstance(result, AccessResult)
        assert result.success is True
        assert "Role 'Network Operator' created" in result.message
        assert "role_id" in result.data


class TestAuditLoggingService:
    """Test Audit Logging Service functionality"""

    @pytest.fixture
    def audit_logging_service(self, db_session):
        return AuditLoggingService(db_session)

    @pytest.mark.asyncio
    async def test_log_event(self, audit_logging_service):
        """Test logging an audit event"""
        event = AuditEvent(
            event_type="authentication",
            event_category="authentication",
            event_action="login",
            user_id=1,
            username="testuser",
            success=True,
            ip_address="192.168.1.100"
        )
        
        result = await audit_logging_service.log_event(event)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "Event logged successfully" in result.message

    @pytest.mark.asyncio
    async def test_log_security_event(self, audit_logging_service):
        """Test logging a security event"""
        result = await audit_logging_service.log_security_event(
            event_type="access_control",
            user_id=1,
            resource_type="device",
            resource_id="1",
            action="read",
            success=True
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_log_authentication_event(self, audit_logging_service):
        """Test logging an authentication event"""
        result = await audit_logging_service.log_authentication_event(
            user_id=1,
            username="testuser",
            success=True
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_query_audit_logs(self, audit_logging_service):
        """Test querying audit logs"""
        # Create some test audit logs first
        for i in range(5):
            event = AuditEvent(
                event_type="authentication",
                event_category="authentication",
                event_action="login",
                user_id=1,
                success=True
            )
            await audit_logging_service.log_event(event)
        
        # Flush buffer to ensure events are in database
        await audit_logging_service._flush_buffer()
        
        query = AuditQuery(
            event_types=["authentication"],
            success_only=True,
            limit=10
        )
        
        result = await audit_logging_service.query_audit_logs(query)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert len(result.data) >= 5

    @pytest.mark.asyncio
    async def test_get_audit_statistics(self, audit_logging_service):
        """Test getting audit statistics"""
        start_time = datetime.now() - timedelta(hours=24)
        end_time = datetime.now()
        
        stats = await audit_logging_service.get_audit_statistics(start_time, end_time)
        
        assert isinstance(stats, AuditStats)
        assert stats.time_range == (start_time, end_time)
        assert stats.total_events >= 0

    @pytest.mark.asyncio
    async def test_detect_anomalies(self, audit_logging_service):
        """Test anomaly detection"""
        result = await audit_logging_service.detect_anomalies(time_window_hours=24)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_generate_compliance_report(self, audit_logging_service, compliance_framework):
        """Test generating compliance report"""
        start_time = datetime.now() - timedelta(days=30)
        end_time = datetime.now()
        
        result = await audit_logging_service.generate_compliance_report(
            framework_name=compliance_framework.name,
            start_time=start_time,
            end_time=end_time
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "framework" in result.data

    @pytest.mark.asyncio
    async def test_archive_old_logs(self, audit_logging_service):
        """Test archiving old logs"""
        result = await audit_logging_service.archive_old_logs(retention_days=365)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True


class TestThreatDetectionService:
    """Test Threat Detection Service functionality"""

    @pytest.fixture
    def threat_detection_service(self, db_session):
        return ThreatDetectionService(db_session)

    @pytest.mark.asyncio
    async def test_detect_threats(self, threat_detection_service):
        """Test threat detection"""
        result = await threat_detection_service.detect_threats(time_window_minutes=60)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "detected_threats" in result.data
        assert "correlated_incidents" in result.data
        assert "created_incidents" in result.data

    @pytest.mark.asyncio
    async def test_create_incident(self, threat_detection_service):
        """Test creating a security incident"""
        incident_data = {
            "title": "Test Security Incident",
            "description": "Test incident for unit testing",
            "incident_type": "security_breach",
            "threat_level": ThreatLevel.MEDIUM,
            "category": "security",
            "affected_systems": ["test_system"],
            "business_impact": "low"
        }
        
        result = await threat_detection_service.create_incident(incident_data, created_by=1)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "incident_id" in result.data
        assert "INC-" in result.data["incident_id"]

    @pytest.mark.asyncio
    async def test_update_incident_status(self, threat_detection_service):
        """Test updating incident status"""
        # Create an incident first
        incident_data = {
            "title": "Test Incident",
            "description": "Test incident",
            "incident_type": "security_breach",
            "threat_level": ThreatLevel.MEDIUM
        }
        
        create_result = await threat_detection_service.create_incident(incident_data, created_by=1)
        incident_id = create_result.data["incident_id"]
        
        # Update status
        result = await threat_detection_service.update_incident_status(
            incident_id=incident_id,
            new_status=IncidentStatus.INVESTIGATING,
            updated_by=1,
            notes="Starting investigation"
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_get_active_incidents(self, threat_detection_service):
        """Test getting active incidents"""
        result = await threat_detection_service.get_active_incidents()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_get_incident_timeline(self, threat_detection_service):
        """Test getting incident timeline"""
        # Create an incident first
        incident_data = {
            "title": "Test Incident",
            "description": "Test incident",
            "incident_type": "security_breach",
            "threat_level": ThreatLevel.MEDIUM
        }
        
        create_result = await threat_detection_service.create_incident(incident_data, created_by=1)
        incident_id = create_result.data["incident_id"]
        
        result = await threat_detection_service.get_incident_timeline(incident_id)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_scan_vulnerabilities(self, threat_detection_service):
        """Test vulnerability scanning"""
        target_scope = {
            "networks": ["192.168.1.0/24"],
            "max_vulnerabilities": 5
        }
        
        result = await threat_detection_service.scan_vulnerabilities(target_scope)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "assessment_id" in result.data
        assert "total_vulnerabilities" in result.data

    @pytest.mark.asyncio
    async def test_get_vulnerability_summary(self, threat_detection_service):
        """Test getting vulnerability summary"""
        result = await threat_detection_service.get_vulnerability_summary()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "vulnerability_summary" in result.data
        assert "recent_assessments" in result.data


# Fixtures for test data

@pytest.fixture
async def vulnerability_assessment(db_session):
    """Create a test vulnerability assessment"""
    assessment = VulnerabilityAssessment(
        assessment_id="VULN-TEST-001",
        name="Test Assessment",
        description="Test vulnerability assessment",
        assessment_type="automated",
        status="completed",
        total_vulnerabilities=0
    )
    
    db_session.add(assessment)
    await db_session.commit()
    await db_session.refresh(assessment)
    
    return assessment

@pytest.fixture
async def compliance_framework(db_session):
    """Create a test compliance framework"""
    framework = ComplianceFramework(
        name="Test Framework",
        description="Test compliance framework",
        framework_type="internal",
        total_requirements=10,
        implemented_requirements=8,
        compliance_percentage=80.0
    )
    
    db_session.add(framework)
    await db_session.commit()
    await db_session.refresh(framework)
    
    return framework


@pytest.mark.asyncio
async def test_integration_workflow(db_session):
    """Test integration workflow between security services"""
    # Initialize services
    access_control = AccessControlService(db_session)
    audit_logging = AuditLoggingService(db_session)
    threat_detection = ThreatDetectionService(db_session)
    
    # Test that services can be initialized and share the database session
    assert access_control.db_session == db_session
    assert audit_logging.db_session == db_session
    assert threat_detection.db_session == db_session
    
    # Test basic functionality
    event = AuditEvent(
        event_type="test",
        event_category="test",
        event_action="test",
        success=True
    )
    
    log_result = await audit_logging.log_event(event)
    assert log_result.success is True
    
    # Test threat detection
    threat_result = await threat_detection.detect_threats(time_window_minutes=60)
    assert threat_result.success is True
