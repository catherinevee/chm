"""
Tests for CHM Compliance Framework System

This module contains comprehensive tests for the compliance framework including:
- Compliance monitoring and policy enforcement
- Policy engine evaluation and automation
- Compliance reporting and dashboard capabilities
- Regulatory compliance and evidence collection
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from typing import List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.security import (
    ComplianceFramework, ComplianceRequirement, SecurityPolicy, SecurityAuditLog,
    ComplianceStatus, SecurityLevel
)
from ..models.result_objects import CollectionResult, OperationStatus
from ..services.compliance_monitoring import (
    ComplianceMonitoringService, ComplianceCheck, ComplianceViolation, ComplianceReport
)
from ..services.policy_engine import (
    PolicyEngine, PolicyRule, PolicyEvaluationContext, PolicyEvaluationResult,
    PolicyOperator, PolicyAction, PolicySeverity
)
from ..services.compliance_reporting import (
    ComplianceReportingService, ReportTemplate, ReportSchedule, ComplianceReport as ReportingComplianceReport
)


class TestComplianceMonitoringService:
    """Test Compliance Monitoring Service functionality"""

    @pytest.fixture
    def compliance_monitoring_service(self, db_session):
        return ComplianceMonitoringService(db_session)

    @pytest.mark.asyncio
    async def test_monitor_compliance_all_frameworks(self, compliance_monitoring_service):
        """Test monitoring compliance for all frameworks"""
        result = await compliance_monitoring_service.monitor_compliance()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "frameworks_monitored" in result.data
        assert "total_checks_performed" in result.data
        assert "total_violations_detected" in result.data

    @pytest.mark.asyncio
    async def test_monitor_compliance_specific_framework(self, compliance_monitoring_service, compliance_framework):
        """Test monitoring compliance for specific framework"""
        result = await compliance_monitoring_service.monitor_compliance(framework_id=compliance_framework.id)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert result.data["frameworks_monitored"] == 1

    @pytest.mark.asyncio
    async def test_assess_requirement_compliance(self, compliance_monitoring_service, compliance_requirement):
        """Test assessing compliance for a specific requirement"""
        result = await compliance_monitoring_service.assess_requirement_compliance(
            requirement_id=compliance_requirement.requirement_id,
            framework_id=compliance_requirement.framework_id
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "status" in result.data

    @pytest.mark.asyncio
    async def test_detect_compliance_violations(self, compliance_monitoring_service):
        """Test detecting compliance violations"""
        result = await compliance_monitoring_service.detect_compliance_violations()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_generate_compliance_report(self, compliance_monitoring_service, compliance_framework):
        """Test generating compliance report"""
        period_start = datetime.now() - timedelta(days=30)
        period_end = datetime.now()
        
        result = await compliance_monitoring_service.generate_compliance_report(
            framework_id=compliance_framework.id,
            report_type="assessment",
            period_start=period_start,
            period_end=period_end,
            generated_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "overall_compliance" in result.data
        assert "total_requirements" in result.data

    @pytest.mark.asyncio
    async def test_remediate_violation(self, compliance_monitoring_service):
        """Test remediating a compliance violation"""
        violation_id = "VIOL-TEST-001"
        remediation_actions = ["Update policy", "Implement controls"]
        
        result = await compliance_monitoring_service.remediate_violation(
            violation_id=violation_id,
            remediation_actions=remediation_actions,
            remediated_by=1,
            notes="Violation remediated through policy update"
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_get_compliance_dashboard_data(self, compliance_monitoring_service):
        """Test getting compliance dashboard data"""
        result = await compliance_monitoring_service.get_compliance_dashboard_data()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "overview" in result.data
        assert "frameworks" in result.data
        assert "recent_violations" in result.data

    @pytest.mark.asyncio
    async def test_schedule_compliance_assessment(self, compliance_monitoring_service, compliance_framework):
        """Test scheduling compliance assessment"""
        scheduled_date = datetime.now() + timedelta(days=30)
        
        result = await compliance_monitoring_service.schedule_compliance_assessment(
            framework_id=compliance_framework.id,
            assessment_type="annual",
            scheduled_date=scheduled_date,
            assessor="External Auditor",
            scheduled_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True


class TestPolicyEngine:
    """Test Policy Engine functionality"""

    @pytest.fixture
    def policy_engine(self, db_session):
        return PolicyEngine(db_session)

    @pytest.mark.asyncio
    async def test_evaluate_policies(self, policy_engine):
        """Test policy evaluation"""
        context = PolicyEvaluationContext(
            user_id=1,
            username="testuser",
            resource_type="device",
            resource_id="1",
            action="read",
            ip_address="192.168.1.100"
        )
        
        results = await policy_engine.evaluate_policies(context)
        
        assert isinstance(results, list)
        # Results may be empty if no policies match

    @pytest.mark.asyncio
    async def test_create_policy_rule(self, policy_engine):
        """Test creating a policy rule"""
        rule_data = {
            "name": "Test Access Policy",
            "description": "Test policy for access control",
            "conditions": [
                {
                    "type": "field_comparison",
                    "field": "action",
                    "operator": "equals",
                    "value": "read"
                }
            ],
            "actions": [
                {
                    "type": "allow",
                    "params": {}
                }
            ],
            "priority": 100,
            "enabled": True,
            "tags": ["access_control", "test"]
        }
        
        result = await policy_engine.create_policy_rule(rule_data, created_by=1)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "rule_id" in result.data

    @pytest.mark.asyncio
    async def test_update_policy_rule(self, policy_engine):
        """Test updating a policy rule"""
        # First create a rule
        rule_data = {
            "name": "Test Policy",
            "description": "Test policy",
            "conditions": [{"type": "field_comparison", "field": "action", "operator": "equals", "value": "read"}],
            "actions": [{"type": "allow", "params": {}}]
        }
        
        create_result = await policy_engine.create_policy_rule(rule_data, created_by=1)
        rule_id = create_result.data["rule_id"]
        
        # Update the rule
        updates = {
            "name": "Updated Test Policy",
            "description": "Updated test policy description"
        }
        
        result = await policy_engine.update_policy_rule(rule_id, updates, updated_by=1)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_delete_policy_rule(self, policy_engine):
        """Test deleting a policy rule"""
        # First create a rule
        rule_data = {
            "name": "Test Policy",
            "description": "Test policy",
            "conditions": [{"type": "field_comparison", "field": "action", "operator": "equals", "value": "read"}],
            "actions": [{"type": "allow", "params": {}}]
        }
        
        create_result = await policy_engine.create_policy_rule(rule_data, created_by=1)
        rule_id = create_result.data["rule_id"]
        
        # Delete the rule
        result = await policy_engine.delete_policy_rule(rule_id, deleted_by=1)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True

    @pytest.mark.asyncio
    async def test_get_policy_violations(self, policy_engine):
        """Test getting policy violations"""
        result = await policy_engine.get_policy_violations(time_window_hours=24)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_get_policy_performance_metrics(self, policy_engine):
        """Test getting policy performance metrics"""
        result = await policy_engine.get_policy_performance_metrics(time_window_hours=24)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "total_evaluations" in result.data
        assert "total_violations" in result.data
        assert "average_evaluation_time_ms" in result.data

    @pytest.mark.asyncio
    async def test_test_policy_rule(self, policy_engine):
        """Test testing a policy rule"""
        rule_data = {
            "name": "Test Policy",
            "description": "Test policy",
            "conditions": [
                {
                    "type": "field_comparison",
                    "field": "action",
                    "operator": "equals",
                    "value": "read"
                }
            ],
            "actions": [
                {
                    "type": "allow",
                    "params": {}
                }
            ]
        }
        
        test_context = PolicyEvaluationContext(
            user_id=1,
            resource_type="device",
            action="read"
        )
        
        result = await policy_engine.test_policy_rule(rule_data, test_context)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "evaluation_result" in result.data


class TestComplianceReportingService:
    """Test Compliance Reporting Service functionality"""

    @pytest.fixture
    def compliance_reporting_service(self, db_session):
        return ComplianceReportingService(db_session)

    @pytest.mark.asyncio
    async def test_generate_report(self, compliance_reporting_service, compliance_framework):
        """Test generating compliance report"""
        period_start = datetime.now() - timedelta(days=30)
        period_end = datetime.now()
        
        result = await compliance_reporting_service.generate_report(
            template_id="executive_template",
            framework_id=compliance_framework.id,
            period_start=period_start,
            period_end=period_end,
            generated_by=1,
            format="html"
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "report_id" in result.data
        assert "file_path" in result.data

    @pytest.mark.asyncio
    async def test_generate_executive_summary(self, compliance_reporting_service, compliance_framework):
        """Test generating executive summary"""
        period_start = datetime.now() - timedelta(days=30)
        period_end = datetime.now()
        
        result = await compliance_reporting_service.generate_executive_summary(
            framework_id=compliance_framework.id,
            period_start=period_start,
            period_end=period_end,
            generated_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "report_id" in result.data
        assert "file_path" in result.data
        assert "summary_data" in result.data

    @pytest.mark.asyncio
    async def test_generate_regulatory_report(self, compliance_reporting_service, compliance_framework):
        """Test generating regulatory report"""
        period_start = datetime.now() - timedelta(days=30)
        period_end = datetime.now()
        
        result = await compliance_reporting_service.generate_regulatory_report(
            framework_id=compliance_framework.id,
            report_type="annual",
            period_start=period_start,
            period_end=period_end,
            generated_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "report_id" in result.data
        assert "file_path" in result.data

    @pytest.mark.asyncio
    async def test_export_compliance_data_csv(self, compliance_reporting_service, compliance_framework):
        """Test exporting compliance data to CSV"""
        period_start = datetime.now() - timedelta(days=30)
        period_end = datetime.now()
        
        result = await compliance_reporting_service.export_compliance_data(
            framework_id=compliance_framework.id,
            format="csv",
            period_start=period_start,
            period_end=period_end
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "file_path" in result.data

    @pytest.mark.asyncio
    async def test_export_compliance_data_json(self, compliance_reporting_service, compliance_framework):
        """Test exporting compliance data to JSON"""
        period_start = datetime.now() - timedelta(days=30)
        period_end = datetime.now()
        
        result = await compliance_reporting_service.export_compliance_data(
            framework_id=compliance_framework.id,
            format="json",
            period_start=period_start,
            period_end=period_end
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "file_path" in result.data

    @pytest.mark.asyncio
    async def test_schedule_report(self, compliance_reporting_service, compliance_framework):
        """Test scheduling report"""
        result = await compliance_reporting_service.schedule_report(
            template_id="executive_template",
            framework_id=compliance_framework.id,
            frequency="monthly",
            recipients=["executives@company.com"],
            delivery_method="email",
            delivery_config={"subject": "Monthly Compliance Report"},
            scheduled_by=1
        )
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert "schedule_id" in result.data

    @pytest.mark.asyncio
    async def test_get_report_history(self, compliance_reporting_service):
        """Test getting report history"""
        result = await compliance_reporting_service.get_report_history(limit=10)
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)

    @pytest.mark.asyncio
    async def test_get_report_templates(self, compliance_reporting_service):
        """Test getting report templates"""
        result = await compliance_reporting_service.get_report_templates()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)
        assert len(result.data) > 0

    @pytest.mark.asyncio
    async def test_get_scheduled_reports(self, compliance_reporting_service):
        """Test getting scheduled reports"""
        result = await compliance_reporting_service.get_scheduled_reports()
        
        assert isinstance(result, CollectionResult)
        assert result.success is True
        assert isinstance(result.data, list)


class TestComplianceModels:
    """Test compliance model functionality"""

    @pytest.mark.asyncio
    async def test_compliance_framework_creation(self, db_session):
        """Test creating compliance framework"""
        framework = ComplianceFramework(
            name="Test Compliance Framework",
            description="Test framework for compliance testing",
            framework_type="regulatory",
            version="2023",
            jurisdiction="United States",
            applicable_industries=["technology", "finance"],
            total_requirements=25,
            implemented_requirements=20,
            compliance_percentage=80.0,
            assessment_frequency="annual",
            is_active=True
        )
        
        db_session.add(framework)
        await db_session.commit()
        await db_session.refresh(framework)
        
        assert framework.id is not None
        assert framework.name == "Test Compliance Framework"
        assert framework.framework_type == "regulatory"
        assert framework.compliance_percentage == 80.0

    @pytest.mark.asyncio
    async def test_compliance_requirement_creation(self, db_session, compliance_framework):
        """Test creating compliance requirement"""
        requirement = ComplianceRequirement(
            requirement_id="TEST-001",
            title="Test Compliance Requirement",
            description="Test requirement for compliance testing",
            framework_id=compliance_framework.id,
            category="access_control",
            priority="high",
            implementation_status="implemented",
            implementation_notes="Requirement implemented with RBAC system",
            responsible_party="IT Security Team",
            implementation_date=datetime.now(),
            is_automated=True,
            monitoring_enabled=True
        )
        
        db_session.add(requirement)
        await db_session.commit()
        await db_session.refresh(requirement)
        
        assert requirement.id is not None
        assert requirement.requirement_id == "TEST-001"
        assert requirement.framework_id == compliance_framework.id
        assert requirement.implementation_status == "implemented"
        assert requirement.is_automated is True

    @pytest.mark.asyncio
    async def test_security_policy_creation(self, db_session):
        """Test creating security policy"""
        policy = SecurityPolicy(
            name="Test Security Policy",
            description="Test policy for security testing",
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
            target_roles=["admin", "operator"],
            compliance_framework="SOX"
        )
        
        db_session.add(policy)
        await db_session.commit()
        await db_session.refresh(policy)
        
        assert policy.id is not None
        assert policy.name == "Test Security Policy"
        assert policy.policy_type == "access"
        assert policy.enforcement_level == "enforce"
        assert policy.is_active is True


class TestComplianceDataStructures:
    """Test compliance data structures"""

    def test_compliance_check_creation(self):
        """Test creating compliance check"""
        check = ComplianceCheck(
            requirement_id="TEST-001",
            framework_id=1,
            check_type="automated",
            check_frequency="real_time",
            check_conditions={
                "check_type": "rbac_validation",
                "required_roles": ["admin", "operator"]
            },
            last_check=datetime.now(),
            last_result=ComplianceStatus.COMPLIANT,
            evidence_location="/compliance/evidence/test.json",
            remediation_required=False
        )
        
        assert check.requirement_id == "TEST-001"
        assert check.check_type == "automated"
        assert check.last_result == ComplianceStatus.COMPLIANT
        assert check.remediation_required is False

    def test_compliance_violation_creation(self):
        """Test creating compliance violation"""
        violation = ComplianceViolation(
            violation_id="VIOL-TEST-001",
            requirement_id="TEST-001",
            framework_id=1,
            violation_type="implementation_gap",
            severity="high",
            description="Test compliance violation",
            detected_at=datetime.now(),
            affected_resources=["access_control"],
            evidence={"implementation_status": "not_implemented"},
            remediation_actions=["Implement requirement", "Update documentation"],
            status="open"
        )
        
        assert violation.violation_id == "VIOL-TEST-001"
        assert violation.severity == "high"
        assert violation.status == "open"
        assert len(violation.remediation_actions) == 2

    def test_policy_rule_creation(self):
        """Test creating policy rule"""
        rule = PolicyRule(
            rule_id="POL-TEST-001",
            name="Test Policy Rule",
            description="Test policy rule for testing",
            conditions=[
                {
                    "type": "field_comparison",
                    "field": "action",
                    "operator": "equals",
                    "value": "read"
                }
            ],
            actions=[
                {
                    "type": "allow",
                    "params": {}
                }
            ],
            priority=100,
            enabled=True,
            tags=["access_control", "test"],
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        assert rule.rule_id == "POL-TEST-001"
        assert rule.name == "Test Policy Rule"
        assert rule.priority == 100
        assert rule.enabled is True
        assert len(rule.conditions) == 1
        assert len(rule.actions) == 1

    def test_policy_evaluation_context_creation(self):
        """Test creating policy evaluation context"""
        context = PolicyEvaluationContext(
            user_id=1,
            username="testuser",
            session_id="session123",
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
            resource_type="device",
            resource_id="1",
            action="read",
            timestamp=datetime.now(),
            metadata={"department": "IT", "location": "office"}
        )
        
        assert context.user_id == 1
        assert context.username == "testuser"
        assert context.resource_type == "device"
        assert context.action == "read"
        assert context.metadata["department"] == "IT"

    def test_report_template_creation(self):
        """Test creating report template"""
        template = ReportTemplate(
            template_id="TEMPLATE-TEST-001",
            name="Test Report Template",
            description="Test template for report generation",
            report_type="executive",
            framework_type="all",
            sections=[
                {"name": "overview", "title": "Compliance Overview"},
                {"name": "metrics", "title": "Key Metrics"}
            ],
            format_options={"include_charts": True, "include_details": False},
            created_at=datetime.now(),
            updated_at=datetime.now()
        )
        
        assert template.template_id == "TEMPLATE-TEST-001"
        assert template.report_type == "executive"
        assert len(template.sections) == 2
        assert template.format_options["include_charts"] is True


# Fixtures for test data

@pytest.fixture
async def compliance_framework(db_session):
    """Create a test compliance framework"""
    framework = ComplianceFramework(
        name="Test Framework",
        description="Test compliance framework",
        framework_type="regulatory",
        version="2023",
        jurisdiction="United States",
        total_requirements=10,
        implemented_requirements=8,
        compliance_percentage=80.0
    )
    
    db_session.add(framework)
    await db_session.commit()
    await db_session.refresh(framework)
    
    return framework

@pytest.fixture
async def compliance_requirement(db_session, compliance_framework):
    """Create a test compliance requirement"""
    requirement = ComplianceRequirement(
        requirement_id="TEST-001",
        title="Test Requirement",
        description="Test compliance requirement",
        framework_id=compliance_framework.id,
        category="access_control",
        priority="high",
        implementation_status="implemented"
    )
    
    db_session.add(requirement)
    await db_session.commit()
    await db_session.refresh(requirement)
    
    return requirement


@pytest.mark.asyncio
async def test_integration_workflow(db_session):
    """Test integration workflow between compliance services"""
    # Initialize services
    compliance_monitoring = ComplianceMonitoringService(db_session)
    policy_engine = PolicyEngine(db_session)
    compliance_reporting = ComplianceReportingService(db_session)
    
    # Test that services can be initialized and share the database session
    assert compliance_monitoring.db_session == db_session
    assert policy_engine.db_session == db_session
    assert compliance_reporting.db_session == db_session
    
    # Test basic functionality
    monitoring_result = await compliance_monitoring.monitor_compliance()
    assert monitoring_result.success is True
    
    # Test policy evaluation
    context = PolicyEvaluationContext(
        user_id=1,
        resource_type="device",
        action="read"
    )
    policy_results = await policy_engine.evaluate_policies(context)
    assert isinstance(policy_results, list)
    
    # Test report generation
    templates_result = await compliance_reporting.get_report_templates()
    assert templates_result.success is True
    assert len(templates_result.data) > 0
