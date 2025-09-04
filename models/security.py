"""
Security Models for CHM Security & Compliance System

This module defines comprehensive security models including:
- Role-Based Access Control (RBAC)
- Security policies and permissions
- Audit logging and compliance tracking
- Threat detection and incident management
- Vulnerability assessment and remediation
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, ARRAY as PG_ARRAY, INET
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from ..core.database import Base


class SecurityLevel(str, Enum):
    """Security classification levels"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"


class ThreatLevel(str, Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IncidentStatus(str, Enum):
    """Security incident status"""
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ComplianceStatus(str, Enum):
    """Compliance status levels"""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"
    EXEMPT = "exempt"


class SecurityRole(Base):
    """Security roles for RBAC system"""
    __tablename__ = "security_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    security_level = Column(String(50), default=SecurityLevel.INTERNAL, nullable=False)
    
    # Role configuration
    is_system_role = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    max_session_duration = Column(Integer, default=28800, nullable=False)  # 8 hours in seconds
    requires_mfa = Column(Boolean, default=False, nullable=False)
    allowed_ip_ranges = Column(PG_ARRAY(String), nullable=True)
    allowed_time_windows = Column(JSON, nullable=True)  # Time-based access control
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    permissions = relationship("SecurityPermission", secondary="role_permissions", back_populates="roles")
    users = relationship("User", secondary="user_roles", back_populates="security_roles")
    
    def __repr__(self):
        return f"<SecurityRole(id={self.id}, name='{self.name}', level='{self.security_level}')>"


class SecurityPermission(Base):
    """Security permissions for fine-grained access control"""
    __tablename__ = "security_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    resource_type = Column(String(100), nullable=False, index=True)  # device, metric, alert, etc.
    action = Column(String(50), nullable=False, index=True)  # read, write, delete, execute
    resource_pattern = Column(String(500), nullable=True)  # Pattern for resource matching
    
    # Permission configuration
    is_system_permission = Column(Boolean, default=False, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    conditions = Column(JSON, nullable=True)  # Additional conditions for permission
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    roles = relationship("SecurityRole", secondary="role_permissions", back_populates="permissions")
    
    def __repr__(self):
        return f"<SecurityPermission(id={self.id}, name='{self.name}', resource='{self.resource_type}')>"


class RolePermission(Base):
    """Many-to-many relationship between roles and permissions"""
    __tablename__ = "role_permissions"
    
    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("security_roles.id"), nullable=False)
    permission_id = Column(Integer, ForeignKey("security_permissions.id"), nullable=False)
    
    # Relationship configuration
    granted_at = Column(DateTime, default=func.now(), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('role_id', 'permission_id', name='uq_role_permission'),
        Index('idx_role_permission_active', 'role_id', 'permission_id', 'is_active'),
    )


class UserRole(Base):
    """Many-to-many relationship between users and security roles"""
    __tablename__ = "user_roles"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    role_id = Column(Integer, ForeignKey("security_roles.id"), nullable=False)
    
    # Role assignment configuration
    assigned_at = Column(DateTime, default=func.now(), nullable=False)
    assigned_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Audit fields
    last_used = Column(DateTime, nullable=True)
    usage_count = Column(Integer, default=0, nullable=False)
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='uq_user_role'),
        Index('idx_user_role_active', 'user_id', 'role_id', 'is_active'),
    )


class SecurityPolicy(Base):
    """Security policies for access control and compliance"""
    __tablename__ = "security_policies"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    policy_type = Column(String(100), nullable=False, index=True)  # access, data, network, etc.
    
    # Policy configuration
    policy_rules = Column(JSON, nullable=False)  # Policy rules and conditions
    enforcement_level = Column(String(50), default="enforce", nullable=False)  # enforce, warn, audit
    is_active = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False)  # Lower number = higher priority
    
    # Scope and targeting
    target_roles = Column(PG_ARRAY(String), nullable=True)
    target_resources = Column(PG_ARRAY(String), nullable=True)
    target_users = Column(PG_ARRAY(Integer), nullable=True)
    
    # Compliance and audit
    compliance_framework = Column(String(100), nullable=True)  # SOX, HIPAA, PCI-DSS, etc.
    audit_frequency = Column(String(50), default="daily", nullable=False)
    last_audit = Column(DateTime, nullable=True)
    next_audit = Column(DateTime, nullable=True)
    
    # Timestamps
    effective_from = Column(DateTime, default=func.now(), nullable=False)
    effective_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    def __repr__(self):
        return f"<SecurityPolicy(id={self.id}, name='{self.name}', type='{self.policy_type}')>"


class SecurityAuditLog(Base):
    """Comprehensive security audit logging"""
    __tablename__ = "security_audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(UUID(as_uuid=True), unique=True, default=func.uuid_generate_v4(), index=True)
    
    # Event details
    event_type = Column(String(100), nullable=False, index=True)  # login, access, policy_violation, etc.
    event_category = Column(String(50), nullable=False, index=True)  # authentication, authorization, data_access, etc.
    event_action = Column(String(100), nullable=False, index=True)  # create, read, update, delete, execute
    
    # Actor information
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)
    session_id = Column(String(255), nullable=True, index=True)
    ip_address = Column(INET, nullable=True, index=True)
    user_agent = Column(Text, nullable=True)
    
    # Resource information
    resource_type = Column(String(100), nullable=True, index=True)
    resource_id = Column(String(100), nullable=True, index=True)
    resource_name = Column(String(500), nullable=True)
    
    # Event outcome
    success = Column(Boolean, nullable=False, index=True)
    failure_reason = Column(String(500), nullable=True)
    risk_score = Column(Float, nullable=True)  # 0.0 to 10.0
    
    # Additional context
    event_data = Column(JSON, nullable=True)  # Additional event-specific data
    tags = Column(PG_ARRAY(String), nullable=True)
    
    # Compliance and correlation
    compliance_framework = Column(String(100), nullable=True)
    correlation_id = Column(String(255), nullable=True, index=True)
    parent_event_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    
    # Timestamps
    timestamp = Column(DateTime, default=func.now(), nullable=False, index=True)
    processed_at = Column(DateTime, nullable=True)
    
    # Relationships
    user = relationship("User", foreign_keys=[user_id])
    
    def __repr__(self):
        return f"<SecurityAuditLog(id={self.id}, event='{self.event_type}', user='{self.username}')>"


class SecurityIncident(Base):
    """Security incident management and tracking"""
    __tablename__ = "security_incidents"
    
    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Incident classification
    incident_type = Column(String(100), nullable=False, index=True)  # breach, malware, ddos, etc.
    threat_level = Column(String(50), default=ThreatLevel.MEDIUM, nullable=False, index=True)
    status = Column(String(50), default=IncidentStatus.OPEN, nullable=False, index=True)
    category = Column(String(100), nullable=True, index=True)  # security, privacy, availability, etc.
    
    # Impact assessment
    affected_systems = Column(PG_ARRAY(String), nullable=True)
    affected_users = Column(PG_ARRAY(Integer), nullable=True)
    business_impact = Column(String(50), nullable=True)  # low, medium, high, critical
    data_impact = Column(String(50), nullable=True)  # none, limited, significant, severe
    
    # Incident details
    source_ip = Column(INET, nullable=True)
    target_ip = Column(INET, nullable=True)
    attack_vector = Column(String(200), nullable=True)
    indicators_of_compromise = Column(JSON, nullable=True)
    
    # Response and resolution
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    response_team = Column(PG_ARRAY(Integer), nullable=True)
    containment_actions = Column(JSON, nullable=True)
    remediation_actions = Column(JSON, nullable=True)
    
    # Timeline
    detected_at = Column(DateTime, nullable=False, index=True)
    reported_at = Column(DateTime, default=func.now(), nullable=False)
    contained_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    
    # Compliance and reporting
    regulatory_notification_required = Column(Boolean, default=False, nullable=False)
    notification_sent = Column(Boolean, default=False, nullable=False)
    notification_date = Column(DateTime, nullable=True)
    compliance_framework = Column(String(100), nullable=True)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    assignee = relationship("User", foreign_keys=[assigned_to])
    creator = relationship("User", foreign_keys=[created_by])
    
    def __repr__(self):
        return f"<SecurityIncident(id={self.id}, incident_id='{self.incident_id}', status='{self.status}')>"


class VulnerabilityAssessment(Base):
    """Vulnerability assessment and management"""
    __tablename__ = "vulnerability_assessments"
    
    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(String(100), unique=True, nullable=False, index=True)
    name = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Assessment details
    assessment_type = Column(String(100), nullable=False, index=True)  # automated, manual, penetration_test
    target_scope = Column(JSON, nullable=True)  # Devices, networks, applications to assess
    assessment_tool = Column(String(200), nullable=True)  # Tool used for assessment
    
    # Vulnerability findings
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    informational_count = Column(Integer, default=0, nullable=False)
    
    # Assessment status
    status = Column(String(50), default="scheduled", nullable=False, index=True)  # scheduled, running, completed, failed
    progress_percentage = Column(Float, default=0.0, nullable=False)
    
    # Timestamps
    scheduled_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    
    # Audit fields
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    vulnerabilities = relationship("Vulnerability", back_populates="assessment")
    
    def __repr__(self):
        return f"<VulnerabilityAssessment(id={self.id}, assessment_id='{self.assessment_id}', status='{self.status}')>"


class Vulnerability(Base):
    """Individual vulnerability findings"""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    vulnerability_id = Column(String(100), unique=True, nullable=False, index=True)
    cve_id = Column(String(50), nullable=True, index=True)  # Common Vulnerabilities and Exposures ID
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Vulnerability details
    severity = Column(String(50), nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)  # Common Vulnerability Scoring System
    cvss_vector = Column(String(200), nullable=True)
    exploit_available = Column(Boolean, default=False, nullable=False)
    exploit_maturity = Column(String(50), nullable=True)  # proof_of_concept, functional, high
    
    # Affected systems
    assessment_id = Column(Integer, ForeignKey("vulnerability_assessments.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    service_name = Column(String(200), nullable=True)
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    
    # Vulnerability status
    status = Column(String(50), default="open", nullable=False, index=True)  # open, confirmed, mitigated, resolved, false_positive
    remediation_status = Column(String(50), nullable=True)  # not_started, in_progress, completed, not_applicable
    
    # Remediation information
    remediation_notes = Column(Text, nullable=True)
    remediation_priority = Column(String(50), nullable=True)  # critical, high, medium, low
    estimated_effort = Column(String(50), nullable=True)  # hours, days, weeks
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Timeline
    discovered_at = Column(DateTime, default=func.now(), nullable=False)
    confirmed_at = Column(DateTime, nullable=True)
    mitigated_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    assessment = relationship("VulnerabilityAssessment", back_populates="vulnerabilities")
    device = relationship("Device")
    assignee = relationship("User", foreign_keys=[assigned_to])
    
    def __repr__(self):
        return f"<Vulnerability(id={self.id}, cve_id='{self.cve_id}', severity='{self.severity}')>"


class ComplianceFramework(Base):
    """Compliance framework definitions and requirements"""
    __tablename__ = "compliance_frameworks"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    framework_type = Column(String(100), nullable=False, index=True)  # regulatory, industry, internal
    
    # Framework details
    version = Column(String(50), nullable=True)
    jurisdiction = Column(String(100), nullable=True)  # Country or region
    applicable_industries = Column(PG_ARRAY(String), nullable=True)
    
    # Requirements and controls
    total_requirements = Column(Integer, default=0, nullable=False)
    implemented_requirements = Column(Integer, default=0, nullable=False)
    compliance_percentage = Column(Float, default=0.0, nullable=False)
    
    # Assessment and audit
    last_assessment = Column(DateTime, nullable=True)
    next_assessment = Column(DateTime, nullable=True)
    assessment_frequency = Column(String(50), default="annual", nullable=False)
    auditor = Column(String(200), nullable=True)
    
    # Status and configuration
    is_active = Column(Boolean, default=True, nullable=False)
    auto_assessment_enabled = Column(Boolean, default=False, nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Relationships
    creator = relationship("User", foreign_keys=[created_by])
    requirements = relationship("ComplianceRequirement", back_populates="framework")
    
    def __repr__(self):
        return f"<ComplianceFramework(id={self.id}, name='{self.name}', type='{self.framework_type}')>"


class ComplianceRequirement(Base):
    """Individual compliance requirements and controls"""
    __tablename__ = "compliance_requirements"
    
    id = Column(Integer, primary_key=True, index=True)
    requirement_id = Column(String(100), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Requirement details
    framework_id = Column(Integer, ForeignKey("compliance_frameworks.id"), nullable=False)
    category = Column(String(100), nullable=True, index=True)  # access_control, data_protection, etc.
    subcategory = Column(String(100), nullable=True)
    priority = Column(String(50), default="medium", nullable=False)  # critical, high, medium, low
    
    # Implementation details
    implementation_status = Column(String(50), default="not_implemented", nullable=False, index=True)
    implementation_notes = Column(Text, nullable=True)
    responsible_party = Column(String(200), nullable=True)
    implementation_date = Column(DateTime, nullable=True)
    
    # Assessment and evidence
    last_assessed = Column(DateTime, nullable=True)
    assessment_result = Column(String(50), nullable=True)  # compliant, non_compliant, partially_compliant
    evidence_location = Column(String(500), nullable=True)
    assessor = Column(String(200), nullable=True)
    
    # Automation and monitoring
    is_automated = Column(Boolean, default=False, nullable=False)
    monitoring_enabled = Column(Boolean, default=False, nullable=False)
    alert_threshold = Column(String(100), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    framework = relationship("ComplianceFramework", back_populates="requirements")
    
    def __repr__(self):
        return f"<ComplianceRequirement(id={self.id}, requirement_id='{self.requirement_id}', status='{self.implementation_status}')>"
