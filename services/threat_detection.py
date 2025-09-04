"""
Threat Detection & Incident Response Service for CHM Security & Compliance System

This service provides comprehensive threat detection and incident response capabilities including:
- Real-time threat detection and analysis
- Security incident management and tracking
- Automated response and containment
- Threat intelligence integration
- Incident correlation and escalation
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import uuid
from collections import defaultdict, Counter
import statistics

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload

from ..models.security import (
    SecurityIncident, SecurityAuditLog, VulnerabilityAssessment, Vulnerability,
    ThreatLevel, IncidentStatus, VulnerabilitySeverity
)
from ..models.result_objects import CollectionResult, OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class ThreatIndicator:
    """Threat indicator data structure"""
    indicator_type: str  # ip, domain, hash, email, etc.
    indicator_value: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    source: str
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: Optional[List[str]] = None


@dataclass
class IncidentContext:
    """Incident context and metadata"""
    incident_id: str
    title: str
    description: str
    incident_type: str
    threat_level: ThreatLevel
    affected_systems: List[str]
    indicators_of_compromise: List[Dict[str, Any]]
    timeline: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    response_actions: List[Dict[str, Any]]


@dataclass
class DetectionRule:
    """Threat detection rule configuration"""
    rule_id: str
    name: str
    description: str
    rule_type: str  # pattern, threshold, anomaly, correlation
    conditions: Dict[str, Any]
    actions: List[str]
    enabled: bool = True
    priority: int = 100
    tags: Optional[List[str]] = None


class ThreatDetectionService:
    """Service for threat detection and incident response"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._detection_rules = {}
        self._threat_indicators = {}
        self._incident_correlations = defaultdict(list)
        self._load_detection_rules()
    
    async def detect_threats(self, time_window_minutes: int = 60) -> CollectionResult:
        """Detect threats based on audit logs and detection rules"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(minutes=time_window_minutes)
            
            # Get recent audit events
            events_result = await self.db_session.execute(
                select(SecurityAuditLog).where(
                    and_(
                        SecurityAuditLog.timestamp >= start_time,
                        SecurityAuditLog.timestamp <= end_time
                    )
                ).order_by(desc(SecurityAuditLog.timestamp))
            )
            events = events_result.scalars().all()
            
            detected_threats = []
            
            # Run detection rules
            for rule_id, rule in self._detection_rules.items():
                if not rule.enabled:
                    continue
                
                threats = await self._evaluate_detection_rule(rule, events)
                detected_threats.extend(threats)
            
            # Correlate related threats
            correlated_incidents = await self._correlate_threats(detected_threats)
            
            # Create incidents for high-priority threats
            created_incidents = []
            for threat in detected_threats:
                if threat.get('threat_level') in ['critical', 'high']:
                    incident = await self._create_incident_from_threat(threat)
                    if incident:
                        created_incidents.append(incident)
            
            return CollectionResult(
                success=True,
                data={
                    "detected_threats": detected_threats,
                    "correlated_incidents": correlated_incidents,
                    "created_incidents": created_incidents,
                    "time_window": f"{time_window_minutes} minutes"
                },
                message=f"Detected {len(detected_threats)} threats, created {len(created_incidents)} incidents"
            )
            
        except Exception as e:
            logger.error(f"Error detecting threats: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to detect threats: {str(e)}"
            )
    
    async def create_incident(self, incident_data: Dict[str, Any], created_by: int) -> CollectionResult:
        """Create a new security incident"""
        try:
            # Generate incident ID
            incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            
            # Create incident
            incident = SecurityIncident(
                incident_id=incident_id,
                title=incident_data.get('title', 'Security Incident'),
                description=incident_data.get('description', ''),
                incident_type=incident_data.get('incident_type', 'security_breach'),
                threat_level=incident_data.get('threat_level', ThreatLevel.MEDIUM),
                status=IncidentStatus.OPEN,
                category=incident_data.get('category', 'security'),
                affected_systems=incident_data.get('affected_systems', []),
                affected_users=incident_data.get('affected_users', []),
                business_impact=incident_data.get('business_impact'),
                data_impact=incident_data.get('data_impact'),
                source_ip=incident_data.get('source_ip'),
                target_ip=incident_data.get('target_ip'),
                attack_vector=incident_data.get('attack_vector'),
                indicators_of_compromise=incident_data.get('indicators_of_compromise', {}),
                assigned_to=incident_data.get('assigned_to'),
                response_team=incident_data.get('response_team', []),
                detected_at=incident_data.get('detected_at', datetime.now()),
                created_by=created_by
            )
            
            self.db_session.add(incident)
            await self.db_session.commit()
            await self.db_session.refresh(incident)
            
            # Log incident creation
            await self._log_incident_event(
                incident_id=incident_id,
                event_type="incident_created",
                user_id=created_by,
                event_data={"incident_data": incident_data}
            )
            
            return CollectionResult(
                success=True,
                data={"incident_id": incident_id, "incident": incident},
                message=f"Created incident {incident_id}"
            )
            
        except Exception as e:
            logger.error(f"Error creating incident: {str(e)}")
            await self.db_session.rollback()
            return CollectionResult(
                success=False,
                error=f"Failed to create incident: {str(e)}"
            )
    
    async def update_incident_status(self, incident_id: str, new_status: IncidentStatus,
                                   updated_by: int, notes: Optional[str] = None) -> CollectionResult:
        """Update incident status"""
        try:
            # Find incident
            incident_result = await self.db_session.execute(
                select(SecurityIncident).where(SecurityIncident.incident_id == incident_id)
            )
            incident = incident_result.scalar_one_or_none()
            
            if not incident:
                return CollectionResult(
                    success=False,
                    error=f"Incident {incident_id} not found"
                )
            
            # Update status
            old_status = incident.status
            incident.status = new_status
            
            # Update timestamps based on status
            now = datetime.now()
            if new_status == IncidentStatus.CONTAINED and not incident.contained_at:
                incident.contained_at = now
            elif new_status == IncidentStatus.RESOLVED and not incident.resolved_at:
                incident.resolved_at = now
            elif new_status == IncidentStatus.CLOSED and not incident.closed_at:
                incident.closed_at = now
            
            await self.db_session.commit()
            
            # Log status change
            await self._log_incident_event(
                incident_id=incident_id,
                event_type="status_changed",
                user_id=updated_by,
                event_data={
                    "old_status": old_status,
                    "new_status": new_status,
                    "notes": notes
                }
            )
            
            return CollectionResult(
                success=True,
                message=f"Updated incident {incident_id} status to {new_status}"
            )
            
        except Exception as e:
            logger.error(f"Error updating incident status: {str(e)}")
            await self.db_session.rollback()
            return CollectionResult(
                success=False,
                error=f"Failed to update incident status: {str(e)}"
            )
    
    async def get_active_incidents(self) -> CollectionResult:
        """Get all active security incidents"""
        try:
            active_statuses = [
                IncidentStatus.OPEN,
                IncidentStatus.INVESTIGATING,
                IncidentStatus.CONTAINED
            ]
            
            incidents_result = await self.db_session.execute(
                select(SecurityIncident).where(
                    SecurityIncident.status.in_(active_statuses)
                ).order_by(desc(SecurityIncident.threat_level), desc(SecurityIncident.detected_at))
            )
            incidents = incidents_result.scalars().all()
            
            return CollectionResult(
                success=True,
                data=incidents,
                message=f"Retrieved {len(incidents)} active incidents"
            )
            
        except Exception as e:
            logger.error(f"Error getting active incidents: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get active incidents: {str(e)}"
            )
    
    async def get_incident_timeline(self, incident_id: str) -> CollectionResult:
        """Get timeline of events for an incident"""
        try:
            # Get incident
            incident_result = await self.db_session.execute(
                select(SecurityIncident).where(SecurityIncident.incident_id == incident_id)
            )
            incident = incident_result.scalar_one_or_none()
            
            if not incident:
                return CollectionResult(
                    success=False,
                    error=f"Incident {incident_id} not found"
                )
            
            # Get related audit events
            events_result = await self.db_session.execute(
                select(SecurityAuditLog).where(
                    or_(
                        SecurityAuditLog.correlation_id == incident_id,
                        SecurityAuditLog.event_data.contains({"incident_id": incident_id})
                    )
                ).order_by(asc(SecurityAuditLog.timestamp))
            )
            events = events_result.scalars().all()
            
            # Build timeline
            timeline = []
            
            # Add incident creation
            timeline.append({
                "timestamp": incident.reported_at.isoformat(),
                "event_type": "incident_created",
                "description": f"Incident {incident_id} created",
                "user_id": incident.created_by,
                "data": {"title": incident.title}
            })
            
            # Add status changes
            if incident.contained_at:
                timeline.append({
                    "timestamp": incident.contained_at.isoformat(),
                    "event_type": "incident_contained",
                    "description": f"Incident {incident_id} contained",
                    "data": {}
                })
            
            if incident.resolved_at:
                timeline.append({
                    "timestamp": incident.resolved_at.isoformat(),
                    "event_type": "incident_resolved",
                    "description": f"Incident {incident_id} resolved",
                    "data": {}
                })
            
            # Add audit events
            for event in events:
                timeline.append({
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "description": f"{event.event_action} on {event.resource_type}",
                    "user_id": event.user_id,
                    "success": event.success,
                    "data": event.event_data
                })
            
            # Sort timeline by timestamp
            timeline.sort(key=lambda x: x["timestamp"])
            
            return CollectionResult(
                success=True,
                data=timeline,
                message=f"Retrieved timeline for incident {incident_id}"
            )
            
        except Exception as e:
            logger.error(f"Error getting incident timeline: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get incident timeline: {str(e)}"
            )
    
    async def scan_vulnerabilities(self, target_scope: Dict[str, Any]) -> CollectionResult:
        """Perform vulnerability scan on target scope"""
        try:
            # Create vulnerability assessment
            assessment_id = f"VULN-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            
            assessment = VulnerabilityAssessment(
                assessment_id=assessment_id,
                name=f"Vulnerability Assessment - {datetime.now().strftime('%Y-%m-%d %H:%M')}",
                description="Automated vulnerability assessment",
                assessment_type="automated",
                target_scope=target_scope,
                status="running",
                progress_percentage=0.0,
                started_at=datetime.now()
            )
            
            self.db_session.add(assessment)
            await self.db_session.commit()
            await self.db_session.refresh(assessment)
            
            # Simulate vulnerability scanning
            vulnerabilities = await self._simulate_vulnerability_scan(target_scope)
            
            # Create vulnerability records
            vuln_count = 0
            severity_counts = defaultdict(int)
            
            for vuln_data in vulnerabilities:
                vulnerability = Vulnerability(
                    vulnerability_id=f"VULN-{vuln_count + 1:06d}",
                    cve_id=vuln_data.get('cve_id'),
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', ''),
                    severity=vuln_data.get('severity', VulnerabilitySeverity.MEDIUM),
                    cvss_score=vuln_data.get('cvss_score'),
                    cvss_vector=vuln_data.get('cvss_vector'),
                    exploit_available=vuln_data.get('exploit_available', False),
                    assessment_id=assessment.id,
                    device_id=vuln_data.get('device_id'),
                    service_name=vuln_data.get('service_name'),
                    port=vuln_data.get('port'),
                    protocol=vuln_data.get('protocol'),
                    status="open"
                )
                
                self.db_session.add(vulnerability)
                vuln_count += 1
                severity_counts[vulnerability.severity] += 1
            
            # Update assessment with results
            assessment.status = "completed"
            assessment.progress_percentage = 100.0
            assessment.completed_at = datetime.now()
            assessment.total_vulnerabilities = vuln_count
            assessment.critical_count = severity_counts.get(VulnerabilitySeverity.CRITICAL, 0)
            assessment.high_count = severity_counts.get(VulnerabilitySeverity.HIGH, 0)
            assessment.medium_count = severity_counts.get(VulnerabilitySeverity.MEDIUM, 0)
            assessment.low_count = severity_counts.get(VulnerabilitySeverity.LOW, 0)
            assessment.informational_count = severity_counts.get(VulnerabilitySeverity.INFORMATIONAL, 0)
            
            await self.db_session.commit()
            
            return CollectionResult(
                success=True,
                data={
                    "assessment_id": assessment_id,
                    "total_vulnerabilities": vuln_count,
                    "severity_breakdown": dict(severity_counts)
                },
                message=f"Completed vulnerability assessment with {vuln_count} findings"
            )
            
        except Exception as e:
            logger.error(f"Error scanning vulnerabilities: {str(e)}")
            await self.db_session.rollback()
            return CollectionResult(
                success=False,
                error=f"Failed to scan vulnerabilities: {str(e)}"
            )
    
    async def get_vulnerability_summary(self) -> CollectionResult:
        """Get summary of all vulnerabilities"""
        try:
            # Get vulnerability counts by status and severity
            summary_result = await self.db_session.execute(
                select(
                    Vulnerability.status,
                    Vulnerability.severity,
                    func.count(Vulnerability.id)
                ).group_by(Vulnerability.status, Vulnerability.severity)
            )
            
            summary = defaultdict(lambda: defaultdict(int))
            for status, severity, count in summary_result.fetchall():
                summary[status][severity] = count
            
            # Get recent assessments
            assessments_result = await self.db_session.execute(
                select(VulnerabilityAssessment).where(
                    VulnerabilityAssessment.status == "completed"
                ).order_by(desc(VulnerabilityAssessment.completed_at)).limit(10)
            )
            recent_assessments = assessments_result.scalars().all()
            
            return CollectionResult(
                success=True,
                data={
                    "vulnerability_summary": dict(summary),
                    "recent_assessments": [
                        {
                            "assessment_id": a.assessment_id,
                            "name": a.name,
                            "completed_at": a.completed_at.isoformat() if a.completed_at else None,
                            "total_vulnerabilities": a.total_vulnerabilities,
                            "critical_count": a.critical_count,
                            "high_count": a.high_count
                        }
                        for a in recent_assessments
                    ]
                },
                message="Retrieved vulnerability summary"
            )
            
        except Exception as e:
            logger.error(f"Error getting vulnerability summary: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get vulnerability summary: {str(e)}"
            )
    
    # Private helper methods
    
    def _load_detection_rules(self):
        """Load threat detection rules"""
        self._detection_rules = {
            "failed_login_brute_force": DetectionRule(
                rule_id="failed_login_brute_force",
                name="Failed Login Brute Force",
                description="Detect multiple failed login attempts from same IP",
                rule_type="threshold",
                conditions={
                    "event_type": "authentication",
                    "success": False,
                    "threshold": 5,
                    "time_window_minutes": 15,
                    "group_by": "ip_address"
                },
                actions=["create_incident", "block_ip"],
                priority=80
            ),
            "privilege_escalation": DetectionRule(
                rule_id="privilege_escalation",
                name="Privilege Escalation Attempt",
                description="Detect attempts to gain elevated privileges",
                rule_type="pattern",
                conditions={
                    "event_type": "access_control",
                    "resource_type": "role",
                    "action": "grant",
                    "risk_score_threshold": 7.0
                },
                actions=["create_incident", "alert_admin"],
                priority=90
            ),
            "unusual_data_access": DetectionRule(
                rule_id="unusual_data_access",
                name="Unusual Data Access Pattern",
                description="Detect unusual data access patterns",
                rule_type="anomaly",
                conditions={
                    "event_type": "data_access",
                    "anomaly_threshold": 3.0,
                    "baseline_window_hours": 168
                },
                actions=["create_incident", "investigate"],
                priority=70
            )
        }
    
    async def _evaluate_detection_rule(self, rule: DetectionRule, events: List[SecurityAuditLog]) -> List[Dict[str, Any]]:
        """Evaluate a detection rule against events"""
        threats = []
        
        try:
            if rule.rule_type == "threshold":
                threats.extend(await self._evaluate_threshold_rule(rule, events))
            elif rule.rule_type == "pattern":
                threats.extend(await self._evaluate_pattern_rule(rule, events))
            elif rule.rule_type == "anomaly":
                threats.extend(await self._evaluate_anomaly_rule(rule, events))
            
        except Exception as e:
            logger.error(f"Error evaluating rule {rule.rule_id}: {str(e)}")
        
        return threats
    
    async def _evaluate_threshold_rule(self, rule: DetectionRule, events: List[SecurityAuditLog]) -> List[Dict[str, Any]]:
        """Evaluate threshold-based detection rule"""
        threats = []
        conditions = rule.conditions
        
        # Filter events by rule conditions
        filtered_events = []
        for event in events:
            if (event.event_type == conditions.get("event_type") and
                event.success == conditions.get("success", True)):
                filtered_events.append(event)
        
        # Group by specified field
        group_field = conditions.get("group_by", "user_id")
        groups = defaultdict(list)
        
        for event in filtered_events:
            if group_field == "ip_address":
                key = event.ip_address
            elif group_field == "user_id":
                key = event.user_id
            else:
                key = getattr(event, group_field, None)
            
            if key:
                groups[key].append(event)
        
        # Check threshold
        threshold = conditions.get("threshold", 5)
        time_window = timedelta(minutes=conditions.get("time_window_minutes", 15))
        
        for key, group_events in groups.items():
            # Count events within time window
            recent_events = [
                e for e in group_events 
                if datetime.now() - e.timestamp <= time_window
            ]
            
            if len(recent_events) >= threshold:
                threats.append({
                    "rule_id": rule.rule_id,
                    "threat_level": "high" if len(recent_events) >= threshold * 2 else "medium",
                    "description": f"{rule.name}: {len(recent_events)} events from {key}",
                    "affected_resource": key,
                    "event_count": len(recent_events),
                    "time_window": time_window.total_seconds() / 60,
                    "events": recent_events[:10]  # Limit to first 10 events
                })
        
        return threats
    
    async def _evaluate_pattern_rule(self, rule: DetectionRule, events: List[SecurityAuditLog]) -> List[Dict[str, Any]]:
        """Evaluate pattern-based detection rule"""
        threats = []
        conditions = rule.conditions
        
        # Filter events by pattern conditions
        for event in events:
            match = True
            
            if conditions.get("event_type") and event.event_type != conditions["event_type"]:
                match = False
            if conditions.get("resource_type") and event.resource_type != conditions["resource_type"]:
                match = False
            if conditions.get("action") and event.event_action != conditions["action"]:
                match = False
            if conditions.get("risk_score_threshold") and (not event.risk_score or event.risk_score < conditions["risk_score_threshold"]):
                match = False
            
            if match:
                threats.append({
                    "rule_id": rule.rule_id,
                    "threat_level": "high",
                    "description": f"{rule.name}: Pattern match detected",
                    "affected_resource": f"{event.resource_type}:{event.resource_id}",
                    "risk_score": event.risk_score,
                    "events": [event]
                })
        
        return threats
    
    async def _evaluate_anomaly_rule(self, rule: DetectionRule, events: List[SecurityAuditLog]) -> List[Dict[str, Any]]:
        """Evaluate anomaly-based detection rule"""
        threats = []
        conditions = rule.conditions
        
        # This is a simplified anomaly detection
        # In production, you would use more sophisticated algorithms
        
        # Group events by user and resource
        user_resource_counts = defaultdict(int)
        for event in events:
            if (event.event_type == conditions.get("event_type") and
                event.user_id and event.resource_type):
                key = f"{event.user_id}:{event.resource_type}"
                user_resource_counts[key] += 1
        
        # Calculate baseline (mean + 2*std)
        if user_resource_counts:
            counts = list(user_resource_counts.values())
            mean_count = statistics.mean(counts)
            std_count = statistics.stdev(counts) if len(counts) > 1 else 0
            threshold = mean_count + (2 * std_count)
            
            # Find anomalies
            for key, count in user_resource_counts.items():
                if count > threshold:
                    user_id, resource_type = key.split(":", 1)
                    threats.append({
                        "rule_id": rule.rule_id,
                        "threat_level": "medium",
                        "description": f"{rule.name}: Unusual access pattern detected",
                        "affected_resource": key,
                        "access_count": count,
                        "baseline_threshold": threshold,
                        "user_id": int(user_id)
                    })
        
        return threats
    
    async def _correlate_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Correlate related threats into incidents"""
        correlations = []
        
        # Group threats by affected resource
        resource_groups = defaultdict(list)
        for threat in threats:
            resource = threat.get("affected_resource")
            if resource:
                resource_groups[resource].append(threat)
        
        # Create correlations for resources with multiple threats
        for resource, resource_threats in resource_groups.items():
            if len(resource_threats) > 1:
                # Calculate combined threat level
                threat_levels = [t.get("threat_level", "low") for t in resource_threats]
                if "high" in threat_levels:
                    combined_level = "high"
                elif "medium" in threat_levels:
                    combined_level = "medium"
                else:
                    combined_level = "low"
                
                correlations.append({
                    "correlation_id": str(uuid.uuid4()),
                    "affected_resource": resource,
                    "threat_count": len(resource_threats),
                    "combined_threat_level": combined_level,
                    "threats": resource_threats,
                    "description": f"Multiple threats detected for {resource}"
                })
        
        return correlations
    
    async def _create_incident_from_threat(self, threat: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create incident from detected threat"""
        try:
            incident_data = {
                "title": f"Threat Detected: {threat.get('description', 'Unknown Threat')}",
                "description": f"Automated threat detection triggered by rule: {threat.get('rule_id')}",
                "incident_type": "threat_detection",
                "threat_level": threat.get("threat_level", "medium"),
                "category": "security",
                "affected_systems": [threat.get("affected_resource", "unknown")],
                "indicators_of_compromise": {
                    "detection_rule": threat.get("rule_id"),
                    "threat_level": threat.get("threat_level"),
                    "event_count": threat.get("event_count", 1)
                },
                "detected_at": datetime.now()
            }
            
            # Create incident
            result = await self.create_incident(incident_data, created_by=1)  # System user
            return result.data if result.success else None
            
        except Exception as e:
            logger.error(f"Error creating incident from threat: {str(e)}")
            return None
    
    async def _simulate_vulnerability_scan(self, target_scope: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate vulnerability scanning (placeholder implementation)"""
        # In production, this would integrate with actual vulnerability scanners
        # like Nessus, OpenVAS, Qualys, etc.
        
        vulnerabilities = []
        
        # Simulate some common vulnerabilities
        common_vulns = [
            {
                "cve_id": "CVE-2023-1234",
                "title": "SQL Injection Vulnerability",
                "description": "Application vulnerable to SQL injection attacks",
                "severity": VulnerabilitySeverity.HIGH,
                "cvss_score": 8.5,
                "exploit_available": True,
                "service_name": "web_server",
                "port": 80,
                "protocol": "http"
            },
            {
                "cve_id": "CVE-2023-5678",
                "title": "Outdated SSL/TLS Configuration",
                "description": "Server supports weak SSL/TLS protocols",
                "severity": VulnerabilitySeverity.MEDIUM,
                "cvss_score": 5.3,
                "exploit_available": False,
                "service_name": "ssl_service",
                "port": 443,
                "protocol": "https"
            },
            {
                "cve_id": "CVE-2023-9012",
                "title": "Default Credentials",
                "description": "Device using default administrative credentials",
                "severity": VulnerabilitySeverity.CRITICAL,
                "cvss_score": 9.8,
                "exploit_available": True,
                "service_name": "admin_interface",
                "port": 22,
                "protocol": "ssh"
            }
        ]
        
        # Return subset based on target scope
        target_count = target_scope.get("max_vulnerabilities", 3)
        return common_vulns[:target_count]
    
    async def _log_incident_event(self, incident_id: str, event_type: str, user_id: int, event_data: Dict[str, Any]):
        """Log incident-related event"""
        # This would typically log to the audit system
        logger.info(f"Incident event: {event_type} for {incident_id} by user {user_id}")
