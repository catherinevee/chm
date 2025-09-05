"""
Tests for CHM models
"""

import pytest
import sys
import os
from datetime import datetime

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_user_model_creation():
    """Test User model creation and attributes"""
    from models.user import User, UserRole, UserStatus
    
    # Test enum values
    assert UserRole.ADMIN == "admin"
    assert UserRole.OPERATOR == "operator"
    assert UserRole.VIEWER == "viewer"
    
    assert UserStatus.ACTIVE == "active"
    assert UserStatus.INACTIVE == "inactive"
    assert UserStatus.SUSPENDED == "suspended"
    
    print("✅ User model enums work correctly")

def test_device_model_creation():
    """Test Device model creation and attributes"""
    from models.device import Device, DeviceStatus, DeviceProtocol
    
    # Test enum values
    assert DeviceStatus.ONLINE == "online"
    assert DeviceStatus.OFFLINE == "offline"
    assert DeviceStatus.UNKNOWN == "unknown"
    
    assert DeviceProtocol.SNMP == "snmp"
    assert DeviceProtocol.SSH == "ssh"
    assert DeviceProtocol.REST == "rest"
    
    print("✅ Device model enums work correctly")

def test_metric_model_creation():
    """Test Metric model creation and attributes"""
    from models.metric import Metric, MetricType, MetricCategory
    
    # Test enum values
    assert MetricType.GAUGE == "gauge"
    assert MetricType.COUNTER == "counter"
    assert MetricType.HISTOGRAM == "histogram"
    
    assert MetricCategory.SYSTEM == "system"
    assert MetricCategory.NETWORK == "network"
    assert MetricCategory.APPLICATION == "application"
    
    print("✅ Metric model enums work correctly")

def test_alert_model_creation():
    """Test Alert model creation and attributes"""
    from models.alert import Alert, AlertSeverity, AlertStatus, AlertCategory
    
    # Test enum values
    assert AlertSeverity.CRITICAL == "critical"
    assert AlertSeverity.WARNING == "warning"
    assert AlertSeverity.INFO == "info"
    
    assert AlertStatus.OPEN == "open"
    assert AlertStatus.ACKNOWLEDGED == "acknowledged"
    assert AlertStatus.RESOLVED == "resolved"
    
    assert AlertCategory.PERFORMANCE == "performance"
    assert AlertCategory.AVAILABILITY == "availability"
    assert AlertCategory.SECURITY == "security"
    
    print("✅ Alert model enums work correctly")

def test_notification_model_creation():
    """Test Notification model creation and attributes"""
    from models.notification import Notification, NotificationType, NotificationStatus, NotificationPriority
    
    # Test enum values
    assert NotificationType.EMAIL == "email"
    assert NotificationType.SMS == "sms"
    assert NotificationType.WEBHOOK == "webhook"
    
    assert NotificationStatus.PENDING == "pending"
    assert NotificationStatus.SENT == "sent"
    assert NotificationStatus.FAILED == "failed"
    
    assert NotificationPriority.HIGH == "high"
    assert NotificationPriority.NORMAL == "normal"
    assert NotificationPriority.LOW == "low"
    
    print("✅ Notification model enums work correctly")

def test_discovery_job_model_creation():
    """Test DiscoveryJob model creation and attributes"""
    from models.discovery_job import DiscoveryJob, DiscoveryType, DiscoveryStatus
    
    # Test enum values
    assert DiscoveryType.NETWORK_SCAN == "network_scan"
    assert DiscoveryType.SNMP_DISCOVERY == "snmp_discovery"
    assert DiscoveryType.MANUAL == "manual"
    
    assert DiscoveryStatus.PENDING == "pending"
    assert DiscoveryStatus.RUNNING == "running"
    assert DiscoveryStatus.COMPLETED == "completed"
    assert DiscoveryStatus.FAILED == "failed"
    
    print("✅ DiscoveryJob model enums work correctly")

def test_network_topology_model_creation():
    """Test NetworkTopology model creation and attributes"""
    from models.network_topology import (
        TopologyType, InterfaceType, InterfaceStatus, PathStatus
    )
    
    # Test enum values
    assert TopologyType.LAYER2 == "layer2"
    assert TopologyType.LAYER3 == "layer3"
    assert TopologyType.PHYSICAL == "physical"
    
    assert InterfaceType.ETHERNET == "ethernet"
    assert InterfaceType.WIRELESS == "wireless"
    assert InterfaceType.SERIAL == "serial"
    
    assert InterfaceStatus.UP == "up"
    assert InterfaceStatus.DOWN == "down"
    assert InterfaceStatus.UNKNOWN == "unknown"
    
    assert PathStatus.ACTIVE == "active"
    assert PathStatus.INACTIVE == "inactive"
    assert PathStatus.UNKNOWN == "unknown"
    
    print("✅ NetworkTopology model enums work correctly")

def test_analytics_model_creation():
    """Test Analytics model creation and attributes"""
    from models.analytics import (
        AnalysisType, AnomalySeverity, ReportType, ReportFormat
    )
    
    # Test enum values
    assert AnalysisType.PERFORMANCE == "performance"
    assert AnalysisType.CAPACITY == "capacity"
    assert AnalysisType.TREND == "trend"
    
    assert AnomalySeverity.HIGH == "high"
    assert AnomalySeverity.MEDIUM == "medium"
    assert AnomalySeverity.LOW == "low"
    
    assert ReportType.SUMMARY == "summary"
    assert ReportType.DETAILED == "detailed"
    assert ReportType.CUSTOM == "custom"
    
    assert ReportFormat.PDF == "pdf"
    assert ReportFormat.HTML == "html"
    assert ReportFormat.JSON == "json"
    
    print("✅ Analytics model enums work correctly")

def test_security_model_creation():
    """Test Security model creation and attributes"""
    from models.security import (
        SecurityLevel, ThreatLevel, IncidentStatus, VulnerabilitySeverity, ComplianceStatus
    )
    
    # Test enum values
    assert SecurityLevel.HIGH == "high"
    assert SecurityLevel.MEDIUM == "medium"
    assert SecurityLevel.LOW == "low"
    
    assert ThreatLevel.CRITICAL == "critical"
    assert ThreatLevel.HIGH == "high"
    assert ThreatLevel.MEDIUM == "medium"
    assert ThreatLevel.LOW == "low"
    
    assert IncidentStatus.OPEN == "open"
    assert IncidentStatus.INVESTIGATING == "investigating"
    assert IncidentStatus.RESOLVED == "resolved"
    
    assert VulnerabilitySeverity.CRITICAL == "critical"
    assert VulnerabilitySeverity.HIGH == "high"
    assert VulnerabilitySeverity.MEDIUM == "medium"
    assert VulnerabilitySeverity.LOW == "low"
    
    assert ComplianceStatus.COMPLIANT == "compliant"
    assert ComplianceStatus.NON_COMPLIANT == "non_compliant"
    assert ComplianceStatus.PARTIAL == "partial"
    
    print("✅ Security model enums work correctly")

def test_result_objects_creation():
    """Test Result objects creation and attributes"""
    from models.result_objects import (
        OperationStatus, BaseResult, DeviceStatusResult, MetricsCollectionResult
    )
    
    # Test enum values
    assert OperationStatus.SUCCESS == "success"
    assert OperationStatus.FAILURE == "failure"
    assert OperationStatus.PARTIAL == "partial"
    
    # Test that result objects can be instantiated
    result = BaseResult(status=OperationStatus.SUCCESS, message="Test")
    assert result.status == OperationStatus.SUCCESS
    assert result.message == "Test"
    
    device_result = DeviceStatusResult(
        status=OperationStatus.SUCCESS,
        message="Device check completed",
        device_id=1,
        device_status="online"
    )
    assert device_result.device_id == 1
    assert device_result.device_status == "online"
    
    print("✅ Result objects work correctly")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
