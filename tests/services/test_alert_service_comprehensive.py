"""
Comprehensive tests for Alert Service
Testing alert lifecycle, escalation, correlation, and notification integration
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, Mock, call
import uuid
import json
from enum import Enum
from typing import List, Dict, Any

# Test infrastructure imports
from tests.test_infrastructure.test_fixtures_comprehensive import (
    TestInfrastructureManager,
    TestDataFactory
)

# Service and model imports
from backend.services.alert_service import AlertService
from backend.database.models import Alert, Device, AlertRule, AlertEscalation
from backend.services.notification_service import NotificationService


class AlertSeverity(Enum):
    """Alert severity levels"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status values"""
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    CLOSED = "closed"
    SUPPRESSED = "suppressed"


class TestAlertServiceCore:
    """Core alert service functionality tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance with mocked dependencies"""
        service = AlertService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        service.notification_service = AsyncMock(spec=NotificationService)
        service.email_service = AsyncMock()
        return service
    
    @pytest.fixture
    def sample_alert_data(self):
        """Sample alert data for testing"""
        return {
            "device_id": uuid.uuid4(),
            "alert_type": "cpu_high",
            "severity": AlertSeverity.WARNING.value,
            "message": "CPU usage exceeded 80%",
            "details": {
                "cpu_usage": 85.5,
                "threshold": 80,
                "duration": "5 minutes"
            },
            "source": "snmp_monitor",
            "status": AlertStatus.OPEN.value
        }
    
    @pytest.mark.asyncio
    async def test_create_alert(self, alert_service, sample_alert_data):
        """Test alert creation"""
        # Create alert
        alert = await alert_service.create_alert(sample_alert_data)
        
        # Verify alert created
        alert_service.db.add.assert_called_once()
        alert_service.db.commit.assert_called_once()
        assert alert is not None
        
        # Verify notification sent
        alert_service.notification_service.send_alert_notification.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_create_alert_with_deduplication(self, alert_service, sample_alert_data):
        """Test alert deduplication"""
        # Mock existing similar alert
        existing_alert = MagicMock(spec=Alert)
        existing_alert.id = uuid.uuid4()
        existing_alert.status = AlertStatus.OPEN.value
        existing_alert.occurrence_count = 1
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = existing_alert
        
        # Try to create duplicate alert
        alert = await alert_service.create_alert(sample_alert_data, deduplicate=True)
        
        # Verify existing alert updated instead of creating new
        assert existing_alert.occurrence_count == 2
        assert existing_alert.last_occurrence is not None
        alert_service.db.add.assert_not_called()  # No new alert created
        alert_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_get_alert_by_id(self, alert_service):
        """Test getting alert by ID"""
        alert_id = uuid.uuid4()
        
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.severity = AlertSeverity.WARNING.value
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        # Get alert
        alert = await alert_service.get_alert(alert_id)
        
        assert alert == mock_alert
        alert_service.db.query.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_alert_status(self, alert_service):
        """Test alert status update"""
        alert_id = uuid.uuid4()
        new_status = AlertStatus.ACKNOWLEDGED.value
        
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.status = AlertStatus.OPEN.value
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        # Update status
        result = await alert_service.update_alert_status(alert_id, new_status, user_id=uuid.uuid4())
        
        assert result is True
        assert mock_alert.status == new_status
        assert mock_alert.acknowledged_at is not None
        assert mock_alert.acknowledged_by is not None
        alert_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_resolve_alert(self, alert_service):
        """Test alert resolution"""
        alert_id = uuid.uuid4()
        resolution_notes = "Issue resolved by restarting service"
        
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.status = AlertStatus.OPEN.value
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        # Resolve alert
        result = await alert_service.resolve_alert(
            alert_id,
            resolution_notes=resolution_notes,
            resolved_by=uuid.uuid4()
        )
        
        assert result is True
        assert mock_alert.status == AlertStatus.RESOLVED.value
        assert mock_alert.resolved_at is not None
        assert mock_alert.resolution_notes == resolution_notes
        alert_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_list_alerts_with_filters(self, alert_service):
        """Test listing alerts with filters"""
        filters = {
            "severity": AlertSeverity.CRITICAL.value,
            "status": AlertStatus.OPEN.value,
            "device_id": uuid.uuid4()
        }
        
        mock_alerts = [
            MagicMock(spec=Alert, id=uuid.uuid4()),
            MagicMock(spec=Alert, id=uuid.uuid4())
        ]
        
        query_mock = MagicMock()
        query_mock.filter.return_value = query_mock
        query_mock.order_by.return_value = query_mock
        query_mock.offset.return_value = query_mock
        query_mock.limit.return_value = query_mock
        query_mock.all.return_value = mock_alerts
        
        alert_service.db.query.return_value = query_mock
        
        # List alerts
        alerts = await alert_service.list_alerts(filters=filters, offset=0, limit=10)
        
        assert len(alerts) == 2
        assert query_mock.filter.called


class TestAlertEscalation:
    """Alert escalation tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        service.notification_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_escalate_alert_by_time(self, alert_service):
        """Test time-based alert escalation"""
        alert = MagicMock(spec=Alert)
        alert.id = uuid.uuid4()
        alert.severity = AlertSeverity.WARNING.value
        alert.created_at = datetime.utcnow() - timedelta(hours=2)
        alert.status = AlertStatus.OPEN.value
        alert.escalation_level = 0
        
        # Define escalation rules
        escalation_rules = [
            {"after_minutes": 60, "severity": AlertSeverity.ERROR.value},
            {"after_minutes": 120, "severity": AlertSeverity.CRITICAL.value}
        ]
        
        with patch.object(alert_service, 'get_escalation_rules', return_value=escalation_rules):
            # Check and escalate
            escalated = await alert_service.check_and_escalate(alert)
            
            assert escalated is True
            assert alert.severity == AlertSeverity.CRITICAL.value
            assert alert.escalation_level == 2
            alert_service.notification_service.send_escalation_notification.assert_called()
    
    @pytest.mark.asyncio
    async def test_escalate_alert_by_occurrence(self, alert_service):
        """Test occurrence-based alert escalation"""
        alert = MagicMock(spec=Alert)
        alert.id = uuid.uuid4()
        alert.severity = AlertSeverity.INFO.value
        alert.occurrence_count = 5
        alert.escalation_level = 0
        
        # Escalate based on occurrence count
        escalated = await alert_service.escalate_by_occurrence(alert, threshold=3)
        
        assert escalated is True
        assert alert.severity == AlertSeverity.WARNING.value
        assert alert.escalation_level == 1
    
    @pytest.mark.asyncio
    async def test_escalation_chain(self, alert_service):
        """Test alert escalation chain"""
        alert_id = uuid.uuid4()
        
        # Define escalation chain
        escalation_chain = [
            {"level": 1, "notify": ["team_lead"], "after_minutes": 30},
            {"level": 2, "notify": ["manager"], "after_minutes": 60},
            {"level": 3, "notify": ["director", "on_call"], "after_minutes": 120}
        ]
        
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.created_at = datetime.utcnow() - timedelta(minutes=65)
        mock_alert.escalation_level = 0
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        # Process escalation chain
        level = await alert_service.process_escalation_chain(alert_id, escalation_chain)
        
        assert level == 2  # Should escalate to level 2
        assert alert_service.notification_service.notify_users.call_count == 2
    
    @pytest.mark.asyncio
    async def test_auto_escalation_scheduler(self, alert_service):
        """Test automatic alert escalation scheduling"""
        open_alerts = [
            MagicMock(spec=Alert, id=uuid.uuid4(), created_at=datetime.utcnow() - timedelta(hours=1)),
            MagicMock(spec=Alert, id=uuid.uuid4(), created_at=datetime.utcnow() - timedelta(minutes=10))
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = open_alerts
        alert_service.check_and_escalate = AsyncMock(return_value=True)
        
        # Run auto escalation
        escalated_count = await alert_service.auto_escalate_alerts()
        
        assert escalated_count >= 1
        alert_service.check_and_escalate.assert_called()


class TestAlertCorrelation:
    """Alert correlation and grouping tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_correlate_alerts_by_device(self, alert_service):
        """Test alert correlation by device"""
        device_id = uuid.uuid4()
        
        alerts = [
            MagicMock(spec=Alert, device_id=device_id, alert_type="cpu_high"),
            MagicMock(spec=Alert, device_id=device_id, alert_type="memory_high"),
            MagicMock(spec=Alert, device_id=device_id, alert_type="disk_full")
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = alerts
        
        # Correlate alerts
        correlation = await alert_service.correlate_device_alerts(device_id)
        
        assert correlation["device_id"] == device_id
        assert correlation["alert_count"] == 3
        assert correlation["correlation_type"] == "resource_exhaustion"
        assert correlation["root_cause_probability"] > 0.7
    
    @pytest.mark.asyncio
    async def test_correlate_alerts_by_time_window(self, alert_service):
        """Test alert correlation within time window"""
        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow()
        
        alerts = [
            MagicMock(spec=Alert, created_at=start_time + timedelta(minutes=1)),
            MagicMock(spec=Alert, created_at=start_time + timedelta(minutes=2)),
            MagicMock(spec=Alert, created_at=start_time + timedelta(minutes=3))
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = alerts
        
        # Correlate by time window
        correlated = await alert_service.correlate_by_time_window(start_time, end_time)
        
        assert len(correlated) == 3
        assert all(start_time <= a.created_at <= end_time for a in correlated)
    
    @pytest.mark.asyncio
    async def test_create_correlation_group(self, alert_service):
        """Test creating alert correlation group"""
        alert_ids = [uuid.uuid4() for _ in range(3)]
        
        # Create correlation group
        group = await alert_service.create_correlation_group(
            alert_ids=alert_ids,
            correlation_type="network_outage",
            confidence=0.85
        )
        
        assert group is not None
        assert len(group["alert_ids"]) == 3
        assert group["correlation_type"] == "network_outage"
        assert group["confidence"] == 0.85
        alert_service.db.add.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_pattern_based_correlation(self, alert_service):
        """Test pattern-based alert correlation"""
        # Define correlation patterns
        patterns = [
            {
                "name": "cascade_failure",
                "conditions": ["connectivity_lost", "interface_down", "routing_failure"],
                "confidence": 0.9
            }
        ]
        
        recent_alerts = [
            MagicMock(alert_type="connectivity_lost"),
            MagicMock(alert_type="interface_down"),
            MagicMock(alert_type="routing_failure")
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = recent_alerts
        
        # Find pattern matches
        matches = await alert_service.find_pattern_matches(patterns)
        
        assert len(matches) > 0
        assert matches[0]["pattern"] == "cascade_failure"
        assert matches[0]["confidence"] >= 0.9


class TestAlertRules:
    """Alert rule management tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_create_alert_rule(self, alert_service):
        """Test alert rule creation"""
        rule_data = {
            "name": "High CPU Alert",
            "condition": "cpu_usage > 80",
            "severity": AlertSeverity.WARNING.value,
            "actions": ["notify", "log"],
            "enabled": True
        }
        
        # Create rule
        rule = await alert_service.create_alert_rule(rule_data)
        
        assert rule is not None
        alert_service.db.add.assert_called_once()
        alert_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_evaluate_alert_rule(self, alert_service):
        """Test alert rule evaluation"""
        rule = MagicMock(spec=AlertRule)
        rule.condition = "metric.value > threshold"
        rule.threshold = 80
        rule.severity = AlertSeverity.WARNING.value
        
        metric_data = {"value": 85, "name": "cpu_usage"}
        
        # Evaluate rule
        triggered = await alert_service.evaluate_rule(rule, metric_data)
        
        assert triggered is True
    
    @pytest.mark.asyncio
    async def test_complex_alert_rule_evaluation(self, alert_service):
        """Test complex alert rule evaluation"""
        rule = MagicMock(spec=AlertRule)
        rule.condition = "(cpu > 80 AND memory > 90) OR disk > 95"
        
        # Test various metric combinations
        test_cases = [
            ({"cpu": 85, "memory": 92, "disk": 50}, True),   # CPU and memory high
            ({"cpu": 85, "memory": 80, "disk": 50}, False),  # Only CPU high
            ({"cpu": 50, "memory": 50, "disk": 96}, True),   # Disk critical
            ({"cpu": 50, "memory": 50, "disk": 50}, False)   # All normal
        ]
        
        for metrics, expected in test_cases:
            result = await alert_service.evaluate_complex_rule(rule, metrics)
            assert result == expected
    
    @pytest.mark.asyncio
    async def test_rule_based_alert_generation(self, alert_service):
        """Test automatic alert generation from rules"""
        rules = [
            MagicMock(id=uuid.uuid4(), name="CPU Rule", enabled=True),
            MagicMock(id=uuid.uuid4(), name="Memory Rule", enabled=True),
            MagicMock(id=uuid.uuid4(), name="Disk Rule", enabled=False)
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = rules
        alert_service.evaluate_rule = AsyncMock(side_effect=[True, False, False])
        alert_service.create_alert = AsyncMock()
        
        # Process rules
        alerts_created = await alert_service.process_alert_rules({"cpu": 85})
        
        assert alerts_created == 1  # Only CPU rule triggered
        alert_service.create_alert.assert_called_once()


class TestAlertSuppression:
    """Alert suppression and maintenance window tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        service.redis = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_suppress_alert(self, alert_service):
        """Test alert suppression"""
        alert_id = uuid.uuid4()
        suppress_until = datetime.utcnow() + timedelta(hours=2)
        
        mock_alert = MagicMock(spec=Alert)
        mock_alert.id = alert_id
        mock_alert.status = AlertStatus.OPEN.value
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        # Suppress alert
        result = await alert_service.suppress_alert(
            alert_id,
            suppress_until=suppress_until,
            reason="Scheduled maintenance"
        )
        
        assert result is True
        assert mock_alert.status == AlertStatus.SUPPRESSED.value
        assert mock_alert.suppressed_until == suppress_until
        alert_service.db.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_maintenance_window(self, alert_service):
        """Test maintenance window alert suppression"""
        device_id = uuid.uuid4()
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(hours=4)
        
        # Create maintenance window
        window = await alert_service.create_maintenance_window(
            device_id=device_id,
            start_time=start_time,
            end_time=end_time,
            suppress_alerts=True
        )
        
        assert window is not None
        alert_service.db.add.assert_called_once()
        
        # Verify alerts suppressed during window
        is_suppressed = await alert_service.is_in_maintenance_window(device_id, datetime.utcnow())
        assert is_suppressed is True
    
    @pytest.mark.asyncio
    async def test_bulk_alert_suppression(self, alert_service):
        """Test bulk alert suppression"""
        alert_ids = [uuid.uuid4() for _ in range(5)]
        
        mock_alerts = [
            MagicMock(spec=Alert, id=aid, status=AlertStatus.OPEN.value)
            for aid in alert_ids
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = mock_alerts
        
        # Bulk suppress
        count = await alert_service.bulk_suppress_alerts(
            alert_ids,
            suppress_until=datetime.utcnow() + timedelta(hours=1)
        )
        
        assert count == 5
        for alert in mock_alerts:
            assert alert.status == AlertStatus.SUPPRESSED.value
    
    @pytest.mark.asyncio
    async def test_auto_unsuppress_alerts(self, alert_service):
        """Test automatic alert unsuppression"""
        suppressed_alerts = [
            MagicMock(
                spec=Alert,
                id=uuid.uuid4(),
                status=AlertStatus.SUPPRESSED.value,
                suppressed_until=datetime.utcnow() - timedelta(minutes=1)
            )
            for _ in range(3)
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = suppressed_alerts
        
        # Auto unsuppress
        count = await alert_service.auto_unsuppress_alerts()
        
        assert count == 3
        for alert in suppressed_alerts:
            assert alert.status == AlertStatus.OPEN.value
            assert alert.suppressed_until is None


class TestAlertNotifications:
    """Alert notification integration tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        service.notification_service = AsyncMock()
        service.email_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_send_alert_notification(self, alert_service):
        """Test sending alert notification"""
        alert = MagicMock(spec=Alert)
        alert.id = uuid.uuid4()
        alert.severity = AlertSeverity.CRITICAL.value
        alert.message = "Critical system failure"
        
        recipients = ["admin@example.com", "oncall@example.com"]
        
        # Send notification
        sent = await alert_service.send_alert_notification(alert, recipients)
        
        assert sent is True
        alert_service.notification_service.send_notification.assert_called()
        assert alert_service.notification_service.send_notification.call_count == len(recipients)
    
    @pytest.mark.asyncio
    async def test_notification_channels(self, alert_service):
        """Test multiple notification channels"""
        alert = MagicMock(spec=Alert)
        alert.severity = AlertSeverity.CRITICAL.value
        
        channels = {
            "email": ["admin@example.com"],
            "sms": ["+1234567890"],
            "slack": ["#alerts"],
            "pagerduty": ["service_key_123"]
        }
        
        # Send to all channels
        results = await alert_service.send_multi_channel_notification(alert, channels)
        
        assert len(results) == 4
        assert all(r["sent"] for r in results.values())
    
    @pytest.mark.asyncio
    async def test_notification_rate_limiting(self, alert_service):
        """Test notification rate limiting"""
        alert = MagicMock(spec=Alert)
        alert.id = uuid.uuid4()
        recipient = "admin@example.com"
        
        # Set rate limit in Redis
        alert_service.redis.get.return_value = b"5"  # Already sent 5 notifications
        
        # Try to send notification (should be rate limited)
        sent = await alert_service.send_notification_with_rate_limit(
            alert,
            recipient,
            limit=5,
            window=3600
        )
        
        assert sent is False  # Rate limited
    
    @pytest.mark.asyncio
    async def test_notification_templates(self, alert_service):
        """Test notification template rendering"""
        alert = MagicMock(spec=Alert)
        alert.severity = AlertSeverity.WARNING.value
        alert.message = "High CPU usage on {device_name}"
        alert.details = {"cpu_usage": 85, "device_name": "router-01"}
        
        # Render template
        rendered = await alert_service.render_notification_template(alert, "email")
        
        assert "router-01" in rendered["subject"]
        assert "85" in rendered["body"]
        assert "WARNING" in rendered["body"]


class TestAlertAnalytics:
    """Alert analytics and reporting tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_alert_statistics(self, alert_service):
        """Test alert statistics generation"""
        start_date = datetime.utcnow() - timedelta(days=7)
        end_date = datetime.utcnow()
        
        mock_stats = MagicMock()
        mock_stats.total_alerts = 150
        mock_stats.open_alerts = 25
        mock_stats.resolved_alerts = 120
        mock_stats.suppressed_alerts = 5
        
        alert_service.db.query.return_value.filter.return_value.first.return_value = mock_stats
        
        # Get statistics
        stats = await alert_service.get_alert_statistics(start_date, end_date)
        
        assert stats["total"] == 150
        assert stats["open"] == 25
        assert stats["resolved"] == 120
        assert stats["resolution_rate"] == 80.0  # 120/150
    
    @pytest.mark.asyncio
    async def test_alert_trends(self, alert_service):
        """Test alert trend analysis"""
        # Mock hourly alert counts
        hourly_data = [
            (datetime.utcnow() - timedelta(hours=i), 10 + i % 5)
            for i in range(24)
        ]
        
        alert_service.db.execute = AsyncMock(return_value=MagicMock(fetchall=MagicMock(return_value=hourly_data)))
        
        # Get trends
        trends = await alert_service.get_alert_trends("hourly", 24)
        
        assert len(trends) == 24
        assert "timestamp" in trends[0]
        assert "count" in trends[0]
    
    @pytest.mark.asyncio
    async def test_mttr_calculation(self, alert_service):
        """Test Mean Time To Resolution (MTTR) calculation"""
        resolved_alerts = [
            MagicMock(
                created_at=datetime.utcnow() - timedelta(hours=2),
                resolved_at=datetime.utcnow() - timedelta(hours=1)
            ),
            MagicMock(
                created_at=datetime.utcnow() - timedelta(hours=4),
                resolved_at=datetime.utcnow() - timedelta(hours=2)
            )
        ]
        
        alert_service.db.query.return_value.filter.return_value.all.return_value = resolved_alerts
        
        # Calculate MTTR
        mttr = await alert_service.calculate_mttr(datetime.utcnow() - timedelta(days=1))
        
        assert mttr["hours"] == 1.5  # Average of 1 and 2 hours
        assert mttr["count"] == 2
    
    @pytest.mark.asyncio
    async def test_top_alert_types(self, alert_service):
        """Test getting top alert types"""
        alert_counts = [
            ("cpu_high", 45),
            ("memory_high", 32),
            ("disk_full", 28),
            ("connectivity", 15),
            ("interface_down", 10)
        ]
        
        alert_service.db.execute = AsyncMock(
            return_value=MagicMock(fetchall=MagicMock(return_value=alert_counts))
        )
        
        # Get top alert types
        top_types = await alert_service.get_top_alert_types(limit=3)
        
        assert len(top_types) == 3
        assert top_types[0]["type"] == "cpu_high"
        assert top_types[0]["count"] == 45


class TestAlertLifecycle:
    """Complete alert lifecycle tests"""
    
    @pytest.fixture
    def alert_service(self):
        """Create alert service instance"""
        service = AlertService()
        service.db = AsyncMock()
        service.notification_service = AsyncMock()
        return service
    
    @pytest.mark.asyncio
    async def test_complete_alert_lifecycle(self, alert_service):
        """Test complete alert lifecycle from creation to resolution"""
        device_id = uuid.uuid4()
        user_id = uuid.uuid4()
        
        # 1. Create alert
        alert_data = {
            "device_id": device_id,
            "alert_type": "cpu_high",
            "severity": AlertSeverity.WARNING.value,
            "message": "CPU usage high"
        }
        
        alert = await alert_service.create_alert(alert_data)
        assert alert.status == AlertStatus.OPEN.value
        
        # 2. Acknowledge alert
        alert.status = AlertStatus.OPEN.value  # Reset for test
        await alert_service.acknowledge_alert(alert.id, user_id)
        assert alert.status == AlertStatus.ACKNOWLEDGED.value
        
        # 3. Escalate alert
        alert.created_at = datetime.utcnow() - timedelta(hours=2)
        escalated = await alert_service.check_and_escalate(alert)
        assert escalated is True
        assert alert.severity == AlertSeverity.ERROR.value
        
        # 4. Resolve alert
        await alert_service.resolve_alert(
            alert.id,
            resolution_notes="Issue fixed",
            resolved_by=user_id
        )
        assert alert.status == AlertStatus.RESOLVED.value
        
        # 5. Close alert
        await alert_service.close_alert(alert.id)
        assert alert.status == AlertStatus.CLOSED.value
    
    @pytest.mark.asyncio
    async def test_alert_state_transitions(self, alert_service):
        """Test valid alert state transitions"""
        alert = MagicMock(spec=Alert)
        alert.id = uuid.uuid4()
        
        # Valid transitions
        valid_transitions = [
            (AlertStatus.OPEN, AlertStatus.ACKNOWLEDGED),
            (AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED),
            (AlertStatus.RESOLVED, AlertStatus.CLOSED),
            (AlertStatus.OPEN, AlertStatus.SUPPRESSED),
            (AlertStatus.SUPPRESSED, AlertStatus.OPEN)
        ]
        
        for from_status, to_status in valid_transitions:
            alert.status = from_status.value
            result = await alert_service.transition_alert_status(alert, to_status.value)
            assert result is True
            
        # Invalid transition
        alert.status = AlertStatus.CLOSED.value
        result = await alert_service.transition_alert_status(alert, AlertStatus.OPEN.value)
        assert result is False  # Cannot reopen closed alert