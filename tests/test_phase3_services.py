"""
Phase 3: Comprehensive tests for backend services
Target: Achieve significant coverage for all service classes
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime, timedelta
import json


class TestAuthService:
    """Test backend/services/auth_service.py"""
    
    @pytest.mark.asyncio
    async def test_auth_service_creation(self):
        """Test AuthService instantiation"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_hash_password(self):
        """Test password hashing"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        password = "TestPassword123!"
        
        hashed = service.hash_password(password)
        assert hashed != password
        assert len(hashed) > 20
        assert "$2b$" in hashed  # bcrypt marker
        
    @pytest.mark.asyncio
    async def test_verify_password(self):
        """Test password verification"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        password = "TestPassword123!"
        
        hashed = service.hash_password(password)
        
        # Test correct password
        assert service.verify_password(password, hashed) is True
        
        # Test incorrect password
        assert service.verify_password("WrongPassword", hashed) is False
        
    @pytest.mark.asyncio
    async def test_create_access_token(self):
        """Test JWT access token creation"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        data = {"user_id": 1, "username": "testuser"}
        
        token = service.create_access_token(data)
        assert isinstance(token, str)
        assert len(token) > 20
        assert token.count('.') == 2  # JWT format
        
    @pytest.mark.asyncio
    async def test_create_refresh_token(self):
        """Test refresh token creation"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        data = {"user_id": 1}
        
        token = service.create_refresh_token(data)
        assert isinstance(token, str)
        assert len(token) > 20
        
    @pytest.mark.asyncio 
    async def test_verify_token(self):
        """Test token verification"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        data = {"user_id": 1, "username": "test"}
        
        token = service.create_access_token(data)
        decoded = service.verify_token(token)
        
        assert decoded is not None
        assert decoded.get("user_id") == 1
        assert decoded.get("username") == "test"
        
    @pytest.mark.asyncio
    async def test_authenticate_user(self):
        """Test user authentication"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        service.db = AsyncMock()
        
        # Mock database query
        mock_user = Mock()
        mock_user.username = "testuser"
        mock_user.hashed_password = service.hash_password("password123")
        mock_user.is_active = True
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        # Test authentication
        result = await service.authenticate_user("testuser", "password123")
        assert result == mock_user
        
        # Test wrong password
        result = await service.authenticate_user("testuser", "wrongpass")
        assert result is None
        
    @pytest.mark.asyncio
    async def test_register_user(self):
        """Test user registration"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        service.db = AsyncMock()
        service.db.add = Mock()
        service.db.commit = AsyncMock()
        service.db.refresh = AsyncMock()
        
        user_data = {
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!"
        }
        
        result = await service.register_user(user_data)
        
        # Verify user was added to database
        service.db.add.assert_called_once()
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_logout_user(self):
        """Test user logout"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        service.redis_client = AsyncMock()
        
        # Test logout
        result = await service.logout_user("test_token")
        
        # Verify token was blacklisted
        service.redis_client.set.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_password_reset_request(self):
        """Test password reset request"""
        from backend.services.auth_service import AuthService
        
        service = AuthService()
        service.db = AsyncMock()
        service.email_service = AsyncMock()
        
        mock_user = Mock()
        mock_user.email = "test@example.com"
        mock_user.id = 1
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        result = await service.request_password_reset("test@example.com")
        
        # Verify email was sent
        service.email_service.send_password_reset_email.assert_called_once()


class TestUserService:
    """Test backend/services/user_service.py"""
    
    @pytest.mark.asyncio
    async def test_user_service_creation(self):
        """Test UserService instantiation"""
        from backend.services.user_service import UserService
        
        service = UserService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_get_user_by_id(self):
        """Test getting user by ID"""
        from backend.services.user_service import UserService
        
        service = UserService()
        service.db = AsyncMock()
        
        mock_user = Mock()
        mock_user.id = 1
        mock_user.username = "testuser"
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        result = await service.get_user_by_id(1)
        assert result == mock_user
        
    @pytest.mark.asyncio
    async def test_get_user_by_username(self):
        """Test getting user by username"""
        from backend.services.user_service import UserService
        
        service = UserService()
        service.db = AsyncMock()
        
        mock_user = Mock()
        mock_user.username = "testuser"
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        result = await service.get_user_by_username("testuser")
        assert result == mock_user
        
    @pytest.mark.asyncio
    async def test_update_user(self):
        """Test updating user"""
        from backend.services.user_service import UserService
        
        service = UserService()
        service.db = AsyncMock()
        
        mock_user = Mock()
        mock_user.id = 1
        mock_user.email = "old@example.com"
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        update_data = {"email": "new@example.com"}
        result = await service.update_user(1, update_data)
        
        assert mock_user.email == "new@example.com"
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_delete_user(self):
        """Test deleting user (soft delete)"""
        from backend.services.user_service import UserService
        
        service = UserService()
        service.db = AsyncMock()
        
        mock_user = Mock()
        mock_user.id = 1
        mock_user.is_active = True
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_user
        
        result = await service.delete_user(1)
        
        assert mock_user.is_active is False
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_list_users(self):
        """Test listing users with pagination"""
        from backend.services.user_service import UserService
        
        service = UserService()
        service.db = AsyncMock()
        
        mock_users = [Mock(id=i, username=f"user{i}") for i in range(5)]
        service.db.query.return_value.offset.return_value.limit.return_value.all.return_value = mock_users
        service.db.query.return_value.count.return_value = 5
        
        result = await service.list_users(page=1, page_size=10)
        
        assert len(result["items"]) == 5
        assert result["total"] == 5
        assert result["page"] == 1


class TestDeviceService:
    """Test backend/services/device_service.py"""
    
    @pytest.mark.asyncio
    async def test_device_service_creation(self):
        """Test DeviceService instantiation"""
        from backend.services.device_service import DeviceService
        
        service = DeviceService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_create_device(self):
        """Test device creation"""
        from backend.services.device_service import DeviceService
        
        service = DeviceService()
        service.db = AsyncMock()
        
        device_data = {
            "name": "router1",
            "ip_address": "192.168.1.1",
            "device_type": "router",
            "vendor": "cisco"
        }
        
        result = await service.create_device(device_data)
        
        service.db.add.assert_called_once()
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_get_device_by_ip(self):
        """Test getting device by IP"""
        from backend.services.device_service import DeviceService
        
        service = DeviceService()
        service.db = AsyncMock()
        
        mock_device = Mock()
        mock_device.ip_address = "192.168.1.1"
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_device
        
        result = await service.get_device_by_ip("192.168.1.1")
        assert result == mock_device
        
    @pytest.mark.asyncio
    async def test_update_device_status(self):
        """Test updating device status"""
        from backend.services.device_service import DeviceService
        
        service = DeviceService()
        service.db = AsyncMock()
        
        mock_device = Mock()
        mock_device.id = 1
        mock_device.status = "active"
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_device
        
        result = await service.update_device_status(1, "inactive")
        
        assert mock_device.status == "inactive"
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_bulk_import_devices(self):
        """Test bulk device import"""
        from backend.services.device_service import DeviceService
        
        service = DeviceService()
        service.db = AsyncMock()
        
        devices = [
            {"name": f"device{i}", "ip_address": f"192.168.1.{i}"}
            for i in range(10)
        ]
        
        result = await service.bulk_import_devices(devices)
        
        # Should call add for each device
        assert service.db.add.call_count == 10
        service.db.commit.assert_called_once()


class TestMetricsService:
    """Test backend/services/metrics_service.py"""
    
    @pytest.mark.asyncio
    async def test_metrics_service_creation(self):
        """Test MetricsService instantiation"""
        from backend.services.metrics_service import MetricsService
        
        service = MetricsService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_record_metric(self):
        """Test recording a metric"""
        from backend.services.metrics_service import MetricsService
        
        service = MetricsService()
        service.db = AsyncMock()
        
        metric_data = {
            "device_id": 1,
            "metric_type": "cpu_usage",
            "value": 75.5,
            "timestamp": datetime.utcnow()
        }
        
        result = await service.record_metric(metric_data)
        
        service.db.add.assert_called_once()
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_get_device_metrics(self):
        """Test getting metrics for a device"""
        from backend.services.metrics_service import MetricsService
        
        service = MetricsService()
        service.db = AsyncMock()
        
        mock_metrics = [
            Mock(metric_type="cpu", value=50),
            Mock(metric_type="memory", value=80)
        ]
        
        service.db.query.return_value.filter.return_value.all.return_value = mock_metrics
        
        result = await service.get_device_metrics(device_id=1)
        assert len(result) == 2
        
    @pytest.mark.asyncio
    async def test_aggregate_metrics(self):
        """Test metric aggregation"""
        from backend.services.metrics_service import MetricsService
        
        service = MetricsService()
        service.db = AsyncMock()
        
        # Mock aggregation result
        service.db.query.return_value.filter.return_value.group_by.return_value.all.return_value = [
            (50.0, 75.0, 60.0)  # min, max, avg
        ]
        
        result = await service.aggregate_metrics(
            device_id=1,
            metric_type="cpu_usage",
            start_time=datetime.utcnow() - timedelta(hours=1),
            end_time=datetime.utcnow()
        )
        
        assert result["min"] == 50.0
        assert result["max"] == 75.0
        assert result["avg"] == 60.0
        
    @pytest.mark.asyncio
    async def test_check_thresholds(self):
        """Test threshold checking"""
        from backend.services.metrics_service import MetricsService
        
        service = MetricsService()
        service.alert_service = AsyncMock()
        
        # Test threshold exceeded
        result = await service.check_threshold(
            device_id=1,
            metric_type="cpu_usage",
            value=95,
            threshold=80
        )
        
        # Should generate alert
        service.alert_service.create_alert.assert_called_once()


class TestAlertService:
    """Test backend/services/alert_service.py"""
    
    @pytest.mark.asyncio
    async def test_alert_service_creation(self):
        """Test AlertService instantiation"""
        from backend.services.alert_service import AlertService
        
        service = AlertService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_create_alert(self):
        """Test alert creation"""
        from backend.services.alert_service import AlertService
        
        service = AlertService()
        service.db = AsyncMock()
        service.notification_service = AsyncMock()
        
        alert_data = {
            "device_id": 1,
            "alert_type": "cpu_high",
            "severity": "warning",
            "message": "CPU usage above 80%"
        }
        
        result = await service.create_alert(alert_data)
        
        service.db.add.assert_called_once()
        service.db.commit.assert_called_once()
        service.notification_service.send_alert_notification.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_acknowledge_alert(self):
        """Test alert acknowledgment"""
        from backend.services.alert_service import AlertService
        
        service = AlertService()
        service.db = AsyncMock()
        
        mock_alert = Mock()
        mock_alert.id = 1
        mock_alert.status = "open"
        mock_alert.acknowledged_by = None
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        result = await service.acknowledge_alert(1, user_id=1)
        
        assert mock_alert.status == "acknowledged"
        assert mock_alert.acknowledged_by == 1
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_resolve_alert(self):
        """Test alert resolution"""
        from backend.services.alert_service import AlertService
        
        service = AlertService()
        service.db = AsyncMock()
        
        mock_alert = Mock()
        mock_alert.id = 1
        mock_alert.status = "acknowledged"
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        result = await service.resolve_alert(1, resolution="Fixed the issue")
        
        assert mock_alert.status == "resolved"
        assert mock_alert.resolution == "Fixed the issue"
        service.db.commit.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_escalate_alert(self):
        """Test alert escalation"""
        from backend.services.alert_service import AlertService
        
        service = AlertService()
        service.db = AsyncMock()
        service.notification_service = AsyncMock()
        
        mock_alert = Mock()
        mock_alert.id = 1
        mock_alert.severity = "warning"
        mock_alert.escalation_level = 0
        
        service.db.query.return_value.filter.return_value.first.return_value = mock_alert
        
        result = await service.escalate_alert(1)
        
        assert mock_alert.severity == "critical"
        assert mock_alert.escalation_level == 1
        service.notification_service.send_escalation_notification.assert_called_once()


class TestNotificationService:
    """Test backend/services/notification_service.py"""
    
    @pytest.mark.asyncio
    async def test_notification_service_creation(self):
        """Test NotificationService instantiation"""
        from backend.services.notification_service import NotificationService
        
        service = NotificationService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_send_email_notification(self):
        """Test email notification"""
        from backend.services.notification_service import NotificationService
        
        service = NotificationService()
        service.email_client = AsyncMock()
        service.db = AsyncMock()
        
        notification_data = {
            "recipient": "user@example.com",
            "subject": "Alert",
            "message": "System alert"
        }
        
        result = await service.send_email_notification(notification_data)
        
        service.email_client.send_email.assert_called_once()
        service.db.add.assert_called_once()  # Log notification
        
    @pytest.mark.asyncio
    async def test_send_sms_notification(self):
        """Test SMS notification"""
        from backend.services.notification_service import NotificationService
        
        service = NotificationService()
        service.sms_client = AsyncMock()
        service.db = AsyncMock()
        
        notification_data = {
            "recipient": "+1234567890",
            "message": "System alert"
        }
        
        result = await service.send_sms_notification(notification_data)
        
        service.sms_client.send_sms.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_send_webhook_notification(self):
        """Test webhook notification"""
        from backend.services.notification_service import NotificationService
        
        service = NotificationService()
        service.webhook_client = AsyncMock()
        
        notification_data = {
            "url": "https://example.com/webhook",
            "payload": {"alert": "test"}
        }
        
        result = await service.send_webhook_notification(notification_data)
        
        service.webhook_client.send.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_notification_templates(self):
        """Test notification templates"""
        from backend.services.notification_service import NotificationService
        
        service = NotificationService()
        
        template_data = {
            "device_name": "router1",
            "alert_type": "cpu_high",
            "value": 95
        }
        
        message = service.render_template("alert_email", template_data)
        
        assert "router1" in message
        assert "cpu_high" in message
        assert "95" in message


class TestDiscoveryService:
    """Test backend/services/discovery_service.py"""
    
    @pytest.mark.asyncio
    async def test_discovery_service_creation(self):
        """Test DiscoveryService instantiation"""
        from backend.services.discovery_service import DiscoveryService
        
        service = DiscoveryService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_discover_subnet(self):
        """Test subnet discovery"""
        from backend.services.discovery_service import DiscoveryService
        
        service = DiscoveryService()
        service.snmp_service = AsyncMock()
        service.device_service = AsyncMock()
        
        # Mock SNMP responses
        service.snmp_service.scan_subnet.return_value = [
            {"ip": "192.168.1.1", "sysName": "router1"},
            {"ip": "192.168.1.2", "sysName": "switch1"}
        ]
        
        result = await service.discover_subnet("192.168.1.0/24")
        
        assert len(result) == 2
        # Should create devices
        assert service.device_service.create_device.call_count == 2
        
    @pytest.mark.asyncio
    async def test_identify_device(self):
        """Test device identification"""
        from backend.services.discovery_service import DiscoveryService
        
        service = DiscoveryService()
        service.snmp_service = AsyncMock()
        service.ssh_service = AsyncMock()
        
        # Mock SNMP response
        service.snmp_service.get_device_info.return_value = {
            "sysDescr": "Cisco IOS Software",
            "sysName": "router1",
            "sysObjectID": "1.3.6.1.4.1.9"
        }
        
        result = await service.identify_device("192.168.1.1")
        
        assert result["vendor"] == "cisco"
        assert result["name"] == "router1"
        
    @pytest.mark.asyncio
    async def test_schedule_discovery(self):
        """Test discovery scheduling"""
        from backend.services.discovery_service import DiscoveryService
        
        service = DiscoveryService()
        service.task_scheduler = AsyncMock()
        
        job_data = {
            "name": "Daily Discovery",
            "subnet": "192.168.0.0/16",
            "schedule": "0 2 * * *"  # 2 AM daily
        }
        
        result = await service.schedule_discovery(job_data)
        
        service.task_scheduler.schedule.assert_called_once()


class TestMonitoringService:
    """Test backend/services/monitoring_service.py"""
    
    @pytest.mark.asyncio
    async def test_monitoring_service_creation(self):
        """Test MonitoringService instantiation"""
        from backend.services.monitoring_service import MonitoringService
        
        service = MonitoringService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_poll_device(self):
        """Test device polling"""
        from backend.services.monitoring_service import MonitoringService
        
        service = MonitoringService()
        service.snmp_service = AsyncMock()
        service.metrics_service = AsyncMock()
        
        # Mock SNMP data
        service.snmp_service.get_metrics.return_value = {
            "cpu_usage": 45,
            "memory_usage": 60,
            "interface_status": "up"
        }
        
        result = await service.poll_device(device_id=1)
        
        # Should record metrics
        assert service.metrics_service.record_metric.call_count >= 3
        
    @pytest.mark.asyncio
    async def test_check_device_health(self):
        """Test device health check"""
        from backend.services.monitoring_service import MonitoringService
        
        service = MonitoringService()
        service.snmp_service = AsyncMock()
        service.alert_service = AsyncMock()
        
        # Mock unhealthy response
        service.snmp_service.ping.return_value = False
        
        result = await service.check_device_health(device_id=1)
        
        assert result["status"] == "down"
        # Should create alert
        service.alert_service.create_alert.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_start_monitoring(self):
        """Test starting monitoring for a device"""
        from backend.services.monitoring_service import MonitoringService
        
        service = MonitoringService()
        service.task_scheduler = AsyncMock()
        
        result = await service.start_monitoring(device_id=1, interval=60)
        
        service.task_scheduler.schedule_recurring.assert_called_once()


class TestSNMPService:
    """Test backend/services/snmp_service.py"""
    
    @pytest.mark.asyncio
    async def test_snmp_service_creation(self):
        """Test SNMPService instantiation"""
        from backend.services.snmp_service import SNMPService
        
        service = SNMPService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_get_device_info(self):
        """Test getting device info via SNMP"""
        from backend.services.snmp_service import SNMPService
        
        service = SNMPService()
        
        with patch('pysnmp.hlapi.getCmd') as mock_get:
            # Mock SNMP response
            mock_get.return_value = iter([(None, None, None, [
                Mock(prettyPrint=lambda: "Cisco IOS Software"),
                Mock(prettyPrint=lambda: "router1"),
                Mock(prettyPrint=lambda: "1.3.6.1.4.1.9")
            ])])
            
            result = await service.get_device_info(
                "192.168.1.1",
                community="public"
            )
            
            assert "sysDescr" in result
            assert "sysName" in result
            
    @pytest.mark.asyncio
    async def test_walk_oid(self):
        """Test SNMP walk operation"""
        from backend.services.snmp_service import SNMPService
        
        service = SNMPService()
        
        with patch('pysnmp.hlapi.nextCmd') as mock_walk:
            # Mock SNMP walk response
            mock_walk.return_value = iter([
                (None, None, None, [Mock(prettyPrint=lambda: "value1")]),
                (None, None, None, [Mock(prettyPrint=lambda: "value2")])
            ])
            
            result = await service.walk_oid(
                "192.168.1.1",
                "1.3.6.1.2.1.2.2.1",  # interfaces
                community="public"
            )
            
            assert len(result) == 2


class TestSSHService:
    """Test backend/services/ssh_service.py"""
    
    @pytest.mark.asyncio
    async def test_ssh_service_creation(self):
        """Test SSHService instantiation"""
        from backend.services.ssh_service import SSHService
        
        service = SSHService()
        assert service is not None
        
    @pytest.mark.asyncio
    async def test_execute_command(self):
        """Test SSH command execution"""
        from backend.services.ssh_service import SSHService
        
        service = SSHService()
        
        with patch('asyncssh.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.run.return_value = Mock(stdout="Command output")
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            result = await service.execute_command(
                "192.168.1.1",
                "show version",
                username="admin",
                password="password"
            )
            
            assert result == "Command output"
            
    @pytest.mark.asyncio
    async def test_execute_multiple_commands(self):
        """Test executing multiple SSH commands"""
        from backend.services.ssh_service import SSHService
        
        service = SSHService()
        
        with patch('asyncssh.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_conn.run.side_effect = [
                Mock(stdout="Output 1"),
                Mock(stdout="Output 2")
            ]
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            commands = ["show version", "show interfaces"]
            result = await service.execute_multiple_commands(
                "192.168.1.1",
                commands,
                username="admin",
                password="password"
            )
            
            assert len(result) == 2
            assert result[0] == "Output 1"
            assert result[1] == "Output 2"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])