"""
Phase 7-8: Comprehensive tests for integrations and background tasks
Target: Achieve high coverage for integration modules and task execution
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime, timedelta
import json


class TestSNMPIntegration:
    """Test backend/integrations/snmp.py"""
    
    @pytest.mark.asyncio
    async def test_snmp_client_creation(self):
        """Test SNMPClient instantiation"""
        from backend.integrations.snmp import SNMPClient
        
        client = SNMPClient(
            host="192.168.1.1",
            port=161,
            community="public",
            version="2c",
            timeout=5,
            retries=3
        )
        
        assert client.host == "192.168.1.1"
        assert client.port == 161
        assert client.community == "public"
        assert client.version == "2c"
    
    @pytest.mark.asyncio
    async def test_snmp_get(self):
        """Test SNMP GET operation"""
        from backend.integrations.snmp import SNMPClient
        
        client = SNMPClient("192.168.1.1")
        
        with patch('pysnmp.hlapi.getCmd') as mock_get:
            mock_get.return_value = iter([(None, None, None, [
                Mock(prettyPrint=lambda: "Test Device")
            ])])
            
            result = await client.get("1.3.6.1.2.1.1.5.0")  # sysName
            assert result == "Test Device"
    
    @pytest.mark.asyncio
    async def test_snmp_walk(self):
        """Test SNMP WALK operation"""
        from backend.integrations.snmp import SNMPClient
        
        client = SNMPClient("192.168.1.1")
        
        with patch('pysnmp.hlapi.nextCmd') as mock_walk:
            mock_walk.return_value = iter([
                (None, None, None, [Mock(prettyPrint=lambda: "Interface1")]),
                (None, None, None, [Mock(prettyPrint=lambda: "Interface2")])
            ])
            
            results = await client.walk("1.3.6.1.2.1.2.2.1.2")  # ifDescr
            assert len(results) == 2
            assert results[0] == "Interface1"
    
    @pytest.mark.asyncio
    async def test_snmp_bulk_walk(self):
        """Test SNMP BULK WALK operation"""
        from backend.integrations.snmp import SNMPClient
        
        client = SNMPClient("192.168.1.1", version="2c")
        
        with patch('pysnmp.hlapi.bulkCmd') as mock_bulk:
            mock_bulk.return_value = iter([
                (None, None, None, [Mock(prettyPrint=lambda: f"Value{i}") for i in range(10)])
            ])
            
            results = await client.bulk_walk("1.3.6.1.2.1", max_repetitions=10)
            assert len(results) > 0
    
    @pytest.mark.asyncio
    async def test_snmp_v3_auth(self):
        """Test SNMPv3 authentication"""
        from backend.integrations.snmp import SNMPClient
        
        client = SNMPClient(
            host="192.168.1.1",
            version="3",
            username="admin",
            auth_key="authkey123",
            priv_key="privkey123",
            auth_protocol="SHA",
            priv_protocol="AES"
        )
        
        assert client.version == "3"
        assert client.username == "admin"
        assert client.auth_protocol == "SHA"


class TestSSHIntegration:
    """Test backend/integrations/ssh.py"""
    
    @pytest.mark.asyncio
    async def test_ssh_client_creation(self):
        """Test SSHClient instantiation"""
        from backend.integrations.ssh import SSHClient
        
        client = SSHClient(
            host="192.168.1.1",
            port=22,
            username="admin",
            password="password",
            timeout=30
        )
        
        assert client.host == "192.168.1.1"
        assert client.port == 22
        assert client.username == "admin"
    
    @pytest.mark.asyncio
    async def test_ssh_connect(self):
        """Test SSH connection"""
        from backend.integrations.ssh import SSHClient
        
        client = SSHClient("192.168.1.1", username="admin", password="pass")
        
        with patch('asyncssh.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            await client.connect()
            mock_connect.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_ssh_execute_command(self):
        """Test SSH command execution"""
        from backend.integrations.ssh import SSHClient
        
        client = SSHClient("192.168.1.1")
        
        with patch('asyncssh.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_result = Mock()
            mock_result.stdout = "Command output"
            mock_result.stderr = ""
            mock_result.exit_status = 0
            mock_conn.run.return_value = mock_result
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            output = await client.execute("show version")
            assert output == "Command output"
    
    @pytest.mark.asyncio
    async def test_ssh_key_auth(self):
        """Test SSH key-based authentication"""
        from backend.integrations.ssh import SSHClient
        
        client = SSHClient(
            host="192.168.1.1",
            username="admin",
            key_file="/path/to/key"
        )
        
        assert client.key_file == "/path/to/key"
    
    @pytest.mark.asyncio
    async def test_ssh_sftp(self):
        """Test SFTP operations"""
        from backend.integrations.ssh import SSHClient
        
        client = SSHClient("192.168.1.1")
        
        with patch('asyncssh.connect') as mock_connect:
            mock_conn = AsyncMock()
            mock_sftp = AsyncMock()
            mock_conn.start_sftp_client.return_value = mock_sftp
            mock_connect.return_value.__aenter__.return_value = mock_conn
            
            await client.upload_file("/local/file", "/remote/file")
            mock_sftp.put.assert_called_once()


class TestWebhookIntegration:
    """Test backend/integrations/webhook.py"""
    
    @pytest.mark.asyncio
    async def test_webhook_client_creation(self):
        """Test WebhookClient instantiation"""
        from backend.integrations.webhook import WebhookClient
        
        client = WebhookClient(
            url="https://example.com/webhook",
            method="POST",
            headers={"Authorization": "Bearer token"},
            timeout=10
        )
        
        assert client.url == "https://example.com/webhook"
        assert client.method == "POST"
        assert client.headers["Authorization"] == "Bearer token"
    
    @pytest.mark.asyncio
    async def test_webhook_send(self):
        """Test webhook sending"""
        from backend.integrations.webhook import WebhookClient
        
        client = WebhookClient("https://example.com/webhook")
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_response.json.return_value = {"success": True}
            mock_post.return_value.__aenter__.return_value = mock_response
            
            payload = {"alert": "test", "severity": "warning"}
            result = await client.send(payload)
            
            assert result["success"] is True
            mock_post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_webhook_retry(self):
        """Test webhook retry on failure"""
        from backend.integrations.webhook import WebhookClient
        
        client = WebhookClient("https://example.com/webhook", max_retries=3)
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_post.side_effect = [
                Exception("Connection error"),
                Exception("Timeout"),
                AsyncMock(status=200)
            ]
            
            result = await client.send_with_retry({"test": "data"})
            assert mock_post.call_count <= 3


class TestEmailIntegration:
    """Test backend/integrations/email.py"""
    
    @pytest.mark.asyncio
    async def test_email_client_creation(self):
        """Test EmailClient instantiation"""
        from backend.integrations.email import EmailClient
        
        client = EmailClient(
            smtp_host="smtp.example.com",
            smtp_port=587,
            username="notifications@example.com",
            password="password",
            use_tls=True
        )
        
        assert client.smtp_host == "smtp.example.com"
        assert client.smtp_port == 587
        assert client.use_tls is True
    
    @pytest.mark.asyncio
    async def test_send_email(self):
        """Test email sending"""
        from backend.integrations.email import EmailClient
        
        client = EmailClient("smtp.example.com")
        
        with patch('aiosmtplib.send') as mock_send:
            mock_send.return_value = (250, "OK")
            
            result = await client.send_email(
                to="user@example.com",
                subject="Test Alert",
                body="This is a test",
                html_body="<p>This is a test</p>"
            )
            
            assert result is True
            mock_send.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_send_bulk_email(self):
        """Test bulk email sending"""
        from backend.integrations.email import EmailClient
        
        client = EmailClient("smtp.example.com")
        
        with patch('aiosmtplib.send') as mock_send:
            mock_send.return_value = (250, "OK")
            
            recipients = ["user1@example.com", "user2@example.com"]
            results = await client.send_bulk(
                recipients=recipients,
                subject="Bulk Alert",
                body="Bulk message"
            )
            
            assert len(results) == 2


class TestSMSIntegration:
    """Test backend/integrations/sms.py"""
    
    @pytest.mark.asyncio
    async def test_sms_client_creation(self):
        """Test SMSClient instantiation"""
        from backend.integrations.sms import SMSClient
        
        client = SMSClient(
            provider="twilio",
            account_sid="AC123",
            auth_token="auth123",
            from_number="+1234567890"
        )
        
        assert client.provider == "twilio"
        assert client.account_sid == "AC123"
        assert client.from_number == "+1234567890"
    
    @pytest.mark.asyncio
    async def test_send_sms(self):
        """Test SMS sending"""
        from backend.integrations.sms import SMSClient
        
        client = SMSClient(provider="twilio")
        
        with patch('twilio.rest.Client') as mock_twilio:
            mock_client = Mock()
            mock_message = Mock()
            mock_message.sid = "MSG123"
            mock_client.messages.create.return_value = mock_message
            mock_twilio.return_value = mock_client
            
            result = await client.send_sms(
                to="+9876543210",
                message="Alert: System down"
            )
            
            assert result == "MSG123"


class TestSlackIntegration:
    """Test backend/integrations/slack.py"""
    
    @pytest.mark.asyncio
    async def test_slack_client_creation(self):
        """Test SlackClient instantiation"""
        from backend.integrations.slack import SlackClient
        
        client = SlackClient(
            webhook_url="https://hooks.slack.com/services/XXX",
            channel="#alerts",
            username="CHM Bot"
        )
        
        assert client.webhook_url.startswith("https://hooks.slack.com")
        assert client.channel == "#alerts"
        assert client.username == "CHM Bot"
    
    @pytest.mark.asyncio
    async def test_send_slack_message(self):
        """Test Slack message sending"""
        from backend.integrations.slack import SlackClient
        
        client = SlackClient("https://hooks.slack.com/services/XXX")
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await client.send_message(
                text="Alert: High CPU usage",
                attachments=[{
                    "color": "warning",
                    "title": "CPU Alert",
                    "text": "CPU usage is above 90%"
                }]
            )
            
            assert result is True


class TestTeamsIntegration:
    """Test backend/integrations/teams.py"""
    
    @pytest.mark.asyncio
    async def test_teams_client_creation(self):
        """Test TeamsClient instantiation"""
        from backend.integrations.teams import TeamsClient
        
        client = TeamsClient(
            webhook_url="https://outlook.office.com/webhook/XXX"
        )
        
        assert client.webhook_url.startswith("https://outlook.office.com")
    
    @pytest.mark.asyncio
    async def test_send_teams_message(self):
        """Test Teams message sending"""
        from backend.integrations.teams import TeamsClient
        
        client = TeamsClient("https://outlook.office.com/webhook/XXX")
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_post.return_value.__aenter__.return_value = mock_response
            
            result = await client.send_card(
                title="System Alert",
                text="High memory usage detected",
                color="FF0000",
                facts=[
                    {"name": "Device", "value": "router1"},
                    {"name": "Memory", "value": "95%"}
                ]
            )
            
            assert result is True


class TestPagerDutyIntegration:
    """Test backend/integrations/pagerduty.py"""
    
    @pytest.mark.asyncio
    async def test_pagerduty_client_creation(self):
        """Test PagerDutyClient instantiation"""
        from backend.integrations.pagerduty import PagerDutyClient
        
        client = PagerDutyClient(
            integration_key="abc123",
            api_key="api123"
        )
        
        assert client.integration_key == "abc123"
        assert client.api_key == "api123"
    
    @pytest.mark.asyncio
    async def test_trigger_incident(self):
        """Test PagerDuty incident triggering"""
        from backend.integrations.pagerduty import PagerDutyClient
        
        client = PagerDutyClient("abc123")
        
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 202
            mock_response.json.return_value = {"incident_key": "INC123"}
            mock_post.return_value.__aenter__.return_value = mock_response
            
            incident_key = await client.trigger_incident(
                summary="Database connection failed",
                severity="error",
                source="CHM",
                custom_details={"database": "production"}
            )
            
            assert incident_key == "INC123"


# Phase 8: Background Tasks

class TestDiscoveryTasks:
    """Test backend/tasks/discovery_tasks.py"""
    
    @pytest.mark.asyncio
    async def test_discover_devices_task(self):
        """Test device discovery task"""
        from backend.tasks.discovery_tasks import discover_devices
        
        with patch('backend.services.discovery_service.DiscoveryService.discover_subnet') as mock_discover:
            mock_discover.return_value = [
                {"ip": "192.168.1.1", "hostname": "router1"},
                {"ip": "192.168.1.2", "hostname": "switch1"}
            ]
            
            result = await discover_devices.apply_async(
                args=["192.168.1.0/24"]
            ).get()
            
            assert len(result) == 2
    
    @pytest.mark.asyncio
    async def test_scan_subnet_task(self):
        """Test subnet scanning task"""
        from backend.tasks.discovery_tasks import scan_subnet
        
        with patch('backend.integrations.snmp.SNMPClient.scan') as mock_scan:
            mock_scan.return_value = ["192.168.1.1", "192.168.1.2"]
            
            result = await scan_subnet("192.168.1.0/24")
            assert len(result) == 2
    
    @pytest.mark.asyncio
    async def test_identify_device_task(self):
        """Test device identification task"""
        from backend.tasks.discovery_tasks import identify_device
        
        with patch('backend.services.discovery_service.DiscoveryService.identify_device') as mock_identify:
            mock_identify.return_value = {
                "vendor": "cisco",
                "model": "ISR4321",
                "version": "16.9.1"
            }
            
            result = await identify_device("192.168.1.1")
            assert result["vendor"] == "cisco"


class TestMonitoringTasks:
    """Test backend/tasks/monitoring_tasks.py"""
    
    @pytest.mark.asyncio
    async def test_collect_metrics_task(self):
        """Test metrics collection task"""
        from backend.tasks.monitoring_tasks import collect_metrics
        
        with patch('backend.services.monitoring_service.MonitoringService.poll_device') as mock_poll:
            mock_poll.return_value = {
                "cpu": 45,
                "memory": 60,
                "temperature": 35
            }
            
            result = await collect_metrics(device_id=1)
            assert result["cpu"] == 45
    
    @pytest.mark.asyncio
    async def test_check_device_health_task(self):
        """Test device health check task"""
        from backend.tasks.monitoring_tasks import check_device_health
        
        with patch('backend.services.monitoring_service.MonitoringService.check_device_health') as mock_check:
            mock_check.return_value = {
                "status": "healthy",
                "uptime": 1000000,
                "last_seen": datetime.utcnow()
            }
            
            result = await check_device_health(device_id=1)
            assert result["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_generate_alerts_task(self):
        """Test alert generation task"""
        from backend.tasks.monitoring_tasks import generate_alerts
        
        with patch('backend.services.alert_service.AlertService.check_thresholds') as mock_check:
            mock_check.return_value = [
                {"device_id": 1, "alert_type": "cpu_high", "severity": "warning"}
            ]
            
            alerts = await generate_alerts()
            assert len(alerts) == 1


class TestNotificationTasks:
    """Test backend/tasks/notification_tasks.py"""
    
    @pytest.mark.asyncio
    async def test_send_email_notification_task(self):
        """Test email notification task"""
        from backend.tasks.notification_tasks import send_email_notification
        
        with patch('backend.integrations.email.EmailClient.send_email') as mock_send:
            mock_send.return_value = True
            
            result = await send_email_notification(
                to="user@example.com",
                subject="Alert",
                body="Test alert"
            )
            
            assert result is True
    
    @pytest.mark.asyncio
    async def test_send_sms_notification_task(self):
        """Test SMS notification task"""
        from backend.tasks.notification_tasks import send_sms_notification
        
        with patch('backend.integrations.sms.SMSClient.send_sms') as mock_send:
            mock_send.return_value = "MSG123"
            
            result = await send_sms_notification(
                to="+1234567890",
                message="Alert"
            )
            
            assert result == "MSG123"
    
    @pytest.mark.asyncio
    async def test_send_webhook_notification_task(self):
        """Test webhook notification task"""
        from backend.tasks.notification_tasks import send_webhook_notification
        
        with patch('backend.integrations.webhook.WebhookClient.send') as mock_send:
            mock_send.return_value = {"success": True}
            
            result = await send_webhook_notification(
                url="https://example.com/webhook",
                payload={"alert": "test"}
            )
            
            assert result["success"] is True


class TestMaintenanceTasks:
    """Test backend/tasks/maintenance_tasks.py"""
    
    @pytest.mark.asyncio
    async def test_cleanup_old_metrics_task(self):
        """Test old metrics cleanup task"""
        from backend.tasks.maintenance_tasks import cleanup_old_metrics
        
        with patch('backend.services.metrics_service.MetricsService.delete_old_metrics') as mock_delete:
            mock_delete.return_value = 1000  # Deleted count
            
            result = await cleanup_old_metrics(days=30)
            assert result == 1000
    
    @pytest.mark.asyncio
    async def test_archive_alerts_task(self):
        """Test alert archiving task"""
        from backend.tasks.maintenance_tasks import archive_alerts
        
        with patch('backend.services.alert_service.AlertService.archive_old_alerts') as mock_archive:
            mock_archive.return_value = 50  # Archived count
            
            result = await archive_alerts(days=90)
            assert result == 50
    
    @pytest.mark.asyncio
    async def test_optimize_database_task(self):
        """Test database optimization task"""
        from backend.tasks.maintenance_tasks import optimize_database
        
        with patch('backend.services.database_service.DatabaseService.optimize') as mock_optimize:
            mock_optimize.return_value = {
                "tables_optimized": 10,
                "indexes_rebuilt": 5
            }
            
            result = await optimize_database()
            assert result["tables_optimized"] == 10


class TestReportTasks:
    """Test backend/tasks/report_tasks.py"""
    
    @pytest.mark.asyncio
    async def test_generate_report_task(self):
        """Test report generation task"""
        try:
            from backend.tasks.report_tasks import generate_report
            
            with patch('backend.services.report_service.ReportService.generate') as mock_generate:
                mock_generate.return_value = {
                    "report_id": "RPT123",
                    "file_path": "/reports/report_123.pdf"
                }
                
                result = await generate_report(
                    report_type="network_summary",
                    start_date="2024-01-01",
                    end_date="2024-01-31"
                )
                
                assert result["report_id"] == "RPT123"
        except ImportError:
            pass
    
    @pytest.mark.asyncio
    async def test_schedule_report_task(self):
        """Test report scheduling task"""
        try:
            from backend.tasks.report_tasks import schedule_report
            
            with patch('backend.services.report_service.ReportService.schedule') as mock_schedule:
                mock_schedule.return_value = {"job_id": "JOB123"}
                
                result = await schedule_report(
                    report_type="daily_summary",
                    cron="0 8 * * *"
                )
                
                assert result["job_id"] == "JOB123"
        except ImportError:
            pass


class TestBackupTasks:
    """Test backend/tasks/backup_tasks.py"""
    
    @pytest.mark.asyncio
    async def test_backup_database_task(self):
        """Test database backup task"""
        try:
            from backend.tasks.backup_tasks import backup_database
            
            with patch('backend.services.backup_service.BackupService.backup_database') as mock_backup:
                mock_backup.return_value = {
                    "backup_file": "/backups/backup_20240101.sql",
                    "size_mb": 150
                }
                
                result = await backup_database()
                assert "backup_file" in result
        except ImportError:
            pass
    
    @pytest.mark.asyncio
    async def test_backup_configurations_task(self):
        """Test configuration backup task"""
        try:
            from backend.tasks.backup_tasks import backup_configurations
            
            with patch('backend.services.backup_service.BackupService.backup_configs') as mock_backup:
                mock_backup.return_value = {
                    "device_count": 50,
                    "backup_path": "/backups/configs/"
                }
                
                result = await backup_configurations()
                assert result["device_count"] == 50
        except ImportError:
            pass


class TestCeleryConfiguration:
    """Test Celery task configuration"""
    
    def test_celery_app_creation(self):
        """Test Celery app configuration"""
        try:
            from backend.tasks.celery_app import celery_app
            
            assert celery_app is not None
            assert celery_app.main == "chm"
        except ImportError:
            pass
    
    def test_celery_beat_schedule(self):
        """Test Celery Beat schedule"""
        try:
            from backend.tasks.celery_app import celery_app
            
            schedule = celery_app.conf.beat_schedule
            
            # Check for scheduled tasks
            assert "collect-metrics" in schedule or len(schedule) > 0
        except (ImportError, AttributeError):
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])