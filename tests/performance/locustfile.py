"""
CHM Performance Testing with Locust

This file contains performance and load testing scenarios for the CHM application.
Run with: locust -f locustfile.py --host=http://localhost:8000
"""

import json
import random
import string
from datetime import datetime, timedelta
from locust import HttpUser, TaskSet, task, between, events
from locust.exception import StopUser
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Test data generators
def generate_random_string(length=10):
    """Generate a random string of specified length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_device_data():
    """Generate random device data for testing."""
    return {
        "name": f"device-{generate_random_string(8)}",
        "ip_address": f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
        "device_type": random.choice(["router", "switch", "firewall", "load_balancer"]),
        "vendor": random.choice(["Cisco", "Juniper", "Arista", "HP"]),
        "model": f"Model-{random.randint(1000, 9999)}",
        "location": random.choice(["DC1", "DC2", "DC3", "Branch1", "Branch2"]),
        "snmp_community": "public",
        "snmp_version": random.choice(["v2c", "v3"]),
        "status": "online"
    }

def generate_metric_data(device_id):
    """Generate random metric data for testing."""
    return {
        "device_id": device_id,
        "metric_name": random.choice(["cpu_usage", "memory_usage", "interface_traffic", "temperature"]),
        "value": round(random.uniform(0, 100), 2),
        "unit": random.choice(["%", "bytes", "packets", "celsius"]),
        "timestamp": datetime.utcnow().isoformat()
    }

def generate_alert_data(device_id):
    """Generate random alert data for testing."""
    return {
        "device_id": device_id,
        "severity": random.choice(["info", "warning", "error", "critical"]),
        "message": f"Test alert: {generate_random_string(20)}",
        "metric_name": random.choice(["cpu_usage", "memory_usage", "interface_status"]),
        "threshold_value": round(random.uniform(70, 95), 2),
        "current_value": round(random.uniform(75, 100), 2)
    }


class AuthenticatedUser(HttpUser):
    """Base class for authenticated users with token management."""
    
    wait_time = between(1, 3)
    host = "http://localhost:8000"
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token = None
        self.user_id = None
        self.device_ids = []
        
    def on_start(self):
        """Called when a simulated user starts."""
        self.login()
        
    def on_stop(self):
        """Called when a simulated user stops."""
        self.logout()
    
    def login(self):
        """Authenticate and get JWT token."""
        username = f"user_{generate_random_string(8)}"
        password = "Test123!@#"
        
        # Register new user
        response = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": f"{username}@test.com",
                "password": password,
                "full_name": f"Test User {username}"
            },
            catch_response=True
        )
        
        if response.status_code == 200:
            response.success()
            
            # Login with created user
            login_response = self.client.post(
                "/api/v1/auth/login",
                data={
                    "username": username,
                    "password": password
                },
                catch_response=True
            )
            
            if login_response.status_code == 200:
                data = login_response.json()
                self.token = data.get("access_token")
                self.user_id = data.get("user_id")
                self.client.headers.update({"Authorization": f"Bearer {self.token}"})
                login_response.success()
                logger.info(f"User {username} logged in successfully")
            else:
                login_response.failure(f"Login failed: {login_response.text}")
        else:
            response.failure(f"Registration failed: {response.text}")
    
    def logout(self):
        """Logout the user."""
        if self.token:
            self.client.post(
                "/api/v1/auth/logout",
                catch_response=True
            )
            logger.info(f"User {self.user_id} logged out")


class DeviceManagementTasks(TaskSet):
    """Task set for device management operations."""
    
    @task(3)
    def list_devices(self):
        """Get list of devices."""
        with self.client.get(
            "/api/v1/devices",
            params={"limit": 20, "offset": 0},
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
                devices = response.json().get("items", [])
                if devices:
                    self.user.device_ids = [d["id"] for d in devices[:5]]
            else:
                response.failure(f"Failed to list devices: {response.status_code}")
    
    @task(2)
    def create_device(self):
        """Create a new device."""
        device_data = generate_device_data()
        
        with self.client.post(
            "/api/v1/devices",
            json=device_data,
            catch_response=True
        ) as response:
            if response.status_code in [200, 201]:
                response.success()
                device_id = response.json().get("id")
                if device_id:
                    self.user.device_ids.append(device_id)
                logger.info(f"Created device: {device_id}")
            else:
                response.failure(f"Failed to create device: {response.status_code}")
    
    @task(4)
    def get_device_details(self):
        """Get details of a specific device."""
        if not self.user.device_ids:
            return
        
        device_id = random.choice(self.user.device_ids)
        
        with self.client.get(
            f"/api/v1/devices/{device_id}",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to get device {device_id}: {response.status_code}")
    
    @task(1)
    def update_device(self):
        """Update a device."""
        if not self.user.device_ids:
            return
        
        device_id = random.choice(self.user.device_ids)
        update_data = {
            "location": random.choice(["DC1", "DC2", "DC3"]),
            "status": random.choice(["online", "offline", "maintenance"])
        }
        
        with self.client.put(
            f"/api/v1/devices/{device_id}",
            json=update_data,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to update device {device_id}: {response.status_code}")
    
    @task(1)
    def delete_device(self):
        """Delete a device."""
        if len(self.user.device_ids) < 5:
            return
        
        device_id = self.user.device_ids.pop()
        
        with self.client.delete(
            f"/api/v1/devices/{device_id}",
            catch_response=True
        ) as response:
            if response.status_code in [200, 204]:
                response.success()
                logger.info(f"Deleted device: {device_id}")
            else:
                response.failure(f"Failed to delete device {device_id}: {response.status_code}")


class MetricsTasks(TaskSet):
    """Task set for metrics operations."""
    
    @task(5)
    def submit_metrics(self):
        """Submit metrics for a device."""
        if not self.user.device_ids:
            return
        
        device_id = random.choice(self.user.device_ids)
        metrics_data = [generate_metric_data(device_id) for _ in range(random.randint(1, 5))]
        
        with self.client.post(
            "/api/v1/metrics",
            json=metrics_data,
            catch_response=True
        ) as response:
            if response.status_code in [200, 201]:
                response.success()
            else:
                response.failure(f"Failed to submit metrics: {response.status_code}")
    
    @task(8)
    def get_device_metrics(self):
        """Get metrics for a device."""
        if not self.user.device_ids:
            return
        
        device_id = random.choice(self.user.device_ids)
        time_range = random.choice(["1h", "6h", "24h", "7d"])
        
        with self.client.get(
            f"/api/v1/metrics/device/{device_id}",
            params={"time_range": time_range},
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to get metrics for device {device_id}: {response.status_code}")
    
    @task(3)
    def get_aggregated_metrics(self):
        """Get aggregated metrics."""
        metric_name = random.choice(["cpu_usage", "memory_usage", "interface_traffic"])
        aggregation = random.choice(["avg", "max", "min"])
        
        with self.client.get(
            f"/api/v1/metrics/aggregate",
            params={
                "metric_name": metric_name,
                "aggregation": aggregation,
                "time_range": "1h"
            },
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to get aggregated metrics: {response.status_code}")


class AlertsTasks(TaskSet):
    """Task set for alerts operations."""
    
    @task(2)
    def create_alert(self):
        """Create an alert."""
        if not self.user.device_ids:
            return
        
        device_id = random.choice(self.user.device_ids)
        alert_data = generate_alert_data(device_id)
        
        with self.client.post(
            "/api/v1/alerts",
            json=alert_data,
            catch_response=True
        ) as response:
            if response.status_code in [200, 201]:
                response.success()
            else:
                response.failure(f"Failed to create alert: {response.status_code}")
    
    @task(5)
    def list_alerts(self):
        """List active alerts."""
        params = {
            "status": random.choice(["active", "acknowledged", "resolved"]),
            "severity": random.choice(["info", "warning", "error", "critical", None]),
            "limit": 20
        }
        
        # Remove None values
        params = {k: v for k, v in params.items() if v is not None}
        
        with self.client.get(
            "/api/v1/alerts",
            params=params,
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to list alerts: {response.status_code}")
    
    @task(1)
    def acknowledge_alert(self):
        """Acknowledge an alert."""
        # Get active alerts first
        response = self.client.get("/api/v1/alerts", params={"status": "active", "limit": 10})
        
        if response.status_code == 200:
            alerts = response.json().get("items", [])
            if alerts:
                alert_id = random.choice(alerts)["id"]
                
                with self.client.put(
                    f"/api/v1/alerts/{alert_id}/acknowledge",
                    catch_response=True
                ) as ack_response:
                    if ack_response.status_code == 200:
                        ack_response.success()
                    else:
                        ack_response.failure(f"Failed to acknowledge alert {alert_id}: {ack_response.status_code}")


class MonitoringTasks(TaskSet):
    """Task set for monitoring endpoints."""
    
    @task(10)
    def health_check(self):
        """Check application health."""
        with self.client.get(
            "/health",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Health check failed: {response.status_code}")
    
    @task(5)
    def liveness_check(self):
        """Check liveness probe."""
        with self.client.get(
            "/api/v1/monitoring/liveness",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Liveness check failed: {response.status_code}")
    
    @task(5)
    def readiness_check(self):
        """Check readiness probe."""
        with self.client.get(
            "/api/v1/monitoring/readiness",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Readiness check failed: {response.status_code}")
    
    @task(2)
    def get_metrics(self):
        """Get Prometheus metrics."""
        with self.client.get(
            "/api/v1/monitoring/metrics",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to get metrics: {response.status_code}")


class StandardUser(AuthenticatedUser):
    """Standard user performing typical operations."""
    
    tasks = {
        DeviceManagementTasks: 3,
        MetricsTasks: 4,
        AlertsTasks: 2,
        MonitoringTasks: 1
    }


class PowerUser(AuthenticatedUser):
    """Power user performing intensive operations."""
    
    wait_time = between(0.5, 2)
    
    tasks = {
        DeviceManagementTasks: 5,
        MetricsTasks: 8,
        AlertsTasks: 3,
        MonitoringTasks: 1
    }


class AdminUser(AuthenticatedUser):
    """Admin user performing administrative operations."""
    
    wait_time = between(2, 5)
    
    @task(3)
    def list_users(self):
        """List all users."""
        with self.client.get(
            "/api/v1/users",
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to list users: {response.status_code}")
    
    @task(2)
    def get_audit_logs(self):
        """Get audit logs."""
        with self.client.get(
            "/api/v1/audit",
            params={"limit": 50},
            catch_response=True
        ) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Failed to get audit logs: {response.status_code}")
    
    @task(1)
    def run_discovery(self):
        """Trigger network discovery."""
        with self.client.post(
            "/api/v1/discovery/scan",
            json={
                "network": "192.168.1.0/24",
                "methods": ["snmp", "ping"]
            },
            catch_response=True
        ) as response:
            if response.status_code in [200, 201, 202]:
                response.success()
            else:
                response.failure(f"Failed to trigger discovery: {response.status_code}")
    
    tasks = {
        DeviceManagementTasks: 2,
        AlertsTasks: 2,
        MonitoringTasks: 1
    }


# Event handlers for test statistics
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when test starts."""
    logger.info("Load test starting...")
    logger.info(f"Target host: {environment.host}")
    logger.info(f"Total users: {environment.parsed_options.num_users}")
    logger.info(f"Spawn rate: {environment.parsed_options.spawn_rate}")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when test stops."""
    logger.info("Load test completed")
    
    # Print summary statistics
    stats = environment.stats
    logger.info(f"Total requests: {stats.total.num_requests}")
    logger.info(f"Total failures: {stats.total.num_failures}")
    logger.info(f"Average response time: {stats.total.avg_response_time}ms")
    logger.info(f"Min response time: {stats.total.min_response_time}ms")
    logger.info(f"Max response time: {stats.total.max_response_time}ms")

# Define user mix for realistic load testing
class WebsiteUser(HttpUser):
    """Mixed user population for realistic load testing."""
    
    wait_time = between(1, 5)
    
    # Define user distribution
    tasks = {
        StandardUser: 70,  # 70% standard users
        PowerUser: 25,     # 25% power users
        AdminUser: 5       # 5% admin users
    }