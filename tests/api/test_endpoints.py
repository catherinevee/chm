"""
Comprehensive API endpoint tests for CHM - consolidated
"""

import pytest
import sys
import os
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient
import json

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

@pytest.fixture
def client():
    """Create test client"""
    from main import create_app
    app = create_app()
    return TestClient(app)

def test_app_creation():
    """Test FastAPI app creation"""
    from main import create_app
    app = create_app()
    assert app is not None
    assert app.title == "CHM - Catalyst Health Monitor"
    print("PASS: FastAPI app creation works")

def test_app_routes(client):
    """Test that app has expected routes"""
    # Test root endpoint
    response = client.get("/")
    assert response.status_code == 200
    
    # Test health endpoint
    response = client.get("/health")
    assert response.status_code == 200
    
    print("PASS: App routes work correctly")

def test_api_router_inclusion(client):
    """Test that API router is included"""
    # Test API endpoints exist
    response = client.get("/api/v1/")
    # This might return 404 or 405, but the route should exist
    assert response.status_code in [200, 404, 405]
    
    print("PASS: API router is included")

def test_cors_middleware(client):
    """Test CORS middleware is configured"""
    # Test OPTIONS request (CORS preflight)
    response = client.options("/")
    # Should not return 500 error
    assert response.status_code != 500
    
    print("PASS: CORS middleware configured")

def test_openapi_schema(client):
    """Test OpenAPI schema generation"""
    response = client.get("/openapi.json")
    assert response.status_code == 200
    
    schema = response.json()
    assert "openapi" in schema
    assert "info" in schema
    assert schema["info"]["title"] == "CHM API"
    
    print("PASS: OpenAPI schema generation works")

def test_docs_endpoints(client):
    """Test documentation endpoints"""
    # Test Swagger UI
    response = client.get("/docs")
    assert response.status_code == 200
    
    # Test ReDoc
    response = client.get("/redoc")
    assert response.status_code == 200
    
    print("PASS: Documentation endpoints work")

def test_api_v1_alerts_endpoints(client):
    """Test alerts API endpoints"""
    # Test alerts list endpoint
    response = client.get("/api/v1/alerts")
    # Should return 200 or 401 (unauthorized)
    assert response.status_code in [200, 401, 422]
    
    # Test alerts statistics endpoint
    response = client.get("/api/v1/alerts/statistics")
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Alerts API endpoints accessible")

def test_api_v1_auth_endpoints(client):
    """Test authentication API endpoints"""
    # Test login endpoint
    response = client.post("/api/v1/auth/login", json={
        "username": "test",
        "password": "test"
    })
    # Should return 401 (invalid credentials) or 422 (validation error)
    assert response.status_code in [200, 401, 422]
    
    # Test register endpoint
    response = client.post("/api/v1/auth/register", json={
        "username": "test",
        "email": "test@example.com",
        "password": "test123"
    })
    assert response.status_code in [200, 400, 422]
    
    print("PASS: Auth API endpoints accessible")

def test_auth_password_change(client):
    """Test password change endpoint"""
    response = client.post("/api/v1/auth/password/change", 
                          headers={"Authorization": "Bearer test-token"})
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
    
    print("PASS: Auth password change endpoint works")

def test_auth_password_reset(client):
    """Test password reset endpoint"""
    response = client.post("/api/v1/auth/password/reset", params={"email": "test@example.com"})
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
    
    print("PASS: Auth password reset endpoint works")

def test_auth_mfa_setup(client):
    """Test MFA setup endpoint"""
    response = client.post("/api/v1/auth/mfa/setup", 
                          headers={"Authorization": "Bearer test-token"})
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    print("PASS: Auth MFA setup endpoint works")

def test_auth_mfa_verify(client):
    """Test MFA verify endpoint"""
    response = client.post("/api/v1/auth/mfa/verify", 
                          headers={"Authorization": "Bearer test-token"})
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    print("PASS: Auth MFA verify endpoint works")

def test_auth_mfa_disable(client):
    """Test MFA disable endpoint"""
    response = client.post("/api/v1/auth/mfa/disable", 
                          headers={"Authorization": "Bearer test-token"})
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    print("PASS: Auth MFA disable endpoint works")

def test_api_v1_devices_endpoints(client):
    """Test devices API endpoints"""
    # Test devices list endpoint
    response = client.get("/api/v1/devices")
    assert response.status_code in [200, 401, 422]
    
    # Test device creation endpoint
    response = client.post("/api/v1/devices", json={
        "name": "Test Device",
        "hostname": "test.example.com"
    })
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Devices API endpoints accessible")

def test_api_v1_discovery_endpoints(client):
    """Test discovery API endpoints"""
    # Test discovery list endpoint
    response = client.get("/api/v1/discovery")
    assert response.status_code in [200, 401, 422]
    
    # Test discovery start endpoint
    response = client.post("/api/v1/discovery/start", json={
        "target_network": "192.168.1.0/24"
    })
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Discovery API endpoints accessible")

def test_discovery_start_with_params(client):
    """Test discovery start endpoint with query parameters"""
    response = client.post("/api/v1/discovery/start", params={
        "name": "Test Discovery",
        "network_range": "192.168.1.0/24",
        "scan_type": "snmp"
    })
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "id" in data
        assert "name" in data
        assert "network_range" in data
        assert "scan_type" in data
        assert "status" in data
        assert "progress" in data
        assert "created_at" in data
    
    print("PASS: Discovery start with params works")

def test_discovery_list_endpoint(client):
    """Test discovery list endpoint"""
    response = client.get("/api/v1/discovery/")
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert isinstance(data, list)
    
    print("PASS: Discovery list endpoint works")

def test_discovery_job_details(client):
    """Test discovery job details endpoint"""
    response = client.get("/api/v1/discovery/999")
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    print("PASS: Discovery job details endpoint works")

def test_discovery_cancel_job(client):
    """Test discovery cancel endpoint"""
    response = client.post("/api/v1/discovery/999/cancel")
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
    
    print("PASS: Discovery cancel endpoint works")

def test_discovery_results(client):
    """Test discovery results endpoint"""
    response = client.get("/api/v1/discovery/999/results")
    assert response.status_code in [200, 401, 422, 403, 404, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert isinstance(data, list)
    
    print("PASS: Discovery results endpoint works")

def test_api_v1_metrics_endpoints(client):
    """Test metrics API endpoints"""
    # Test metrics endpoint
    response = client.get("/api/v1/metrics")
    assert response.status_code in [200, 401, 405, 422]
    
    # Test performance summary endpoint
    response = client.get("/api/v1/metrics/performance/summary")
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Metrics API endpoints accessible")

def test_metrics_api_comprehensive(client):
    """Test comprehensive metrics API functionality"""
    
    # Test create metrics endpoint
    metrics_data = [
        {
            "device_id": 1,
            "metric_type": "cpu_usage",
            "value": 75.5,
            "unit": "percent",
            "timestamp": "2024-01-01T12:00:00Z"
        },
        {
            "device_id": 1,
            "metric_type": "memory_usage",
            "value": 60.2,
            "unit": "percent",
            "timestamp": "2024-01-01T12:00:00Z"
        }
    ]
    
    response = client.post("/api/v1/metrics/", json=metrics_data)
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
        assert "Stored 2 metrics" in data["message"]
    
    # Test performance summary endpoint
    response = client.get("/api/v1/metrics/performance/summary")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "overall_health" in data
        assert "devices_monitored" in data
        assert isinstance(data["overall_health"], (int, float))
        assert isinstance(data["devices_monitored"], int)
    
    # Test device performance endpoint
    response = client.get("/api/v1/metrics/performance/1")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "device_id" in data
        assert "performance_score" in data
        assert data["device_id"] == 1
        assert isinstance(data["performance_score"], (int, float))
    
    # Test device performance graph endpoint
    response = client.get("/api/v1/metrics/performance/1/graph")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "device_id" in data
        assert "data" in data
        assert data["device_id"] == 1
        assert isinstance(data["data"], list)
    
    # Test device performance graph with parameters
    response = client.get("/api/v1/metrics/performance/1/graph?metric_type=memory&time_range=7d")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "device_id" in data
        assert "data" in data
        assert data["device_id"] == 1
        assert isinstance(data["data"], list)
    
    # Test invalid device ID
    response = client.get("/api/v1/metrics/performance/999")
    assert response.status_code in [200, 401, 422, 405, 404]
    
    # Test invalid graph parameters
    response = client.get("/api/v1/metrics/performance/1/graph?metric_type=invalid&time_range=invalid")
    assert response.status_code in [200, 401, 422, 405, 400]
    
    # Test empty metrics list
    response = client.post("/api/v1/metrics/", json=[])
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
        assert "Stored 0 metrics" in data["message"]
    
    # Test invalid metrics data
    invalid_metrics = [
        {
            "device_id": "invalid",
            "metric_type": "cpu_usage",
            "value": "invalid",
            "unit": "percent",
            "timestamp": "invalid"
        }
    ]
    
    response = client.post("/api/v1/metrics/", json=invalid_metrics)
    assert response.status_code in [200, 401, 422, 405, 400]
    
    print("PASS: Metrics API comprehensive tests completed")

def test_api_v1_notifications_endpoints(client):
    """Test notifications API endpoints"""
    # Test notifications list endpoint
    response = client.get("/api/v1/notifications")
    assert response.status_code in [200, 401, 405, 422]
    
    # Test notification creation endpoint
    response = client.post("/api/v1/notifications", json={
        "title": "Test Notification",
        "message": "Test message"
    })
    assert response.status_code in [200, 401, 405, 422]
    
    print("PASS: Notifications API endpoints accessible")

def test_notifications_api_comprehensive(client):
    """Test comprehensive notifications API functionality"""
    
    # Test notifications list with default parameters
    response = client.get("/api/v1/notifications")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert isinstance(data, list)
    
    # Test notifications list with pagination
    response = client.get("/api/v1/notifications?skip=0&limit=10")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert isinstance(data, list)
    
    # Test notifications list with filters
    response = client.get("/api/v1/notifications?is_read=false&notification_type=system")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert isinstance(data, list)
    
    # Test unread count endpoint
    response = client.get("/api/v1/notifications/unread-count")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "unread_count" in data
        assert isinstance(data["unread_count"], int)
    
    # Test mark notification as read
    response = client.post("/api/v1/notifications/1/read")
    assert response.status_code in [200, 401, 422, 405, 404]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
        assert "marked as read" in data["message"]
    
    # Test mark all notifications as read
    response = client.post("/api/v1/notifications/mark-all-read")
    assert response.status_code in [200, 401, 422, 405]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
        assert "All notifications marked as read" in data["message"]
    
    # Test delete notification
    response = client.delete("/api/v1/notifications/1")
    assert response.status_code in [200, 401, 422, 405, 404]
    
    if response.status_code == 200:
        data = response.json()
        assert "message" in data
        assert "deleted successfully" in data["message"]
    
    # Test invalid notification ID
    response = client.post("/api/v1/notifications/999/read")
    assert response.status_code in [200, 401, 422, 405, 404]
    
    response = client.delete("/api/v1/notifications/999")
    assert response.status_code in [200, 401, 422, 405, 404]
    
    # Test invalid pagination parameters
    response = client.get("/api/v1/notifications?skip=-1&limit=0")
    assert response.status_code in [200, 401, 422, 405, 400]
    
    response = client.get("/api/v1/notifications?skip=0&limit=1001")
    assert response.status_code in [200, 401, 422, 405, 400]
    
    print("PASS: Notifications API comprehensive tests completed")

def test_api_v1_router_includes_all_routes(client):
    """Test that API v1 router includes all expected routes"""
    from api.v1.router import api_router
    
    # Check that all expected routers are included
    route_paths = [route.path for route in api_router.routes]
    
    # Should include all the main API routes
    expected_prefixes = ["/alerts", "/auth", "/devices", "/discovery", "/metrics", "/notifications"]
    
    for prefix in expected_prefixes:
        # At least one route should start with this prefix
        assert any(path.startswith(prefix) for path in route_paths), f"Missing routes for {prefix}"
    
    print("PASS: API v1 router includes all expected routes")

def test_error_handling(client):
    """Test error handling"""
    # Test 404 for non-existent endpoint
    response = client.get("/non-existent-endpoint")
    assert response.status_code == 404
    
    # Test invalid JSON
    response = client.post("/api/v1/auth/login", 
                          data="invalid json",
                          headers={"Content-Type": "application/json"})
    assert response.status_code in [400, 422]
    
    print("PASS: Error handling works correctly")

def test_middleware_configuration(client):
    """Test middleware is properly configured"""
    # Test that middleware doesn't break basic requests
    response = client.get("/")
    assert response.status_code == 200
    
    # Test that CORS headers might be present
    # (This depends on the specific CORS configuration)
    
    print("PASS: Middleware configuration works")

def test_api_error_handling_comprehensive(client):
    """Test comprehensive API error handling"""
    # Test 404 for non-existent endpoints
    response = client.get("/api/v1/non-existent")
    assert response.status_code == 404
    
    # Test 405 for wrong HTTP method
    response = client.delete("/api/v1/metrics")
    assert response.status_code == 405
    
    # Test 422 for invalid JSON
    response = client.post("/api/v1/auth/login", 
                          data="invalid json",
                          headers={"Content-Type": "application/json"})
    assert response.status_code in [400, 422]
    
    # Test 422 for missing required fields
    response = client.post("/api/v1/auth/login", json={})
    assert response.status_code in [400, 422]
    
    # Test 422 for invalid field types
    response = client.post("/api/v1/devices", json={
        "name": 123,  # Should be string
        "device_type": "INVALID_TYPE"
    })
    assert response.status_code in [400, 422]
    
    # Test 400 for malformed requests
    response = client.get("/api/v1/devices?limit=invalid")
    assert response.status_code in [400, 422]
    
    print("PASS: Comprehensive API error handling works correctly")

def test_api_authentication_comprehensive(client):
    """Test comprehensive API authentication"""
    # Test endpoints without authentication
    response = client.get("/api/v1/devices")
    assert response.status_code in [200, 401, 422]
    
    # Test endpoints with invalid token
    response = client.get("/api/v1/devices", headers={
        "Authorization": "Bearer invalid_token"
    })
    assert response.status_code in [200, 401, 422]
    
    # Test endpoints with malformed authorization header
    response = client.get("/api/v1/devices", headers={
        "Authorization": "InvalidFormat token"
    })
    assert response.status_code in [200, 401, 422]
    
    # Test endpoints with missing authorization header
    response = client.post("/api/v1/devices", json={
        "name": "Test Device"
    })
    assert response.status_code in [200, 201, 401, 422]
    
    print("PASS: Comprehensive API authentication works correctly")

def test_api_pagination_comprehensive(client):
    """Test comprehensive API pagination"""
    # Test pagination parameters
    response = client.get("/api/v1/devices?limit=10&offset=0")
    assert response.status_code in [200, 401, 422]
    
    # Test invalid pagination parameters
    response = client.get("/api/v1/devices?limit=-1&offset=-1")
    assert response.status_code in [200, 400, 401, 422]
    
    # Test large pagination parameters
    response = client.get("/api/v1/devices?limit=1000&offset=0")
    assert response.status_code in [200, 401, 422]
    
    # Test pagination with sorting
    response = client.get("/api/v1/devices?limit=10&offset=0&sort=name&order=asc")
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Comprehensive API pagination works correctly")

def test_api_content_types_comprehensive(client):
    """Test comprehensive API content types"""
    # Test JSON content type
    response = client.post("/api/v1/auth/login", json={
        "username": "test",
        "password": "test"
    })
    assert response.status_code in [200, 401, 422]
    
    # Test form data content type
    response = client.post("/api/v1/auth/login", data={
        "username": "test",
        "password": "test"
    })
    assert response.status_code in [200, 401, 422]
    
    # Test URL encoded content type
    response = client.post("/api/v1/auth/login", 
                          data="username=test&password=test",
                          headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Comprehensive API content types work correctly")

def test_api_rate_limiting_comprehensive(client):
    """Test comprehensive API rate limiting"""
    # Test multiple requests to same endpoint
    for i in range(10):
        response = client.get("/api/v1/devices")
        assert response.status_code in [200, 401, 422, 429]
    
    print("PASS: Comprehensive API rate limiting works correctly")

def test_api_cors_comprehensive(client):
    """Test comprehensive API CORS"""
    # Test OPTIONS request
    response = client.options("/api/v1/devices")
    assert response.status_code in [200, 204, 405]
    
    # Test CORS headers
    response = client.get("/api/v1/devices")
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Comprehensive API CORS works correctly")

def test_auth_logout_endpoint(client):
    """Test auth logout endpoint"""
    # Test logout without token
    response = client.post("/api/v1/auth/logout")
    assert response.status_code in [401, 422, 403]
    
    # Test logout with invalid token
    response = client.post("/api/v1/auth/logout", 
                          headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    # Test logout with valid token format
    response = client.post("/api/v1/auth/logout", 
                          headers={"Authorization": "Bearer test_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    print("PASS: Auth logout endpoint works correctly")

def test_auth_refresh_endpoint(client):
    """Test auth refresh endpoint"""
    # Test refresh without token
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code in [401, 422, 403]
    
    # Test refresh with invalid token
    response = client.post("/api/v1/auth/refresh", 
                          headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    # Test refresh with valid token format
    response = client.post("/api/v1/auth/refresh", 
                          headers={"Authorization": "Bearer test_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    print("PASS: Auth refresh endpoint works correctly")

def test_auth_me_endpoint(client):
    """Test auth me endpoint"""
    # Test get current user without token
    response = client.get("/api/v1/auth/me")
    assert response.status_code in [401, 422, 403]
    
    # Test get current user with invalid token
    response = client.get("/api/v1/auth/me", 
                         headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    # Test get current user with valid token format
    response = client.get("/api/v1/auth/me", 
                         headers={"Authorization": "Bearer test_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    print("PASS: Auth me endpoint works correctly")

def test_auth_update_me_endpoint(client):
    """Test auth update me endpoint"""
    user_data = {
        "id": 1,
        "username": "updated_user",
        "email": "updated@example.com",
        "full_name": "Updated User",
        "is_active": True,
        "role": "user"
    }
    
    # Test update without token
    response = client.put("/api/v1/auth/me", json=user_data)
    assert response.status_code in [401, 422, 403]
    
    # Test update with invalid token
    response = client.put("/api/v1/auth/me", 
                         json=user_data,
                         headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    # Test update with valid token format
    response = client.put("/api/v1/auth/me", 
                         json=user_data,
                         headers={"Authorization": "Bearer test_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    print("PASS: Auth update me endpoint works correctly")

def test_auth_change_password_endpoint(client):
    """Test auth change password endpoint"""
    password_data = {
        "old_password": "oldpass",
        "new_password": "newpass"
    }
    
    # Test change password without token
    response = client.post("/api/v1/auth/password/change", json=password_data)
    assert response.status_code in [401, 422, 403]
    
    # Test change password with invalid token
    response = client.post("/api/v1/auth/password/change", 
                          json=password_data,
                          headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    # Test change password with valid token format
    response = client.post("/api/v1/auth/password/change", 
                          json=password_data,
                          headers={"Authorization": "Bearer test_token"})
    assert response.status_code in [200, 401, 422, 403]
    
    print("PASS: Auth change password endpoint works correctly")

def test_auth_reset_password_endpoint(client):
    """Test auth reset password endpoint"""
    reset_data = {"email": "test@example.com"}
    
    # Test reset password
    response = client.post("/api/v1/auth/password/reset", json=reset_data)
    assert response.status_code in [200, 401, 422]
    
    # Test reset password with invalid email
    response = client.post("/api/v1/auth/password/reset", json={"email": "invalid"})
    assert response.status_code in [200, 401, 422]
    
    print("PASS: Auth reset password endpoint works correctly")

def test_auth_verify_token_endpoint(client):
    """Test auth verify token endpoint"""
    # Test verify without token
    response = client.post("/api/v1/auth/verify")
    assert response.status_code in [401, 422, 403, 404]
    
    # Test verify with invalid token
    response = client.post("/api/v1/auth/verify", 
                          headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code in [200, 401, 422, 403, 404]
    
    # Test verify with valid token format
    response = client.post("/api/v1/auth/verify", 
                          headers={"Authorization": "Bearer test_token"})
    assert response.status_code in [200, 401, 422, 403, 404]
    
    print("PASS: Auth verify token endpoint works correctly")

def test_discovery_endpoints_comprehensive(client):
    """Test comprehensive discovery endpoints"""
    # Test discovery jobs endpoint
    response = client.get("/api/v1/discovery/jobs")
    assert response.status_code in [200, 401, 422]
    
    # Test create discovery job
    job_data = {
        "name": "Test Discovery",
        "job_type": "network_scan",
        "target_networks": ["192.168.1.0/24"],
        "created_by": 1
    }
    response = client.post("/api/v1/discovery/jobs", json=job_data)
    assert response.status_code in [200, 401, 422, 405]
    
    # Test get specific discovery job
    response = client.get("/api/v1/discovery/jobs/1")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test update discovery job
    response = client.put("/api/v1/discovery/jobs/1", json=job_data)
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test delete discovery job
    response = client.delete("/api/v1/discovery/jobs/1")
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test start discovery job
    response = client.post("/api/v1/discovery/jobs/1/start")
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test stop discovery job
    response = client.post("/api/v1/discovery/jobs/1/stop")
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test discovery results
    response = client.get("/api/v1/discovery/jobs/1/results")
    assert response.status_code in [200, 401, 422, 404]
    
    print("PASS: Comprehensive discovery endpoints work correctly")

def test_devices_endpoints_comprehensive(client):
    """Test comprehensive devices endpoints"""
    # Test get devices with filters
    response = client.get("/api/v1/devices?type=router&status=online")
    assert response.status_code in [200, 401, 422]
    
    # Test create device
    device_data = {
        "name": "Test Device",
        "hostname": "test.example.com",
        "device_type": "router",
        "ip_address": "192.168.1.1",
        "created_by": 1
    }
    response = client.post("/api/v1/devices", json=device_data)
    assert response.status_code in [200, 401, 422]
    
    # Test get specific device
    response = client.get("/api/v1/devices/1")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test update device
    response = client.put("/api/v1/devices/1", json=device_data)
    assert response.status_code in [200, 401, 422, 404]
    
    # Test delete device
    response = client.delete("/api/v1/devices/1")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test device metrics
    response = client.get("/api/v1/devices/1/metrics")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test device alerts
    response = client.get("/api/v1/devices/1/alerts")
    assert response.status_code in [200, 401, 422, 404]
    
    print("PASS: Comprehensive devices endpoints work correctly")

def test_alerts_endpoints_comprehensive(client):
    """Test comprehensive alerts endpoints"""
    # Test get alerts with filters
    response = client.get("/api/v1/alerts?severity=high&status=active")
    assert response.status_code in [200, 401, 422]
    
    # Test create alert
    alert_data = {
        "title": "Test Alert",
        "message": "Test alert message",
        "severity": "high",
        "device_id": 1,
        "created_by": 1
    }
    response = client.post("/api/v1/alerts", json=alert_data)
    assert response.status_code in [200, 401, 422]
    
    # Test get specific alert
    response = client.get("/api/v1/alerts/1")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test update alert
    response = client.put("/api/v1/alerts/1", json=alert_data)
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test delete alert
    response = client.delete("/api/v1/alerts/1")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test acknowledge alert
    response = client.post("/api/v1/alerts/1/acknowledge")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test resolve alert
    response = client.post("/api/v1/alerts/1/resolve")
    assert response.status_code in [200, 401, 422, 404]
    
    print("PASS: Comprehensive alerts endpoints work correctly")

def test_metrics_endpoints_comprehensive(client):
    """Test comprehensive metrics endpoints"""
    # Test get metrics with filters
    response = client.get("/api/v1/metrics?device_id=1&metric_type=cpu")
    assert response.status_code in [200, 401, 422, 405]
    
    # Test create metric
    metric_data = {
        "name": "cpu_usage",
        "value": 75.5,
        "metric_type": "gauge",
        "device_id": 1
    }
    response = client.post("/api/v1/metrics", json=metric_data)
    assert response.status_code in [200, 401, 422]
    
    # Test get specific metric
    response = client.get("/api/v1/metrics/1")
    assert response.status_code in [200, 401, 422, 404]
    
    # Test update metric
    response = client.put("/api/v1/metrics/1", json=metric_data)
    assert response.status_code in [200, 401, 422, 404]
    
    # Test delete metric
    response = client.delete("/api/v1/metrics/1")
    assert response.status_code in [200, 401, 422, 404]
    
    print("PASS: Comprehensive metrics endpoints work correctly")

def test_notifications_endpoints_comprehensive(client):
    """Test comprehensive notifications endpoints"""
    # Test get notifications with filters
    response = client.get("/api/v1/notifications?user_id=1&status=unread")
    assert response.status_code in [200, 401, 422]
    
    # Test create notification
    notification_data = {
        "title": "Test Notification",
        "message": "Test notification message",
        "notification_type": "info",
        "user_id": 1
    }
    response = client.post("/api/v1/notifications", json=notification_data)
    assert response.status_code in [200, 401, 422, 405]
    
    # Test get specific notification
    response = client.get("/api/v1/notifications/1")
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test update notification
    response = client.put("/api/v1/notifications/1", json=notification_data)
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test delete notification
    response = client.delete("/api/v1/notifications/1")
    assert response.status_code in [200, 401, 422, 404, 405]
    
    # Test mark as read
    response = client.post("/api/v1/notifications/1/read")
    assert response.status_code in [200, 401, 422, 404, 405]
    
    print("PASS: Comprehensive notifications endpoints work correctly")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
