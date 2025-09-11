"""
Simple real execution tests to increase coverage
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_main_app_creation():
    """Test main app creation and basic endpoints"""
    from main import app, create_app
    
    # Test app creation
    test_app = create_app()
    assert test_app is not None
    
    with TestClient(test_app) as client:
        # Test root endpoint
        response = client.get("/")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        
        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        
        # Test API status endpoint
        response = client.get("/api/status")
        assert response.status_code == 200
        assert response.json()["status"] == "operational"


def test_middleware_execution():
    """Test middleware is properly executed"""
    from main import app
    from core.middleware import RequestLoggingMiddleware, SecurityMiddleware, RateLimitMiddleware
    
    # Test that middleware classes can be instantiated
    logging_middleware = RequestLoggingMiddleware(app)
    assert logging_middleware is not None
    
    security_middleware = SecurityMiddleware(app)
    assert security_middleware is not None
    
    rate_limit_middleware = RateLimitMiddleware(app)
    assert rate_limit_middleware is not None


def test_config_loading():
    """Test configuration loading"""
    from core.config import get_settings
    from backend.config import Settings
    
    # Test get_settings
    settings = get_settings()
    assert settings is not None
    assert hasattr(settings, 'app_name')
    
    # Test Settings class
    test_settings = Settings()
    assert test_settings.app_name == "CHM"
    assert test_settings.environment in ["development", "production", "testing"]


def test_database_initialization():
    """Test database initialization code"""
    from backend.database.base import init_db, DatabaseManager
    from core.database import get_db_url
    
    # Test database manager
    db_manager = DatabaseManager()
    assert db_manager is not None
    
    # Test get_db_url
    db_url = get_db_url()
    assert db_url is not None
    assert "sqlite" in db_url or "postgresql" in db_url


def test_auth_service_methods():
    """Test auth service method execution"""
    from backend.services.auth_service import AuthService
    
    auth_service = AuthService()
    
    # Test password hashing
    password = "TestPassword123!"
    hashed = auth_service.hash_password(password)
    assert hashed != password
    assert auth_service.verify_password(password, hashed) == True
    assert auth_service.verify_password("WrongPassword", hashed) == False
    
    # Test password validation
    validation = auth_service.validate_password_strength("weak")
    assert validation["valid"] == False
    assert len(validation["errors"]) > 0
    
    validation = auth_service.validate_password_strength("StrongP@ssw0rd123")
    assert validation["valid"] == True


def test_exception_classes():
    """Test custom exception classes"""
    from backend.common.exceptions import (
        CHMException, AuthenticationException, ValidationException,
        NotFoundException, DuplicateException, DatabaseException
    )
    
    # Test base exception
    exc = CHMException("Test error")
    assert str(exc) == "Test error"
    assert exc.timestamp is not None
    
    # Test auth exception
    auth_exc = AuthenticationException("Auth failed")
    assert auth_exc.status_code == 401
    
    # Test validation exception
    val_exc = ValidationException("Invalid data")
    assert val_exc.status_code == 422
    
    # Test not found exception
    not_found = NotFoundException("Resource", "123")
    assert not_found.status_code == 404
    
    # Test duplicate exception
    dup_exc = DuplicateException("User", "email", "test@example.com")
    assert dup_exc.status_code == 409
    
    # Test database exception
    db_exc = DatabaseException("Connection failed")
    assert db_exc.status_code == 500


def test_result_objects():
    """Test result object classes"""
    from backend.common.result_objects import (
        OperationResult, ValidationResult, PaginatedResult,
        ServiceResponse, ErrorResponse
    )
    
    # Test OperationResult
    result = OperationResult(success=True, message="Operation completed")
    assert result.success == True
    assert result.message == "Operation completed"
    
    # Test ValidationResult
    validation = ValidationResult(is_valid=False, errors=["Field required"])
    assert validation.is_valid == False
    assert len(validation.errors) == 1
    
    # Test PaginatedResult
    paginated = PaginatedResult(
        items=[1, 2, 3],
        total=3,
        page=1,
        page_size=10
    )
    assert paginated.total == 3
    assert len(paginated.items) == 3
    
    # Test ServiceResponse
    response = ServiceResponse(status="success", data={"key": "value"})
    assert response.status == "success"
    assert response.data["key"] == "value"
    
    # Test ErrorResponse
    error = ErrorResponse(error="Not found", details={"id": 123})
    assert error.error == "Not found"


def test_security_utilities():
    """Test security utility functions"""
    from backend.common.security import (
        encrypt_data, decrypt_data, hash_password, verify_password,
        generate_api_key, generate_device_token, sanitize_log_data
    )
    
    # Test encryption/decryption
    original = "sensitive data"
    encrypted = encrypt_data(original)
    assert encrypted != original
    decrypted = decrypt_data(encrypted)
    assert decrypted == original
    
    # Test password functions
    password = "MyPassword123"
    hashed = hash_password(password)
    assert hashed != password
    assert verify_password(password, hashed) == True
    
    # Test token generation
    api_key = generate_api_key()
    assert len(api_key) > 20
    
    device_token = generate_device_token()
    assert len(device_token) > 20
    
    # Test log sanitization
    sensitive_data = {"password": "secret", "api_key": "key123", "safe": "data"}
    sanitized = sanitize_log_data(sensitive_data)
    assert "***" in str(sanitized["password"])
    assert "***" in str(sanitized["api_key"])
    assert sanitized["safe"] == "data"


def test_api_router_initialization():
    """Test API router initialization"""
    from api.v1.router import api_router
    
    # Check that router has routes
    assert len(api_router.routes) > 0
    
    # Check specific route paths exist
    route_paths = [route.path for route in api_router.routes]
    assert any("/auth" in path for path in route_paths)
    assert any("/devices" in path for path in route_paths)
    assert any("/alerts" in path for path in route_paths)


@patch('backend.database.base.get_session')
async def test_async_database_operations(mock_get_session):
    """Test async database operation patterns"""
    from backend.database.base import init_db
    
    # Mock async session
    mock_session = AsyncMock()
    mock_get_session.return_value = mock_session
    
    # Test init_db execution
    await init_db()
    
    # Verify it doesn't raise exceptions
    assert True


def test_monitoring_utilities():
    """Test monitoring utility classes"""
    from backend.monitoring.snmp_handler import SNMPHandler
    from backend.monitoring.ssh_handler import SSHHandler
    
    # Test SNMP handler initialization
    snmp = SNMPHandler()
    assert snmp is not None
    assert hasattr(snmp, 'get_device_info')
    
    # Test SSH handler initialization  
    ssh = SSHHandler()
    assert ssh is not None
    assert hasattr(ssh, 'execute_command')


def test_service_initialization():
    """Test service class initialization"""
    from backend.services.device_service import DeviceService
    from backend.services.alert_service import AlertService
    from backend.services.metrics_service import MetricsService
    from backend.services.discovery_service import DiscoveryService
    from backend.services.notification_service import NotificationService
    
    # Test each service can be initialized
    device_service = DeviceService()
    assert device_service is not None
    
    alert_service = AlertService()
    assert alert_service is not None
    
    metrics_service = MetricsService()
    assert metrics_service is not None
    
    discovery_service = DiscoveryService()
    assert discovery_service is not None
    
    notification_service = NotificationService()
    assert notification_service is not None


def test_validation_service():
    """Test validation service methods"""
    from backend.services.validation_service import ValidationService
    
    validator = ValidationService()
    
    # Test IP validation
    assert validator.validate_ip_address("192.168.1.1") == True
    assert validator.validate_ip_address("256.256.256.256") == False
    assert validator.validate_ip_address("not_an_ip") == False
    
    # Test email validation
    assert validator.validate_email("test@example.com") == True
    assert validator.validate_email("invalid.email") == False
    
    # Test hostname validation
    assert validator.validate_hostname("server01") == True
    assert validator.validate_hostname("server-01.example.com") == True
    assert validator.validate_hostname("invalid hostname") == False


def test_prometheus_metrics():
    """Test Prometheus metrics initialization"""
    from backend.services.prometheus_metrics import MetricsMiddleware
    from main import app
    
    # Test metrics middleware
    metrics = MetricsMiddleware(app)
    assert metrics is not None
    assert hasattr(metrics, 'dispatch')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])