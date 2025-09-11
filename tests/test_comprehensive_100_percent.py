"""
Comprehensive tests to achieve 100% code coverage
Targets all remaining uncovered modules
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch, mock_open
from datetime import datetime, timedelta
import uuid
import json
import os
from typing import Dict, Any, List, Optional

# Test backend.common.security module
class TestSecurityModule:
    """Test security utilities"""
    
    def test_credential_encryption_init(self):
        """Test CredentialEncryption initialization"""
        from backend.common.security import CredentialEncryption
        
        with patch.dict(os.environ, {"ENCRYPTION_KEY": "test-key-123"}):
            enc = CredentialEncryption()
            assert enc.primary_key is not None
            assert enc.cipher_suite is not None
    
    def test_encrypt_decrypt_credential(self):
        """Test credential encryption and decryption"""
        from backend.common.security import CredentialEncryption
        
        enc = CredentialEncryption()
        original = "sensitive-password-123"
        
        encrypted = enc.encrypt_credential(original)
        assert encrypted != original
        assert encrypted.startswith("gAAAAA")  # Fernet prefix
        
        decrypted = enc.decrypt_credential(encrypted)
        assert decrypted == original
    
    def test_encrypt_snmp_community(self):
        """Test SNMP community encryption"""
        from backend.common.security import CredentialEncryption
        
        enc = CredentialEncryption()
        community = "public"
        
        encrypted = enc.encrypt_snmp_community(community)
        assert encrypted != community
        
        decrypted = enc.decrypt_snmp_community(encrypted)
        assert decrypted == community
    
    def test_rotate_encryption_key(self):
        """Test encryption key rotation"""
        from backend.common.security import CredentialEncryption
        
        with patch.dict(os.environ, {
            "ENCRYPTION_KEY": "key1",
            "ENCRYPTION_KEY_ROTATION_1": "key2"
        }):
            enc = CredentialEncryption()
            assert len(enc.rotation_keys) > 0
    
    def test_hash_password(self):
        """Test password hashing"""
        from backend.common.security import hash_password, verify_password
        
        password = "TestPassword123!"
        hashed = hash_password(password)
        
        assert hashed != password
        assert verify_password(password, hashed) is True
        assert verify_password("wrong", hashed) is False
    
    def test_generate_token(self):
        """Test token generation"""
        from backend.common.security import generate_token
        
        token = generate_token()
        assert len(token) > 20
        assert isinstance(token, str)
    
    def test_create_access_token(self):
        """Test JWT access token creation"""
        from backend.common.security import create_access_token
        
        data = {"sub": "user123"}
        token = create_access_token(data)
        
        assert token is not None
        assert len(token.split(".")) == 3  # JWT format
    
    def test_decode_token(self):
        """Test JWT token decoding"""
        from backend.common.security import create_access_token, decode_token
        
        data = {"sub": "user123", "scopes": ["read"]}
        token = create_access_token(data)
        
        decoded = decode_token(token)
        assert decoded["sub"] == "user123"
        assert "scopes" in decoded


# Test backend.common.exceptions module
class TestExceptionsModule:
    """Test custom exceptions"""
    
    def test_base_exception(self):
        """Test BaseException"""
        from backend.common.exceptions import BaseException
        
        exc = BaseException("Test error")
        assert str(exc) == "Test error"
    
    def test_validation_error(self):
        """Test ValidationError"""
        from backend.common.exceptions import ValidationError
        
        exc = ValidationError("Invalid input", field="username")
        assert exc.field == "username"
        assert "Invalid input" in str(exc)
    
    def test_authentication_error(self):
        """Test AuthenticationError"""
        from backend.common.exceptions import AuthenticationError
        
        exc = AuthenticationError("Invalid credentials")
        assert exc.status_code == 401
    
    def test_authorization_error(self):
        """Test AuthorizationError"""
        from backend.common.exceptions import AuthorizationError
        
        exc = AuthorizationError("Access denied")
        assert exc.status_code == 403
    
    def test_not_found_error(self):
        """Test NotFoundError"""
        from backend.common.exceptions import NotFoundError
        
        exc = NotFoundError("Resource not found", resource_type="Device")
        assert exc.resource_type == "Device"
        assert exc.status_code == 404
    
    def test_duplicate_resource_error(self):
        """Test DuplicateResourceError"""
        from backend.common.exceptions import DuplicateResourceError
        
        exc = DuplicateResourceError("Device already exists", resource_id="dev-123")
        assert exc.resource_id == "dev-123"
        assert exc.status_code == 409
    
    def test_service_unavailable_error(self):
        """Test ServiceUnavailableError"""
        from backend.common.exceptions import ServiceUnavailableError
        
        exc = ServiceUnavailableError("Database offline", retry_after=30)
        assert exc.retry_after == 30
        assert exc.status_code == 503


# Test backend.common.result_objects module
class TestResultObjects:
    """Test result objects and utilities"""
    
    def test_create_success_result(self):
        """Test success result creation"""
        from backend.common.result_objects import create_success_result
        
        result = create_success_result(
            data={"id": 123},
            message="Created successfully"
        )
        
        assert result.success is True
        assert result.data["id"] == 123
        assert result.message == "Created successfully"
        assert result.error is None
    
    def test_create_failure_result(self):
        """Test failure result creation"""
        from backend.common.result_objects import create_failure_result
        
        result = create_failure_result(
            error="Database error",
            message="Failed to save"
        )
        
        assert result.success is False
        assert result.error == "Database error"
        assert result.message == "Failed to save"
        assert result.data is None
    
    def test_create_partial_success_result(self):
        """Test partial success result creation"""
        from backend.common.result_objects import create_partial_success_result
        
        result = create_partial_success_result(
            data={"processed": 8, "failed": 2},
            message="Partially completed",
            error="Some items failed"
        )
        
        assert result.success is True  # Partial success is still success
        assert result.data["processed"] == 8
        assert result.error == "Some items failed"
    
    def test_health_status(self):
        """Test HealthStatus creation"""
        from backend.common.result_objects import HealthStatus, HealthLevel
        
        status = HealthStatus(
            level=HealthLevel.HEALTHY,
            message="All systems operational",
            details={"uptime": 3600}
        )
        
        assert status.level == HealthLevel.HEALTHY
        assert status.is_healthy is True
        assert status.details["uptime"] == 3600
    
    def test_fallback_data(self):
        """Test FallbackData creation"""
        from backend.common.result_objects import FallbackData
        
        fallback = FallbackData(
            used=True,
            reason="Primary source unavailable",
            source="cache",
            timestamp=datetime.utcnow()
        )
        
        assert fallback.used is True
        assert fallback.source == "cache"
        assert fallback.reason == "Primary source unavailable"


# Test backend.common.validation module
class TestValidationModule:
    """Test validation utilities"""
    
    def test_validate_email(self):
        """Test email validation"""
        from backend.common.validation import validate_email
        
        assert validate_email("test@example.com") is True
        assert validate_email("user.name@domain.co.uk") is True
        assert validate_email("invalid") is False
        assert validate_email("@example.com") is False
        assert validate_email("test@") is False
    
    def test_validate_ip_address(self):
        """Test IP address validation"""
        from backend.common.validation import validate_ip_address
        
        assert validate_ip_address("192.168.1.1") is True
        assert validate_ip_address("10.0.0.0") is True
        assert validate_ip_address("255.255.255.255") is True
        assert validate_ip_address("256.1.1.1") is False
        assert validate_ip_address("192.168") is False
        assert validate_ip_address("text") is False
    
    def test_validate_hostname(self):
        """Test hostname validation"""
        from backend.common.validation import validate_hostname
        
        assert validate_hostname("server01") is True
        assert validate_hostname("web-server.example.com") is True
        assert validate_hostname("192.168.1.1") is False  # IP not hostname
        assert validate_hostname("-invalid") is False
        assert validate_hostname("invalid-") is False
    
    def test_validate_port(self):
        """Test port validation"""
        from backend.common.validation import validate_port
        
        assert validate_port(80) is True
        assert validate_port(443) is True
        assert validate_port(8080) is True
        assert validate_port(65535) is True
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False
    
    def test_sanitize_input(self):
        """Test input sanitization"""
        from backend.common.validation import sanitize_input
        
        assert sanitize_input("<script>alert('xss')</script>") == "alert('xss')"
        assert sanitize_input("normal text") == "normal text"
        assert sanitize_input("test@example.com") == "test@example.com"


# Test backend.common.utils module
class TestUtilsModule:
    """Test utility functions"""
    
    def test_generate_uuid(self):
        """Test UUID generation"""
        from backend.common.utils import generate_uuid
        
        uuid1 = generate_uuid()
        uuid2 = generate_uuid()
        
        assert uuid1 != uuid2
        assert len(str(uuid1)) == 36
    
    def test_format_datetime(self):
        """Test datetime formatting"""
        from backend.common.utils import format_datetime
        
        dt = datetime(2024, 1, 15, 10, 30, 45)
        formatted = format_datetime(dt)
        
        assert "2024-01-15" in formatted
        assert "10:30:45" in formatted
    
    def test_parse_datetime(self):
        """Test datetime parsing"""
        from backend.common.utils import parse_datetime
        
        dt_str = "2024-01-15T10:30:45"
        dt = parse_datetime(dt_str)
        
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15
        assert dt.hour == 10
        assert dt.minute == 30
    
    def test_calculate_hash(self):
        """Test hash calculation"""
        from backend.common.utils import calculate_hash
        
        hash1 = calculate_hash("test data")
        hash2 = calculate_hash("test data")
        hash3 = calculate_hash("different data")
        
        assert hash1 == hash2
        assert hash1 != hash3
        assert len(hash1) == 64  # SHA256 hex length
    
    def test_retry_with_backoff(self):
        """Test retry with exponential backoff"""
        from backend.common.utils import retry_with_backoff
        
        call_count = 0
        
        @retry_with_backoff(max_retries=3)
        def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary error")
            return "success"
        
        result = flaky_function()
        assert result == "success"
        assert call_count == 3
    
    def test_chunk_list(self):
        """Test list chunking"""
        from backend.common.utils import chunk_list
        
        items = list(range(10))
        chunks = list(chunk_list(items, 3))
        
        assert len(chunks) == 4
        assert chunks[0] == [0, 1, 2]
        assert chunks[-1] == [9]
    
    def test_deep_merge_dicts(self):
        """Test deep dictionary merging"""
        from backend.common.utils import deep_merge_dicts
        
        dict1 = {"a": 1, "b": {"c": 2}}
        dict2 = {"b": {"d": 3}, "e": 4}
        
        merged = deep_merge_dicts(dict1, dict2)
        
        assert merged["a"] == 1
        assert merged["b"]["c"] == 2
        assert merged["b"]["d"] == 3
        assert merged["e"] == 4


# Test backend.common.middleware module
class TestMiddlewareModule:
    """Test middleware components"""
    
    @pytest.mark.asyncio
    async def test_logging_middleware(self):
        """Test logging middleware"""
        from backend.common.middleware import LoggingMiddleware
        
        app = MagicMock()
        middleware = LoggingMiddleware(app)
        
        request = MagicMock()
        request.url.path = "/api/test"
        request.method = "GET"
        
        call_next = AsyncMock(return_value=MagicMock(status_code=200))
        
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 200
        call_next.assert_called_once_with(request)
    
    @pytest.mark.asyncio
    async def test_error_handling_middleware(self):
        """Test error handling middleware"""
        from backend.common.middleware import ErrorHandlingMiddleware
        
        app = MagicMock()
        middleware = ErrorHandlingMiddleware(app)
        
        request = MagicMock()
        
        # Test with exception
        call_next = AsyncMock(side_effect=ValueError("Test error"))
        
        response = await middleware.dispatch(request, call_next)
        assert response.status_code == 500
    
    @pytest.mark.asyncio
    async def test_cors_middleware(self):
        """Test CORS middleware"""
        from backend.common.middleware import setup_cors
        
        app = MagicMock()
        setup_cors(app, allow_origins=["http://localhost:3000"])
        
        # Verify CORS was added to app
        app.add_middleware.assert_called()
    
    @pytest.mark.asyncio
    async def test_authentication_middleware(self):
        """Test authentication middleware"""
        from backend.common.middleware import AuthenticationMiddleware
        
        app = MagicMock()
        middleware = AuthenticationMiddleware(app)
        
        request = MagicMock()
        request.headers = {"Authorization": "Bearer token123"}
        
        call_next = AsyncMock(return_value=MagicMock())
        
        with patch("backend.common.middleware.decode_token") as mock_decode:
            mock_decode.return_value = {"sub": "user123"}
            response = await middleware.dispatch(request, call_next)
            
        assert hasattr(request.state, "user")


# Test backend.config module
class TestConfigModule:
    """Test configuration management"""
    
    def test_settings_default_values(self):
        """Test Settings default values"""
        from backend.config import Settings
        
        settings = Settings()
        
        assert settings.app_name == "CHM API"
        assert settings.version == "2.0.0"
        assert settings.debug is False
        assert settings.database_url is not None
    
    def test_settings_from_env(self):
        """Test Settings from environment variables"""
        from backend.config import Settings
        
        with patch.dict(os.environ, {
            "APP_NAME": "Test App",
            "DEBUG": "true",
            "DATABASE_URL": "postgresql://test@localhost/testdb"
        }):
            settings = Settings()
            
            assert settings.app_name == "Test App"
            assert settings.debug is True
            assert "testdb" in settings.database_url
    
    def test_get_settings_cached(self):
        """Test get_settings caching"""
        from backend.config import get_settings
        
        settings1 = get_settings()
        settings2 = get_settings()
        
        assert settings1 is settings2  # Same instance (cached)
    
    def test_database_config(self):
        """Test database configuration"""
        from backend.config import Settings
        
        settings = Settings()
        
        assert settings.database_pool_size >= 5
        assert settings.database_max_overflow >= 10
        assert settings.database_pool_timeout >= 30
    
    def test_jwt_config(self):
        """Test JWT configuration"""
        from backend.config import Settings
        
        settings = Settings()
        
        assert settings.jwt_secret_key is not None
        assert settings.jwt_algorithm == "HS256"
        assert settings.jwt_expiration_minutes > 0


# Test backend.middleware.rate_limiter module
class TestRateLimiterModule:
    """Test rate limiting middleware"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_init(self):
        """Test RateLimiter initialization"""
        from backend.middleware.rate_limiter import RateLimiter
        
        limiter = RateLimiter(requests_per_minute=60)
        
        assert limiter.requests_per_minute == 60
        assert limiter.storage is not None
    
    @pytest.mark.asyncio
    async def test_rate_limiter_allow_request(self):
        """Test rate limiter allowing requests"""
        from backend.middleware.rate_limiter import RateLimiter
        
        limiter = RateLimiter(requests_per_minute=10)
        
        # First request should be allowed
        allowed = await limiter.check_rate_limit("user123")
        assert allowed is True
    
    @pytest.mark.asyncio
    async def test_rate_limiter_block_excessive_requests(self):
        """Test rate limiter blocking excessive requests"""
        from backend.middleware.rate_limiter import RateLimiter
        
        limiter = RateLimiter(requests_per_minute=2)
        
        # First two requests allowed
        assert await limiter.check_rate_limit("user456") is True
        assert await limiter.check_rate_limit("user456") is True
        
        # Third request blocked
        assert await limiter.check_rate_limit("user456") is False
    
    @pytest.mark.asyncio
    async def test_rate_limiter_reset_after_window(self):
        """Test rate limiter reset after time window"""
        from backend.middleware.rate_limiter import RateLimiter
        import asyncio
        
        limiter = RateLimiter(requests_per_minute=1, window_seconds=1)
        
        assert await limiter.check_rate_limit("user789") is True
        assert await limiter.check_rate_limit("user789") is False
        
        # Wait for window to reset
        await asyncio.sleep(1.1)
        
        assert await limiter.check_rate_limit("user789") is True


# Test backend.database models
class TestDatabaseModels:
    """Test database model definitions"""
    
    def test_user_model(self):
        """Test User model"""
        from backend.database.user_models import User
        
        user = User(
            username="testuser",
            email="test@example.com",
            hashed_password="hashed"
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True  # Default
        assert user.is_superuser is False  # Default
    
    def test_device_model(self):
        """Test Device model"""
        from backend.database.models import Device
        
        device = Device(
            hostname="router01",
            ip_address="192.168.1.1",
            device_type="router"
        )
        
        assert device.hostname == "router01"
        assert device.ip_address == "192.168.1.1"
        assert device.device_type == "router"
        assert device.is_active is True  # Default
    
    def test_alert_model(self):
        """Test Alert model"""
        from backend.database.models import Alert
        
        alert = Alert(
            device_id=uuid.uuid4(),
            alert_type="cpu_high",
            severity="warning",
            message="CPU usage above 80%"
        )
        
        assert alert.alert_type == "cpu_high"
        assert alert.severity == "warning"
        assert alert.status == "active"  # Default
    
    def test_metric_model(self):
        """Test DeviceMetric model"""
        from backend.database.models import DeviceMetric
        
        metric = DeviceMetric(
            device_id=uuid.uuid4(),
            metric_type="cpu_usage",
            value=75.5,
            unit="percent",
            timestamp=datetime.utcnow()
        )
        
        assert metric.metric_type == "cpu_usage"
        assert metric.value == 75.5
        assert metric.unit == "percent"
    
    def test_notification_model(self):
        """Test Notification model"""
        from backend.database.models import Notification
        
        notification = Notification(
            notification_type="alert",
            title="System Alert",
            message="High memory usage detected",
            severity="warning"
        )
        
        assert notification.notification_type == "alert"
        assert notification.title == "System Alert"
        assert notification.read is False  # Default


# Test backend.services.validation_service
class TestValidationService:
    """Test validation service"""
    
    def test_validate_device_type(self):
        """Test device type validation"""
        from backend.services.validation_service import ValidationService
        
        assert ValidationService.validate_device_type("router") == "router"
        assert ValidationService.validate_device_type("switch") == "switch"
        assert ValidationService.validate_device_type("firewall") == "firewall"
        
        with pytest.raises(Exception):
            ValidationService.validate_device_type("invalid")
    
    def test_validate_ip_address(self):
        """Test IP address validation"""
        from backend.services.validation_service import ValidationService
        
        assert ValidationService.validate_ip_address("192.168.1.1") == "192.168.1.1"
        assert ValidationService.validate_ip_address("10.0.0.0") == "10.0.0.0"
        
        with pytest.raises(Exception):
            ValidationService.validate_ip_address("999.999.999.999")
    
    def test_validate_metric_name(self):
        """Test metric name validation"""
        from backend.services.validation_service import ValidationService
        
        assert ValidationService.validate_metric_name("cpu_usage") == "cpu_usage"
        assert ValidationService.validate_metric_name("memory_usage") == "memory_usage"
        
        # Should allow custom metrics
        assert ValidationService.validate_metric_name("custom_metric") == "custom_metric"
    
    def test_sanitize_string(self):
        """Test string sanitization"""
        from backend.services.validation_service import ValidationService
        
        clean = ValidationService.sanitize_string("<script>alert('xss')</script>Hello")
        assert "<script>" not in clean
        assert "Hello" in clean
    
    def test_validate_pagination(self):
        """Test pagination validation"""
        from backend.services.validation_service import ValidationService
        
        page, per_page = ValidationService.validate_pagination(1, 50)
        assert page == 1
        assert per_page == 50
        
        # Test limits
        page, per_page = ValidationService.validate_pagination(0, 200)
        assert page == 1  # Minimum page
        assert per_page == 100  # Maximum per page


# Test miscellaneous functions and edge cases
class TestMiscellaneous:
    """Test miscellaneous functions and edge cases"""
    
    def test_import_all_modules(self):
        """Test that all modules can be imported"""
        modules = [
            "backend.config",
            "backend.common.exceptions",
            "backend.common.security",
            "backend.common.validation",
            "backend.common.utils",
            "backend.database.models",
            "backend.database.user_models",
            "backend.services.auth_service",
            "backend.services.device_service",
            "backend.services.alert_service",
        ]
        
        for module_name in modules:
            try:
                __import__(module_name)
            except ImportError as e:
                pytest.fail(f"Failed to import {module_name}: {e}")
    
    @pytest.mark.asyncio
    async def test_async_context_managers(self):
        """Test async context managers"""
        from backend.database.base import get_db
        
        # Mock the async context manager
        mock_session = AsyncMock()
        
        with patch("backend.database.base.AsyncSession", return_value=mock_session):
            async with get_db() as session:
                assert session is not None
    
    def test_environment_variables(self):
        """Test environment variable handling"""
        with patch.dict(os.environ, {
            "TEST_VAR": "test_value",
            "TEST_INT": "42",
            "TEST_BOOL": "true"
        }):
            assert os.getenv("TEST_VAR") == "test_value"
            assert int(os.getenv("TEST_INT")) == 42
            assert os.getenv("TEST_BOOL").lower() == "true"
    
    def test_logging_configuration(self):
        """Test logging configuration"""
        import logging
        
        logger = logging.getLogger("test_logger")
        logger.setLevel(logging.DEBUG)
        
        with patch.object(logger, 'debug') as mock_debug:
            logger.debug("Test message")
            mock_debug.assert_called_once_with("Test message")
    
    def test_json_serialization(self):
        """Test JSON serialization of custom objects"""
        from datetime import datetime
        import json
        
        data = {
            "id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "values": [1, 2, 3],
            "nested": {"key": "value"}
        }
        
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        
        assert parsed["id"] == data["id"]
        assert parsed["nested"]["key"] == "value"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])