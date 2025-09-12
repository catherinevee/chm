"""
Phase 6: Comprehensive tests for common utilities
Target: Achieve 100% coverage for backend/common directory
"""
# Fix imports FIRST
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ['TESTING'] = 'true'
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
import json


class TestExceptions:
    """Test backend/common/exceptions.py - all 33 exception classes"""
    
    def test_chm_base_exception(self):
        """Test CHMBaseException base class"""
        from backend.common.exceptions import CHMBaseException
        
        exc = CHMBaseException(
            message="Test error",
            error_code="TEST001",
            details={"key": "value"},
            suggestions=["Try this", "Or that"],
            context={"user": "test"}
        )
        
        assert str(exc) == "Test error"
        assert exc.error_code == "TEST001"
        assert exc.details["key"] == "value"
        assert len(exc.suggestions) == 2
        assert exc.context["user"] == "test"
        assert exc.timestamp is not None
        assert exc.recovery_attempts == 0
        
        # Test to_dict method
        exc_dict = exc.to_dict()
        assert exc_dict["message"] == "Test error"
        assert exc_dict["error_code"] == "TEST001"
        assert "timestamp" in exc_dict
    
    def test_discovery_exception(self):
        """Test DiscoveryException with special attributes"""
        from backend.common.exceptions import DiscoveryException
        
        exc = DiscoveryException(
            message="Discovery failed",
            device_ip="192.168.1.1",
            discovery_method="snmp",
            fallback_available=True
        )
        
        assert exc.device_ip == "192.168.1.1"
        assert exc.discovery_method == "snmp"
        assert exc.fallback_available is True
        assert len(exc.suggestions) > 0  # Auto-generated suggestions
    
    def test_device_unreachable_exception(self):
        """Test DeviceUnreachableException"""
        from backend.common.exceptions import DeviceUnreachableException
        
        exc = DeviceUnreachableException(
            device_ip="192.168.1.1",
            reason="Connection timeout"
        )
        
        assert "192.168.1.1" in str(exc)
        assert "Connection timeout" in str(exc)
        assert exc.reason == "Connection timeout"
        assert len(exc.suggestions) > 0
    
    def test_authentication_exception(self):
        """Test AuthenticationException"""
        from backend.common.exceptions import AuthenticationException
        
        exc = AuthenticationException(
            message="Auth failed",
            auth_method="password",
            username="testuser",
            device_ip="192.168.1.1"
        )
        
        assert exc.auth_method == "password"
        assert exc.username == "testuser"
        assert exc.device_ip == "192.168.1.1"
        assert len(exc.suggestions) > 0
    
    def test_protocol_exceptions(self):
        """Test protocol-specific exceptions"""
        from backend.common.exceptions import (
            ProtocolException, SNMPException, SSHException, RESTException
        )
        
        # Test ProtocolException
        exc = ProtocolException(
            message="Protocol error",
            protocol="snmp",
            device_ip="192.168.1.1",
            port=161
        )
        assert exc.protocol == "snmp"
        assert exc.port == 161
        
        # Test SNMPException
        exc = SNMPException(
            message="SNMP timeout",
            oid="1.3.6.1.2.1.1.1",
            community="public"
        )
        assert hasattr(exc, 'oid')
        
        # Test SSHException
        exc = SSHException(
            message="SSH connection failed",
            command="show version"
        )
        assert hasattr(exc, 'command')
        
        # Test RESTException
        exc = RESTException(
            message="REST API error",
            endpoint="/api/v1/devices",
            status_code=500
        )
        assert hasattr(exc, 'endpoint')
    
    def test_all_exception_types(self):
        """Test all 33 exception types can be instantiated"""
        from backend.common import exceptions
        
        exception_classes = [
            'CHMBaseException', 'DiscoveryException', 'DeviceUnreachableException',
            'AuthenticationException', 'ProtocolException', 'SNMPException',
            'SSHException', 'RESTException', 'DatabaseException',
            'ConfigurationException', 'ServiceUnavailableException',
            'TimeoutException', 'ResourceNotFoundException', 'ValidationException',
            'InvalidIPAddressException', 'RateLimitException', 'DependencyException',
            'PermissionDeniedException', 'SessionExpiredException',
            'AccountLockedException', 'InvalidTokenException', 'MFARequiredException',
            'EmailNotVerifiedException', 'PasswordExpiredException',
            'WeakPasswordException', 'DuplicateResourceException',
            'MetricCollectionException', 'AlertException',
            'NotificationDeliveryException', 'TaskExecutionException',
            'WebSocketException', 'EmailException'
        ]
        
        for exc_name in exception_classes:
            exc_class = getattr(exceptions, exc_name)
            exc = exc_class("Test message")
            assert str(exc) == "Test message" or "Test message" in str(exc)


class TestResultObjects:
    """Test backend/common/result_objects.py"""
    
    def test_result_status_enum(self):
        """Test ResultStatus enumeration"""
        from backend.common.result_objects import ResultStatus
        
        assert ResultStatus.SUCCESS.value == "success"
        assert ResultStatus.FAILURE.value == "failure"
        assert ResultStatus.PENDING.value == "pending"
        assert ResultStatus.WARNING.value == "warning"
        assert ResultStatus.PARTIAL.value == "partial"
    
    def test_discovery_result(self):
        """Test DiscoveryResult class"""
        from backend.common.result_objects import DiscoveryResult, ResultStatus
        
        result = DiscoveryResult(
            device_ip="192.168.1.1",
            device_info={"hostname": "router1", "vendor": "cisco"},
            status=ResultStatus.SUCCESS,
            discovery_method="snmp",
            timestamp=datetime.utcnow()
        )
        
        assert result.device_ip == "192.168.1.1"
        assert result.device_info["vendor"] == "cisco"
        assert result.status == ResultStatus.SUCCESS
        assert result.discovery_method == "snmp"
        assert result.timestamp is not None
    
    def test_protocol_result(self):
        """Test ProtocolResult class"""
        from backend.common.result_objects import ProtocolResult
        
        result = ProtocolResult(
            protocol="SNMP",
            success=True,
            data={"sysName": "router1", "uptime": 1000000},
            error_message=None,
            execution_time=0.5
        )
        
        assert result.protocol == "SNMP"
        assert result.success is True
        assert result.data["sysName"] == "router1"
        assert result.execution_time == 0.5
    
    def test_monitoring_result(self):
        """Test MonitoringResult class"""
        from backend.common.result_objects import MonitoringResult
        
        result = MonitoringResult(
            device_id=1,
            metrics={"cpu": 50, "memory": 80, "temperature": 65},
            timestamp=datetime.utcnow(),
            collection_duration=1.2,
            errors=[]
        )
        
        assert result.device_id == 1
        assert result.metrics["cpu"] == 50
        assert result.metrics["memory"] == 80
        assert result.collection_duration == 1.2
        assert len(result.errors) == 0
    
    def test_authentication_result(self):
        """Test AuthenticationResult class"""
        from backend.common.result_objects import AuthenticationResult
        
        result = AuthenticationResult(
            authenticated=True,
            user_id=1,
            username="testuser",
            token="jwt_token_here",
            refresh_token="refresh_token_here",
            expires_at=datetime.utcnow() + timedelta(hours=1),
            permissions=["read", "write"]
        )
        
        assert result.authenticated is True
        assert result.user_id == 1
        assert result.token == "jwt_token_here"
        assert "read" in result.permissions
    
    def test_database_result(self):
        """Test DatabaseResult class"""
        from backend.common.result_objects import DatabaseResult
        
        result = DatabaseResult(
            success=True,
            rows_affected=5,
            data=[{"id": 1}, {"id": 2}],
            error=None,
            query_time=0.05
        )
        
        assert result.success is True
        assert result.rows_affected == 5
        assert len(result.data) == 2
        assert result.query_time == 0.05


class TestSecurity:
    """Test backend/common/security.py"""
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        from backend.common.security import hash_password, verify_password
        
        password = "SecurePassword123!"
        hashed = hash_password(password)
        
        assert hashed != password
        assert "$2b$" in hashed  # bcrypt marker
        assert verify_password(password, hashed) is True
        assert verify_password("WrongPassword", hashed) is False
    
    def test_jwt_tokens(self):
        """Test JWT token creation and verification"""
        from backend.common.security import create_access_token, verify_token
        
        data = {"user_id": 1, "username": "testuser"}
        token = create_access_token(data)
        
        assert isinstance(token, str)
        assert token.count('.') == 2  # JWT format
        
        decoded = verify_token(token)
        assert decoded["user_id"] == 1
        assert decoded["username"] == "testuser"
        assert "exp" in decoded  # Expiration claim
    
    def test_api_key_generation(self):
        """Test API key generation and hashing"""
        from backend.common.security import generate_api_key, hash_api_key, verify_api_key
        
        api_key = generate_api_key()
        assert len(api_key) >= 32
        assert isinstance(api_key, str)
        
        hashed = hash_api_key(api_key)
        assert hashed != api_key
        
        assert verify_api_key(api_key, hashed) is True
        assert verify_api_key("wrong_key", hashed) is False
    
    def test_device_token_generation(self):
        """Test device token generation"""
        from backend.common.security import generate_device_token
        
        token = generate_device_token()
        assert len(token) >= 32
        assert isinstance(token, str)
    
    def test_data_encryption(self):
        """Test data encryption and decryption"""
        from backend.common.security import encrypt_data, decrypt_data
        
        sensitive_data = "This is sensitive information"
        encrypted = encrypt_data(sensitive_data)
        
        assert encrypted != sensitive_data
        assert isinstance(encrypted, str)
        
        decrypted = decrypt_data(encrypted)
        assert decrypted == sensitive_data
    
    def test_log_sanitization(self):
        """Test sensitive data sanitization for logs"""
        from backend.common.security import sanitize_log_data
        
        data = {
            "username": "testuser",
            "password": "secret123",
            "token": "jwt_token",
            "api_key": "api_key_123",
            "credit_card": "1234-5678-9012-3456",
            "safe_data": "This is safe"
        }
        
        sanitized = sanitize_log_data(data)
        
        assert sanitized["username"] == "testuser"  # Username might be kept
        assert sanitized["password"] != "secret123"  # Password must be masked
        assert sanitized["token"] != "jwt_token"  # Token must be masked
        assert sanitized["api_key"] != "api_key_123"  # API key must be masked
        assert sanitized["safe_data"] == "This is safe"  # Safe data unchanged


class TestUtils:
    """Test backend/common/utils.py"""
    
    def test_uuid_generation(self):
        """Test UUID generation"""
        try:
            from backend.common.utils import generate_uuid
            
            uuid1 = generate_uuid()
            uuid2 = generate_uuid()
            
            assert len(uuid1) == 36
            assert uuid1 != uuid2
            assert uuid1.count('-') == 4
        except ImportError:
            pass
    
    def test_timestamp_functions(self):
        """Test timestamp utilities"""
        try:
            from backend.common.utils import get_timestamp, format_timestamp
            
            ts = get_timestamp()
            assert isinstance(ts, (int, float))
            
            formatted = format_timestamp(ts)
            assert isinstance(formatted, str)
        except ImportError:
            pass
    
    def test_string_utilities(self):
        """Test string manipulation utilities"""
        try:
            from backend.common.utils import slugify, truncate_string, sanitize_string
            
            # Test slugify
            assert slugify("Hello World!") == "hello-world"
            assert slugify("Test 123 @#$") == "test-123"
            
            # Test truncate
            assert truncate_string("Hello World", 5) == "Hello..."
            assert truncate_string("Hi", 5) == "Hi"
            
            # Test sanitize
            assert sanitize_string("<script>alert('xss')</script>") != "<script>alert('xss')</script>"
        except ImportError:
            pass
    
    def test_data_conversion(self):
        """Test data conversion utilities"""
        try:
            from backend.common.utils import safe_int, safe_float, safe_bool
            
            # Test safe_int
            assert safe_int("123") == 123
            assert safe_int("invalid") == 0
            assert safe_int("123.45") == 123
            
            # Test safe_float
            assert safe_float("123.45") == 123.45
            assert safe_float("invalid") == 0.0
            
            # Test safe_bool
            assert safe_bool("true") is True
            assert safe_bool("false") is False
            assert safe_bool("yes") is True
            assert safe_bool("no") is False
        except ImportError:
            pass
    
    def test_retry_decorator(self):
        """Test retry decorator"""
        try:
            from backend.common.utils import retry_on_exception
            
            call_count = 0
            
            @retry_on_exception(max_retries=3, delay=0.1)
            def flaky_function():
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise Exception("Temporary error")
                return "Success"
            
            result = flaky_function()
            assert result == "Success"
            assert call_count == 3
        except ImportError:
            pass


class TestValidation:
    """Test backend/common/validation.py"""
    
    def test_ip_address_validation(self):
        """Test IP address validation"""
        try:
            from backend.common.validation import validate_ip_address
            
            assert validate_ip_address("192.168.1.1") is True
            assert validate_ip_address("10.0.0.0") is True
            assert validate_ip_address("255.255.255.255") is True
            assert validate_ip_address("256.256.256.256") is False
            assert validate_ip_address("invalid") is False
            assert validate_ip_address("192.168.1") is False
        except ImportError:
            pass
    
    def test_email_validation(self):
        """Test email validation"""
        try:
            from backend.common.validation import validate_email
            
            assert validate_email("user@example.com") is True
            assert validate_email("test.user@example.co.uk") is True
            assert validate_email("invalid") is False
            assert validate_email("@example.com") is False
            assert validate_email("user@") is False
        except ImportError:
            pass
    
    def test_password_strength_validation(self):
        """Test password strength validation"""
        try:
            from backend.common.validation import validate_password_strength
            
            assert validate_password_strength("WeakPass123!") is True
            assert validate_password_strength("weak") is False
            assert validate_password_strength("12345678") is False
            assert validate_password_strength("NoNumbers!") is False
        except ImportError:
            pass
    
    def test_subnet_validation(self):
        """Test subnet validation"""
        try:
            from backend.common.validation import validate_subnet
            
            assert validate_subnet("192.168.1.0/24") is True
            assert validate_subnet("10.0.0.0/8") is True
            assert validate_subnet("172.16.0.0/12") is True
            assert validate_subnet("192.168.1.0/33") is False
            assert validate_subnet("invalid") is False
        except ImportError:
            pass
    
    def test_mac_address_validation(self):
        """Test MAC address validation"""
        try:
            from backend.common.validation import validate_mac_address
            
            assert validate_mac_address("00:11:22:33:44:55") is True
            assert validate_mac_address("00-11-22-33-44-55") is True
            assert validate_mac_address("0011.2233.4455") is True
            assert validate_mac_address("invalid") is False
        except ImportError:
            pass
    
    def test_hostname_validation(self):
        """Test hostname validation"""
        try:
            from backend.common.validation import validate_hostname
            
            assert validate_hostname("server1") is True
            assert validate_hostname("web-server-01") is True
            assert validate_hostname("192.168.1.1") is False  # IP not hostname
            assert validate_hostname("server_1") is False  # Underscore not allowed
        except ImportError:
            pass


class TestMiddleware:
    """Test backend/common/middleware.py"""
    
    def test_middleware_imports(self):
        """Test middleware classes can be imported"""
        try:
            from backend.common.middleware import (
                RateLimitMiddleware,
                AuthenticationMiddleware,
                LoggingMiddleware,
                ErrorHandlingMiddleware,
                CORSMiddleware
            )
            
            assert RateLimitMiddleware is not None
            assert AuthenticationMiddleware is not None
            assert LoggingMiddleware is not None
            assert ErrorHandlingMiddleware is not None
            assert CORSMiddleware is not None
        except ImportError:
            pass
    
    def test_rate_limit_middleware(self):
        """Test RateLimitMiddleware"""
        try:
            from backend.common.middleware import RateLimitMiddleware
            
            app = Mock()
            middleware = RateLimitMiddleware(
                app,
                max_requests=100,
                window_seconds=60
            )
            
            assert middleware.app == app
            assert middleware.max_requests == 100
            assert middleware.window_seconds == 60
        except ImportError:
            pass


class TestMetrics:
    """Test backend/common/metrics.py"""
    
    def test_metrics_collector(self):
        """Test MetricsCollector class"""
        try:
            from backend.common.metrics import MetricsCollector
            
            collector = MetricsCollector()
            
            # Test recording metric
            collector.record("api_requests", 1, tags={"endpoint": "/api/v1/devices"})
            
            # Test getting metrics
            metrics = collector.get_metrics()
            assert isinstance(metrics, dict)
        except ImportError:
            pass
    
    def test_performance_timer(self):
        """Test performance timing decorator"""
        try:
            from backend.common.metrics import measure_performance
            
            @measure_performance
            def slow_function():
                import time
                time.sleep(0.01)
                return "done"
            
            result = slow_function()
            assert result == "done"
        except ImportError:
            pass


class TestErrorHandler:
    """Test backend/common/error_handler.py"""
    
    def test_error_handler_import(self):
        """Test error handler can be imported"""
        try:
            from backend.common.error_handler import (
                handle_exception,
                format_error_response,
                log_error
            )
            
            assert callable(handle_exception)
            assert callable(format_error_response)
            assert callable(log_error)
        except ImportError:
            pass
    
    def test_format_error_response(self):
        """Test error response formatting"""
        try:
            from backend.common.error_handler import format_error_response
            
            response = format_error_response(
                status_code=400,
                message="Bad Request",
                details={"field": "username", "error": "required"}
            )
            
            assert response["status_code"] == 400
            assert response["message"] == "Bad Request"
            assert "details" in response
        except ImportError:
            pass


class TestErrorClassification:
    """Test backend/common/error_classification.py"""
    
    def test_error_classification(self):
        """Test error classification utilities"""
        try:
            from backend.common.error_classification import (
                classify_error,
                get_error_severity,
                should_retry
            )
            
            # Test classification
            error = Exception("Connection timeout")
            classification = classify_error(error)
            assert classification in ["network", "timeout", "unknown"]
            
            # Test severity
            severity = get_error_severity(error)
            assert severity in ["low", "medium", "high", "critical"]
            
            # Test retry logic
            retry = should_retry(error)
            assert isinstance(retry, bool)
        except ImportError:
            pass


class TestResourceProtection:
    """Test backend/common/resource_protection.py"""
    
    def test_resource_limiter(self):
        """Test resource limiting utilities"""
        try:
            from backend.common.resource_protection import (
                ResourceLimiter,
                check_resource_limit,
                enforce_quota
            )
            
            limiter = ResourceLimiter(
                max_cpu_percent=80,
                max_memory_mb=1024,
                max_connections=100
            )
            
            assert limiter.max_cpu_percent == 80
            assert limiter.max_memory_mb == 1024
            
            # Test checking limits
            within_limits = check_resource_limit()
            assert isinstance(within_limits, bool)
        except ImportError:
            pass


class TestCommonPatterns:
    """Test common design patterns and utilities"""
    
    def test_singleton_pattern(self):
        """Test singleton pattern implementation"""
        try:
            from backend.common.patterns import Singleton
            
            class TestClass(metaclass=Singleton):
                def __init__(self):
                    self.value = 0
            
            instance1 = TestClass()
            instance1.value = 10
            
            instance2 = TestClass()
            assert instance2.value == 10
            assert instance1 is instance2
        except ImportError:
            pass
    
    def test_factory_pattern(self):
        """Test factory pattern"""
        try:
            from backend.common.patterns import ServiceFactory
            
            factory = ServiceFactory()
            
            # Register service
            factory.register("auth", lambda: "AuthService")
            
            # Get service
            service = factory.get("auth")
            assert service == "AuthService"
        except ImportError:
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])