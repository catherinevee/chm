"""
Custom exceptions for CHM application with detailed error context and recovery suggestions
"""

from datetime import datetime
from typing import Any, Dict, List, Optional


class CHMBaseException(Exception):
    """Base exception class for CHM application"""
    
    def __init__(self, message: str, error_code: str = None, details: Dict[str, Any] = None,
                 suggestions: List[str] = None, context: Dict[str, Any] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.suggestions = suggestions or []
        self.context = context or {}
        self.timestamp = datetime.utcnow()
        self.recovery_attempts = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'message': self.message,
            'error_code': self.error_code,
            'details': self.details,
            'suggestions': self.suggestions,
            'context': self.context,
            'timestamp': self.timestamp.isoformat(),
            'recovery_attempts': self.recovery_attempts
        }


class DiscoveryException(CHMBaseException):
    """Exception raised during device discovery operations"""
    
    def __init__(self, message: str, device_ip: str = None, discovery_method: str = None,
                 fallback_available: bool = False, **kwargs):
        super().__init__(message, **kwargs)
        self.device_ip = device_ip
        self.discovery_method = discovery_method
        self.fallback_available = fallback_available
        
        if not self.suggestions:
            self.suggestions = [
                "Verify network connectivity to the target device",
                "Check if the device is powered on and accessible",
                "Verify discovery credentials and permissions",
                "Try alternative discovery methods if available"
            ]


class DeviceUnreachableException(DiscoveryException):
    """Exception raised when a device cannot be reached"""
    
    def __init__(self, device_ip: str, reason: str = None, **kwargs):
        message = f"Device {device_ip} is unreachable"
        if reason:
            message += f": {reason}"
        
        super().__init__(message, device_ip=device_ip, **kwargs)
        self.reason = reason
        
        if not self.suggestions:
            self.suggestions = [
                "Check physical network connectivity",
                "Verify IP address configuration",
                "Check firewall rules and access lists",
                "Verify device power and network interface status",
                "Try ping or traceroute to diagnose connectivity"
            ]


class AuthenticationException(CHMBaseException):
    """Exception raised during authentication operations"""
    
    def __init__(self, message: str, auth_method: str = None, username: str = None,
                 device_ip: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.auth_method = auth_method
        self.username = username
        self.device_ip = device_ip
        
        if not self.suggestions:
            self.suggestions = [
                "Verify username and password credentials",
                "Check if the account has necessary permissions",
                "Verify authentication method configuration",
                "Check if the account is locked or expired",
                "Try alternative authentication methods if available"
            ]


class ProtocolException(CHMBaseException):
    """Exception raised during protocol operations (SSH, SNMP, REST, etc.)"""
    
    def __init__(self, message: str, protocol: str = None, device_ip: str = None,
                 port: int = None, **kwargs):
        super().__init__(message, **kwargs)
        self.protocol = protocol
        self.device_ip = device_ip
        self.port = port
        
        if not self.suggestions:
            self.suggestions = [
                "Verify protocol is enabled on the target device",
                "Check if the port is open and accessible",
                "Verify protocol version compatibility",
                "Check firewall rules for the specific protocol",
                "Try alternative protocols if available"
            ]


class SNMPException(ProtocolException):
    """Exception raised during SNMP operations"""
    
    def __init__(self, message: str, community: str = None, version: str = None, **kwargs):
        super().__init__(message, protocol="SNMP", **kwargs)
        self.community = community
        self.version = version
        
        if not self.suggestions:
            self.suggestions = [
                "Verify SNMP community string",
                "Check SNMP version compatibility",
                "Verify SNMP is enabled on the device",
                "Check SNMP access control lists",
                "Verify SNMP user permissions for SNMPv3"
            ]


class SSHException(ProtocolException):
    """Exception raised during SSH operations"""
    
    def __init__(self, message: str, username: str = None, key_file: str = None, **kwargs):
        super().__init__(message, protocol="SSH", **kwargs)
        self.username = username
        self.key_file = key_file
        
        if not self.suggestions:
            self.suggestions = [
                "Verify SSH is enabled on the target device",
                "Check SSH key permissions and format",
                "Verify username and authentication method",
                "Check SSH configuration and allowed users",
                "Try password authentication if key-based auth fails"
            ]


class RESTException(ProtocolException):
    """Exception raised during REST API operations"""
    
    def __init__(self, message: str, endpoint: str = None, method: str = None,
                 status_code: int = None, **kwargs):
        super().__init__(message, protocol="REST", **kwargs)
        self.endpoint = endpoint
        self.method = method
        self.status_code = status_code
        
        if not self.suggestions:
            self.suggestions = [
                "Verify API endpoint URL and method",
                "Check API authentication and authorization",
                "Verify request payload format",
                "Check API rate limiting and quotas",
                "Verify API version compatibility"
            ]


class DatabaseException(CHMBaseException):
    """Exception raised during database operations"""
    
    def __init__(self, message: str, operation: str = None, table: str = None,
                 connection_info: Dict[str, Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.operation = operation
        self.table = table
        self.connection_info = connection_info or {}
        
        if not self.suggestions:
            self.suggestions = [
                "Check database connection and credentials",
                "Verify database server is running and accessible",
                "Check database permissions and user roles",
                "Verify database schema and table structure",
                "Check database connection pool status"
            ]


class ConfigurationException(CHMBaseException):
    """Exception raised during configuration operations"""
    
    def __init__(self, message: str, config_key: str = None, config_file: str = None,
                 required_value: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.config_key = config_key
        self.config_file = config_file
        self.required_value = required_value
        
        if not self.suggestions:
            self.suggestions = [
                "Verify configuration file exists and is readable",
                "Check configuration syntax and format",
                "Verify required configuration values are set",
                "Check environment variable overrides",
                "Verify configuration file permissions"
            ]


class ServiceUnavailableException(CHMBaseException):
    """Exception raised when a service is unavailable"""
    
    def __init__(self, message: str, service_name: str = None, service_url: str = None,
                 fallback_available: bool = False, **kwargs):
        super().__init__(message, **kwargs)
        self.service_name = service_name
        self.service_url = service_url
        self.fallback_available = fallback_available
        
        if not self.suggestions:
            self.suggestions = [
                "Check if the service is running and healthy",
                "Verify service configuration and dependencies",
                "Check network connectivity to the service",
                "Verify service authentication and authorization",
                "Try alternative service endpoints if available"
            ]


class TimeoutException(CHMBaseException):
    """Exception raised when operations timeout"""
    
    def __init__(self, message: str, operation: str = None, timeout_value: float = None,
                 retry_available: bool = True, **kwargs):
        super().__init__(message, **kwargs)
        self.operation = operation
        self.timeout_value = timeout_value
        self.retry_available = retry_available
        
        if not self.suggestions:
            self.suggestions = [
                "Check network latency and connectivity",
                "Verify timeout configuration values",
                "Check if the target system is under heavy load",
                "Consider increasing timeout values if appropriate",
                "Try the operation again if retry is available"
            ]


class ResourceNotFoundException(CHMBaseException):
    """Exception raised when a requested resource is not found"""
    
    def __init__(self, message: str, resource_type: str = None, resource_id: str = None,
                 search_criteria: Dict[str, Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.search_criteria = search_criteria or {}
        
        if not self.suggestions:
            self.suggestions = [
                "Verify the resource ID or search criteria",
                "Check if the resource has been deleted or moved",
                "Verify resource permissions and access rights",
                "Check if the resource exists in a different location",
                "Try broader search criteria if available"
            ]


class ValidationException(CHMBaseException):
    """Exception raised when data validation fails"""
    
    def __init__(self, message: str, field_name: str = None, field_value: Any = None,
                 validation_rules: Dict[str, Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.field_name = field_name
        self.field_value = field_value
        self.validation_rules = validation_rules or {}
        
        if not self.suggestions:
            self.suggestions = [
                "Check the field value format and type",
                "Verify the value meets minimum/maximum requirements",
                "Check if the value is in the allowed range",
                "Verify required fields are not empty",
                "Check field format and pattern requirements"
            ]


class InvalidIPAddressException(ValidationException):
    """Exception raised when IP address validation fails"""
    
    def __init__(self, message: str, ip_address: str = None, **kwargs):
        super().__init__(message, field_name="ip_address", field_value=ip_address, **kwargs)
        self.ip_address = ip_address
        
        if not self.suggestions:
            self.suggestions = [
                "Verify the IP address format (e.g., 192.168.1.1)",
                "Check if the IP address is in valid range",
                "Ensure no extra spaces or characters",
                "Use IPv4 or IPv6 format as appropriate"
            ]


class RateLimitException(CHMBaseException):
    """Exception raised when rate limits are exceeded"""
    
    def __init__(self, message: str, rate_limit: int = None, reset_time: datetime = None,
                 retry_after: int = None, **kwargs):
        super().__init__(message, **kwargs)
        self.rate_limit = rate_limit
        self.reset_time = reset_time
        self.retry_after = retry_after
        
        if not self.suggestions:
            self.suggestions = [
                "Wait for the rate limit to reset",
                "Reduce the frequency of requests",
                "Check if batch operations are available",
                "Verify rate limit configuration",
                "Consider implementing request queuing"
            ]


class DependencyException(CHMBaseException):
    """Exception raised when required dependencies are missing or unavailable"""
    
    def __init__(self, message: str, dependency_name: str = None, dependency_version: str = None,
                 required_version: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.dependency_name = dependency_name
        self.dependency_version = dependency_version
        self.required_version = required_version
        
        if not self.suggestions:
            self.suggestions = [
                "Install or update the required dependency",
                "Check dependency version compatibility",
                "Verify dependency configuration and setup",
                "Check if alternative dependencies are available",
                "Verify system requirements and prerequisites"
            ]




class PermissionDeniedException(AuthenticationException):
    """Exception raised when user lacks required permissions"""
    
    def __init__(self, message: str, required_permission: str = None, user_role: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.required_permission = required_permission
        self.user_role = user_role
        
        if not self.suggestions:
            self.suggestions = [
                "Contact an administrator to request access",
                "Verify your user role and permissions",
                "Check if you're using the correct account",
                "Request permission elevation if needed"
            ]


class SessionExpiredException(AuthenticationException):
    """Exception raised when user session has expired"""
    
    def __init__(self, message: str, session_id: str = None, expiry_time: datetime = None, **kwargs):
        super().__init__(message, **kwargs)
        self.session_id = session_id
        self.expiry_time = expiry_time
        
        if not self.suggestions:
            self.suggestions = [
                "Login again to create a new session",
                "Use refresh token if available",
                "Check session timeout configuration"
            ]


class AccountLockedException(AuthenticationException):
    """Exception raised when user account is locked"""
    
    def __init__(self, message: str, username: str = None, lock_reason: str = None, 
                 unlock_time: datetime = None, **kwargs):
        super().__init__(message, **kwargs)
        self.username = username
        self.lock_reason = lock_reason
        self.unlock_time = unlock_time
        
        if not self.suggestions:
            self.suggestions = [
                "Wait for automatic unlock if configured",
                "Contact administrator to unlock account",
                "Reset password if allowed",
                "Verify you're using correct credentials"
            ]


class InvalidTokenException(AuthenticationException):
    """Exception raised when JWT token is invalid"""
    
    def __init__(self, message: str, token_type: str = None, reason: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.token_type = token_type
        self.reason = reason
        
        if not self.suggestions:
            self.suggestions = [
                "Request a new token",
                "Check token expiration",
                "Verify token signature",
                "Use refresh token to get new access token"
            ]


class MFARequiredException(AuthenticationException):
    """Exception raised when MFA is required but not provided"""
    
    def __init__(self, message: str, mfa_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.mfa_type = mfa_type
        
        if not self.suggestions:
            self.suggestions = [
                "Provide MFA code from authenticator app",
                "Check your SMS for MFA code",
                "Use backup codes if available",
                "Contact admin if MFA device is lost"
            ]


class EmailNotVerifiedException(AuthenticationException):
    """Exception raised when email verification is required"""
    
    def __init__(self, message: str, email: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.email = email
        
        if not self.suggestions:
            self.suggestions = [
                "Check your email for verification link",
                "Request new verification email",
                "Check spam folder",
                "Contact support if email not received"
            ]


class PasswordExpiredException(AuthenticationException):
    """Exception raised when password has expired"""
    
    def __init__(self, message: str, expiry_date: datetime = None, **kwargs):
        super().__init__(message, **kwargs)
        self.expiry_date = expiry_date
        
        if not self.suggestions:
            self.suggestions = [
                "Reset your password",
                "Use password reset link",
                "Contact administrator for assistance"
            ]


class WeakPasswordException(ValidationException):
    """Exception raised when password doesn't meet complexity requirements"""
    
    def __init__(self, message: str, requirements: Dict[str, Any] = None, **kwargs):
        super().__init__(message, **kwargs)
        self.requirements = requirements or {}
        
        if not self.suggestions:
            self.suggestions = [
                "Use at least 8 characters",
                "Include uppercase and lowercase letters",
                "Add numbers and special characters",
                "Avoid common passwords",
                "Don't reuse recent passwords"
            ]


class DuplicateResourceException(CHMBaseException):
    """Exception raised when attempting to create duplicate resource"""
    
    def __init__(self, message: str, resource_type: str = None, duplicate_field: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.resource_type = resource_type
        self.duplicate_field = duplicate_field
        
        if not self.suggestions:
            self.suggestions = [
                "Use a different identifier",
                "Update existing resource instead",
                "Check for existing resources before creating"
            ]


class MetricCollectionException(CHMBaseException):
    """Exception raised during metric collection"""
    
    def __init__(self, message: str, metric_type: str = None, device_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.metric_type = metric_type
        self.device_id = device_id
        
        if not self.suggestions:
            self.suggestions = [
                "Check device connectivity",
                "Verify metric collection configuration",
                "Check if metric is supported by device",
                "Verify polling credentials"
            ]


class AlertException(CHMBaseException):
    """Exception raised during alert processing"""
    
    def __init__(self, message: str, alert_id: str = None, alert_type: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.alert_id = alert_id
        self.alert_type = alert_type
        
        if not self.suggestions:
            self.suggestions = [
                "Check alert configuration",
                "Verify threshold values",
                "Check notification channels",
                "Verify alert rules syntax"
            ]


class NotificationDeliveryException(CHMBaseException):
    """Exception raised when notification delivery fails"""
    
    def __init__(self, message: str, channel: str = None, recipient: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.channel = channel
        self.recipient = recipient
        
        if not self.suggestions:
            self.suggestions = [
                "Verify notification channel configuration",
                "Check recipient contact information",
                "Verify notification service credentials",
                "Check notification rate limits"
            ]


class TaskExecutionException(CHMBaseException):
    """Exception raised during background task execution"""
    
    def __init__(self, message: str, task_name: str = None, task_id: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.task_name = task_name
        self.task_id = task_id
        
        if not self.suggestions:
            self.suggestions = [
                "Check task configuration",
                "Verify task dependencies",
                "Check Celery worker status",
                "Review task logs for errors"
            ]


class WebSocketException(CHMBaseException):
    """Exception raised during WebSocket operations"""
    
    def __init__(self, message: str, connection_id: str = None, reason: str = None, **kwargs):
        super().__init__(message, **kwargs)
        self.connection_id = connection_id
        self.reason = reason
        
        if not self.suggestions:
            self.suggestions = [
                "Check WebSocket connection",
                "Verify authentication token",
                "Check for network issues",
                "Reconnect if connection dropped"
            ]


# Generic AppException for HTTP-like errors
class AppException(CHMBaseException):
    """Generic application exception with HTTP-like status codes"""
    
    def __init__(self, message: str = None, status_code: int = 500, detail: str = None, **kwargs):
        super().__init__(message or detail or "Application error", **kwargs)
        self.status_code = status_code
        self.detail = detail or message or "Application error"


class EmailException(CHMBaseException):
    """Exception raised during email operations"""
    
    def __init__(self, message: str, recipient: str = None, subject: str = None,
                 smtp_error: str = None, retry_available: bool = True, **kwargs):
        super().__init__(message, **kwargs)
        self.recipient = recipient
        self.subject = subject
        self.smtp_error = smtp_error
        self.retry_available = retry_available
        
        if not self.suggestions:
            self.suggestions = [
                "Verify SMTP server configuration and connectivity",
                "Check email credentials and authentication",
                "Verify recipient email address format",
                "Check for network connectivity issues",
                "Review email content for compliance issues"
            ]


# Aliases for backward compatibility and specific use cases
CHMException = CHMBaseException
AppException = CHMBaseException
AuthenticationError = AuthenticationException
AuthorizationError = AuthenticationException
AuthorizationException = AuthenticationException  # Added for compatibility
DeviceNotFoundException = ResourceNotFoundException
DeviceAlreadyExistsException = DuplicateResourceException
MetricException = CHMBaseException
NotificationException = CHMBaseException
CircuitBreakerException = CHMBaseException
ConnectionPoolException = CHMBaseException
UserNotFoundException = ResourceNotFoundException
DuplicateUserException = DuplicateResourceException
SessionException = AuthenticationException
WebSocketError = WebSocketException
PermissionDeniedError = PermissionDeniedException
RoleNotFoundError = ResourceNotFoundException
ResourceNotFoundError = ResourceNotFoundException
