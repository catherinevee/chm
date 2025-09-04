"""
Comprehensive input validation system for production use.
Provides validation, sanitization, and security checks for all user inputs.
"""

import re
import ipaddress
import socket
from typing import Any, Dict, List, Optional, Union, Tuple, Callable
from dataclasses import dataclass
from enum import Enum
import logging
from datetime import datetime, timedelta
import json
import hashlib
import hmac
import secrets
from urllib.parse import urlparse, parse_qs
import html
import unicodedata

try:
    from pydantic import BaseModel, Field, validator, ValidationError
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object
    Field = lambda *args, **kwargs: None
    validator = lambda *args, **kwargs: lambda x: x
    ValidationError = ValueError

logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Validation strictness levels"""
    STRICT = "strict"      # Reject any suspicious input
    MODERATE = "moderate"  # Allow some flexibility
    LENIENT = "lenient"   # Minimal validation


class InputType(Enum):
    """Types of input for validation"""
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    EMAIL = "email"
    URL = "url"
    IP_ADDRESS = "ip_address"
    HOSTNAME = "hostname"
    PORT = "port"
    PATH = "path"
    JSON = "json"
    SQL = "sql"
    COMMAND = "command"
    SNMP_OID = "snmp_oid"
    METRIC_NAME = "metric_name"
    TIMESTAMP = "timestamp"
    UUID = "uuid"


@dataclass
class ValidationRule:
    """Individual validation rule"""
    name: str
    check_func: Callable[[Any], bool]
    error_message: str
    severity: str = "error"  # error, warning, info
    
    def validate(self, value: Any) -> Tuple[bool, Optional[str]]:
        """Execute validation rule"""
        try:
            if self.check_func(value):
                return True, None
            return False, self.error_message
        except Exception as e:
            return False, f"Validation error: {str(e)}"


@dataclass
class ValidationResult:
    """Result of validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    sanitized_value: Any
    metadata: Dict[str, Any]


class InputValidator:
    """Comprehensive input validation system"""
    
    # Security patterns to detect
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|FROM|WHERE)\b)",
        r"(--|\||;|\/\*|\*\/|xp_|sp_|0x)",
        r"(\bOR\b\s*\d+\s*=\s*\d+)",
        r"(\bAND\b\s*\d+\s*=\s*\d+)",
        r"('|\"|`)\s*(OR|AND|SELECT|INSERT|UPDATE|DELETE)",
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<applet[^>]*>",
        r"eval\s*\(",
        r"expression\s*\(",
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\%2[fF]/",
        r"\%2e\%2e/",
        r"\.\.\\",
        r"\.\.\%5[cC]",
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r"[;&|`$]",
        r"\$\([^)]*\)",
        r"`[^`]*`",
        r"\|\|",
        r"&&",
        r">|>>|<",
        r"\n|\r",
    ]
    
    def __init__(self, level: ValidationLevel = ValidationLevel.MODERATE):
        self.level = level
        self._custom_rules: Dict[str, List[ValidationRule]] = {}
        self._sanitizers: Dict[InputType, Callable] = self._init_sanitizers()
        
        # Statistics
        self._validation_count = 0
        self._validation_failures = 0
        self._security_blocks = 0
    
    def _init_sanitizers(self) -> Dict[InputType, Callable]:
        """Initialize sanitization functions"""
        return {
            InputType.STRING: self._sanitize_string,
            InputType.INTEGER: self._sanitize_integer,
            InputType.FLOAT: self._sanitize_float,
            InputType.BOOLEAN: self._sanitize_boolean,
            InputType.EMAIL: self._sanitize_email,
            InputType.URL: self._sanitize_url,
            InputType.IP_ADDRESS: self._sanitize_ip,
            InputType.HOSTNAME: self._sanitize_hostname,
            InputType.PORT: self._sanitize_port,
            InputType.PATH: self._sanitize_path,
            InputType.JSON: self._sanitize_json,
            InputType.SQL: self._sanitize_sql,
            InputType.COMMAND: self._sanitize_command,
            InputType.SNMP_OID: self._sanitize_snmp_oid,
            InputType.METRIC_NAME: self._sanitize_metric_name,
            InputType.TIMESTAMP: self._sanitize_timestamp,
            InputType.UUID: self._sanitize_uuid,
        }
    
    def validate(self, 
                value: Any, 
                input_type: InputType,
                **kwargs) -> ValidationResult:
        """Main validation method"""
        self._validation_count += 1
        
        errors = []
        warnings = []
        metadata = {}
        
        # Type checking
        if not self._check_type(value, input_type):
            errors.append(f"Invalid type for {input_type.value}")
            self._validation_failures += 1
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                sanitized_value=None,
                metadata=metadata
            )
        
        # Security checks
        security_issues = self._check_security(value, input_type)
        if security_issues:
            if self.level == ValidationLevel.STRICT:
                errors.extend(security_issues)
                self._security_blocks += 1
                return ValidationResult(
                    is_valid=False,
                    errors=errors,
                    warnings=warnings,
                    sanitized_value=None,
                    metadata={'security_blocked': True}
                )
            else:
                warnings.extend(security_issues)
        
        # Sanitization
        try:
            sanitizer = self._sanitizers.get(input_type)
            if sanitizer:
                sanitized = sanitizer(value, **kwargs)
            else:
                sanitized = value
        except Exception as e:
            errors.append(f"Sanitization failed: {str(e)}")
            sanitized = None
        
        # Custom rules
        if input_type.value in self._custom_rules:
            for rule in self._custom_rules[input_type.value]:
                valid, error = rule.validate(sanitized if sanitized else value)
                if not valid:
                    if rule.severity == "error":
                        errors.append(error)
                    else:
                        warnings.append(error)
        
        # Length checks
        if isinstance(value, str):
            max_length = kwargs.get('max_length', 10000)
            min_length = kwargs.get('min_length', 0)
            
            if len(value) > max_length:
                errors.append(f"Value exceeds maximum length of {max_length}")
            if len(value) < min_length:
                errors.append(f"Value is shorter than minimum length of {min_length}")
        
        # Range checks for numbers
        if input_type in [InputType.INTEGER, InputType.FLOAT, InputType.PORT]:
            min_value = kwargs.get('min_value')
            max_value = kwargs.get('max_value')
            
            if min_value is not None and sanitized < min_value:
                errors.append(f"Value {sanitized} is below minimum {min_value}")
            if max_value is not None and sanitized > max_value:
                errors.append(f"Value {sanitized} exceeds maximum {max_value}")
        
        is_valid = len(errors) == 0
        
        if not is_valid:
            self._validation_failures += 1
        
        return ValidationResult(
            is_valid=is_valid,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized if is_valid else None,
            metadata=metadata
        )
    
    def _check_type(self, value: Any, input_type: InputType) -> bool:
        """Check if value matches expected type"""
        if value is None:
            return False
        
        type_checks = {
            InputType.STRING: lambda v: isinstance(v, str),
            InputType.INTEGER: lambda v: isinstance(v, (int, str)) and (isinstance(v, int) or v.isdigit()),
            InputType.FLOAT: lambda v: isinstance(v, (float, int, str)),
            InputType.BOOLEAN: lambda v: isinstance(v, (bool, str, int)),
            InputType.EMAIL: lambda v: isinstance(v, str) and '@' in v,
            InputType.URL: lambda v: isinstance(v, str),
            InputType.IP_ADDRESS: lambda v: isinstance(v, str),
            InputType.HOSTNAME: lambda v: isinstance(v, str),
            InputType.PORT: lambda v: isinstance(v, (int, str)),
            InputType.PATH: lambda v: isinstance(v, str),
            InputType.JSON: lambda v: isinstance(v, (str, dict, list)),
            InputType.SQL: lambda v: isinstance(v, str),
            InputType.COMMAND: lambda v: isinstance(v, str),
            InputType.SNMP_OID: lambda v: isinstance(v, str),
            InputType.METRIC_NAME: lambda v: isinstance(v, str),
            InputType.TIMESTAMP: lambda v: isinstance(v, (str, int, float, datetime)),
            InputType.UUID: lambda v: isinstance(v, str),
        }
        
        check = type_checks.get(input_type, lambda v: True)
        return check(value)
    
    def _check_security(self, value: Any, input_type: InputType) -> List[str]:
        """Check for security issues"""
        if not isinstance(value, str):
            return []
        
        issues = []
        
        # SQL injection check
        if input_type in [InputType.SQL, InputType.STRING]:
            for pattern in self.SQL_INJECTION_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append(f"Potential SQL injection detected: pattern {pattern}")
                    break
        
        # XSS check
        if input_type in [InputType.STRING, InputType.URL]:
            for pattern in self.XSS_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    issues.append(f"Potential XSS detected: pattern {pattern}")
                    break
        
        # Path traversal check
        if input_type == InputType.PATH:
            for pattern in self.PATH_TRAVERSAL_PATTERNS:
                if re.search(pattern, value):
                    issues.append(f"Potential path traversal detected: pattern {pattern}")
                    break
        
        # Command injection check
        if input_type == InputType.COMMAND:
            for pattern in self.COMMAND_INJECTION_PATTERNS:
                if re.search(pattern, value):
                    issues.append(f"Potential command injection detected: pattern {pattern}")
                    break
        
        return issues
    
    def _sanitize_string(self, value: str, **kwargs) -> str:
        """Sanitize string input"""
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize unicode
        value = unicodedata.normalize('NFKC', value)
        
        # HTML escape if needed
        if kwargs.get('html_escape', False):
            value = html.escape(value)
        
        # Strip whitespace
        if kwargs.get('strip', True):
            value = value.strip()
        
        # Remove control characters
        if kwargs.get('remove_control', True):
            value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\r\t')
        
        return value
    
    def _sanitize_integer(self, value: Union[int, str], **kwargs) -> int:
        """Sanitize integer input"""
        if isinstance(value, str):
            value = value.strip()
            # Remove non-numeric characters
            value = re.sub(r'[^\d-]', '', value)
        
        return int(value)
    
    def _sanitize_float(self, value: Union[float, int, str], **kwargs) -> float:
        """Sanitize float input"""
        if isinstance(value, str):
            value = value.strip()
            # Remove non-numeric characters except decimal point
            value = re.sub(r'[^\d.-]', '', value)
        
        return float(value)
    
    def _sanitize_boolean(self, value: Union[bool, str, int], **kwargs) -> bool:
        """Sanitize boolean input"""
        if isinstance(value, bool):
            return value
        
        if isinstance(value, str):
            value = value.strip().lower()
            return value in ['true', '1', 'yes', 'on', 'enabled']
        
        return bool(value)
    
    def _sanitize_email(self, value: str, **kwargs) -> str:
        """Sanitize email input"""
        value = value.strip().lower()
        
        # Basic email validation regex
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, value):
            raise ValueError(f"Invalid email format: {value}")
        
        return value
    
    def _sanitize_url(self, value: str, **kwargs) -> str:
        """Sanitize URL input"""
        value = value.strip()
        
        # Parse URL
        try:
            parsed = urlparse(value)
            
            # Check scheme
            allowed_schemes = kwargs.get('allowed_schemes', ['http', 'https'])
            if parsed.scheme not in allowed_schemes:
                raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
            
            # Reconstruct URL
            return parsed.geturl()
        except Exception as e:
            raise ValueError(f"Invalid URL: {str(e)}")
    
    def _sanitize_ip(self, value: str, **kwargs) -> str:
        """Sanitize IP address input"""
        value = value.strip()
        
        try:
            # Try IPv4
            ip = ipaddress.ip_address(value)
            
            # Check if private/reserved
            if kwargs.get('no_private', False) and ip.is_private:
                raise ValueError("Private IP addresses not allowed")
            
            if kwargs.get('no_reserved', False) and ip.is_reserved:
                raise ValueError("Reserved IP addresses not allowed")
            
            return str(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {str(e)}")
    
    def _sanitize_hostname(self, value: str, **kwargs) -> str:
        """Sanitize hostname input"""
        value = value.strip().lower()
        
        # Hostname regex (RFC 1123)
        hostname_pattern = r'^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})*$'
        
        if not re.match(hostname_pattern, value):
            # Try to resolve as a fallback
            try:
                socket.gethostbyname(value)
            except socket.gaierror:
                raise ValueError(f"Invalid hostname: {value}")
        
        return value
    
    def _sanitize_port(self, value: Union[int, str], **kwargs) -> int:
        """Sanitize port number input"""
        if isinstance(value, str):
            value = int(value.strip())
        
        if not 1 <= value <= 65535:
            raise ValueError(f"Invalid port number: {value}")
        
        # Check for privileged ports
        if kwargs.get('no_privileged', False) and value < 1024:
            raise ValueError("Privileged ports (< 1024) not allowed")
        
        return value
    
    def _sanitize_path(self, value: str, **kwargs) -> str:
        """Sanitize file path input"""
        import os
        
        value = value.strip()
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize path
        value = os.path.normpath(value)
        
        # Check for path traversal
        if '..' in value:
            raise ValueError("Path traversal detected")
        
        # Check allowed directories
        allowed_dirs = kwargs.get('allowed_dirs', [])
        if allowed_dirs:
            if not any(value.startswith(d) for d in allowed_dirs):
                raise ValueError(f"Path not in allowed directories: {value}")
        
        return value
    
    def _sanitize_json(self, value: Union[str, dict, list], **kwargs) -> Any:
        """Sanitize JSON input"""
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON: {str(e)}")
        
        # Depth check
        max_depth = kwargs.get('max_depth', 10)
        if self._get_json_depth(value) > max_depth:
            raise ValueError(f"JSON exceeds maximum depth of {max_depth}")
        
        return value
    
    def _sanitize_sql(self, value: str, **kwargs) -> str:
        """Sanitize SQL input (basic)"""
        value = value.strip()
        
        # This is basic sanitization - use parameterized queries in production!
        if kwargs.get('escape_quotes', True):
            value = value.replace("'", "''")
        
        return value
    
    def _sanitize_command(self, value: str, **kwargs) -> str:
        """Sanitize command input"""
        value = value.strip()
        
        # Remove dangerous characters
        dangerous_chars = ['|', '&', ';', '$', '`', '\\', '\n', '\r', '<', '>']
        for char in dangerous_chars:
            if char in value:
                raise ValueError(f"Dangerous character '{char}' in command")
        
        # Check against whitelist if provided
        allowed_commands = kwargs.get('allowed_commands', [])
        if allowed_commands:
            command = value.split()[0] if value else ''
            if command not in allowed_commands:
                raise ValueError(f"Command '{command}' not in allowed list")
        
        return value
    
    def _sanitize_snmp_oid(self, value: str, **kwargs) -> str:
        """Sanitize SNMP OID input"""
        value = value.strip()
        
        # OID pattern (numeric with dots)
        oid_pattern = r'^\.?\d+(\.\d+)*$'
        
        if not re.match(oid_pattern, value):
            raise ValueError(f"Invalid SNMP OID format: {value}")
        
        # Ensure it starts with a dot
        if not value.startswith('.'):
            value = '.' + value
        
        return value
    
    def _sanitize_metric_name(self, value: str, **kwargs) -> str:
        """Sanitize metric name input"""
        value = value.strip().lower()
        
        # Metric name pattern (alphanumeric with underscores)
        metric_pattern = r'^[a-z][a-z0-9_]*$'
        
        if not re.match(metric_pattern, value):
            # Try to clean it
            value = re.sub(r'[^a-z0-9_]', '_', value)
            value = re.sub(r'^[^a-z]', 'metric_', value)
            value = re.sub(r'_+', '_', value)
        
        # Length check
        if len(value) > 100:
            value = value[:100]
        
        return value
    
    def _sanitize_timestamp(self, value: Union[str, int, float, datetime], **kwargs) -> datetime:
        """Sanitize timestamp input"""
        if isinstance(value, datetime):
            return value
        
        if isinstance(value, (int, float)):
            # Unix timestamp
            return datetime.fromtimestamp(value)
        
        if isinstance(value, str):
            value = value.strip()
            
            # Try ISO format
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                pass
            
            # Try other common formats
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
                '%d/%m/%Y %H:%M:%S',
                '%Y-%m-%d',
                '%Y/%m/%d'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt)
                except ValueError:
                    continue
            
            raise ValueError(f"Unable to parse timestamp: {value}")
        
        raise ValueError(f"Invalid timestamp type: {type(value)}")
    
    def _sanitize_uuid(self, value: str, **kwargs) -> str:
        """Sanitize UUID input"""
        import uuid
        
        value = value.strip().lower()
        
        try:
            # Validate UUID
            uuid_obj = uuid.UUID(value)
            
            # Return in standard format
            return str(uuid_obj)
        except ValueError:
            raise ValueError(f"Invalid UUID format: {value}")
    
    def _get_json_depth(self, obj: Any, current_depth: int = 0) -> int:
        """Get maximum depth of JSON object"""
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(self._get_json_depth(v, current_depth + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(self._get_json_depth(item, current_depth + 1) for item in obj)
        else:
            return current_depth
    
    def add_custom_rule(self, input_type: str, rule: ValidationRule):
        """Add custom validation rule"""
        if input_type not in self._custom_rules:
            self._custom_rules[input_type] = []
        self._custom_rules[input_type].append(rule)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get validation statistics"""
        return {
            'total_validations': self._validation_count,
            'validation_failures': self._validation_failures,
            'security_blocks': self._security_blocks,
            'failure_rate': self._validation_failures / max(self._validation_count, 1)
        }


class RequestValidator:
    """Validate HTTP/API requests"""
    
    def __init__(self, validator: Optional[InputValidator] = None):
        self.validator = validator or InputValidator()
    
    def validate_request_body(self, body: Dict[str, Any], schema: Dict[str, Any]) -> ValidationResult:
        """Validate request body against schema"""
        errors = []
        warnings = []
        sanitized = {}
        
        for field, field_schema in schema.items():
            required = field_schema.get('required', False)
            field_type = field_schema.get('type', InputType.STRING)
            
            if field not in body:
                if required:
                    errors.append(f"Required field '{field}' is missing")
                continue
            
            # Validate field
            result = self.validator.validate(
                body[field],
                field_type,
                **field_schema.get('kwargs', {})
            )
            
            if result.is_valid:
                sanitized[field] = result.sanitized_value
            else:
                errors.extend(result.errors)
            
            warnings.extend(result.warnings)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            sanitized_value=sanitized,
            metadata={}
        )
    
    def validate_query_params(self, params: Dict[str, str], schema: Dict[str, Any]) -> ValidationResult:
        """Validate query parameters"""
        # Convert all params to appropriate types based on schema
        converted = {}
        
        for param, value in params.items():
            if param in schema:
                param_schema = schema[param]
                param_type = param_schema.get('type', InputType.STRING)
                
                # Convert based on type
                if param_type == InputType.INTEGER:
                    try:
                        converted[param] = int(value)
                    except ValueError:
                        converted[param] = value
                elif param_type == InputType.FLOAT:
                    try:
                        converted[param] = float(value)
                    except ValueError:
                        converted[param] = value
                elif param_type == InputType.BOOLEAN:
                    converted[param] = value.lower() in ['true', '1', 'yes']
                else:
                    converted[param] = value
            else:
                converted[param] = value
        
        return self.validate_request_body(converted, schema)


def create_secure_token(length: int = 32) -> str:
    """Create a secure random token"""
    return secrets.token_urlsafe(length)


def verify_hmac(message: str, signature: str, secret: str) -> bool:
    """Verify HMAC signature"""
    expected = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, expected)