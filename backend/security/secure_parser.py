"""
Secure parsing utilities to replace regex-based security validation.
Provides proper parsing for common data formats with security validation.
"""

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from ipaddress import IPv4Address, IPv6Address, AddressValueError

try:
    import email.utils
    import email.parser
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False

try:
    from urllib.parse import urlparse, parse_qs, unquote
    URLLIB_AVAILABLE = True
except ImportError:
    URLLIB_AVAILABLE = False

try:
    import phonenumbers
    from phonenumbers import NumberParseException
    PHONENUMBERS_AVAILABLE = True
except ImportError:
    PHONENUMBERS_AVAILABLE = False


logger = logging.getLogger(__name__)


class ValidationResult(Enum):
    """Result of validation."""
    VALID = "valid"
    INVALID = "invalid"
    SUSPICIOUS = "suspicious"


@dataclass
class ParseResult:
    """Result of parsing operation."""
    is_valid: bool
    value: Any
    validation_result: ValidationResult
    errors: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]
    
    def __bool__(self) -> bool:
        return self.is_valid


class SecureEmailParser:
    """Secure email address parser."""
    
    # RFC 5322 compliant email regex (simplified but secure)
    EMAIL_PATTERN = re.compile(
        r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
    )
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r'\.{2,}',  # Multiple consecutive dots
        r'^\.|\.$',  # Starting or ending with dot
        r'@\.|\.$@',  # Dots around @
        r'[<>"\'\\\[\]()]',  # Potentially dangerous characters
        r'javascript:|data:|vbscript:',  # Script protocols
    ]
    
    # Common malicious domains (example list)
    SUSPICIOUS_DOMAINS = {
        'tempmail.org', '10minutemail.com', 'guerrillamail.com',
        'mailinator.com', 'yopmail.com', 'spam4.me'
    }
    
    @classmethod
    def parse(cls, email: str, strict: bool = True) -> ParseResult:
        """Parse and validate email address."""
        errors = []
        warnings = []
        metadata = {}
        
        if not email or not isinstance(email, str):
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=["Email is required and must be a string"],
                warnings=[],
                metadata={}
            )
        
        # Basic cleanup
        email = email.strip().lower()
        
        # Length check
        if len(email) > 320:  # RFC 5321 limit
            errors.append("Email address too long (max 320 characters)")
        
        if len(email) < 3:  # Minimum reasonable length
            errors.append("Email address too short")
        
        # Format validation
        if not cls.EMAIL_PATTERN.match(email):
            errors.append("Invalid email format")
        
        # Check for suspicious patterns
        validation_result = ValidationResult.VALID
        for pattern in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, email):
                warnings.append(f"Suspicious pattern detected: {pattern}")
                validation_result = ValidationResult.SUSPICIOUS
        
        # Parse domain
        try:
            local_part, domain = email.rsplit('@', 1)
            metadata['local_part'] = local_part
            metadata['domain'] = domain
            
            # Validate local part length
            if len(local_part) > 64:  # RFC 5321 limit
                errors.append("Local part too long (max 64 characters)")
            
            # Validate domain
            if domain in cls.SUSPICIOUS_DOMAINS:
                warnings.append("Domain is known for temporary/disposable emails")
                validation_result = ValidationResult.SUSPICIOUS
            
            # Check for homograph attacks (basic check)
            if any(ord(c) > 127 for c in domain):
                warnings.append("Domain contains non-ASCII characters (possible homograph attack)")
                validation_result = ValidationResult.SUSPICIOUS
            
        except ValueError:
            errors.append("Email must contain exactly one @ symbol")
        
        # Advanced validation with email-validator if available
        if EMAIL_AVAILABLE and not errors:
            try:
                parsed = email.parser.Parser().parsestr(f"To: {email}")
                metadata['parsed_header'] = parsed.get('To', '')
            except Exception as e:
                warnings.append(f"Advanced parsing warning: {e}")
        
        is_valid = len(errors) == 0
        
        return ParseResult(
            is_valid=is_valid,
            value=email if is_valid else None,
            validation_result=validation_result,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )


class SecureURLParser:
    """Secure URL parser."""
    
    ALLOWED_SCHEMES = {'http', 'https', 'ftp', 'ftps'}
    SUSPICIOUS_SCHEMES = {'javascript', 'data', 'vbscript', 'file'}
    
    # Suspicious URL patterns
    SUSPICIOUS_PATTERNS = [
        r'%[0-9a-fA-F]{2}',  # URL encoding (could be obfuscation)
        r'[<>"\'\\\[\]{}|\\^`]',  # Dangerous characters
        r'\.{2,}',  # Path traversal attempts
        r'//+',  # Multiple slashes
        r'[^\x20-\x7E]',  # Non-printable characters
    ]
    
    # Suspicious domains/IPs
    SUSPICIOUS_PATTERNS_DOMAIN = [
        r'^\d+\.\d+\.\d+\.\d+$',  # Raw IP addresses
        r'localhost|127\.0\.0\.1|::1',  # Local addresses
        r'[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}',  # IP-like patterns
        r'bit\.ly|tinyurl|t\.co|goo\.gl',  # URL shorteners
    ]
    
    @classmethod
    def parse(cls, url: str, strict: bool = True) -> ParseResult:
        """Parse and validate URL."""
        errors = []
        warnings = []
        metadata = {}
        
        if not url or not isinstance(url, str):
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=["URL is required and must be a string"],
                warnings=[],
                metadata={}
            )
        
        # Basic cleanup
        url = url.strip()
        
        # Length check
        if len(url) > 2048:  # Common browser limit
            errors.append("URL too long (max 2048 characters)")
        
        if len(url) < 3:
            errors.append("URL too short")
        
        # Parse URL
        try:
            if not URLLIB_AVAILABLE:
                raise ImportError("urllib not available")
            
            parsed = urlparse(url)
            metadata['scheme'] = parsed.scheme
            metadata['netloc'] = parsed.netloc
            metadata['path'] = parsed.path
            metadata['params'] = parsed.params
            metadata['query'] = parsed.query
            metadata['fragment'] = parsed.fragment
            
        except Exception as e:
            errors.append(f"Failed to parse URL: {e}")
            parsed = None
        
        validation_result = ValidationResult.VALID
        
        if parsed:
            # Validate scheme
            if parsed.scheme.lower() in cls.SUSPICIOUS_SCHEMES:
                errors.append(f"Dangerous scheme: {parsed.scheme}")
                validation_result = ValidationResult.SUSPICIOUS
            elif parsed.scheme.lower() not in cls.ALLOWED_SCHEMES:
                warnings.append(f"Unusual scheme: {parsed.scheme}")
                validation_result = ValidationResult.SUSPICIOUS
            
            # Validate domain/netloc
            if parsed.netloc:
                for pattern in cls.SUSPICIOUS_PATTERNS_DOMAIN:
                    if re.search(pattern, parsed.netloc, re.IGNORECASE):
                        warnings.append(f"Suspicious domain pattern: {pattern}")
                        validation_result = ValidationResult.SUSPICIOUS
                        break
            else:
                errors.append("URL must contain a domain")
            
            # Check for suspicious patterns in the full URL
            for pattern in cls.SUSPICIOUS_PATTERNS:
                if re.search(pattern, url):
                    warnings.append(f"Suspicious URL pattern: {pattern}")
                    validation_result = ValidationResult.SUSPICIOUS
            
            # Parse query parameters
            if parsed.query:
                try:
                    query_params = parse_qs(parsed.query, strict_parsing=strict)
                    metadata['query_params'] = query_params
                    
                    # Check for suspicious query parameters
                    for key, values in query_params.items():
                        for value in values:
                            if any(char in value for char in '<>"\'\\\0'):
                                warnings.append(f"Suspicious characters in query parameter: {key}")
                                validation_result = ValidationResult.SUSPICIOUS
                except Exception as e:
                    warnings.append(f"Failed to parse query parameters: {e}")
        
        is_valid = len(errors) == 0
        
        return ParseResult(
            is_valid=is_valid,
            value=url if is_valid else None,
            validation_result=validation_result,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )


class SecureIPParser:
    """Secure IP address parser."""
    
    PRIVATE_RANGES = [
        ('10.0.0.0', '10.255.255.255'),
        ('172.16.0.0', '172.31.255.255'),
        ('192.168.0.0', '192.168.255.255'),
        ('127.0.0.0', '127.255.255.255'),  # Loopback
        ('169.254.0.0', '169.254.255.255'),  # Link-local
    ]
    
    @classmethod
    def parse(cls, ip_str: str, allow_private: bool = False) -> ParseResult:
        """Parse and validate IP address."""
        errors = []
        warnings = []
        metadata = {}
        
        if not ip_str or not isinstance(ip_str, str):
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=["IP address is required and must be a string"],
                warnings=[],
                metadata={}
            )
        
        ip_str = ip_str.strip()
        validation_result = ValidationResult.VALID
        
        try:
            # Try IPv4 first
            ip = IPv4Address(ip_str)
            metadata['version'] = 4
            metadata['is_private'] = ip.is_private
            metadata['is_loopback'] = ip.is_loopback
            metadata['is_multicast'] = ip.is_multicast
            metadata['is_reserved'] = ip.is_reserved
            
            # Check if private IP is allowed
            if ip.is_private and not allow_private:
                warnings.append("Private IP address detected")
                validation_result = ValidationResult.SUSPICIOUS
            
            if ip.is_loopback:
                warnings.append("Loopback IP address detected")
                validation_result = ValidationResult.SUSPICIOUS
                
        except AddressValueError:
            try:
                # Try IPv6
                ip = IPv6Address(ip_str)
                metadata['version'] = 6
                metadata['is_private'] = ip.is_private
                metadata['is_loopback'] = ip.is_loopback
                metadata['is_multicast'] = ip.is_multicast
                metadata['is_reserved'] = ip.is_reserved
                
                if ip.is_private and not allow_private:
                    warnings.append("Private IPv6 address detected")
                    validation_result = ValidationResult.SUSPICIOUS
                    
            except AddressValueError:
                errors.append("Invalid IP address format")
                ip = None
        
        is_valid = len(errors) == 0 and ip is not None
        
        return ParseResult(
            is_valid=is_valid,
            value=str(ip) if ip else None,
            validation_result=validation_result,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )


class SecurePhoneParser:
    """Secure phone number parser."""
    
    @classmethod
    def parse(cls, phone: str, region: str = None) -> ParseResult:
        """Parse and validate phone number."""
        errors = []
        warnings = []
        metadata = {}
        
        if not phone or not isinstance(phone, str):
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=["Phone number is required and must be a string"],
                warnings=[],
                metadata={}
            )
        
        # Basic cleanup
        phone = phone.strip()
        
        if not PHONENUMBERS_AVAILABLE:
            # Fallback validation without phonenumbers library
            # Remove common formatting
            cleaned = re.sub(r'[^\d+]', '', phone)
            
            # Basic validation
            if len(cleaned) < 7:
                errors.append("Phone number too short")
            elif len(cleaned) > 15:  # E.164 limit
                errors.append("Phone number too long")
            elif not re.match(r'^\+?[\d]+$', cleaned):
                errors.append("Invalid phone number format")
            
            return ParseResult(
                is_valid=len(errors) == 0,
                value=cleaned if len(errors) == 0 else None,
                validation_result=ValidationResult.VALID,
                errors=errors,
                warnings=warnings,
                metadata={'cleaned': cleaned}
            )
        
        # Use phonenumbers library for proper parsing
        try:
            parsed_number = phonenumbers.parse(phone, region)
            
            metadata['country_code'] = parsed_number.country_code
            metadata['national_number'] = parsed_number.national_number
            metadata['region'] = phonenumbers.region_code_for_number(parsed_number)
            
            # Validate the number
            if not phonenumbers.is_valid_number(parsed_number):
                errors.append("Invalid phone number")
            
            # Format the number
            e164_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.E164)
            national_format = phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.NATIONAL)
            
            metadata['e164_format'] = e164_format
            metadata['national_format'] = national_format
            metadata['number_type'] = phonenumbers.number_type(parsed_number)
            
        except NumberParseException as e:
            errors.append(f"Phone parsing error: {e}")
            parsed_number = None
            e164_format = None
        
        is_valid = len(errors) == 0 and parsed_number is not None
        
        return ParseResult(
            is_valid=is_valid,
            value=e164_format if is_valid else None,
            validation_result=ValidationResult.VALID,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )


class SecureJSONParser:
    """Secure JSON parser with depth and size limits."""
    
    @classmethod
    def parse(
        cls,
        json_str: str,
        max_size: int = 1024 * 1024,  # 1MB
        max_depth: int = 10,
        strict: bool = True
    ) -> ParseResult:
        """Parse and validate JSON string."""
        errors = []
        warnings = []
        metadata = {}
        
        if not json_str or not isinstance(json_str, str):
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=["JSON is required and must be a string"],
                warnings=[],
                metadata={}
            )
        
        # Size check
        if len(json_str.encode('utf-8')) > max_size:
            errors.append(f"JSON too large (max {max_size} bytes)")
        
        # Check for suspicious patterns
        validation_result = ValidationResult.VALID
        suspicious_patterns = [
            r'__proto__',  # Prototype pollution
            r'constructor',  # Constructor manipulation
            r'eval\s*\(',  # Code execution
            r'Function\s*\(',  # Function constructor
            r'<script',  # Script injection
            r'javascript:',  # JavaScript protocol
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, json_str, re.IGNORECASE):
                warnings.append(f"Suspicious pattern in JSON: {pattern}")
                validation_result = ValidationResult.SUSPICIOUS
        
        # Parse JSON
        try:
            parsed = json.loads(json_str, strict=strict)
            
            # Check depth
            depth = cls._get_json_depth(parsed)
            metadata['depth'] = depth
            
            if depth > max_depth:
                errors.append(f"JSON too deep (max depth {max_depth})")
            
            # Check for circular references (basic check)
            try:
                json.dumps(parsed)  # This will fail on circular references
            except ValueError as e:
                if 'circular' in str(e).lower():
                    errors.append("Circular reference detected in JSON")
            
            metadata['type'] = type(parsed).__name__
            if isinstance(parsed, dict):
                metadata['keys'] = list(parsed.keys())[:10]  # First 10 keys
            elif isinstance(parsed, list):
                metadata['length'] = len(parsed)
            
        except json.JSONDecodeError as e:
            errors.append(f"JSON decode error: {e}")
            parsed = None
        
        is_valid = len(errors) == 0 and parsed is not None
        
        return ParseResult(
            is_valid=is_valid,
            value=parsed if is_valid else None,
            validation_result=validation_result,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )
    
    @classmethod
    def _get_json_depth(cls, obj, current_depth: int = 0) -> int:
        """Calculate maximum depth of JSON object."""
        if current_depth > 50:  # Prevent infinite recursion
            return current_depth
        
        if isinstance(obj, dict):
            if not obj:
                return current_depth
            return max(cls._get_json_depth(value, current_depth + 1) for value in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current_depth
            return max(cls._get_json_depth(item, current_depth + 1) for item in obj)
        else:
            return current_depth


class SecureDateTimeParser:
    """Secure date/time parser."""
    
    # Common date formats
    DATE_FORMATS = [
        '%Y-%m-%d',
        '%Y/%m/%d',
        '%m/%d/%Y',
        '%d/%m/%Y',
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S.%fZ',
        '%Y-%m-%dT%H:%M:%S%z',
    ]
    
    @classmethod
    def parse(cls, date_str: str, strict: bool = True) -> ParseResult:
        """Parse and validate date string."""
        errors = []
        warnings = []
        metadata = {}
        
        if not date_str or not isinstance(date_str, str):
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=["Date is required and must be a string"],
                warnings=[],
                metadata={}
            )
        
        date_str = date_str.strip()
        validation_result = ValidationResult.VALID
        
        # Check for suspicious patterns
        if re.search(r'[<>"\'\\\0]', date_str):
            warnings.append("Suspicious characters in date string")
            validation_result = ValidationResult.SUSPICIOUS
        
        # Try to parse with different formats
        parsed_date = None
        used_format = None
        
        for fmt in cls.DATE_FORMATS:
            try:
                parsed_date = datetime.strptime(date_str, fmt)
                used_format = fmt
                break
            except ValueError:
                continue
        
        if parsed_date is None:
            # Try ISO format parsing
            try:
                parsed_date = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                used_format = 'ISO format'
            except ValueError:
                errors.append("Unrecognized date format")
        
        if parsed_date:
            # Validate date range (reasonable bounds)
            current_year = datetime.now().year
            if parsed_date.year < 1900:
                warnings.append("Date is very old (before 1900)")
                validation_result = ValidationResult.SUSPICIOUS
            elif parsed_date.year > current_year + 50:
                warnings.append("Date is far in the future")
                validation_result = ValidationResult.SUSPICIOUS
            
            # Add timezone info if missing
            if parsed_date.tzinfo is None:
                parsed_date = parsed_date.replace(tzinfo=timezone.utc)
                warnings.append("Assumed UTC timezone for naive datetime")
            
            metadata['format_used'] = used_format
            metadata['year'] = parsed_date.year
            metadata['has_timezone'] = parsed_date.tzinfo is not None
            metadata['iso_format'] = parsed_date.isoformat()
        
        is_valid = len(errors) == 0 and parsed_date is not None
        
        return ParseResult(
            is_valid=is_valid,
            value=parsed_date if is_valid else None,
            validation_result=validation_result,
            errors=errors,
            warnings=warnings,
            metadata=metadata
        )


class SecureParser:
    """Main secure parser interface."""
    
    def __init__(self):
        self.email_parser = SecureEmailParser()
        self.url_parser = SecureURLParser()
        self.ip_parser = SecureIPParser()
        self.phone_parser = SecurePhoneParser()
        self.json_parser = SecureJSONParser()
        self.datetime_parser = SecureDateTimeParser()
    
    def parse_email(self, email: str, **kwargs) -> ParseResult:
        """Parse email address."""
        return self.email_parser.parse(email, **kwargs)
    
    def parse_url(self, url: str, **kwargs) -> ParseResult:
        """Parse URL."""
        return self.url_parser.parse(url, **kwargs)
    
    def parse_ip(self, ip: str, **kwargs) -> ParseResult:
        """Parse IP address."""
        return self.ip_parser.parse(ip, **kwargs)
    
    def parse_phone(self, phone: str, **kwargs) -> ParseResult:
        """Parse phone number."""
        return self.phone_parser.parse(phone, **kwargs)
    
    def parse_json(self, json_str: str, **kwargs) -> ParseResult:
        """Parse JSON string."""
        return self.json_parser.parse(json_str, **kwargs)
    
    def parse_datetime(self, date_str: str, **kwargs) -> ParseResult:
        """Parse datetime string."""
        return self.datetime_parser.parse(date_str, **kwargs)
    
    def validate_input(
        self,
        value: str,
        input_type: str,
        **kwargs
    ) -> ParseResult:
        """Generic input validation."""
        parsers = {
            'email': self.parse_email,
            'url': self.parse_url,
            'ip': self.parse_ip,
            'phone': self.parse_phone,
            'json': self.parse_json,
            'datetime': self.parse_datetime,
        }
        
        parser = parsers.get(input_type.lower())
        if not parser:
            return ParseResult(
                is_valid=False,
                value=None,
                validation_result=ValidationResult.INVALID,
                errors=[f"Unknown input type: {input_type}"],
                warnings=[],
                metadata={}
            )
        
        return parser(value, **kwargs)


# Global parser instance
secure_parser = SecureParser()