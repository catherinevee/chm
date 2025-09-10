"""
Input validation and sanitization service
"""

import re
import ipaddress
from typing import Any, Dict, List, Optional, Union
from datetime import datetime
import logging
import html
import urllib.parse
from sqlalchemy import text

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Validation error exception"""
    pass

class ValidationService:
    """Service for input validation and sanitization"""
    
    # Regex patterns for validation
    PATTERNS = {
        'username': re.compile(r'^[a-zA-Z0-9_-]{3,100}$'),
        'hostname': re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'),
        'mac_address': re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'port': re.compile(r'^([1-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{3}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$'),
        'snmp_community': re.compile(r'^[a-zA-Z0-9_-]{1,255}$'),
        'device_type': re.compile(r'^[a-zA-Z0-9_-]+$'),
        'metric_name': re.compile(r'^[a-zA-Z0-9_.-]+$'),
        'alphanumeric': re.compile(r'^[a-zA-Z0-9]+$'),
        'path': re.compile(r'^[a-zA-Z0-9/_.-]+$'),
        'sql_identifier': re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*$'),
    }
    
    # Blacklisted SQL keywords for additional protection
    SQL_BLACKLIST = [
        'drop', 'delete', 'insert', 'update', 'alter', 'create',
        'truncate', 'exec', 'execute', 'union', 'select',
        'grant', 'revoke', '--', '/*', '*/', 'xp_', 'sp_'
    ]
    
    # XSS dangerous tags and attributes
    XSS_DANGEROUS_TAGS = [
        'script', 'iframe', 'object', 'embed', 'form',
        'meta', 'link', 'style', 'base', 'body', 'head'
    ]
    
    XSS_DANGEROUS_ATTRS = [
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus',
        'onblur', 'onchange', 'onsubmit', 'javascript:', 'data:'
    ]
    
    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """Validate and sanitize IP address"""
        try:
            # Remove whitespace
            ip = ip.strip()
            
            # Validate IP address format
            ip_obj = ipaddress.ip_address(ip)
            
            # Check for reserved addresses
            if ip_obj.is_reserved or ip_obj.is_multicast:
                raise ValidationError(f"Invalid IP address type: {ip}")
            
            return str(ip_obj)
            
        except (ipaddress.AddressValueError, ValueError) as e:
            raise ValidationError(f"Invalid IP address: {ip}")
    
    @staticmethod
    def validate_ip_range(ip_range: str) -> str:
        """Validate IP range or CIDR notation"""
        try:
            ip_range = ip_range.strip()
            
            # Try to parse as network
            network = ipaddress.ip_network(ip_range, strict=False)
            
            # Check for reserved networks
            if network.is_reserved or network.is_multicast:
                raise ValidationError(f"Invalid network type: {ip_range}")
            
            return str(network)
            
        except (ipaddress.AddressValueError, ValueError):
            # Try to parse as range (e.g., "192.168.1.1-192.168.1.10")
            if '-' in ip_range:
                parts = ip_range.split('-')
                if len(parts) == 2:
                    start_ip = ValidationService.validate_ip_address(parts[0])
                    end_ip = ValidationService.validate_ip_address(parts[1])
                    
                    # Validate range order
                    if ipaddress.ip_address(start_ip) > ipaddress.ip_address(end_ip):
                        raise ValidationError(f"Invalid IP range: start > end")
                    
                    return f"{start_ip}-{end_ip}"
            
            raise ValidationError(f"Invalid IP range format: {ip_range}")
    
    @staticmethod
    def validate_hostname(hostname: str) -> str:
        """Validate and sanitize hostname"""
        hostname = hostname.strip().lower()
        
        if not hostname or len(hostname) > 253:
            raise ValidationError(f"Invalid hostname length: {len(hostname)}")
        
        if not ValidationService.PATTERNS['hostname'].match(hostname):
            raise ValidationError(f"Invalid hostname format: {hostname}")
        
        return hostname
    
    @staticmethod
    def validate_port(port: Union[int, str]) -> int:
        """Validate port number"""
        try:
            port_int = int(port)
            if port_int < 1 or port_int > 65535:
                raise ValidationError(f"Port out of range: {port}")
            return port_int
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid port number: {port}")
    
    @staticmethod
    def validate_snmp_community(community: str) -> str:
        """Validate SNMP community string"""
        community = community.strip()
        
        if not community or len(community) > 255:
            raise ValidationError(f"Invalid community string length")
        
        if not ValidationService.PATTERNS['snmp_community'].match(community):
            raise ValidationError(f"Invalid community string format")
        
        return community
    
    @staticmethod
    def validate_snmp_version(version: str) -> str:
        """Validate SNMP version"""
        valid_versions = ['1', '2c', '3']
        version = version.strip().lower()
        
        if version not in valid_versions:
            raise ValidationError(f"Invalid SNMP version: {version}")
        
        return version
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize string input for safety"""
        if not value:
            return ""
        
        # Truncate to max length
        value = value[:max_length]
        
        # HTML escape
        value = html.escape(value)
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Remove control characters except newline and tab
        value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
        
        return value.strip()
    
    @staticmethod
    def sanitize_for_sql(value: str) -> str:
        """Sanitize string for SQL queries"""
        if not value:
            return ""
        
        value = ValidationService.sanitize_string(value)
        
        # Check for SQL keywords
        value_lower = value.lower()
        for keyword in ValidationService.SQL_BLACKLIST:
            if keyword in value_lower:
                raise ValidationError(f"Potentially dangerous SQL keyword detected")
        
        # Escape single quotes
        value = value.replace("'", "''")
        
        return value
    
    @staticmethod
    def validate_sql_identifier(identifier: str) -> str:
        """Validate SQL identifier (table/column name)"""
        identifier = identifier.strip()
        
        if not ValidationService.PATTERNS['sql_identifier'].match(identifier):
            raise ValidationError(f"Invalid SQL identifier: {identifier}")
        
        # Check against blacklist
        if identifier.lower() in ValidationService.SQL_BLACKLIST:
            raise ValidationError(f"Reserved SQL keyword: {identifier}")
        
        return identifier
    
    @staticmethod
    def validate_device_type(device_type: str) -> str:
        """Validate device type"""
        valid_types = [
            'router', 'switch', 'firewall', 'load_balancer',
            'server', 'workstation', 'printer', 'access_point',
            'controller', 'sensor', 'camera', 'other'
        ]
        
        device_type = device_type.strip().lower()
        
        if device_type not in valid_types:
            raise ValidationError(f"Invalid device type: {device_type}")
        
        return device_type
    
    @staticmethod
    def validate_email(email: str) -> str:
        """Validate email address"""
        email = email.strip().lower()
        
        if not email or len(email) > 254:
            raise ValidationError(f"Invalid email length")
        
        if not ValidationService.PATTERNS['email'].match(email):
            raise ValidationError(f"Invalid email format")
        
        return email
    
    @staticmethod
    def validate_mac_address(mac: str) -> str:
        """Validate MAC address"""
        mac = mac.strip().upper()
        
        if not ValidationService.PATTERNS['mac_address'].match(mac):
            raise ValidationError(f"Invalid MAC address format")
        
        # Normalize to colon format
        mac = mac.replace('-', ':')
        
        return mac
    
    @staticmethod
    def validate_metric_name(name: str) -> str:
        """Validate metric name"""
        name = name.strip()
        
        if not name or len(name) > 100:
            raise ValidationError(f"Invalid metric name length")
        
        if not ValidationService.PATTERNS['metric_name'].match(name):
            raise ValidationError(f"Invalid metric name format")
        
        return name
    
    @staticmethod
    def validate_json(data: Any) -> Dict:
        """Validate JSON data"""
        if not isinstance(data, dict):
            raise ValidationError("Invalid JSON: expected object")
        
        # Recursively sanitize strings in JSON
        def sanitize_json(obj):
            if isinstance(obj, dict):
                return {k: sanitize_json(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [sanitize_json(item) for item in obj]
            elif isinstance(obj, str):
                return ValidationService.sanitize_string(obj)
            else:
                return obj
        
        return sanitize_json(data)
    
    @staticmethod
    def validate_pagination(page: int, per_page: int) -> tuple:
        """Validate pagination parameters"""
        try:
            page = int(page)
            per_page = int(per_page)
            
            if page < 1:
                page = 1
            
            if per_page < 1:
                per_page = 10
            elif per_page > 100:
                per_page = 100
            
            return page, per_page
            
        except (ValueError, TypeError):
            return 1, 10
    
    @staticmethod
    def validate_date_range(start_date: str, end_date: str) -> tuple:
        """Validate date range"""
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            
            if start > end:
                raise ValidationError("Start date must be before end date")
            
            # Limit range to prevent excessive queries
            max_days = 365
            if (end - start).days > max_days:
                raise ValidationError(f"Date range exceeds maximum of {max_days} days")
            
            return start, end
            
        except (ValueError, TypeError) as e:
            raise ValidationError(f"Invalid date format: {e}")
    
    @staticmethod
    def validate_threshold(value: float, operator: str) -> tuple:
        """Validate threshold value and operator"""
        try:
            value = float(value)
            
            valid_operators = ['>', '<', '>=', '<=', '==', '!=']
            if operator not in valid_operators:
                raise ValidationError(f"Invalid operator: {operator}")
            
            return value, operator
            
        except (ValueError, TypeError):
            raise ValidationError(f"Invalid threshold value: {value}")
    
    @staticmethod
    def validate_file_upload(filename: str, content_type: str, max_size: int = 10485760) -> bool:
        """Validate file upload"""
        # Allowed extensions
        allowed_extensions = ['.csv', '.json', '.xml', '.txt', '.log']
        allowed_content_types = [
            'text/csv', 'application/json', 'text/xml',
            'application/xml', 'text/plain'
        ]
        
        # Check filename
        filename = filename.strip()
        if not filename:
            raise ValidationError("Empty filename")
        
        # Check extension
        import os
        _, ext = os.path.splitext(filename.lower())
        if ext not in allowed_extensions:
            raise ValidationError(f"File type not allowed: {ext}")
        
        # Check content type
        if content_type not in allowed_content_types:
            raise ValidationError(f"Content type not allowed: {content_type}")
        
        return True
    
    @staticmethod
    def sanitize_path(path: str) -> str:
        """Sanitize file path to prevent directory traversal"""
        if not path:
            return ""
        
        # Remove any directory traversal attempts
        path = path.replace('../', '').replace('..\\', '')
        path = path.replace('./', '').replace('.\\', '')
        
        # Remove null bytes
        path = path.replace('\x00', '')
        
        # Normalize path
        import os
        path = os.path.normpath(path)
        
        # Ensure path doesn't start with separator
        if path.startswith(os.sep):
            path = path[1:]
        
        return path
    
    @staticmethod
    def validate_batch_operation(items: List[Any], max_items: int = 100) -> List[Any]:
        """Validate batch operation size"""
        if not isinstance(items, list):
            raise ValidationError("Batch operation requires a list")
        
        if len(items) > max_items:
            raise ValidationError(f"Batch size exceeds maximum of {max_items}")
        
        if len(items) == 0:
            raise ValidationError("Empty batch operation")
        
        return items
    
    @staticmethod
    def validate_search_query(query: str, max_length: int = 100) -> str:
        """Validate search query"""
        query = query.strip()
        
        if not query:
            raise ValidationError("Empty search query")
        
        if len(query) > max_length:
            raise ValidationError(f"Search query exceeds maximum length of {max_length}")
        
        # Sanitize for safety
        query = ValidationService.sanitize_string(query, max_length)
        
        # Remove SQL wildcards if present
        query = query.replace('%', '').replace('_', '')
        
        return query
    
    @staticmethod
    def validate_url(url: str) -> str:
        """Validate URL"""
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                raise ValidationError(f"Invalid URL scheme: {parsed.scheme}")
            
            # Check for localhost/private IPs (optional security measure)
            if parsed.hostname:
                try:
                    ip = ipaddress.ip_address(parsed.hostname)
                    if ip.is_private or ip.is_loopback:
                        raise ValidationError("Private/loopback addresses not allowed")
                except ValueError:
                    # Not an IP, probably a domain
                    pass
            
            return url
            
        except Exception as e:
            raise ValidationError(f"Invalid URL: {e}")