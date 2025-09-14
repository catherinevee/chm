"""
Validation Service for CHM
"""
from typing import Any, Dict, List, Optional
import re
import ipaddress
from datetime import datetime

class ValidationService:
    """Service for data validation"""

    def validate_device_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate device data"""
        errors = {}

        # Validate IP address
        if 'ip_address' in data:
            try:
                ipaddress.ip_address(data['ip_address'])
            except ValueError:
                errors['ip_address'] = 'Invalid IP address'

        # Validate hostname
        if 'hostname' in data:
            if not re.match(r'^[a-zA-Z0-9-_.]+$', data['hostname']):
                errors['hostname'] = 'Invalid hostname format'

        # Validate device type
        valid_types = ['router', 'switch', 'firewall', 'server', 'unknown']
        if 'device_type' in data and data['device_type'] not in valid_types:
            errors['device_type'] = f'Must be one of {valid_types}'

        if errors:
            raise ValueError(f"Validation errors: {errors}")

        return data

    def validate_metric_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate metric data"""
        errors = {}

        # Validate metric name
        if 'metric_name' not in data or not data['metric_name']:
            errors['metric_name'] = 'Metric name is required'

        # Validate value
        if 'value' in data:
            try:
                float(data['value'])
            except (TypeError, ValueError):
                errors['value'] = 'Value must be numeric'

        if errors:
            raise ValueError(f"Validation errors: {errors}")

        return data

    def validate_credentials(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate credentials"""
        errors = {}

        # Validate SNMP community
        if 'snmp_community' in data and not data['snmp_community']:
            errors['snmp_community'] = 'SNMP community cannot be empty'

        # Validate SSH username
        if 'ssh_username' in data and not data['ssh_username']:
            errors['ssh_username'] = 'SSH username cannot be empty'

        if errors:
            raise ValueError(f"Validation errors: {errors}")

        return data
