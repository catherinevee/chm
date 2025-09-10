"""
Bulk Import Service
Handles importing devices from various file formats (CSV, Excel, JSON)
"""

import csv
import json
import pandas as pd
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime
import logging
from io import StringIO, BytesIO
import asyncio
from pathlib import Path

from backend.storage.database import db
from backend.storage.models import Device, DeviceCredential, DeviceType

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)

logger = logging.getLogger(__name__)

@dataclass
class ImportResult:
    total_rows: int
    successful_imports: int
    failed_imports: int
    errors: List[str]
    imported_devices: List[Dict[str, Any]]

class BulkImportService:
    def __init__(self):
        self.required_fields = ['hostname', 'ip_address']
        self.optional_fields = [
            'device_type', 'model', 'serial_number', 'location',
            'poll_interval', 'gentle_mode', 'monitor_poe', 'monitor_stack',
            'monitor_supervisor', 'snmp_community', 'snmp_version',
            'ssh_username', 'ssh_password', 'tags'
        ]
    
    async def import_from_csv(self, file_content: str, has_header: bool = True) -> ImportResult:
        """Import devices from CSV content"""
        try:
            # Parse CSV
            csv_reader = csv.DictReader(StringIO(file_content))
            rows = list(csv_reader)
            
            return await self._process_import_data(rows)
            
        except Exception as e:
            logger.error(f"CSV import failed: {e}")
            return ImportResult(
                total_rows=0,
                successful_imports=0,
                failed_imports=0,
                errors=[f"CSV parsing failed: {str(e)}"],
                imported_devices=[]
            )
    
    async def import_from_excel(self, file_content: bytes, sheet_name: Optional[str] = None) -> ImportResult:
        """Import devices from Excel file"""
        try:
            # Read Excel file
            df = pd.read_excel(BytesIO(file_content), sheet_name=sheet_name)
            rows = df.to_dict('records')
            
            return await self._process_import_data(rows)
            
        except Exception as e:
            logger.error(f"Excel import failed: {e}")
            return ImportResult(
                total_rows=0,
                successful_imports=0,
                failed_imports=0,
                errors=[f"Excel parsing failed: {str(e)}"],
                imported_devices=[]
            )
    
    async def import_from_json(self, file_content: str) -> ImportResult:
        """Import devices from JSON content"""
        try:
            # Parse JSON
            data = json.loads(file_content)
            
            # Handle both array and object formats
            if isinstance(data, list):
                rows = data
            elif isinstance(data, dict) and 'devices' in data:
                rows = data['devices']
            else:
                rows = [data]
            
            return await self._process_import_data(rows)
            
        except Exception as e:
            logger.error(f"JSON import failed: {e}")
            return ImportResult(
                total_rows=0,
                successful_imports=0,
                failed_imports=0,
                errors=[f"JSON parsing failed: {str(e)}"],
                imported_devices=[]
            )
    
    async def _process_import_data(self, rows: List[Dict[str, Any]]) -> ImportResult:
        """Process imported data and create devices"""
        result = ImportResult(
            total_rows=len(rows),
            successful_imports=0,
            failed_imports=0,
            errors=[],
            imported_devices=[]
        )
        
        for i, row in enumerate(rows):
            try:
                # Validate required fields
                if not self._validate_required_fields(row):
                    result.failed_imports += 1
                    result.errors.append(f"Row {i+1}: Missing required fields")
                    continue
                
                # Create device
                device_data = await self._create_device_from_row(row)
                if device_data:
                    result.successful_imports += 1
                    result.imported_devices.append(device_data)
                else:
                    result.failed_imports += 1
                    result.errors.append(f"Row {i+1}: Failed to create device")
                    
            except Exception as e:
                result.failed_imports += 1
                result.errors.append(f"Row {i+1}: {str(e)}")
                logger.error(f"Error processing row {i+1}: {e}")
        
        return result
    
    def _validate_required_fields(self, row: Dict[str, Any]) -> bool:
        """Validate that required fields are present"""
        for field in self.required_fields:
            if field not in row or not row[field]:
                return False
        return True
    
    async def _create_device_from_row(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Create a device from import row data"""
        try:
            async with db.get_session() as session:
                # Check if device already exists
                existing_device = await session.execute(
                    f"SELECT id FROM devices WHERE hostname = '{row['hostname']}' OR ip_address = '{row['ip_address']}'"
                )
                if existing_device.fetchone():
                    logger.warning(f"Device {row['hostname']} already exists")
                    return create_partial_success_result(
                        data=None,
                        error_code="DEVICE_ALREADY_EXISTS",
                        message=f"Device {row['hostname']} already exists",
                        fallback_data=FallbackData(
                            data=None,
                            health_status=HealthStatus(
                                level=HealthLevel.WARNING,
                                message="Device already exists",
                                details=f"Device with hostname {row['hostname']} or IP {row['ip_address']} already exists"
                            )
                        ),
                        suggestions=["Use different hostname/IP", "Update existing device", "Check device inventory"]
                    )
                
                # Create device
                device = Device(
                    hostname=row['hostname'],
                    ip_address=row['ip_address'],
                    device_type=self._parse_device_type(row.get('device_type', 'UNKNOWN')),
                    model=row.get('model'),
                    serial_number=row.get('serial_number'),
                    location=row.get('location'),
                    poll_interval=int(row.get('poll_interval', 60)),
                    gentle_mode=bool(row.get('gentle_mode', False)),
                    monitor_poe=bool(row.get('monitor_poe', False)),
                    monitor_stack=bool(row.get('monitor_stack', False)),
                    monitor_supervisor=bool(row.get('monitor_supervisor', False)),
                    tags=self._parse_tags(row.get('tags', ''))
                )
                
                session.add(device)
                await session.flush()  # Get the device ID
                
                # Create credentials
                await self._create_credentials(session, device.id, row)
                
                await session.commit()
                
                return {
                    'id': str(device.id),
                    'hostname': device.hostname,
                    'ip_address': str(device.ip_address),
                    'device_type': device.device_type.value,
                    'status': 'created'
                }
                
        except Exception as e:
            logger.error(f"Error creating device from row: {e}")
            return create_failure_result(
                error_code="DEVICE_CREATION_ERROR",
                message="Failed to create device from import row",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.ERROR,
                        message="Device creation failed",
                        details=f"Error creating device from row: {str(e)}"
                    )
                ),
                suggestions=["Check import data format", "Verify database connectivity", "Review error details"]
            )
    
    def _parse_device_type(self, device_type: str) -> DeviceType:
        """Parse device type string to enum"""
        device_type_upper = device_type.upper()
        
        if device_type_upper in ['2960', 'C2960']:
            return DeviceType.C2960
        elif device_type_upper in ['3560', 'C3560']:
            return DeviceType.C3560
        elif device_type_upper in ['4500', 'C4500']:
            return DeviceType.C4500
        else:
            return DeviceType.UNKNOWN
    
    def _parse_tags(self, tags_str: str) -> Dict[str, Any]:
        """Parse tags string to dictionary"""
        if not tags_str:
            return {}
        
        try:
            # Handle different tag formats
            if tags_str.startswith('{') and tags_str.endswith('}'):
                return json.loads(tags_str)
            else:
                # Simple key=value format
                tags = {}
                for tag in tags_str.split(','):
                    if '=' in tag:
                        key, value = tag.strip().split('=', 1)
                        tags[key.strip()] = value.strip()
                return tags
        except:
            return {}
    
    async def _create_credentials(self, session, device_id: str, row: Dict[str, Any]):
        """Create device credentials from import data"""
        credentials = []
        
        # SNMP credentials
        if row.get('snmp_community'):
            snmp_cred = DeviceCredential(
                device_id=device_id,
                protocol='snmp',
                version=row.get('snmp_version', '2c'),
                priority=1,
                credentials={
                    'community': row['snmp_community']
                }
            )
            credentials.append(snmp_cred)
        
        # SSH credentials
        if row.get('ssh_username') and row.get('ssh_password'):
            ssh_cred = DeviceCredential(
                device_id=device_id,
                protocol='ssh',
                version='2',
                priority=2,
                credentials={
                    'username': row['ssh_username'],
                    'password': row['ssh_password']
                }
            )
            credentials.append(ssh_cred)
        
        # Add credentials to session
        for cred in credentials:
            session.add(cred)
    
    async def export_template(self, format_type: str = 'csv') -> str:
        """Generate import template"""
        if format_type == 'csv':
            return self._generate_csv_template()
        elif format_type == 'excel':
            return self._generate_excel_template()
        elif format_type == 'json':
            return self._generate_json_template()
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def _generate_csv_template(self) -> str:
        """Generate CSV template"""
        output = StringIO()
        writer = csv.writer(output)
        
        # Header row
        header = self.required_fields + self.optional_fields
        writer.writerow(header)
        
        # Example row
        example_row = [
            'core-switch-01',  # hostname
            '192.168.1.1',     # ip_address
            '2960',            # device_type
            'WS-C2960-24TC-L', # model
            'ABC123456789',    # serial_number
            'Data Center',     # location
            '60',              # poll_interval
            'false',           # gentle_mode
            'true',            # monitor_poe
            'false',           # monitor_stack
            'false',           # monitor_supervisor
            'public',          # snmp_community
            '2c',              # snmp_version
            'admin',           # ssh_username
            'password123',     # ssh_password
            'environment=prod,rack=A1'  # tags
        ]
        writer.writerow(example_row)
        
        return output.getvalue()
    
    def _generate_excel_template(self) -> str:
        """Generate Excel template (returns base64 encoded content)"""
        import base64
        
        # Create DataFrame
        header = self.required_fields + self.optional_fields
        example_row = [
            'core-switch-01', '192.168.1.1', '2960', 'WS-C2960-24TC-L',
            'ABC123456789', 'Data Center', '60', 'false', 'true',
            'false', 'false', 'public', '2c', 'admin', 'password123',
            'environment=prod,rack=A1'
        ]
        
        df = pd.DataFrame([example_row], columns=header)
        
        # Save to bytes
        output = BytesIO()
        df.to_excel(output, index=False)
        output.seek(0)
        
        return base64.b64encode(output.getvalue()).decode()
    
    def _generate_json_template(self) -> str:
        """Generate JSON template"""
        template = {
            "devices": [
                {
                    "hostname": "core-switch-01",
                    "ip_address": "192.168.1.1",
                    "device_type": "2960",
                    "model": "WS-C2960-24TC-L",
                    "serial_number": "ABC123456789",
                    "location": "Data Center",
                    "poll_interval": 60,
                    "gentle_mode": False,
                    "monitor_poe": True,
                    "monitor_stack": False,
                    "monitor_supervisor": False,
                    "snmp_community": "public",
                    "snmp_version": "2c",
                    "ssh_username": "admin",
                    "ssh_password": "password123",
                    "tags": {
                        "environment": "prod",
                        "rack": "A1"
                    }
                }
            ]
        }
        
        return json.dumps(template, indent=2)

# Global import service instance
import_service = BulkImportService()
