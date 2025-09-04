"""
Import and export functionality API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Path
from fastapi.responses import StreamingResponse
from typing import List, Optional, Dict, Any
from datetime import datetime
import csv
import json
import io
import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from pydantic import BaseModel, Field

from backend.database.models import Device, Alert, DeviceMetric, NetworkInterface
from backend.database.base import get_db
from backend.services.validation_service import ValidationService, ValidationError
from backend.api.dependencies.auth import (
    get_current_user,
    standard_rate_limit
)
from backend.database.user_models import User
from backend.common.security import credential_encryption

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["import_export"])

# Database session dependency is imported from backend.database.base

class ImportResult(BaseModel):
    total_records: int
    successful: int
    failed: int
    errors: List[Dict[str, Any]]
    created_devices: List[str]

class ExportRequest(BaseModel):
    export_type: str = Field(..., pattern="^(devices|alerts|metrics|full)$")
    format: str = Field(default="csv", pattern="^(csv|json)$")
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    device_ids: Optional[List[str]] = None

@router.post("/import/csv", response_model=ImportResult, dependencies=[Depends(standard_rate_limit)])
async def import_devices_csv(
    file: UploadFile = File(...),
    update_existing: bool = Form(default=False),
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Import devices from CSV file
    """
    try:
        # Validate file type
        if not file.filename.endswith('.csv'):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="File must be CSV format"
            )
        
        # Read CSV content
        content = await file.read()
        csv_file = io.StringIO(content.decode('utf-8'))
        csv_reader = csv.DictReader(csv_file)
        
        # Process records
        total_records = 0
        successful = 0
        failed = 0
        errors = []
        created_devices = []
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 to account for header
            total_records += 1
            
            try:
                # Validate required fields
                if not row.get('hostname') or not row.get('ip_address'):
                    raise ValidationError("Missing required fields: hostname or ip_address")
                
                # Validate data
                hostname = ValidationService.validate_hostname(row['hostname'])
                ip_address = ValidationService.validate_ip_address(row['ip_address'])
                device_type = ValidationService.validate_device_type(
                    row.get('device_type', 'other')
                )
                
                # Check if device exists
                existing = await db_session.execute(
                    select(Device).where(
                        and_(
                            Device.ip_address == ip_address
                        )
                    )
                )
                existing_device = existing.scalar_one_or_none()
                
                if existing_device:
                    if update_existing:
                        # Update existing device
                        existing_device.hostname = hostname
                        existing_device.device_type = device_type
                        existing_device.manufacturer = row.get('manufacturer')
                        existing_device.model = row.get('model')
                        existing_device.location = row.get('location')
                        existing_device.department = row.get('department')
                        existing_device.updated_at = datetime.utcnow()
                        
                        # Update credentials if provided
                        if row.get('snmp_community'):
                            existing_device.snmp_community_encrypted = (
                                credential_encryption.encrypt_snmp_credential(
                                    row['snmp_community'],
                                    row.get('snmp_version', '2c')
                                )
                            )
                        
                        successful += 1
                        logger.info(f"Updated device: {hostname}")
                    else:
                        failed += 1
                        errors.append({
                            "row": row_num,
                            "hostname": hostname,
                            "error": "Device already exists"
                        })
                else:
                    # Create new device
                    new_device = Device(
                        hostname=hostname,
                        ip_address=ip_address,
                        device_type=device_type,
                        manufacturer=row.get('manufacturer'),
                        model=row.get('model'),
                        location=row.get('location'),
                        department=row.get('department'),
                        device_group=row.get('device_group'),
                        discovery_protocol=row.get('discovery_protocol', 'snmp'),
                        is_active=True,
                        current_state="unknown",
                        created_at=datetime.utcnow()
                    )
                    
                    # Encrypt and store credentials if provided
                    if row.get('snmp_community'):
                        new_device.snmp_community_encrypted = (
                            credential_encryption.encrypt_snmp_credential(
                                row['snmp_community'],
                                row.get('snmp_version', '2c')
                            )
                        )
                    
                    if row.get('ssh_username'):
                        new_device.ssh_username = row['ssh_username']
                    
                    if row.get('ssh_password'):
                        new_device.ssh_password_encrypted = (
                            credential_encryption.encrypt_credential(
                                row['ssh_password'],
                                metadata={"type": "ssh"}
                            )
                        )
                    
                    db_session.add(new_device)
                    created_devices.append(hostname)
                    successful += 1
                    logger.info(f"Created device: {hostname}")
                    
            except (ValidationError, ValueError) as e:
                failed += 1
                errors.append({
                    "row": row_num,
                    "hostname": row.get('hostname', 'unknown'),
                    "error": str(e)
                })
            except Exception as e:
                failed += 1
                errors.append({
                    "row": row_num,
                    "hostname": row.get('hostname', 'unknown'),
                    "error": f"Unexpected error: {str(e)}"
                })
        
        # Commit all changes
        await db_session.commit()
        
        logger.info(f"Import completed by user {current_user.username}: "
                   f"{successful} successful, {failed} failed")
        
        return ImportResult(
            total_records=total_records,
            successful=successful,
            failed=failed,
            errors=errors,
            created_devices=created_devices
        )
        
    except Exception as e:
        logger.error(f"Error importing CSV: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to import CSV file"
        )

@router.get("/import/template/{format_type}")
async def get_import_template(
    format_type: str = Path(..., pattern="^(csv|json)$"),
    current_user: User = Depends(get_current_user)
):
    """
    Download import template file
    """
    try:
        if format_type == "csv":
            # Create CSV template
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            headers = [
                'hostname', 'ip_address', 'device_type', 'manufacturer', 'model',
                'location', 'department', 'device_group', 'discovery_protocol',
                'snmp_community', 'snmp_version', 'ssh_username', 'ssh_password'
            ]
            writer.writerow(headers)
            
            # Write example rows
            writer.writerow([
                'switch-01', '192.168.1.1', 'switch', 'Cisco', '3560',
                'Data Center', 'IT', 'core-switches', 'snmp',
                'public', '2c', '', ''
            ])
            writer.writerow([
                'router-01', '192.168.1.254', 'router', 'Cisco', 'ISR4331',
                'Data Center', 'IT', 'core-routers', 'snmp',
                'public', '2c', '', ''
            ])
            
            output.seek(0)
            
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode()),
                media_type="text/csv",
                headers={
                    "Content-Disposition": "attachment; filename=device_import_template.csv"
                }
            )
            
        elif format_type == "json":
            # Create JSON template
            template = {
                "devices": [
                    {
                        "hostname": "switch-01",
                        "ip_address": "192.168.1.1",
                        "device_type": "switch",
                        "manufacturer": "Cisco",
                        "model": "3560",
                        "location": "Data Center",
                        "department": "IT",
                        "device_group": "core-switches",
                        "discovery_protocol": "snmp",
                        "snmp_community": "public",
                        "snmp_version": "2c"
                    },
                    {
                        "hostname": "router-01",
                        "ip_address": "192.168.1.254",
                        "device_type": "router",
                        "manufacturer": "Cisco",
                        "model": "ISR4331",
                        "location": "Data Center",
                        "department": "IT",
                        "device_group": "core-routers",
                        "discovery_protocol": "snmp",
                        "snmp_community": "public",
                        "snmp_version": "2c"
                    }
                ]
            }
            
            return StreamingResponse(
                io.BytesIO(json.dumps(template, indent=2).encode()),
                media_type="application/json",
                headers={
                    "Content-Disposition": "attachment; filename=device_import_template.json"
                }
            )
            
    except Exception as e:
        logger.error(f"Error generating template: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate template"
        )

@router.post("/export")
async def export_data(
    export_request: ExportRequest,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Export data in CSV or JSON format
    """
    try:
        data_to_export = []
        
        if export_request.export_type in ["devices", "full"]:
            # Export devices
            device_query = select(Device)
            
            if export_request.device_ids:
                device_query = device_query.where(Device.id.in_(export_request.device_ids))
            
            device_result = await db_session.execute(device_query)
            devices = device_result.scalars().all()
            
            for device in devices:
                device_data = {
                    "id": str(device.id),
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "device_type": device.device_type,
                    "manufacturer": device.manufacturer,
                    "model": device.model,
                    "location": device.location,
                    "department": device.department,
                    "device_group": device.device_group,
                    "discovery_protocol": device.discovery_protocol,
                    "current_state": device.current_state,
                    "is_active": device.is_active,
                    "created_at": device.created_at.isoformat() if device.created_at else None
                }
                
                if export_request.export_type == "devices":
                    data_to_export.append(device_data)
                else:
                    # For full export, include more data
                    device_data["interfaces"] = []
                    device_data["recent_alerts"] = []
                    
                    # Get interfaces
                    interface_result = await db_session.execute(
                        select(NetworkInterface).where(NetworkInterface.device_id == device.id)
                    )
                    interfaces = interface_result.scalars().all()
                    for interface in interfaces:
                        device_data["interfaces"].append({
                            "name": interface.name,
                            "type": interface.interface_type,
                            "status": interface.status,
                            "ip_address": interface.ip_address,
                            "mac_address": interface.mac_address
                        })
                    
                    # Get recent alerts
                    alert_result = await db_session.execute(
                        select(Alert).where(
                            and_(
                                Alert.device_id == device.id,
                                Alert.status == "active"
                            )
                        ).limit(5)
                    )
                    alerts = alert_result.scalars().all()
                    for alert in alerts:
                        device_data["recent_alerts"].append({
                            "type": alert.alert_type,
                            "severity": alert.severity,
                            "message": alert.message,
                            "created_at": alert.created_at.isoformat()
                        })
                    
                    data_to_export.append(device_data)
        
        elif export_request.export_type == "alerts":
            # Export alerts
            alert_query = select(Alert)
            
            if export_request.start_date:
                alert_query = alert_query.where(Alert.created_at >= export_request.start_date)
            if export_request.end_date:
                alert_query = alert_query.where(Alert.created_at <= export_request.end_date)
            
            alert_result = await db_session.execute(alert_query)
            alerts = alert_result.scalars().all()
            
            for alert in alerts:
                data_to_export.append({
                    "id": str(alert.id),
                    "device_id": str(alert.device_id),
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "status": alert.status,
                    "message": alert.message,
                    "created_at": alert.created_at.isoformat(),
                    "acknowledged_by": alert.acknowledged_by,
                    "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
                })
        
        elif export_request.export_type == "metrics":
            # Export metrics
            metric_query = select(DeviceMetric)
            
            if export_request.start_date:
                metric_query = metric_query.where(DeviceMetric.timestamp >= export_request.start_date)
            if export_request.end_date:
                metric_query = metric_query.where(DeviceMetric.timestamp <= export_request.end_date)
            if export_request.device_ids:
                metric_query = metric_query.where(DeviceMetric.device_id.in_(export_request.device_ids))
            
            metric_result = await db_session.execute(metric_query.limit(10000))  # Limit for performance
            metrics = metric_result.scalars().all()
            
            for metric in metrics:
                data_to_export.append({
                    "device_id": str(metric.device_id),
                    "metric_type": metric.metric_type,
                    "value": metric.value,
                    "unit": metric.unit,
                    "timestamp": metric.timestamp.isoformat()
                })
        
        # Format output
        if export_request.format == "csv":
            if not data_to_export:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="No data to export"
                )
            
            # Create CSV
            output = io.StringIO()
            if data_to_export:
                writer = csv.DictWriter(output, fieldnames=data_to_export[0].keys())
                writer.writeheader()
                writer.writerows(data_to_export)
            
            output.seek(0)
            
            return StreamingResponse(
                io.BytesIO(output.getvalue().encode()),
                media_type="text/csv",
                headers={
                    "Content-Disposition": f"attachment; filename=export_{export_request.export_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
                }
            )
            
        else:  # JSON format
            return StreamingResponse(
                io.BytesIO(json.dumps(data_to_export, indent=2).encode()),
                media_type="application/json",
                headers={
                    "Content-Disposition": f"attachment; filename=export_{export_request.export_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting data: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to export data"
        )