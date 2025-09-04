"""
Device management API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, delete
from sqlalchemy.orm import selectinload
import uuid
import logging

from backend.database.models import Device, DeviceMetric, NetworkInterface, Alert
from backend.database.base import get_db
from backend.services.validation_service import ValidationService, ValidationError
from backend.api.dependencies.auth import (
    get_current_user,
    require_device_read,
    require_device_write,
    require_device_delete,
    standard_rate_limit
)
from backend.database.user_models import User
from backend.common.security import SecureCredentialStore

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/devices", tags=["devices"])

# Pydantic models for request/response
from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime

class DeviceCreate(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=255)
    ip_address: str
    device_type: str
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    snmp_community: Optional[str] = None  # Will be encrypted
    snmp_version: Optional[str] = "2c"
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None  # Will be encrypted
    discovery_protocol: Optional[str] = "snmp"
    device_group: Optional[str] = None
    
    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            return ValidationService.validate_ip_address(v)
        except ValidationError as e:
            raise ValueError(str(e))
    
    @validator('device_type')
    def validate_type(cls, v):
        try:
            return ValidationService.validate_device_type(v)
        except ValidationError as e:
            raise ValueError(str(e))
    
    @validator('hostname')
    def validate_hostname(cls, v):
        try:
            return ValidationService.validate_hostname(v)
        except ValidationError as e:
            raise ValueError(str(e))

class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    location: Optional[str] = None
    department: Optional[str] = None
    is_active: Optional[bool] = None
    device_group: Optional[str] = None
    notes: Optional[str] = None

class DeviceResponse(BaseModel):
    id: str
    hostname: str
    ip_address: str
    device_type: str
    current_state: str
    manufacturer: Optional[str]
    model: Optional[str]
    location: Optional[str]
    department: Optional[str]
    is_active: bool
    last_poll_time: Optional[datetime]
    discovery_status: str
    created_at: datetime
    updated_at: Optional[datetime]
    interface_count: Optional[int] = 0
    active_alerts: Optional[int] = 0

class DeviceListResponse(BaseModel):
    devices: List[DeviceResponse]
    total: int
    page: int
    per_page: int

@router.post("", response_model=DeviceResponse, dependencies=[Depends(standard_rate_limit)])
async def create_device(
    device_data: DeviceCreate,
    current_user: User = Depends(require_device_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new device
    """
    try:
        # Check if device already exists
        existing = await db.execute(
            select(Device).where(
                or_(
                    Device.ip_address == device_data.ip_address,
                    Device.hostname == device_data.hostname
                )
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Device with this IP or hostname already exists"
            )
        
        # Create device
        device = Device(
            hostname=device_data.hostname,
            ip_address=device_data.ip_address,
            device_type=device_data.device_type,
            manufacturer=device_data.manufacturer,
            model=device_data.model,
            location=device_data.location,
            department=device_data.department,
            discovery_protocol=device_data.discovery_protocol,
            device_group=device_data.device_group,
            ssh_username=device_data.ssh_username,
            current_state="unknown"
        )
        
        db.add(device)
        await db.flush()
        
        # Store encrypted credentials
        if device_data.snmp_community:
            await SecureCredentialStore.store_device_credential(
                db, str(device.id), "snmp_community", device_data.snmp_community
            )
        
        if device_data.ssh_password:
            await SecureCredentialStore.store_device_credential(
                db, str(device.id), "ssh_password", device_data.ssh_password
            )
        
        await db.commit()
        await db.refresh(device)
        
        # Create response
        return DeviceResponse(
            id=str(device.id),
            hostname=device.hostname,
            ip_address=device.ip_address,
            device_type=device.device_type,
            current_state=device.current_state,
            manufacturer=device.manufacturer,
            model=device.model,
            location=device.location,
            department=device.department,
            is_active=device.is_active,
            last_poll_time=device.last_poll_time,
            discovery_status=device.discovery_status,
            created_at=device.created_at,
            updated_at=device.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating device: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create device"
        )

@router.get("", response_model=DeviceListResponse)
async def list_devices(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    device_type: Optional[str] = None,
    state: Optional[str] = None,
    location: Optional[str] = None,
    department: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(require_device_read),
    db: AsyncSession = Depends(get_db)
):
    """
    List devices with filtering and pagination
    """
    try:
        # Validate pagination
        page, per_page = ValidationService.validate_pagination(page, per_page)
        
        # Build query
        query = select(Device)
        
        # Apply filters
        filters = []
        if device_type:
            filters.append(Device.device_type == device_type)
        if state:
            filters.append(Device.current_state == state)
        if location:
            filters.append(Device.location == location)
        if department:
            filters.append(Device.department == department)
        if search:
            search_term = f"%{search}%"
            filters.append(
                or_(
                    Device.hostname.ilike(search_term),
                    Device.ip_address.ilike(search_term),
                    Device.model.ilike(search_term)
                )
            )
        
        if filters:
            query = query.where(and_(*filters))
        
        # Get total count
        count_query = select(func.count()).select_from(Device)
        if filters:
            count_query = count_query.where(and_(*filters))
        total = await db.scalar(count_query)
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db.execute(query)
        devices = result.scalars().all()
        
        # Get additional counts for each device
        device_responses = []
        for device in devices:
            # Count interfaces
            interface_count = await db.scalar(
                select(func.count()).select_from(NetworkInterface)
                .where(NetworkInterface.device_id == device.id)
            )
            
            # Count active alerts
            active_alerts = await db.scalar(
                select(func.count()).select_from(Alert)
                .where(and_(
                    Alert.device_id == device.id,
                    Alert.status == "active"
                ))
            )
            
            device_responses.append(DeviceResponse(
                id=str(device.id),
                hostname=device.hostname,
                ip_address=device.ip_address,
                device_type=device.device_type,
                current_state=device.current_state,
                manufacturer=device.manufacturer,
                model=device.model,
                location=device.location,
                department=device.department,
                is_active=device.is_active,
                last_poll_time=device.last_poll_time,
                discovery_status=device.discovery_status,
                created_at=device.created_at,
                updated_at=device.updated_at,
                interface_count=interface_count,
                active_alerts=active_alerts
            ))
        
        return DeviceListResponse(
            devices=device_responses,
            total=total,
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error listing devices: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list devices"
        )

@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: str = Path(..., description="Device UUID"),
    current_user: User = Depends(require_device_read),
    db: AsyncSession = Depends(get_db)
):
    """
    Get device details by ID
    """
    try:
        # Validate UUID
        try:
            uuid.UUID(device_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid device ID format"
            )
        
        # Get device
        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Get additional counts
        interface_count = await db.scalar(
            select(func.count()).select_from(NetworkInterface)
            .where(NetworkInterface.device_id == device.id)
        )
        
        active_alerts = await db.scalar(
            select(func.count()).select_from(Alert)
            .where(and_(
                Alert.device_id == device.id,
                Alert.status == "active"
            ))
        )
        
        return DeviceResponse(
            id=str(device.id),
            hostname=device.hostname,
            ip_address=device.ip_address,
            device_type=device.device_type,
            current_state=device.current_state,
            manufacturer=device.manufacturer,
            model=device.model,
            location=device.location,
            department=device.department,
            is_active=device.is_active,
            last_poll_time=device.last_poll_time,
            discovery_status=device.discovery_status,
            created_at=device.created_at,
            updated_at=device.updated_at,
            interface_count=interface_count,
            active_alerts=active_alerts
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting device: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get device"
        )

@router.put("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: str,
    device_data: DeviceUpdate,
    current_user: User = Depends(require_device_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Update device information
    """
    try:
        # Get device
        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Update fields
        update_data = device_data.dict(exclude_unset=True)
        for field, value in update_data.items():
            if value is not None:
                # Validate specific fields
                if field == "hostname":
                    value = ValidationService.validate_hostname(value)
                elif field == "device_type":
                    value = ValidationService.validate_device_type(value)
                
                setattr(device, field, value)
        
        device.updated_at = datetime.utcnow()
        
        await db.commit()
        await db.refresh(device)
        
        return DeviceResponse(
            id=str(device.id),
            hostname=device.hostname,
            ip_address=device.ip_address,
            device_type=device.device_type,
            current_state=device.current_state,
            manufacturer=device.manufacturer,
            model=device.model,
            location=device.location,
            department=device.department,
            is_active=device.is_active,
            last_poll_time=device.last_poll_time,
            discovery_status=device.discovery_status,
            created_at=device.created_at,
            updated_at=device.updated_at
        )
        
    except HTTPException:
        raise
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error updating device: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update device"
        )

@router.delete("/{device_id}")
async def delete_device(
    device_id: str,
    current_user: User = Depends(require_device_delete),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a device and all related data
    """
    try:
        # Get device
        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        # Delete related data (cascading should handle most)
        await db.execute(
            delete(DeviceMetric).where(DeviceMetric.device_id == device_id)
        )
        await db.execute(
            delete(NetworkInterface).where(NetworkInterface.device_id == device_id)
        )
        await db.execute(
            delete(Alert).where(Alert.device_id == device_id)
        )
        
        # Delete device
        await db.delete(device)
        await db.commit()
        
        return {"message": "Device deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting device: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete device"
        )

@router.post("/{device_id}/poll")
async def poll_device(
    device_id: str,
    current_user: User = Depends(require_device_write),
    db: AsyncSession = Depends(get_db)
):
    """
    Trigger immediate polling of a device
    """
    try:
        # Get device
        result = await db.execute(
            select(Device).where(Device.id == device_id)
        )
        device = result.scalar_one_or_none()
        
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Device not found"
            )
        
        if not device.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Device is not active"
            )
        
        # TODO: Trigger actual polling through background service
        # For now, just update the poll time
        device.last_poll_time = datetime.utcnow()
        await db.commit()
        
        return {"message": f"Polling triggered for device {device.hostname}"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error polling device: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to poll device"
        )