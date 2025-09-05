"""
CHM Devices API
Device management and monitoring endpoints
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel
from typing import List, Optional
import logging
from datetime import datetime

from core.database import get_db
from models.device import Device as DeviceModel, DeviceStatus, DeviceType, DeviceProtocol
from services.device_operations import device_operations_service
from services.network_discovery_service import network_discovery_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Pydantic models
class DeviceCreate(BaseModel):
    name: str
    ip_address: str
    device_type: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    ip_address: Optional[str] = None
    device_type: Optional[str] = None
    vendor: Optional[str] = None
    model: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None

class Device(BaseModel):
    id: int
    name: str
    ip_address: str
    device_type: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    location: Optional[str] = None
    description: Optional[str] = None
    status: str
    last_seen: Optional[str] = None

# Device endpoints
@router.get("/", response_model=List[Device])
async def list_devices(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    device_type: Optional[str] = None,
    vendor: Optional[str] = None,
    status: Optional[str] = None,
    db = Depends(get_db)
):
    """List devices with filtering and pagination"""
    logger.info(f"Device list request: skip={skip}, limit={limit}")
    
    try:
        # Build query with filters
        query = db.query(DeviceModel)
        
        if device_type:
            query = query.filter(DeviceModel.device_type == device_type)
        if vendor:
            query = query.filter(DeviceModel.vendor == vendor)
        if status:
            query = query.filter(DeviceModel.status == status)
        
        # Apply pagination
        devices = query.offset(skip).limit(limit).all()
        
        # Convert to response models
        result = []
        for device in devices:
            result.append(Device(
                id=device.id,
                name=device.name,
                ip_address=device.ip_address,
                device_type=device.device_type.value if device.device_type else "unknown",
                vendor=device.vendor,
                model=device.model,
                location=device.location,
                description=device.description,
                status=device.status.value if device.status else "unknown",
                last_seen=device.last_seen.isoformat() if device.last_seen else None
            ))
        
        logger.info(f"Returning {len(result)} devices")
        return result
        
    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve devices")

@router.post("/", response_model=Device)
async def create_device(device_data: DeviceCreate, db = Depends(get_db)):
    """Create a new device"""
    logger.info(f"Device creation request: {device_data.name}")
    
    try:
        # Check for duplicate IP addresses
        existing_device = db.query(DeviceModel).filter(
            DeviceModel.ip_address == device_data.ip_address
        ).first()
        
        if existing_device:
            raise HTTPException(
                status_code=400, 
                detail=f"Device with IP address {device_data.ip_address} already exists"
            )
        
        # Create new device
        new_device = DeviceModel(
            name=device_data.name,
            ip_address=device_data.ip_address,
            device_type=DeviceType(device_data.device_type) if device_data.device_type else DeviceType.ROUTER,
            vendor=device_data.vendor,
            model=device_data.model,
            location=device_data.location,
            description=device_data.description,
            status=DeviceStatus.UNKNOWN,
            protocol=DeviceProtocol.SNMP,  # Default protocol
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        
        logger.info(f"Created device {new_device.id}: {new_device.name}")
        
        return Device(
            id=new_device.id,
            name=new_device.name,
            ip_address=new_device.ip_address,
            device_type=new_device.device_type.value,
            vendor=new_device.vendor,
            model=new_device.model,
            location=new_device.location,
            description=new_device.description,
            status=new_device.status.value,
            last_seen=new_device.last_seen.isoformat() if new_device.last_seen else None
        )
        
    except ValueError as e:
        logger.error(f"Invalid device data: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid device data: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to create device: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create device")

@router.get("/{device_id}", response_model=Device)
async def get_device(device_id: int, db = Depends(get_db)):
    """Get device details"""
    logger.info(f"Device details request: {device_id}")
    
    try:
        device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        return Device(
            id=device.id,
            name=device.name,
            ip_address=device.ip_address,
            device_type=device.device_type.value if device.device_type else "unknown",
            vendor=device.vendor,
            model=device.model,
            location=device.location,
            description=device.description,
            status=device.status.value if device.status else "unknown",
            last_seen=device.last_seen.isoformat() if device.last_seen else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve device")

@router.put("/{device_id}", response_model=Device)
async def update_device(device_id: int, device_data: DeviceUpdate, db = Depends(get_db)):
    """Update device"""
    logger.info(f"Device update request: {device_id}")
    
    try:
        device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Update fields if provided
        if device_data.name is not None:
            device.name = device_data.name
        if device_data.ip_address is not None:
            # Check for duplicate IP if changing
            if device_data.ip_address != device.ip_address:
                existing = db.query(DeviceModel).filter(
                    DeviceModel.ip_address == device_data.ip_address,
                    DeviceModel.id != device_id
                ).first()
                if existing:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Device with IP address {device_data.ip_address} already exists"
                    )
            device.ip_address = device_data.ip_address
        if device_data.device_type is not None:
            device.device_type = DeviceType(device_data.device_type)
        if device_data.vendor is not None:
            device.vendor = device_data.vendor
        if device_data.model is not None:
            device.model = device_data.model
        if device_data.location is not None:
            device.location = device_data.location
        if device_data.description is not None:
            device.description = device_data.description
        
        device.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(device)
        
        logger.info(f"Updated device {device_id}")
        
        return Device(
            id=device.id,
            name=device.name,
            ip_address=device.ip_address,
            device_type=device.device_type.value if device.device_type else "unknown",
            vendor=device.vendor,
            model=device.model,
            location=device.location,
            description=device.description,
            status=device.status.value if device.status else "unknown",
            last_seen=device.last_seen.isoformat() if device.last_seen else None
        )
        
    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Invalid device data: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid device data: {str(e)}")
    except Exception as e:
        logger.error(f"Failed to update device {device_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to update device")

@router.delete("/{device_id}")
async def delete_device(device_id: int, db = Depends(get_db)):
    """Delete device"""
    logger.info(f"Device deletion request: {device_id}")
    
    try:
        device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # TODO: Stop monitoring for this device
        # This would integrate with the monitoring service to stop polling
        
        # Delete the device
        db.delete(device)
        db.commit()
        
        logger.info(f"Deleted device {device_id}: {device.name}")
        
        return {"message": "Device deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete device {device_id}: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete device")

@router.post("/{device_id}/poll")
async def poll_device(device_id: int, db = Depends(get_db)):
    """Trigger immediate device polling"""
    logger.info(f"Device poll request: {device_id}")
    
    try:
        # Validate device exists
        device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Trigger device polling using the device operations service
        result = await device_operations_service.get_device_status(device_id)
        
        if result.success:
            return {
                "message": "Device polling completed successfully",
                "device_id": device_id,
                "status": result.device_status.value if result.device_status else "unknown",
                "response_time_ms": result.response_time_ms,
                "timestamp": result.timestamp.isoformat() if result.timestamp else None
            }
        else:
            return {
                "message": "Device polling completed with errors",
                "device_id": device_id,
                "error": result.error_message,
                "fallback_data": result.fallback_data,
                "timestamp": result.timestamp.isoformat() if result.timestamp else None
            }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to poll device {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to poll device")

@router.get("/{device_id}/status")
async def get_device_status(device_id: int, db = Depends(get_db)):
    """Get device status and health"""
    logger.info(f"Device status request: {device_id}")
    
    try:
        # Get device from database
        device = db.query(DeviceModel).filter(DeviceModel.id == device_id).first()
        
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get real-time status using device operations service
        result = await device_operations_service.get_device_status(device_id)
        
        # Calculate health score based on various factors
        health_score = 0.0
        if result.success and result.device_status:
            if result.device_status.value == "online":
                health_score = 100.0
            elif result.device_status.value == "degraded":
                health_score = 60.0
            elif result.device_status.value == "offline":
                health_score = 0.0
            else:
                health_score = 50.0
        
        return {
            "device_id": device_id,
            "status": result.device_status.value if result.device_status else "unknown",
            "last_poll": result.timestamp.isoformat() if result.timestamp else None,
            "response_time_ms": result.response_time_ms,
            "health_score": health_score,
            "success": result.success,
            "error_message": result.error_message if not result.success else None,
            "fallback_data": result.fallback_data if not result.success else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device status for {device_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to get device status")

__all__ = ["router"]
