"""
Device service layer for business logic
"""

from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, update, delete
from sqlalchemy.orm import selectinload
import logging
import uuid

from backend.database.models import Device, DeviceMetric, NetworkInterface, Alert
from backend.services.validation_service import ValidationService, ValidationError
from backend.common.security import SecureCredentialStore, credential_encryption
from backend.common.exceptions import (
    DeviceNotFoundException,
    DeviceAlreadyExistsException,
    InvalidIPAddressException,
    ValidationException
)

logger = logging.getLogger(__name__)

class DeviceService:
    """Service layer for device operations"""
    
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.validator = ValidationService()
    
    async def create_device(
        self,
        device_data: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> Device:
        """
        Create a new device with validation and encryption
        """
        try:
            # Validate input data
            validated_data = await self._validate_device_data(device_data)
            
            # Check for existing device
            existing = await self._check_device_exists(
                validated_data["ip_address"],
                validated_data.get("hostname")
            )
            if existing:
                raise DeviceAlreadyExistsException(
                    f"Device with IP {validated_data['ip_address']} or "
                    f"hostname {validated_data.get('hostname')} already exists"
                )
            
            # Create device entity
            device = Device(
                hostname=validated_data["hostname"],
                ip_address=validated_data["ip_address"],
                device_type=validated_data["device_type"],
                manufacturer=validated_data.get("manufacturer"),
                model=validated_data.get("model"),
                location=validated_data.get("location"),
                department=validated_data.get("department"),
                discovery_protocol=validated_data.get("discovery_protocol", "snmp"),
                device_group=validated_data.get("device_group"),
                ssh_username=validated_data.get("ssh_username"),
                current_state="unknown",
                is_active=True,
                created_at=datetime.utcnow()
            )
            
            # Encrypt and store credentials
            if validated_data.get("snmp_community"):
                device.snmp_community_encrypted = credential_encryption.encrypt_snmp_credential(
                    validated_data["snmp_community"],
                    validated_data.get("snmp_version", "2c")
                )
            
            if validated_data.get("ssh_password"):
                device.ssh_password_encrypted = credential_encryption.encrypt_credential(
                    validated_data["ssh_password"],
                    metadata={"device_id": str(device.id), "type": "ssh"}
                )
            
            if validated_data.get("api_key"):
                device.api_key_encrypted = credential_encryption.encrypt_credential(
                    validated_data["api_key"],
                    metadata={"device_id": str(device.id), "type": "api"}
                )
            
            # Save to database
            self.db.add(device)
            await self.db.commit()
            await self.db.refresh(device)
            
            # Log device creation
            logger.info(f"Device created: {device.hostname} ({device.ip_address}) by user {user_id}")
            
            # Broadcast device creation event via WebSocket
            from backend.api.websocket_manager import ws_manager
            await ws_manager.broadcast_device_update({
                "action": "created",
                "device_id": str(device.id),
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "device_type": device.device_type,
                "state": device.current_state
            })
            
            # Trigger initial discovery/polling
            await self._trigger_device_discovery(device)
            
            return device
            
        except (DeviceAlreadyExistsException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Error creating device: {str(e)}")
            await self.db.rollback()
            raise
    
    async def get_device(self, device_id: str) -> Device:
        """Get device by ID with related data"""
        try:
            # Validate UUID
            try:
                uuid.UUID(device_id)
            except ValueError:
                raise ValidationException("Invalid device ID format")
            
            # Query device with relationships
            result = await self.db.execute(
                select(Device)
                .options(
                    selectinload(Device.interfaces),
                    selectinload(Device.alerts),
                    selectinload(Device.metrics)
                )
                .where(Device.id == device_id)
            )
            device = result.scalar_one_or_none()
            
            if not device:
                raise DeviceNotFoundException(f"Device {device_id} not found")
            
            return device
            
        except (DeviceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Error getting device: {str(e)}")
            raise
    
    async def list_devices(
        self,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        per_page: int = 50,
        sort_by: str = "created_at",
        sort_order: str = "desc"
    ) -> Tuple[List[Device], int]:
        """List devices with filtering, pagination, and sorting"""
        try:
            # Build base query
            query = select(Device)
            
            # Apply filters
            if filters:
                filter_conditions = []
                
                if filters.get("device_type"):
                    filter_conditions.append(Device.device_type == filters["device_type"])
                
                if filters.get("state"):
                    filter_conditions.append(Device.current_state == filters["state"])
                
                if filters.get("location"):
                    filter_conditions.append(Device.location == filters["location"])
                
                if filters.get("department"):
                    filter_conditions.append(Device.department == filters["department"])
                
                if filters.get("is_active") is not None:
                    filter_conditions.append(Device.is_active == filters["is_active"])
                
                if filters.get("search"):
                    search_term = f"%{filters['search']}%"
                    filter_conditions.append(
                        or_(
                            Device.hostname.ilike(search_term),
                            Device.ip_address.ilike(search_term),
                            Device.model.ilike(search_term),
                            Device.serial_number.ilike(search_term)
                        )
                    )
                
                if filter_conditions:
                    query = query.where(and_(*filter_conditions))
            
            # Get total count
            count_query = select(func.count()).select_from(Device)
            if filters and filter_conditions:
                count_query = count_query.where(and_(*filter_conditions))
            total = await self.db.scalar(count_query)
            
            # Apply sorting
            sort_column = getattr(Device, sort_by, Device.created_at)
            if sort_order.lower() == "desc":
                query = query.order_by(sort_column.desc())
            else:
                query = query.order_by(sort_column)
            
            # Apply pagination
            offset = (page - 1) * per_page
            query = query.offset(offset).limit(per_page)
            
            # Execute query
            result = await self.db.execute(query)
            devices = result.scalars().all()
            
            return devices, total
            
        except Exception as e:
            logger.error(f"Error listing devices: {str(e)}")
            raise
    
    async def update_device(
        self,
        device_id: str,
        update_data: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> Device:
        """Update device information"""
        try:
            # Get existing device
            device = await self.get_device(device_id)
            
            # Validate update data
            validated_data = await self._validate_device_update_data(update_data)
            
            # Update fields
            for field, value in validated_data.items():
                if value is not None and hasattr(device, field):
                    # Handle credential updates specially
                    if field == "snmp_community":
                        device.snmp_community_encrypted = credential_encryption.encrypt_snmp_credential(
                            value,
                            validated_data.get("snmp_version", "2c")
                        )
                    elif field == "ssh_password":
                        device.ssh_password_encrypted = credential_encryption.encrypt_credential(
                            value,
                            metadata={"device_id": str(device.id), "type": "ssh"}
                        )
                    elif field == "api_key":
                        device.api_key_encrypted = credential_encryption.encrypt_credential(
                            value,
                            metadata={"device_id": str(device.id), "type": "api"}
                        )
                    else:
                        setattr(device, field, value)
            
            device.updated_at = datetime.utcnow()
            
            await self.db.commit()
            await self.db.refresh(device)
            
            logger.info(f"Device updated: {device.hostname} by user {user_id}")
            
            # Broadcast device update event via WebSocket
            from backend.api.websocket_manager import ws_manager
            await ws_manager.broadcast_device_update({
                "action": "updated",
                "device_id": str(device.id),
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "device_type": device.device_type,
                "state": device.current_state
            })
            
            return device
            
        except (DeviceNotFoundException, ValidationException):
            raise
        except Exception as e:
            logger.error(f"Error updating device: {str(e)}")
            await self.db.rollback()
            raise
    
    async def delete_device(
        self,
        device_id: str,
        user_id: Optional[str] = None,
        cascade: bool = True
    ) -> bool:
        """Delete device and optionally cascade delete related data"""
        try:
            # Get device
            device = await self.get_device(device_id)
            
            if cascade:
                # Delete related data
                await self.db.execute(
                    delete(DeviceMetric).where(DeviceMetric.device_id == device_id)
                )
                await self.db.execute(
                    delete(NetworkInterface).where(NetworkInterface.device_id == device_id)
                )
                await self.db.execute(
                    delete(Alert).where(Alert.device_id == device_id)
                )
            
            # Delete device
            await self.db.delete(device)
            await self.db.commit()
            
            logger.info(f"Device deleted: {device.hostname} by user {user_id}")
            
            return True
            
        except DeviceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Error deleting device: {str(e)}")
            await self.db.rollback()
            raise
    
    async def get_device_metrics(
        self,
        device_id: str,
        metric_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        aggregation: Optional[str] = None
    ) -> List[DeviceMetric]:
        """Get device metrics with optional filtering and aggregation"""
        try:
            # Verify device exists
            await self.get_device(device_id)
            
            # Build query
            query = select(DeviceMetric).where(DeviceMetric.device_id == device_id)
            
            # Apply filters
            filters = []
            if metric_type:
                filters.append(DeviceMetric.metric_type == metric_type)
            if start_time:
                filters.append(DeviceMetric.timestamp >= start_time)
            if end_time:
                filters.append(DeviceMetric.timestamp <= end_time)
            
            if filters:
                query = query.where(and_(*filters))
            
            # Apply aggregation if requested
            if aggregation:
                # This would need more complex query building for aggregation
                # For now, just order by timestamp
                query = query.order_by(DeviceMetric.timestamp.desc())
            else:
                query = query.order_by(DeviceMetric.timestamp.desc())
            
            # Execute query
            result = await self.db.execute(query)
            metrics = result.scalars().all()
            
            return metrics
            
        except DeviceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Error getting device metrics: {str(e)}")
            raise
    
    async def get_device_status(self, device_id: str) -> Dict[str, Any]:
        """Get comprehensive device status"""
        try:
            device = await self.get_device(device_id)
            
            # Get latest metrics
            latest_metrics = await self.db.execute(
                select(DeviceMetric)
                .where(DeviceMetric.device_id == device_id)
                .order_by(DeviceMetric.timestamp.desc())
                .limit(10)
            )
            
            # Get active alerts count
            active_alerts_count = await self.db.scalar(
                select(func.count())
                .select_from(Alert)
                .where(and_(
                    Alert.device_id == device_id,
                    Alert.status == "active"
                ))
            )
            
            # Get interface count
            interface_count = await self.db.scalar(
                select(func.count())
                .select_from(NetworkInterface)
                .where(NetworkInterface.device_id == device_id)
            )
            
            # Build status response
            status = {
                "device_id": str(device.id),
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "current_state": device.current_state,
                "is_active": device.is_active,
                "last_poll_time": device.last_poll_time,
                "discovery_status": device.discovery_status,
                "consecutive_failures": device.consecutive_failures,
                "active_alerts": active_alerts_count,
                "interface_count": interface_count,
                "latest_metrics": [
                    {
                        "type": m.metric_type,
                        "value": m.value,
                        "unit": m.unit,
                        "timestamp": m.timestamp
                    }
                    for m in latest_metrics.scalars()
                ],
                "health_score": await self._calculate_health_score(device)
            }
            
            return status
            
        except DeviceNotFoundException:
            raise
        except Exception as e:
            logger.error(f"Error getting device status: {str(e)}")
            raise
    
    async def _validate_device_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate device creation data"""
        validated = {}
        
        # Required fields
        validated["hostname"] = self.validator.validate_hostname(data["hostname"])
        validated["ip_address"] = self.validator.validate_ip_address(data["ip_address"])
        validated["device_type"] = self.validator.validate_device_type(data["device_type"])
        
        # Optional fields
        if data.get("manufacturer"):
            validated["manufacturer"] = self.validator.sanitize_string(data["manufacturer"], 100)
        
        if data.get("model"):
            validated["model"] = self.validator.sanitize_string(data["model"], 100)
        
        if data.get("location"):
            validated["location"] = self.validator.sanitize_string(data["location"], 255)
        
        if data.get("department"):
            validated["department"] = self.validator.sanitize_string(data["department"], 100)
        
        if data.get("snmp_community"):
            validated["snmp_community"] = self.validator.validate_snmp_community(data["snmp_community"])
        
        if data.get("snmp_version"):
            validated["snmp_version"] = self.validator.validate_snmp_version(data["snmp_version"])
        
        # Copy other safe fields
        safe_fields = ["discovery_protocol", "device_group", "ssh_username"]
        for field in safe_fields:
            if field in data:
                validated[field] = data[field]
        
        return validated
    
    async def _validate_device_update_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate device update data"""
        validated = {}
        
        # Validate only provided fields
        if "hostname" in data:
            validated["hostname"] = self.validator.validate_hostname(data["hostname"])
        
        if "device_type" in data:
            validated["device_type"] = self.validator.validate_device_type(data["device_type"])
        
        # Sanitize string fields
        string_fields = ["manufacturer", "model", "location", "department", "notes"]
        for field in string_fields:
            if field in data:
                validated[field] = self.validator.sanitize_string(data[field], 255)
        
        # Copy boolean fields
        if "is_active" in data:
            validated["is_active"] = bool(data["is_active"])
        
        return validated
    
    async def _check_device_exists(
        self,
        ip_address: str,
        hostname: Optional[str] = None
    ) -> Optional[Device]:
        """Check if device already exists"""
        conditions = [Device.ip_address == ip_address]
        if hostname:
            conditions.append(Device.hostname == hostname)
        
        result = await self.db.execute(
            select(Device).where(or_(*conditions))
        )
        return result.scalar_one_or_none()
    
    async def _trigger_device_discovery(self, device: Device):
        """Trigger initial discovery for new device"""
        # This would integrate with the discovery service
        # For now, just log
        logger.info(f"Triggering discovery for device {device.hostname}")
    
    async def _calculate_health_score(self, device: Device) -> float:
        """Calculate device health score based on various factors"""
        score = 100.0
        
        # Deduct for state
        if device.current_state == "down":
            score -= 50
        elif device.current_state == "critical":
            score -= 30
        elif device.current_state == "warning":
            score -= 15
        
        # Deduct for consecutive failures
        if device.consecutive_failures > 0:
            score -= min(device.consecutive_failures * 5, 25)
        
        # Deduct for circuit breaker trips
        if device.circuit_breaker_trips > 0:
            score -= min(device.circuit_breaker_trips * 10, 30)
        
        return max(0, score)