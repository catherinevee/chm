"""
Metrics Service - Business logic for performance metrics
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import selectinload

from backend.database.models import DeviceMetric, Device, Alert
from backend.database.base import get_session
# from backend.services.validation_service import ValidationService
from backend.common.exceptions import AppException
import logging

logger = logging.getLogger(__name__)

class MetricsService:
    """Service for managing device metrics and performance data"""
    
    @staticmethod
    async def create_metric(
        db: AsyncSession,
        device_id: UUID,
        metric_data: Dict[str, Any]
    ) -> DeviceMetric:
        """Create a new metric entry"""
        try:
            # Validate device exists
            device = await db.get(Device, device_id)
            if not device:
                raise AppException(
                    status_code=404,
                    detail=f"Device {device_id} not found"
                )
            
            # Validate metric data
            validation = ValidationService()
            if not validation.validate_metric_data(metric_data):
                raise AppException(
                    status_code=400,
                    detail="Invalid metric data format"
                )
            
            # Create metric
            metric = DeviceMetric(
                device_id=device_id,
                metric_type=metric_data.get('name', 'performance'),  # Use name as type
                value=metric_data['value'],
                unit=metric_data.get('unit'),
                timestamp=metric_data.get('timestamp', datetime.utcnow())
            )
            
            db.add(metric)
            await db.commit()
            await db.refresh(metric)
            
            # Check thresholds and create alerts if needed
            await MetricsService._check_thresholds(db, device, metric)
            
            # Broadcast metric update via WebSocket
            from backend.api.websocket_manager import ws_manager
            await ws_manager.broadcast_metric_update({
                "device_id": str(device_id),
                "device_name": device.hostname,
                "metric_type": metric.metric_type,
                "value": metric.value,
                "unit": metric.unit,
                "timestamp": metric.timestamp.isoformat()
            })
            
            return metric
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating metric: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to create metric: {str(e)}"
            )
    
    @staticmethod
    async def get_performance_summary(
        db: AsyncSession,
        device_id: Optional[UUID] = None,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get performance summary for device(s)"""
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            
            query = select(
                DeviceMetric.metric_type,
                func.avg(DeviceMetric.value).label('avg_value'),
                func.min(DeviceMetric.value).label('min_value'),
                func.max(DeviceMetric.value).label('max_value'),
                func.count(DeviceMetric.id).label('sample_count')
            ).where(
                DeviceMetric.timestamp >= since
            ).group_by(DeviceMetric.metric_type)
            
            if device_id:
                query = query.where(DeviceMetric.device_id == device_id)
            
            result = await db.execute(query)
            metrics = result.all()
            
            summary = {
                'period_hours': hours,
                'since': since.isoformat(),
                'metrics': {}
            }
            
            for metric in metrics:
                summary['metrics'][metric.metric_type] = {
                    'average': float(metric.avg_value) if metric.avg_value else 0,
                    'minimum': float(metric.min_value) if metric.min_value else 0,
                    'maximum': float(metric.max_value) if metric.max_value else 0,
                    'samples': metric.sample_count
                }
            
            # Add availability calculation
            if device_id:
                availability = await MetricsService._calculate_availability(
                    db, device_id, since
                )
                summary['availability'] = availability
            
            return summary
            
        except Exception as e:
            logger.error(f"Error getting performance summary: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get performance summary: {str(e)}"
            )
    
    @staticmethod
    async def get_graph_data(
        db: AsyncSession,
        device_id: UUID,
        metric_name: str,
        hours: int = 24,
        interval_minutes: int = 5
    ) -> List[Dict[str, Any]]:
        """Get time-series data for graphing"""
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            
            query = select(DeviceMetric).where(
                and_(
                    DeviceMetric.device_id == device_id,
                    DeviceMetric.metric_type == metric_name,
                    DeviceMetric.timestamp >= since
                )
            ).order_by(DeviceMetric.timestamp)
            
            result = await db.execute(query)
            metrics = result.scalars().all()
            
            # Group by interval
            graph_data = []
            current_interval = None
            interval_sum = 0
            interval_count = 0
            
            for metric in metrics:
                metric_interval = metric.timestamp.replace(
                    minute=(metric.timestamp.minute // interval_minutes) * interval_minutes,
                    second=0,
                    microsecond=0
                )
                
                if current_interval != metric_interval:
                    if current_interval and interval_count > 0:
                        graph_data.append({
                            'timestamp': current_interval.isoformat(),
                            'value': interval_sum / interval_count
                        })
                    
                    current_interval = metric_interval
                    interval_sum = metric.value
                    interval_count = 1
                else:
                    interval_sum += metric.value
                    interval_count += 1
            
            # Add last interval
            if current_interval and interval_count > 0:
                graph_data.append({
                    'timestamp': current_interval.isoformat(),
                    'value': interval_sum / interval_count
                })
            
            return graph_data
            
        except Exception as e:
            logger.error(f"Error getting graph data: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get graph data: {str(e)}"
            )
    
    @staticmethod
    async def bulk_create_metrics(
        db: AsyncSession,
        metrics_data: List[Dict[str, Any]]
    ) -> List[DeviceMetric]:
        """Create multiple metrics in a single transaction"""
        try:
            metrics = []
            validation = ValidationService()
            
            for metric_data in metrics_data:
                # Validate each metric
                if not validation.validate_metric_data(metric_data):
                    logger.warning(f"Skipping invalid metric: {metric_data}")
                    continue
                
                # Validate device exists
                device = await db.get(Device, metric_data['device_id'])
                if not device:
                    logger.warning(f"Device {metric_data['device_id']} not found")
                    continue
                
                metric = DeviceMetric(
                    device_id=metric_data['device_id'],
                    metric_type=metric_data.get('name', 'performance'),
                    value=metric_data['value'],
                    unit=metric_data.get('unit'),
                    timestamp=metric_data.get('timestamp', datetime.utcnow())
                )
                metrics.append(metric)
                db.add(metric)
            
            await db.commit()
            
            # Check thresholds for all metrics
            for metric in metrics:
                device = await db.get(Device, metric.device_id)
                await MetricsService._check_thresholds(db, device, metric)
            
            return metrics
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error bulk creating metrics: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to bulk create metrics: {str(e)}"
            )
    
    @staticmethod
    async def delete_old_metrics(
        db: AsyncSession,
        days: int = 90
    ) -> int:
        """Delete metrics older than specified days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            query = select(DeviceMetric).where(
                DeviceMetric.timestamp < cutoff_date
            )
            result = await db.execute(query)
            old_metrics = result.scalars().all()
            
            count = len(old_metrics)
            for metric in old_metrics:
                await db.delete(metric)
            
            await db.commit()
            
            logger.info(f"Deleted {count} metrics older than {days} days")
            return count
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error deleting old metrics: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to delete old metrics: {str(e)}"
            )
    
    @staticmethod
    async def _check_thresholds(
        db: AsyncSession,
        device: Device,
        metric: DeviceMetric
    ) -> None:
        """Check if metric exceeds thresholds and create alerts"""
        try:
            # Get thresholds from device configuration
            if hasattr(device, 'configuration') and device.configuration:
                thresholds = device.configuration.get('thresholds', {})
                metric_threshold = thresholds.get(metric.metric_type, {})
            else:
                metric_threshold = {}
            
            if not metric_threshold:
                return
            
            # Check critical threshold
            if 'critical' in metric_threshold:
                if metric.value >= metric_threshold['critical']:
                    await MetricsService._create_alert(
                        db, device, metric, 'critical',
                        f"{metric.metric_type} exceeded critical threshold"
                    )
            
            # Check warning threshold
            elif 'warning' in metric_threshold:
                if metric.value >= metric_threshold['warning']:
                    await MetricsService._create_alert(
                        db, device, metric, 'warning',
                        f"{metric.metric_type} exceeded warning threshold"
                    )
            
        except Exception as e:
            logger.error(f"Error checking thresholds: {str(e)}")
    
    @staticmethod
    async def _create_alert(
        db: AsyncSession,
        device: Device,
        metric: DeviceMetric,
        severity: str,
        message: str
    ) -> None:
        """Create an alert for threshold violation"""
        try:
            # Check if similar alert already exists
            existing = await db.execute(
                select(Alert).where(
                    and_(
                        Alert.device_id == device.id,
                        Alert.alert_type == 'threshold',
                        Alert.severity == severity,
                        Alert.status == 'active',
                        Alert.alert_metadata['metric_type'].astext == metric.metric_type
                    )
                )
            )
            
            if existing.scalar():
                return  # Alert already exists
            
            alert = Alert(
                device_id=device.id,
                alert_type='threshold',
                severity=severity,
                message=message,
                status='active',
                alert_metadata={
                    'metric_type': metric.metric_type,
                    'metric_value': metric.value,
                    'metric_unit': metric.unit
                }
            )
            
            db.add(alert)
            await db.commit()
            
        except Exception as e:
            logger.error(f"Error creating alert: {str(e)}")
    
    @staticmethod
    async def _calculate_availability(
        db: AsyncSession,
        device_id: UUID,
        since: datetime
    ) -> float:
        """Calculate device availability percentage"""
        try:
            # Get availability metrics
            query = select(DeviceMetric).where(
                and_(
                    DeviceMetric.device_id == device_id,
                    DeviceMetric.metric_name == 'availability',
                    DeviceMetric.timestamp >= since
                )
            )
            
            result = await db.execute(query)
            metrics = result.scalars().all()
            
            if not metrics:
                return 100.0  # Assume 100% if no data
            
            # Calculate uptime percentage
            total_checks = len(metrics)
            up_checks = sum(1 for m in metrics if m.metric_value == 1)
            
            return (up_checks / total_checks) * 100 if total_checks > 0 else 0
            
        except Exception as e:
            logger.error(f"Error calculating availability: {str(e)}")
            return 0