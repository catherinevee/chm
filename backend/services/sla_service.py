"""
SLA Service - Business logic for SLA monitoring
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from sqlalchemy.orm import selectinload

from backend.database.models import SLAMetric, Device, DeviceMetric
from backend.services.notification_service import NotificationService
from backend.common.exceptions import AppException
import logging

logger = logging.getLogger(__name__)

class SLAService:
    """Service for managing SLA metrics and compliance"""
    
    @staticmethod
    async def create_sla_metric(
        db: AsyncSession,
        sla_data: Dict[str, Any]
    ) -> SLAMetric:
        """Create a new SLA metric"""
        try:
            # Validate device exists
            device_id = sla_data.get('device_id')
            if device_id:
                device = await db.get(Device, device_id)
                if not device:
                    raise AppException(
                        status_code=404,
                        detail=f"Device {device_id} not found"
                    )
            
            # Create SLA metric
            sla_metric = SLAMetric(
                device_id=device_id,
                metric_name=sla_data['metric_name'],
                target_value=sla_data['target_value'],
                current_value=sla_data.get('current_value', 0),
                compliance_percentage=0,
                measurement_period=sla_data.get('measurement_period', 'daily'),
                threshold_type=sla_data.get('threshold_type', 'min'),
                is_compliant=True,
                metadata=sla_data.get('metadata', {}),
                created_at=datetime.utcnow()
            )
            
            db.add(sla_metric)
            await db.commit()
            await db.refresh(sla_metric)
            
            # Calculate initial compliance
            await SLAService._calculate_compliance(db, sla_metric)
            
            return sla_metric
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating SLA metric: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to create SLA metric: {str(e)}"
            )
    
    @staticmethod
    async def get_device_sla_metrics(
        db: AsyncSession,
        device_id: UUID
    ) -> List[SLAMetric]:
        """Get SLA metrics for a device"""
        try:
            query = select(SLAMetric).where(
                SLAMetric.device_id == device_id
            ).order_by(SLAMetric.created_at.desc())
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Error getting device SLA metrics: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get device SLA metrics: {str(e)}"
            )
    
    @staticmethod
    async def generate_sla_report(
        db: AsyncSession,
        device_id: Optional[UUID] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Generate SLA compliance report"""
        try:
            if not start_date:
                start_date = datetime.utcnow() - timedelta(days=30)
            if not end_date:
                end_date = datetime.utcnow()
            
            # Build query
            query = select(SLAMetric).where(
                and_(
                    SLAMetric.created_at >= start_date,
                    SLAMetric.created_at <= end_date
                )
            )
            
            if device_id:
                query = query.where(SLAMetric.device_id == device_id)
            
            result = await db.execute(query)
            sla_metrics = result.scalars().all()
            
            # Calculate report statistics
            total_metrics = len(sla_metrics)
            compliant_metrics = sum(1 for m in sla_metrics if m.is_compliant)
            
            report = {
                'period': {
                    'start': start_date.isoformat(),
                    'end': end_date.isoformat()
                },
                'summary': {
                    'total_metrics': total_metrics,
                    'compliant_metrics': compliant_metrics,
                    'non_compliant_metrics': total_metrics - compliant_metrics,
                    'compliance_percentage': (
                        (compliant_metrics / total_metrics * 100) 
                        if total_metrics > 0 else 100
                    )
                },
                'metrics': []
            }
            
            # Group metrics by name
            metric_groups = {}
            for metric in sla_metrics:
                if metric.metric_name not in metric_groups:
                    metric_groups[metric.metric_name] = {
                        'name': metric.metric_name,
                        'measurements': [],
                        'average_compliance': 0,
                        'min_value': float('inf'),
                        'max_value': float('-inf')
                    }
                
                group = metric_groups[metric.metric_name]
                group['measurements'].append(metric.compliance_percentage)
                group['min_value'] = min(group['min_value'], metric.current_value)
                group['max_value'] = max(group['max_value'], metric.current_value)
            
            # Calculate averages
            for group in metric_groups.values():
                if group['measurements']:
                    group['average_compliance'] = sum(group['measurements']) / len(group['measurements'])
                    report['metrics'].append(group)
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating SLA report: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to generate SLA report: {str(e)}"
            )
    
    @staticmethod
    async def update_sla_metric(
        db: AsyncSession,
        sla_id: UUID,
        update_data: Dict[str, Any]
    ) -> SLAMetric:
        """Update an SLA metric"""
        try:
            sla_metric = await db.get(SLAMetric, sla_id)
            if not sla_metric:
                raise AppException(
                    status_code=404,
                    detail=f"SLA metric {sla_id} not found"
                )
            
            # Update fields
            for key, value in update_data.items():
                if hasattr(sla_metric, key):
                    setattr(sla_metric, key, value)
            
            sla_metric.updated_at = datetime.utcnow()
            
            # Recalculate compliance
            await SLAService._calculate_compliance(db, sla_metric)
            
            await db.commit()
            await db.refresh(sla_metric)
            
            return sla_metric
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error updating SLA metric: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to update SLA metric: {str(e)}"
            )
    
    @staticmethod
    async def delete_sla_metric(
        db: AsyncSession,
        sla_id: UUID
    ) -> bool:
        """Delete an SLA metric"""
        try:
            sla_metric = await db.get(SLAMetric, sla_id)
            if not sla_metric:
                raise AppException(
                    status_code=404,
                    detail=f"SLA metric {sla_id} not found"
                )
            
            await db.delete(sla_metric)
            await db.commit()
            
            return True
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error deleting SLA metric: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to delete SLA metric: {str(e)}"
            )
    
    @staticmethod
    async def check_sla_compliance(
        db: AsyncSession,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Check SLA compliance for all metrics"""
        try:
            # Get all active SLA metrics
            query = select(SLAMetric).options(
                selectinload(SLAMetric.device)
            )
            
            result = await db.execute(query)
            sla_metrics = result.scalars().all()
            
            violations = []
            notification_service = NotificationService()
            
            for sla_metric in sla_metrics:
                # Calculate current compliance
                compliance = await SLAService._calculate_compliance(db, sla_metric)
                
                # Check if violated
                if not sla_metric.is_compliant:
                    violation = {
                        'sla_id': str(sla_metric.id),
                        'device_id': str(sla_metric.device_id) if sla_metric.device_id else None,
                        'device_name': sla_metric.device.hostname if sla_metric.device else 'System',
                        'metric_name': sla_metric.metric_name,
                        'target_value': sla_metric.target_value,
                        'current_value': sla_metric.current_value,
                        'compliance_percentage': sla_metric.compliance_percentage
                    }
                    violations.append(violation)
                    
                    # Send notification for new violations
                    if sla_metric.device:
                        # Get all users to notify
                        users_query = select(User).where(User.is_active == True)
                        users_result = await db.execute(users_query)
                        users = users_result.scalars().all()
                        
                        for user in users:
                            await notification_service.create_notification(
                                db,
                                user_id=user.id,
                                title=f"SLA Violation: {sla_metric.metric_name}",
                                message=f"SLA violation on {sla_metric.device.hostname}: {sla_metric.metric_name} is {sla_metric.current_value} (target: {sla_metric.target_value})",
                                notification_type='sla_violation',
                                priority='high',
                                metadata={
                                    'sla_id': str(sla_metric.id),
                                    'device_id': str(sla_metric.device_id)
                                }
                            )
            
            await db.commit()
            
            return violations
            
        except Exception as e:
            logger.error(f"Error checking SLA compliance: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to check SLA compliance: {str(e)}"
            )
    
    @staticmethod
    async def _calculate_compliance(
        db: AsyncSession,
        sla_metric: SLAMetric
    ) -> float:
        """Calculate SLA compliance percentage"""
        try:
            if not sla_metric.device_id:
                return 100.0  # System-wide SLAs default to compliant
            
            # Determine measurement period
            if sla_metric.measurement_period == 'hourly':
                since = datetime.utcnow() - timedelta(hours=1)
            elif sla_metric.measurement_period == 'daily':
                since = datetime.utcnow() - timedelta(days=1)
            elif sla_metric.measurement_period == 'weekly':
                since = datetime.utcnow() - timedelta(weeks=1)
            elif sla_metric.measurement_period == 'monthly':
                since = datetime.utcnow() - timedelta(days=30)
            else:
                since = datetime.utcnow() - timedelta(days=1)
            
            # Get metrics for the period
            metrics_query = select(DeviceMetric).where(
                and_(
                    DeviceMetric.device_id == sla_metric.device_id,
                    DeviceMetric.metric_name == sla_metric.metric_name,
                    DeviceMetric.timestamp >= since
                )
            )
            
            metrics_result = await db.execute(metrics_query)
            metrics = metrics_result.scalars().all()
            
            if not metrics:
                sla_metric.compliance_percentage = 100.0
                sla_metric.is_compliant = True
                return 100.0
            
            # Calculate compliance based on threshold type
            if sla_metric.threshold_type == 'min':
                # Value should be >= target
                compliant_count = sum(1 for m in metrics if m.metric_value >= sla_metric.target_value)
            elif sla_metric.threshold_type == 'max':
                # Value should be <= target
                compliant_count = sum(1 for m in metrics if m.metric_value <= sla_metric.target_value)
            else:
                # Exact match
                compliant_count = sum(1 for m in metrics if m.metric_value == sla_metric.target_value)
            
            # Calculate current value (average)
            sla_metric.current_value = sum(m.metric_value for m in metrics) / len(metrics)
            
            # Calculate compliance percentage
            compliance = (compliant_count / len(metrics)) * 100 if metrics else 100
            sla_metric.compliance_percentage = compliance
            sla_metric.is_compliant = compliance >= 95  # 95% compliance threshold
            
            return compliance
            
        except Exception as e:
            logger.error(f"Error calculating compliance: {str(e)}")
            return 0

# Import User model for notifications
from backend.database.user_models import User