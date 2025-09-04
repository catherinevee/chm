"""
SLA Monitoring Service
Provides automatic SLA monitoring, threshold violation detection, and alerting
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass
from sqlalchemy import select, and_, or_, func, desc

from backend.storage.database import db
from backend.storage.models import (
    Device, SLAMetrics, PerformanceMetrics, Alert, AlertSeverity,
    DeviceStatus, NotificationType
)
from backend.services.notification_service import notification_service
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

@dataclass
class SLAViolation:
    """SLA violation information"""
    sla_metric: SLAMetrics
    current_value: float
    target_value: float
    violation_type: str  # 'breach', 'warning', 'recovery'
    violation_time: datetime
    severity: AlertSeverity

class SLAMonitoringService:
    """Service for automatic SLA monitoring and alerting"""
    
    def __init__(self):
        self.monitoring_active = False
        self.monitoring_task = None
        self.check_interval = 60  # Check every minute
    
    async def start_monitoring(self):
        """Start automatic SLA monitoring"""
        
        if self.monitoring_active:
            logger.warning("SLA monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("SLA monitoring started")
    
    async def stop_monitoring(self):
        """Stop automatic SLA monitoring"""
        
        self.monitoring_active = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("SLA monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        
        try:
            while self.monitoring_active:
                await self._check_all_slas()
                await asyncio.sleep(self.check_interval)
        
        except asyncio.CancelledError:
            logger.info("SLA monitoring loop cancelled")
        except Exception as e:
            logger.error(f"SLA monitoring loop error: {e}")
            self.monitoring_active = False
    
    async def _check_all_slas(self):
        """Check all SLA metrics for violations"""
        
        try:
            # Get all active SLA metrics
            sla_query = select(SLAMetrics).where(SLAMetrics.is_active == True)
            result = await db.execute(sla_query)
            sla_metrics = result.scalars().all()
            
            violations = []
            
            for sla_metric in sla_metrics:
                try:
                    violation = await self._check_sla_metric(sla_metric)
                    if violation:
                        violations.append(violation)
                except Exception as e:
                    logger.error(f"Failed to check SLA metric {sla_metric.id}: {e}")
            
            # Process violations
            for violation in violations:
                await self._handle_sla_violation(violation)
            
            if violations:
                logger.info(f"Processed {len(violations)} SLA violations")
            
        except Exception as e:
            logger.error(f"Failed to check SLA metrics: {e}")
    
    async def _check_sla_metric(self, sla_metric: SLAMetrics) -> Optional[SLAViolation]:
        """Check a single SLA metric for violations"""
        
        try:
            # Calculate current value based on SLA type
            current_value = await self._calculate_current_sla_value(sla_metric)
            
            if current_value is None:
                # Return fallback SLA violation data when no current value
                fallback_data = FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No SLA current value",
                        details="No current value available for SLA metric check",
                        timestamp=datetime.now().isoformat()
                    )
                )
                
                return create_partial_success_result(
                    data=None,
                    fallback_data=fallback_data,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No SLA current value",
                        details="No current value available for SLA metric check",
                        timestamp=datetime.now().isoformat()
                    ),
                    suggestions=[
                        "No SLA current value",
                        "Check metrics collection",
                        "Verify SLA configuration",
                        "Use fallback data"
                    ]
                )
            
            # Update SLA metric with current value
            sla_metric.current_value = current_value
            sla_metric.last_measurement = datetime.utcnow()
            
            # Determine violation type
            violation_type = None
            severity = AlertSeverity.INFO
            
            # Check for breach (below target)
            if current_value < sla_metric.target_value:
                # Calculate how severe the breach is
                breach_percentage = (sla_metric.target_value - current_value) / sla_metric.target_value * 100
                
                if breach_percentage >= 5.0:  # 5% or more below target
                    violation_type = "breach"
                    severity = AlertSeverity.CRITICAL
                elif breach_percentage >= 1.0:  # 1-5% below target
                    violation_type = "warning"
                    severity = AlertSeverity.WARNING
                
                # Update SLA status
                if violation_type == "breach":
                    sla_metric.sla_status = "breached"
                elif violation_type == "warning":
                    sla_metric.sla_status = "warning"
            else:
                # SLA is being met
                if sla_metric.sla_status in ["breached", "warning"]:
                    violation_type = "recovery"
                    severity = AlertSeverity.INFO
                
                sla_metric.sla_status = "met"
            
            # Update additional metrics
            await self._update_sla_statistics(sla_metric, current_value)
            
            await db.commit()
            
            # Return violation if one occurred
            if violation_type:
                return SLAViolation(
                    sla_metric=sla_metric,
                    current_value=current_value,
                    target_value=sla_metric.target_value,
                    violation_type=violation_type,
                    violation_time=datetime.utcnow(),
                    severity=severity
                )
        
        except Exception as e:
            logger.error(f"Failed to check SLA metric {sla_metric.id}: {e}")
            await db.rollback()
            
            # Return fallback SLA violation data when checking fails
            fallback_data = FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="SLA metric check failed",
                    details=f"Failed to check SLA metric {sla_metric.id}: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to check SLA metric {sla_metric.id}",
                error_code="SLA_METRIC_CHECK_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "SLA metric check failed",
                    "Check database connection",
                    "Verify SLA metric configuration",
                    "Review error logs"
                ]
            )
    
    async def _calculate_current_sla_value(self, sla_metric: SLAMetrics) -> Optional[float]:
        """Calculate current SLA value based on type"""
        
        try:
            measurement_period = sla_metric.measurement_period or 60  # Default 60 minutes
            since_time = datetime.utcnow() - timedelta(minutes=measurement_period)
            
            if sla_metric.sla_type == "uptime":
                return await self._calculate_uptime_sla(sla_metric.device_id, since_time)
            
            elif sla_metric.sla_type == "response_time":
                return await self._calculate_response_time_sla(sla_metric.device_id, since_time)
            
            elif sla_metric.sla_type == "availability":
                return await self._calculate_availability_sla(sla_metric.device_id, since_time)
            
            else:
                logger.warning(f"Unknown SLA type: {sla_metric.sla_type}")
                
                # Return fallback SLA value for unknown type
                fallback_data = FallbackData(
                    data=0.0,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Unknown SLA type",
                        details=f"Unknown SLA type: {sla_metric.sla_type}",
                        timestamp=datetime.now().isoformat()
                    )
                )
                
                return create_partial_success_result(
                    data=0.0,
                    fallback_data=fallback_data,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Unknown SLA type",
                        details=f"Unknown SLA type: {sla_metric.sla_type}",
                        timestamp=datetime.now().isoformat()
                    ),
                    suggestions=[
                        "Unknown SLA type",
                        "Check SLA configuration",
                        "Use fallback value",
                        "Contact administrator"
                    ]
                ).data
        
        except Exception as e:
            logger.error(f"Failed to calculate SLA value for {sla_metric.sla_name}: {e}")
            
            # Return fallback SLA value when calculation fails
            fallback_data = FallbackData(
                data=0.0,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="SLA calculation failed",
                    details=f"Failed to calculate SLA value for {sla_metric.sla_name}: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to calculate SLA value for {sla_metric.sla_name}",
                error_code="SLA_CALCULATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "SLA calculation failed",
                    "Check database connection",
                    "Verify SLA configuration",
                    "Review error logs"
                ]
            ).data
    
    async def _calculate_uptime_sla(self, device_id: str, since_time: datetime) -> Optional[float]:
        """Calculate uptime SLA percentage"""
        
        try:
            # Get device status history (simplified - assumes we track status changes)
            device_query = select(Device).where(Device.id == device_id)
            device_result = await db.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                # Return fallback uptime value when device not found
                fallback_data = FallbackData(
                    data=0.0,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Device not found",
                        details=f"Device {device_id} not found for uptime SLA calculation",
                        timestamp=datetime.now().isoformat()
                    )
                )
                
                return create_partial_success_result(
                    data=0.0,
                    fallback_data=fallback_data,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Device not found",
                        details=f"Device {device_id} not found for uptime SLA calculation",
                        timestamp=datetime.now().isoformat()
                    ),
                    suggestions=[
                        "Device not found",
                        "Check device ID",
                        "Use fallback uptime value",
                        "Verify device configuration"
                    ]
                ).data
            
            # For now, use simple calculation based on current status
            # In a real implementation, this would analyze status change history
            if device.current_state == DeviceStatus.ONLINE:
                # Check if there were any recent outages in performance metrics
                outage_query = select(func.count(PerformanceMetrics.id)).where(
                    and_(
                        PerformanceMetrics.device_id == device_id,
                        PerformanceMetrics.timestamp >= since_time,
                        PerformanceMetrics.metric_type == "connectivity",
                        PerformanceMetrics.metric_value == 0  # 0 = offline
                    )
                )
                outage_result = await db.execute(outage_query)
                outage_count = outage_result.scalar() or 0
                
                # Get total measurement points
                total_query = select(func.count(PerformanceMetrics.id)).where(
                    and_(
                        PerformanceMetrics.device_id == device_id,
                        PerformanceMetrics.timestamp >= since_time,
                        PerformanceMetrics.metric_type == "connectivity"
                    )
                )
                total_result = await db.execute(total_query)
                total_count = total_result.scalar() or 1
                
                # Calculate uptime percentage
                uptime_percentage = ((total_count - outage_count) / total_count) * 100
                return uptime_percentage
            else:
                # Device is currently offline
                return 0.0
        
        except Exception as e:
            logger.error(f"Failed to calculate uptime SLA: {e}")
            
            # Return fallback uptime value when calculation fails
            fallback_data = FallbackData(
                data=0.0,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Uptime SLA calculation failed",
                    details=f"Failed to calculate uptime SLA: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to calculate uptime SLA",
                error_code="UPTIME_SLA_CALCULATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Uptime SLA calculation failed",
                    "Check database connection",
                    "Verify device configuration",
                    "Review error logs"
                ]
            ).data
    
    async def _calculate_response_time_sla(self, device_id: str, since_time: datetime) -> Optional[float]:
        """Calculate response time SLA (average response time)"""
        
        try:
            # Get average latency metrics
            latency_query = select(func.avg(PerformanceMetrics.metric_value)).where(
                and_(
                    PerformanceMetrics.device_id == device_id,
                    PerformanceMetrics.timestamp >= since_time,
                    PerformanceMetrics.metric_type == "latency"
                )
            )
            result = await db.execute(latency_query)
            avg_latency = result.scalar()
            
            if avg_latency is not None:
                # Convert to percentage (lower latency = higher SLA)
                # Assume target is < 100ms, calculate percentage based on that
                max_acceptable_latency = 100.0  # ms
                if avg_latency <= max_acceptable_latency:
                    percentage = ((max_acceptable_latency - avg_latency) / max_acceptable_latency) * 100
                    return min(100.0, max(0.0, percentage))
                else:
                    return 0.0
            
            # Return fallback response time value when no latency data
            fallback_data = FallbackData(
                data=0.0,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No latency data available",
                    details="No latency metrics available for response time SLA calculation",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_partial_success_result(
                data=0.0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No latency data available",
                    details="No latency metrics available for response time SLA calculation",
                    timestamp=datetime.now().isoformat()
                ),
                suggestions=[
                    "No latency data available",
                    "Check metrics collection",
                    "Use fallback response time value",
                    "Verify monitoring configuration"
                ]
            ).data
        
        except Exception as e:
            logger.error(f"Failed to calculate response time SLA: {e}")
            
            # Return fallback response time value when calculation fails
            fallback_data = FallbackData(
                data=0.0,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Response time SLA calculation failed",
                    details=f"Failed to calculate response time SLA: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to calculate response time SLA",
                error_code="RESPONSE_TIME_SLA_CALCULATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Response time SLA calculation failed",
                    "Check database connection",
                    "Verify metrics configuration",
                    "Review error logs"
                ]
            ).data
    
    async def _calculate_availability_sla(self, device_id: str, since_time: datetime) -> Optional[float]:
        """Calculate availability SLA (combination of uptime and response)"""
        
        try:
            uptime = await self._calculate_uptime_sla(device_id, since_time)
            response_time = await self._calculate_response_time_sla(device_id, since_time)
            
            if uptime is not None and response_time is not None:
                # Weighted average: 70% uptime, 30% response time
                availability = (uptime * 0.7) + (response_time * 0.3)
                return availability
            elif uptime is not None:
                return uptime
            elif response_time is not None:
                return response_time
            
            # Return fallback availability value when no data available
            fallback_data = FallbackData(
                data=0.0,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No availability data available",
                    details="No uptime or response time data available for availability SLA calculation",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_partial_success_result(
                data=0.0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No availability data available",
                    details="No uptime or response time data available for availability SLA calculation",
                    timestamp=datetime.now().isoformat()
                ),
                suggestions=[
                    "No availability data available",
                    "Check metrics collection",
                    "Use fallback availability value",
                    "Verify monitoring configuration"
                ]
            ).data
        
        except Exception as e:
            logger.error(f"Failed to calculate availability SLA: {e}")
            
            # Return fallback availability value when calculation fails
            fallback_data = FallbackData(
                data=0.0,
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Availability SLA calculation failed",
                    details=f"Failed to calculate availability SLA: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to calculate availability SLA",
                error_code="AVAILABILITY_SLA_CALCULATION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Availability SLA calculation failed",
                    "Check database connection",
                    "Verify metrics configuration",
                    "Review error logs"
                ]
            ).data
    
    async def _update_sla_statistics(self, sla_metric: SLAMetrics, current_value: float):
        """Update SLA statistics and history"""
        
        try:
            # Update uptime percentage
            if sla_metric.sla_type in ["uptime", "availability"]:
                sla_metric.uptime_percentage = current_value
                
                # Calculate downtime
                if current_value < 100:
                    measurement_period = sla_metric.measurement_period or 60
                    downtime_minutes = (measurement_period * (100 - current_value)) / 100
                    sla_metric.downtime_minutes = (sla_metric.downtime_minutes or 0) + downtime_minutes
            
            # Track total outages (simplified)
            if sla_metric.sla_status == "breached" and sla_metric.current_value != current_value:
                if current_value < sla_metric.target_value:
                    sla_metric.total_outages = (sla_metric.total_outages or 0) + 1
        
        except Exception as e:
            logger.error(f"Failed to update SLA statistics: {e}")
    
    async def _handle_sla_violation(self, violation: SLAViolation):
        """Handle SLA violation by creating alerts and notifications"""
        
        try:
            # Get device information
            device_query = select(Device).where(Device.id == violation.sla_metric.device_id)
            device_result = await db.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                logger.error(f"Device not found for SLA violation: {violation.sla_metric.device_id}")
                return
            
            # Create alert for violation
            if violation.violation_type in ["breach", "warning"]:
                alert_message = self._create_violation_message(violation, device)
                
                alert = Alert(
                    device_id=device.id,
                    severity=violation.severity,
                    metric_name=f"SLA: {violation.sla_metric.sla_name}",
                    message=alert_message
                )
                
                await db.add(alert)
                await db.commit()
                await db.refresh(alert)
                
                # Create notification
                await notification_service.create_sla_breach_notification(
                    device=device,
                    sla_name=violation.sla_metric.sla_name,
                    current_value=violation.current_value,
                    target_value=violation.target_value
                )
                
                logger.warning(f"SLA violation: {violation.sla_metric.sla_name} on {device.hostname}")
            
            elif violation.violation_type == "recovery":
                # Create recovery notification
                await notification_service.create_notification(
                    title=f"SLA Recovery: {violation.sla_metric.sla_name}",
                    message=f"SLA {violation.sla_metric.sla_name} on {device.hostname} has recovered. Current: {violation.current_value:.2f}%, Target: {violation.target_value:.2f}%",
                    notification_type=NotificationType.SLA_BREACH,
                    severity=AlertSeverity.INFO,
                    device_id=str(device.id),
                    action_url=f"/sla?device_id={device.id}",
                    metadata={
                        "sla_name": violation.sla_metric.sla_name,
                        "current_value": violation.current_value,
                        "target_value": violation.target_value,
                        "recovery": True
                    }
                )
                
                logger.info(f"SLA recovery: {violation.sla_metric.sla_name} on {device.hostname}")
        
        except Exception as e:
            logger.error(f"Failed to handle SLA violation: {e}")
            await db.rollback()
    
    def _create_violation_message(self, violation: SLAViolation, device: Device) -> str:
        """Create violation message"""
        
        if violation.violation_type == "breach":
            return (f"SLA breach detected for {violation.sla_metric.sla_name} on {device.hostname}. "
                   f"Current: {violation.current_value:.2f}%, Target: {violation.target_value:.2f}%")
        elif violation.violation_type == "warning":
            return (f"SLA warning for {violation.sla_metric.sla_name} on {device.hostname}. "
                   f"Current: {violation.current_value:.2f}%, Target: {violation.target_value:.2f}%")
        else:
            return (f"SLA status change for {violation.sla_metric.sla_name} on {device.hostname}. "
                   f"Current: {violation.current_value:.2f}%")
    
    async def create_sla_metric(
        self,
        device_id: str,
        sla_name: str,
        sla_type: str,
        target_value: float,
        measurement_period: Optional[int] = None
    ) -> SLAMetrics:
        """Create a new SLA metric"""
        
        try:
            sla_metric = SLAMetrics(
                device_id=device_id,
                sla_name=sla_name,
                sla_type=sla_type,
                target_value=target_value,
                measurement_period=measurement_period or 60,
                sla_status="unknown",
                is_active=True
            )
            
            await db.add(sla_metric)
            await db.commit()
            await db.refresh(sla_metric)
            
            logger.info(f"Created SLA metric: {sla_name} for device {device_id}")
            return sla_metric
        
        except Exception as e:
            logger.error(f"Failed to create SLA metric: {e}")
            await db.rollback()
            raise
    
    async def update_sla_metric(self, sla_id: str, updates: Dict[str, Any]) -> Optional[SLAMetrics]:
        """Update SLA metric"""
        
        try:
            sla_query = select(SLAMetrics).where(SLAMetrics.id == sla_id)
            result = await db.execute(sla_query)
            sla_metric = result.scalar_one_or_none()
            
            if not sla_metric:
                # Return fallback SLA metric data when not found
                fallback_data = FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="SLA metric not found",
                        details=f"SLA metric {sla_id} not found for update",
                        timestamp=datetime.now().isoformat()
                    )
                )
                
                return create_failure_result(
                    error=f"SLA metric {sla_id} not found",
                    error_code="SLA_METRIC_NOT_FOUND",
                    fallback_data=fallback_data,
                    suggestions=[
                        "SLA metric not found",
                        "Check SLA metric ID",
                        "Verify SLA metric exists",
                        "Create SLA metric if needed"
                    ]
                )
            
            # Update fields
            for field, value in updates.items():
                if hasattr(sla_metric, field):
                    setattr(sla_metric, field, value)
            
            await db.commit()
            
            logger.info(f"Updated SLA metric: {sla_id}")
            return sla_metric
        
        except Exception as e:
            logger.error(f"Failed to update SLA metric: {e}")
            await db.rollback()
            raise
    
    async def delete_sla_metric(self, sla_id: str) -> bool:
        """Delete SLA metric"""
        
        try:
            sla_query = select(SLAMetrics).where(SLAMetrics.id == sla_id)
            result = await db.execute(sla_query)
            sla_metric = result.scalar_one_or_none()
            
            if not sla_metric:
                return False
            
            await db.delete(sla_metric)
            await db.commit()
            
            logger.info(f"Deleted SLA metric: {sla_id}")
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete SLA metric: {e}")
            await db.rollback()
            return False
    
    async def get_sla_report(self, device_id: Optional[str] = None, days: int = 30) -> Dict[str, Any]:
        """Generate SLA report"""
        
        try:
            since_date = datetime.utcnow() - timedelta(days=days)
            
            # Build query
            query = select(SLAMetrics)
            if device_id:
                query = query.where(SLAMetrics.device_id == device_id)
            
            result = await db.execute(query)
            sla_metrics = result.scalars().all()
            
            # Generate report data
            report_data = {
                "report_period_days": days,
                "generated_at": datetime.utcnow().isoformat(),
                "total_slas": len(sla_metrics),
                "sla_summary": {
                    "met": 0,
                    "warning": 0,
                    "breached": 0,
                    "unknown": 0
                },
                "sla_details": []
            }
            
            for sla in sla_metrics:
                # Update summary counts
                report_data["sla_summary"][sla.sla_status] += 1
                
                # Add detailed information
                sla_detail = {
                    "id": str(sla.id),
                    "device_id": str(sla.device_id),
                    "sla_name": sla.sla_name,
                    "sla_type": sla.sla_type,
                    "target_value": sla.target_value,
                    "current_value": sla.current_value,
                    "status": sla.sla_status,
                    "uptime_percentage": sla.uptime_percentage,
                    "downtime_minutes": sla.downtime_minutes,
                    "total_outages": sla.total_outages,
                    "last_measurement": sla.last_measurement.isoformat() if sla.last_measurement else None,
                    "measurement_period": sla.measurement_period
                }
                
                report_data["sla_details"].append(sla_detail)
            
            return report_data
        
        except Exception as e:
            logger.error(f"Failed to generate SLA report: {e}")
            raise

# Global SLA monitoring service instance
sla_monitor = SLAMonitoringService()
