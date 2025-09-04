"""
Alert Engine for CHM - Implements threshold-based alerting with correlation and escalation
"""
import asyncio
import logging
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
import json
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from sqlalchemy.orm import selectinload

from database.models.alerts import Alert, AlertRule, AlertSeverity, AlertStatus, AlertCategory, AlertHistory
from database.models.device import Device
from database.models.metrics import DeviceMetric, MetricType
from services.notification_service import notification_service
from services.websocket_manager import websocket_manager
from services.cache_service import cache_service

logger = logging.getLogger(__name__)


class AlertEngine:
    """
    Comprehensive alert engine with rule evaluation, correlation, and escalation
    """
    
    def __init__(self):
        self.evaluation_interval = 30  # seconds
        self.is_running = False
        self.alert_cache: Dict[str, Alert] = {}
        self.flapping_cache: Dict[str, List[datetime]] = {}
        self.correlation_window = 300  # 5 minutes
        self.suppression_cache: Set[str] = set()
        
    async def start(self, db: AsyncSession):
        """Start the alert engine"""
        logger.info("Starting alert engine")
        self.is_running = True
        
        while self.is_running:
            try:
                await self.evaluate_all_rules(db)
                await asyncio.sleep(self.evaluation_interval)
            except Exception as e:
                logger.error(f"Alert engine error: {e}", exc_info=True)
                await asyncio.sleep(60)
    
    async def stop(self):
        """Stop the alert engine"""
        logger.info("Stopping alert engine")
        self.is_running = False
    
    async def evaluate_all_rules(self, db: AsyncSession):
        """Evaluate all active alert rules"""
        try:
            # Get all enabled alert rules
            stmt = select(AlertRule).where(
                AlertRule.enabled == True
            ).options(selectinload(AlertRule.device))
            
            result = await db.execute(stmt)
            rules = result.scalars().all()
            
            logger.debug(f"Evaluating {len(rules)} alert rules")
            
            # Evaluate each rule
            tasks = []
            for rule in rules:
                task = self.evaluate_rule(db, rule)
                tasks.append(task)
            
            # Execute evaluations in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            alerts_triggered = 0
            alerts_cleared = 0
            
            for result in results:
                if isinstance(result, dict):
                    if result.get("triggered"):
                        alerts_triggered += 1
                    elif result.get("cleared"):
                        alerts_cleared += 1
            
            if alerts_triggered > 0 or alerts_cleared > 0:
                logger.info(f"Alert evaluation complete: {alerts_triggered} triggered, {alerts_cleared} cleared")
                
        except Exception as e:
            logger.error(f"Failed to evaluate alert rules: {e}")
    
    async def evaluate_rule(self, db: AsyncSession, rule: AlertRule) -> Dict[str, Any]:
        """Evaluate a single alert rule"""
        try:
            # Check if rule is suppressed
            if await self._is_rule_suppressed(rule):
                return {"rule_id": str(rule.id), "suppressed": True}
            
            # Get devices for rule
            devices = await self._get_devices_for_rule(db, rule)
            
            results = []
            for device in devices:
                # Get latest metric value
                metric_value = await self._get_metric_value(
                    db, 
                    device.id, 
                    rule.metric_type, 
                    rule.metric_name
                )
                
                if metric_value is None:
                    continue
                
                # Evaluate threshold
                threshold_exceeded = self._evaluate_threshold(
                    metric_value, 
                    rule.operator, 
                    rule.threshold
                )
                
                # Check hysteresis
                if rule.hysteresis > 0:
                    threshold_exceeded = await self._apply_hysteresis(
                        db, 
                        rule, 
                        device, 
                        metric_value, 
                        threshold_exceeded
                    )
                
                # Check duration requirement
                if rule.duration_seconds > 0:
                    threshold_exceeded = await self._check_duration(
                        db, 
                        rule, 
                        device, 
                        threshold_exceeded
                    )
                
                # Process alert state
                if threshold_exceeded:
                    alert = await self._trigger_alert(db, rule, device, metric_value)
                    results.append({"triggered": True, "alert_id": str(alert.id)})
                else:
                    cleared = await self._clear_alert(db, rule, device)
                    if cleared:
                        results.append({"cleared": True})
            
            return {"rule_id": str(rule.id), "results": results}
            
        except Exception as e:
            logger.error(f"Failed to evaluate rule {rule.id}: {e}")
            return {"rule_id": str(rule.id), "error": str(e)}
    
    async def _get_devices_for_rule(self, db: AsyncSession, rule: AlertRule) -> List[Device]:
        """Get devices that the rule applies to"""
        if rule.device_id:
            # Rule applies to specific device
            stmt = select(Device).where(
                and_(
                    Device.id == rule.device_id,
                    Device.is_active == True,
                    Device.monitoring_enabled == True
                )
            )
        elif rule.applies_to_all:
            # Rule applies to all devices
            stmt = select(Device).where(
                and_(
                    Device.is_active == True,
                    Device.monitoring_enabled == True
                )
            )
        else:
            # Rule applies to device group
            # TODO: Implement device group filtering
            return []
        
        result = await db.execute(stmt)
        return result.scalars().all()
    
    async def _get_metric_value(
        self, 
        db: AsyncSession, 
        device_id: str, 
        metric_type: str, 
        metric_name: str
    ) -> Optional[float]:
        """Get latest metric value for device"""
        try:
            # Check cache first
            cache_key = f"metric:{device_id}:{metric_type}:{metric_name}"
            cached_value = await cache_service.get(cache_key)
            if cached_value:
                return float(cached_value)
            
            # Query database
            stmt = select(DeviceMetric).where(
                and_(
                    DeviceMetric.device_id == device_id,
                    DeviceMetric.metric_type == MetricType[metric_type.upper()],
                    DeviceMetric.metric_name == metric_name
                )
            ).order_by(DeviceMetric.timestamp.desc()).limit(1)
            
            result = await db.execute(stmt)
            metric = result.scalar_one_or_none()
            
            if metric:
                # Cache the value
                await cache_service.set(cache_key, str(metric.value), ttl=60)
                return metric.value
            
            # Return fallback metric value when no metric found
            fallback_data = FallbackData(
                data=0.0,
                source="metric_value_fallback",
                confidence=0.0,
                metadata={"device_id": device_id, "metric_name": metric_name, "reason": "No metric found"}
            )
            
            return create_partial_success_result(
                data=0.0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="No metric value found",
                    fallback_available=True
                ),
                suggestions=[
                    "No metric value found",
                    "Check metric collection",
                    "Verify device connectivity",
                    "Use fallback value"
                ]
            ).data
            
        except Exception as e:
            logger.error(f"Failed to get metric value: {e}")
            
            # Return fallback metric value when operation fails
            fallback_data = FallbackData(
                data=0.0,
                source="metric_operation_fallback",
                confidence=0.0,
                metadata={"device_id": device_id, "metric_name": metric_name, "error": str(e)}
            )
            
            return create_partial_success_result(
                data=0.0,
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    status=HealthLevel.DEGRADED,
                    degradation_reason="Metric operation failed",
                    fallback_available=True
                ),
                suggestions=[
                    "Metric operation failed",
                    "Check error logs",
                    "Verify system configuration",
                    "Use fallback value"
                ]
            ).data
    
    def _evaluate_threshold(self, value: float, operator: str, threshold: float) -> bool:
        """Evaluate if value exceeds threshold based on operator"""
        operators = {
            ">": lambda x, y: x > y,
            ">=": lambda x, y: x >= y,
            "<": lambda x, y: x < y,
            "<=": lambda x, y: x <= y,
            "==": lambda x, y: x == y,
            "!=": lambda x, y: x != y
        }
        
        if operator in operators:
            return operators[operator](value, threshold)
        
        logger.warning(f"Unknown operator: {operator}")
        return False
    
    async def _apply_hysteresis(
        self, 
        db: AsyncSession, 
        rule: AlertRule, 
        device: Device, 
        value: float, 
        threshold_exceeded: bool
    ) -> bool:
        """Apply hysteresis to prevent alert flapping"""
        # Get existing alert
        stmt = select(Alert).where(
            and_(
                Alert.rule_id == rule.id,
                Alert.device_id == device.id,
                Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])
            )
        )
        result = await db.execute(stmt)
        existing_alert = result.scalar_one_or_none()
        
        if existing_alert:
            # Alert exists, check if it should be cleared
            if not threshold_exceeded:
                # Apply hysteresis for clearing
                clear_threshold = rule.clear_threshold or (rule.threshold - rule.hysteresis)
                if rule.operator in [">", ">="]:
                    return value > clear_threshold
                else:
                    return value < clear_threshold
        else:
            # No existing alert, use normal threshold
            return threshold_exceeded
        
        return threshold_exceeded
    
    async def _check_duration(
        self, 
        db: AsyncSession, 
        rule: AlertRule, 
        device: Device, 
        threshold_exceeded: bool
    ) -> bool:
        """Check if threshold has been exceeded for required duration"""
        if not threshold_exceeded:
            return False
        
        # Get metrics for duration period
        start_time = datetime.utcnow() - timedelta(seconds=rule.duration_seconds)
        
        stmt = select(DeviceMetric).where(
            and_(
                DeviceMetric.device_id == device.id,
                DeviceMetric.metric_type == MetricType[rule.metric_type.upper()],
                DeviceMetric.metric_name == rule.metric_name,
                DeviceMetric.timestamp >= start_time
            )
        ).order_by(DeviceMetric.timestamp)
        
        result = await db.execute(stmt)
        metrics = result.scalars().all()
        
        # Check if all metrics exceed threshold
        for metric in metrics:
            if not self._evaluate_threshold(metric.value, rule.operator, rule.threshold):
                return False
        
        return len(metrics) > 0
    
    async def _trigger_alert(
        self, 
        db: AsyncSession, 
        rule: AlertRule, 
        device: Device, 
        metric_value: float
    ) -> Alert:
        """Trigger a new alert or update existing one"""
        try:
            # Check for existing alert
            stmt = select(Alert).where(
                and_(
                    Alert.rule_id == rule.id,
                    Alert.device_id == device.id,
                    Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])
                )
            )
            result = await db.execute(stmt)
            existing_alert = result.scalar_one_or_none()
            
            if existing_alert:
                # Update existing alert
                existing_alert.current_value = metric_value
                existing_alert.last_seen_at = datetime.utcnow()
                existing_alert.duration_seconds = int(
                    (datetime.utcnow() - existing_alert.created_at).total_seconds()
                )
                
                # Check for flapping
                await self._check_flapping(db, existing_alert)
                
                await db.commit()
                return existing_alert
            
            # Create new alert
            alert = Alert(
                rule_id=rule.id,
                device_id=device.id,
                title=f"{rule.name} - {device.hostname}",
                message=self._generate_alert_message(rule, device, metric_value),
                details={
                    "rule_name": rule.name,
                    "device_hostname": device.hostname,
                    "device_ip": str(device.ip_address),
                    "metric_value": metric_value,
                    "threshold": rule.threshold,
                    "operator": rule.operator
                },
                metric_type=rule.metric_type,
                metric_name=rule.metric_name,
                current_value=metric_value,
                threshold=rule.threshold,
                unit=rule.threshold_unit,
                severity=rule.severity,
                category=rule.category,
                priority=rule.priority,
                status=AlertStatus.NEW,
                first_seen_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow()
            )
            
            db.add(alert)
            await db.commit()
            
            # Send notifications
            await self._send_alert_notification(alert, rule, device)
            
            # Send real-time update
            await self._send_realtime_update(alert, "triggered")
            
            # Check for correlation
            await self._correlate_alert(db, alert, rule)
            
            # Log alert history
            await self._log_alert_history(db, alert, "created", None, AlertStatus.NEW)
            
            logger.info(f"Alert triggered: {alert.title}")
            return alert
            
        except Exception as e:
            logger.error(f"Failed to trigger alert: {e}")
            await db.rollback()
            raise
    
    async def _clear_alert(self, db: AsyncSession, rule: AlertRule, device: Device) -> bool:
        """Clear an existing alert"""
        try:
            # Find existing alert
            stmt = select(Alert).where(
                and_(
                    Alert.rule_id == rule.id,
                    Alert.device_id == device.id,
                    Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])
                )
            )
            result = await db.execute(stmt)
            alert = result.scalar_one_or_none()
            
            if not alert:
                return False
            
            # Update alert status
            alert.status = AlertStatus.RESOLVED
            alert.resolved_at = datetime.utcnow()
            alert.resolution_code = "auto"
            alert.resolution_comment = "Alert condition cleared"
            alert.cleared_at = datetime.utcnow()
            alert.duration_seconds = int(
                (datetime.utcnow() - alert.created_at).total_seconds()
            )
            alert.time_to_resolve = int(
                (datetime.utcnow() - alert.created_at).total_seconds()
            )
            
            await db.commit()
            
            # Send clear notification
            await self._send_clear_notification(alert, rule, device)
            
            # Send real-time update
            await self._send_realtime_update(alert, "cleared")
            
            # Log alert history
            await self._log_alert_history(
                db, 
                alert, 
                "resolved", 
                AlertStatus.NEW, 
                AlertStatus.RESOLVED
            )
            
            logger.info(f"Alert cleared: {alert.title}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear alert: {e}")
            await db.rollback()
            return False
    
    async def _check_flapping(self, db: AsyncSession, alert: Alert):
        """Check if alert is flapping"""
        alert_key = f"{alert.rule_id}:{alert.device_id}"
        
        # Track state changes
        if alert_key not in self.flapping_cache:
            self.flapping_cache[alert_key] = []
        
        self.flapping_cache[alert_key].append(datetime.utcnow())
        
        # Remove old entries (outside flap window)
        flap_window = timedelta(seconds=300)  # 5 minutes
        cutoff_time = datetime.utcnow() - flap_window
        self.flapping_cache[alert_key] = [
            t for t in self.flapping_cache[alert_key] if t > cutoff_time
        ]
        
        # Check flap count
        if len(self.flapping_cache[alert_key]) >= 5:
            alert.is_flapping = True
            alert.flap_count = len(self.flapping_cache[alert_key])
            alert.flap_start_time = self.flapping_cache[alert_key][0]
            logger.warning(f"Alert is flapping: {alert.title}")
    
    async def _correlate_alert(self, db: AsyncSession, alert: Alert, rule: AlertRule):
        """Correlate alert with other alerts"""
        if not rule.correlation_enabled:
            return
        
        # Find related alerts within correlation window
        cutoff_time = datetime.utcnow() - timedelta(seconds=rule.correlation_window)
        
        stmt = select(Alert).where(
            and_(
                Alert.id != alert.id,
                Alert.device_id == alert.device_id,
                Alert.created_at >= cutoff_time,
                Alert.status.in_([AlertStatus.NEW, AlertStatus.ACKNOWLEDGED])
            )
        )
        
        result = await db.execute(stmt)
        related_alerts = result.scalars().all()
        
        if related_alerts:
            # Create correlation group
            import uuid
            correlation_id = str(uuid.uuid4())
            
            alert.correlation_id = correlation_id
            alert.is_correlated = True
            alert.correlation_count = len(related_alerts) + 1
            
            # Update related alerts
            for related_alert in related_alerts:
                related_alert.correlation_id = correlation_id
                related_alert.is_correlated = True
                related_alert.correlation_count = len(related_alerts) + 1
            
            await db.commit()
            logger.info(f"Correlated {len(related_alerts) + 1} alerts")
    
    def _generate_alert_message(self, rule: AlertRule, device: Device, value: float) -> str:
        """Generate alert message"""
        return (
            f"Alert: {rule.name}\n"
            f"Device: {device.hostname} ({device.ip_address})\n"
            f"Metric: {rule.metric_name}\n"
            f"Current Value: {value} {rule.threshold_unit or ''}\n"
            f"Threshold: {rule.operator} {rule.threshold} {rule.threshold_unit or ''}\n"
            f"Severity: {rule.severity.value}\n"
            f"Time: {datetime.utcnow().isoformat()}"
        )
    
    async def _send_alert_notification(self, alert: Alert, rule: AlertRule, device: Device):
        """Send alert notification"""
        if not rule.notification_enabled:
            return
        
        # Apply notification delay if configured
        if rule.notification_delay_seconds > 0:
            await asyncio.sleep(rule.notification_delay_seconds)
        
        # Send notification
        await notification_service.send_alert_notification(alert, rule, device)
    
    async def _send_clear_notification(self, alert: Alert, rule: AlertRule, device: Device):
        """Send alert clear notification"""
        if not rule.notification_enabled:
            return
        
        await notification_service.send_clear_notification(alert, rule, device)
    
    async def _send_realtime_update(self, alert: Alert, action: str):
        """Send real-time update via WebSocket"""
        update = {
            "type": "alert_update",
            "action": action,
            "alert": {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "device_id": str(alert.device_id),
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
        await websocket_manager.broadcast(json.dumps(update))
    
    async def _log_alert_history(
        self, 
        db: AsyncSession, 
        alert: Alert, 
        action: str, 
        old_status: Optional[AlertStatus], 
        new_status: AlertStatus
    ):
        """Log alert state change to history"""
        history = AlertHistory(
            alert_id=alert.id,
            action=action,
            old_status=old_status,
            new_status=new_status,
            comment=f"Alert {action}",
            metadata={
                "timestamp": datetime.utcnow().isoformat(),
                "current_value": alert.current_value,
                "threshold": alert.threshold
            }
        )
        
        db.add(history)
        await db.commit()
    
    async def _is_rule_suppressed(self, rule: AlertRule) -> bool:
        """Check if rule is suppressed"""
        if not rule.suppression_enabled:
            return False
        
        # Check suppression rules
        if rule.suppression_rules:
            # TODO: Implement suppression rule evaluation
            pass
        
        return str(rule.id) in self.suppression_cache
    
    async def acknowledge_alert(
        self, 
        db: AsyncSession, 
        alert_id: str, 
        user_id: str, 
        comment: Optional[str] = None
    ) -> bool:
        """Acknowledge an alert"""
        try:
            stmt = select(Alert).where(Alert.id == alert_id)
            result = await db.execute(stmt)
            alert = result.scalar_one_or_none()
            
            if not alert:
                return False
            
            alert.status = AlertStatus.ACKNOWLEDGED
            alert.acknowledged_by = user_id
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledgment_comment = comment
            alert.time_to_acknowledge = int(
                (datetime.utcnow() - alert.created_at).total_seconds()
            )
            
            await db.commit()
            
            # Log history
            await self._log_alert_history(
                db, 
                alert, 
                "acknowledged", 
                AlertStatus.NEW, 
                AlertStatus.ACKNOWLEDGED
            )
            
            # Send real-time update
            await self._send_realtime_update(alert, "acknowledged")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to acknowledge alert: {e}")
            await db.rollback()
            return False


# Global alert engine instance
alert_engine = AlertEngine()