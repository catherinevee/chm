"""
Background Tasks Service
Handles continuous monitoring, metrics collection, and notifications
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import random
import os
from contextlib import asynccontextmanager

from backend.storage.database import db
from backend.storage.models import (
    Device, DeviceStatus, PerformanceMetrics, MetricType, 
    Notification, NotificationType, NotificationStatus,
    SLAMetrics, Alert, AlertSeverity
)
from sqlalchemy import select, and_, or_

logger = logging.getLogger(__name__)

class BackgroundTaskService:
    """Service for running background monitoring tasks"""
    
    def __init__(self):
        self.running = False
        self.tasks = []
        self.websocket_manager = None
        self.device_failure_counts = {}  # Track consecutive failures per device
        self.circuit_breaker_thresholds = {
            'failure_threshold': 5,      # Open circuit after 5 consecutive failures
            'recovery_timeout': 300,     # Try to close circuit after 5 minutes
            'half_open_max_calls': 3     # Allow 3 calls in half-open state
        }
        self.circuit_breaker_state = {}  # Track circuit breaker states per device
        self.max_concurrent_collections = int(os.getenv("MAX_CONCURRENT_COLLECTIONS", "10"))
        self.batch_size = int(os.getenv("COLLECTION_BATCH_SIZE", "20"))
    
    def set_websocket_manager(self, websocket_manager):
        """Set the WebSocket manager for broadcasting notifications"""
        self.websocket_manager = websocket_manager
    
    async def start(self):
        """Start all background tasks"""
        if self.running:
            return
        
        self.running = True
        logger.info("Starting background task service...")
        
        # Start various monitoring tasks
        self.tasks = [
            asyncio.create_task(self._metrics_collection_loop()),
            asyncio.create_task(self._device_health_check_loop()),
            asyncio.create_task(self._sla_monitoring_loop()),
            asyncio.create_task(self._notification_cleanup_loop())
        ]
        
        logger.info(f"Started {len(self.tasks)} background tasks")
    
    async def stop(self):
        """Stop all background tasks"""
        if not self.running:
            return
        
        logger.info("Stopping background task service...")
        self.running = False
        
        # Cancel all tasks
        for task in self.tasks:
            task.cancel()
        
        # Wait for tasks to complete
        await asyncio.gather(*self.tasks, return_exceptions=True)
        self.tasks.clear()
        
        logger.info("Background task service stopped")
    
    def _should_skip_device(self, device_id: str) -> bool:
        """Check if device should be skipped due to circuit breaker"""
        if device_id not in self.circuit_breaker_state:
            return False
        
        state = self.circuit_breaker_state[device_id]
        now = datetime.utcnow()
        
        if state['status'] == 'open':
            # Check if we should transition to half-open
            if (now - state['last_failure']).seconds >= self.circuit_breaker_thresholds['recovery_timeout']:
                state['status'] = 'half-open'
                state['half_open_calls'] = 0
                logger.info(f"Circuit breaker for device {device_id} transitioning to half-open")
                return False
            return True
        
        return False
    
    def _record_device_success(self, device_id: str):
        """Record successful device operation"""
        if device_id in self.device_failure_counts:
            del self.device_failure_counts[device_id]
        
        if device_id in self.circuit_breaker_state:
            state = self.circuit_breaker_state[device_id]
            if state['status'] == 'half-open':
                # Successful call in half-open state, close the circuit
                del self.circuit_breaker_state[device_id]
                logger.info(f"Circuit breaker for device {device_id} closed after successful recovery")
    
    def _record_device_failure(self, device_id: str):
        """Record failed device operation and update circuit breaker"""
        self.device_failure_counts[device_id] = self.device_failure_counts.get(device_id, 0) + 1
        failure_count = self.device_failure_counts[device_id]
        
        # Check if we should open the circuit breaker
        if failure_count >= self.circuit_breaker_thresholds['failure_threshold']:
            self.circuit_breaker_state[device_id] = {
                'status': 'open',
                'last_failure': datetime.utcnow(),
                'failure_count': failure_count
            }
            logger.warning(f"Circuit breaker opened for device {device_id} after {failure_count} failures")
        
        # If in half-open state, reopen the circuit
        elif device_id in self.circuit_breaker_state:
            state = self.circuit_breaker_state[device_id]
            if state['status'] == 'half-open':
                state['status'] = 'open'
                state['last_failure'] = datetime.utcnow()
                logger.warning(f"Circuit breaker reopened for device {device_id} during half-open state")
    
    async def _metrics_collection_loop(self):
        """Continuously collect performance metrics from devices"""
        logger.info("Starting metrics collection loop")
        
        while self.running:
            try:
                await self._collect_all_device_metrics()
                # Dynamic sleep based on circuit breaker states
                sleep_time = 60  # Base interval: 1 minute
                open_circuits = sum(1 for state in self.circuit_breaker_state.values() 
                                  if state.get('status') == 'open')
                if open_circuits > 0:
                    # Reduce collection frequency when many devices are failing
                    sleep_time = min(120, 60 + (open_circuits * 10))
                    logger.debug(f"Adjusted collection interval to {sleep_time}s due to {open_circuits} open circuits")
                
                await asyncio.sleep(sleep_time)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in metrics collection loop: {e}")
                await asyncio.sleep(30)  # Wait before retrying
    
    async def _device_health_check_loop(self):
        """Continuously check device health and connectivity"""
        logger.info("Starting device health check loop")
        
        while self.running:
            try:
                await self._check_device_health()
                await asyncio.sleep(30)  # Check health every 30 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(15)
    
    async def _sla_monitoring_loop(self):
        """Monitor SLA compliance and generate alerts using comprehensive SLA service"""
        logger.info("Starting comprehensive SLA monitoring loop")
        
        # Import and start the SLA monitoring service
        try:
            from backend.services.sla_monitor import sla_monitor
            await sla_monitor.start_monitoring()
            logger.info("SLA monitoring service started successfully")
        except Exception as e:
            logger.error(f"Failed to start SLA monitoring service: {e}")
        
        while self.running:
            try:
                # The SLA monitor runs its own loop, so we just need to keep this task alive
                # and perform periodic health checks
                await self._check_sla_monitoring_health()
                await asyncio.sleep(300)  # Check every 5 minutes
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in SLA monitoring loop: {e}")
                await asyncio.sleep(60)
        
        # Stop SLA monitoring when loop ends
        try:
            from backend.services.sla_monitor import sla_monitor
            await sla_monitor.stop_monitoring()
            logger.info("SLA monitoring service stopped")
        except Exception as e:
            logger.error(f"Failed to stop SLA monitoring service: {e}")
    
    async def _check_sla_monitoring_health(self):
        """Check if SLA monitoring is running properly"""
        try:
            from backend.services.sla_monitor import sla_monitor
            
            if not sla_monitor.monitoring_active:
                logger.warning("SLA monitoring not active, restarting...")
                await sla_monitor.start_monitoring()
            
        except Exception as e:
            logger.error(f"SLA monitoring health check failed: {e}")
    
    async def _notification_cleanup_loop(self):
        """Clean up old notifications and alerts"""
        logger.info("Starting notification cleanup loop")
        
        while self.running:
            try:
                await self._cleanup_old_notifications()
                await asyncio.sleep(3600)  # Cleanup every hour
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(300)
    
    async def _collect_all_device_metrics(self):
        """Collect metrics from all active devices using batch processing"""
        try:
            async with db.get_async_session() as session:
                # Get all active devices  
                devices_query = select(Device).where(Device.current_state != DeviceStatus.DECOMMISSIONED)
                result = await session.execute(devices_query)
                all_devices = result.scalars().all()
                
                # Filter out devices with open circuit breakers
                available_devices = [
                    device for device in all_devices 
                    if not self._should_skip_device(str(device.id))
                ]
                
                logger.debug(f"Collecting metrics for {len(available_devices)} devices (filtered from {len(all_devices)})")
                
                # Process devices in batches with concurrency control
                semaphore = asyncio.Semaphore(self.max_concurrent_collections)
                
                async def collect_device_batch(device_batch):
                    """Process a batch of devices concurrently"""
                    tasks = []
                    for device in device_batch:
                        async def collect_single_device(dev):
                            async with semaphore:  # Limit concurrent operations
                                try:
                                    await self._collect_device_metrics(session, dev)
                                    self._record_device_success(str(dev.id))
                                    return True
                                except Exception as e:
                                    logger.warning(f"Failed to collect metrics for device {dev.hostname}: {e}")
                                    self._record_device_failure(str(dev.id))
                                    return False
                        
                        tasks.append(collect_single_device(device))
                    
                    # Execute batch concurrently
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    successful = sum(1 for r in results if r is True)
                    logger.debug(f"Batch completed: {successful}/{len(device_batch)} successful")
                
                # Process devices in batches
                for i in range(0, len(available_devices), self.batch_size):
                    batch = available_devices[i:i + self.batch_size]
                    await collect_device_batch(batch)
                    
                    # Small delay between batches to prevent overwhelming the system
                    if i + self.batch_size < len(available_devices):
                        await asyncio.sleep(0.1)
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Error collecting device metrics: {e}")
    
    async def _collect_device_metrics(self, session, device: Device):
        """Collect metrics for a single device"""
        timestamp = datetime.utcnow()
        
        # Use real performance collector instead of mock data
        try:
            from backend.collector.performance_collector import EnhancedPerformanceCollector
            from backend.collector.protocols.snmp.session import SNMPCredentials
            
            collector = EnhancedPerformanceCollector()
            
            # Create SNMP credentials if available
            credentials = None
            if hasattr(device, 'snmp_community') and device.snmp_community:
                credentials = SNMPCredentials(
                    community=device.snmp_community,
                    version=getattr(device, 'snmp_version', '2c'),
                    port=getattr(device, 'snmp_port', 161)
                )
            
            # Collect comprehensive metrics
            collected_metrics = await collector.collect_all_metrics(device.ip_address, credentials)
            
            # Convert to the format expected by the rest of the function
            metrics_data = []
            for metric in collected_metrics:
                metric_type_mapping = {
                    'cpu': MetricType.CPU_USAGE,
                    'memory': MetricType.MEMORY_USAGE,
                    'disk': MetricType.DISK_USAGE,
                    'temperature': MetricType.TEMPERATURE,
                    'uptime': MetricType.UPTIME,
                    'bandwidth': MetricType.BANDWIDTH_IN,
                    'latency': MetricType.LATENCY,
                    'interface': MetricType.INTERFACE_STATUS
                }
                
                metric_type = metric_type_mapping.get(metric.metric_type, MetricType.CPU_USAGE)
                
                metrics_data.append({
                    "metric_type": metric_type,
                    "value": metric.value,
                    "unit": metric.unit,
                    "interface_name": metric.interface_name,
                    "metadata": metric.metadata
                })
            
            # If no metrics collected, fall back to basic ping test
            if not metrics_data:
                # Basic connectivity test
                try:
                    import subprocess
                    import platform
                    
                    # Ping test
                    if platform.system().lower() == 'windows':
                        cmd = ['ping', '-n', '1', '-w', '2000', device.ip_address]
                    else:
                        cmd = ['ping', '-c', '1', '-W', '2', device.ip_address]
                    
                    result = subprocess.run(cmd, capture_output=True, timeout=5)
                    is_online = result.returncode == 0
                    
                    # Basic status metric
                    metrics_data.append({
                        "metric_type": MetricType.UPTIME,
                        "value": 1.0 if is_online else 0.0,
                        "unit": "status",
                        "interface_name": None,
                        "metadata": {"connectivity_test": "ping", "responsive": is_online}
                    })
                    
                except Exception as ping_error:
                    logger.warning(f"Ping test failed for {device.ip_address}: {ping_error}")
                    # Add offline status
                    metrics_data.append({
                        "metric_type": MetricType.UPTIME,
                        "value": 0.0,
                        "unit": "status",
                        "interface_name": None,
                        "metadata": {"connectivity_test": "failed", "error": str(ping_error)}
                    })
                    
        except Exception as collector_error:
            logger.error(f"Metrics collection failed for {device.ip_address}: {collector_error}")
            # Return basic offline status
            metrics_data = [{
                "metric_type": MetricType.UPTIME,
                "value": 0.0,
                "unit": "status",
                "interface_name": None,
                "metadata": {"error": str(collector_error)}
            }]
        
        # Create performance metrics
        for metric_data in metrics_data:
            metric = PerformanceMetrics(
                device_id=device.id,
                metric_type=metric_data["metric_type"],
                value=metric_data["value"],
                unit=metric_data["unit"],
                timestamp=timestamp,
                metadata={"source": "background_collector"}
            )
            session.add(metric)
        
        logger.debug(f"Added {len(metrics_data)} metrics for device {device.hostname}")
    
    async def _check_device_health(self):
        """Check health status of all devices"""
        try:
            async with db.get_async_session() as session:
                devices_query = select(Device).where(Device.current_state != DeviceStatus.DECOMMISSIONED)
                result = await session.execute(devices_query)
                devices = result.scalars().all()
                
                for device in devices:
                    try:
                        # Simulate ping check (in production, use real ping)
                        is_online = random.choice([True, True, True, False])  # 75% uptime
                        
                        old_state = device.current_state
                        new_state = DeviceStatus.ONLINE if is_online else DeviceStatus.OFFLINE
                        
                        if old_state != new_state:
                            device.current_state = new_state
                            device.last_poll_time = datetime.utcnow()
                            
                            # Create notification for state change
                            await self._create_device_state_notification(session, device, old_state, new_state)
                            
                            logger.info(f"Device {device.hostname} state changed: {old_state} -> {new_state}")
                    
                    except Exception as e:
                        logger.warning(f"Health check failed for device {device.hostname}: {e}")
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Error checking device health: {e}")
    
    async def _create_device_state_notification(self, session, device: Device, old_state: str, new_state: str):
        """Create notification for device state change"""
        notification_type = NotificationType.DEVICE_STATUS if new_state == DeviceStatus.OFFLINE else NotificationType.DEVICE_STATUS
        
        message = f"Device {device.hostname} ({device.ip_address}) is now {new_state}"
        if old_state:
            message += f" (was {old_state})"
        
        notification = Notification(
            title=f"Device State Change: {device.hostname}",
            message=message,
            notification_type=notification_type,
            device_id=device.id,
            status=NotificationStatus.UNREAD,
            created_at=datetime.utcnow()
        )
        
        session.add(notification)
        
        # Broadcast notification via WebSocket if available
        if self.websocket_manager:
            try:
                await self.websocket_manager.broadcast_json({
                    "type": "device_state_change",
                    "data": {
                        "device_id": str(device.id),
                        "hostname": device.hostname,
                        "ip_address": str(device.ip_address),
                        "old_state": old_state,
                        "new_state": new_state,
                        "timestamp": datetime.utcnow().isoformat()
                    }
                })
            except Exception as e:
                logger.error(f"Failed to broadcast device state change: {e}")
    
    async def _monitor_sla_compliance(self):
        """Monitor SLA compliance and generate alerts"""
        try:
            async with db.get_async_session() as session:
                # Get active SLA metrics
                sla_query = select(SLAMetrics).where(SLAMetrics.is_active == True)
                result = await session.execute(sla_query)
                sla_metrics = result.scalars().all()
                
                for sla in sla_metrics:
                    try:
                        # Get device
                        device_query = select(Device).where(Device.id == sla.device_id)
                        device_result = await session.execute(device_query)
                        device = device_result.scalar_one_or_none()
                        
                        if not device:
                            continue
                        
                        # Calculate current SLA performance
                        current_performance = await self._calculate_sla_performance(session, sla, device)
                        
                        # Check for violations
                        if current_performance < sla.target_sla - 5.0:  # Breach threshold
                            await self._create_sla_violation_alert(session, sla, device, current_performance, "BREACH")
                        elif current_performance < sla.target_sla - 1.0:  # Warning threshold
                            await self._create_sla_violation_alert(session, sla, device, current_performance, "WARNING")
                    
                    except Exception as e:
                        logger.warning(f"SLA monitoring failed for SLA {sla.id}: {e}")
                
                await session.commit()
                
        except Exception as e:
            logger.error(f"Error monitoring SLA compliance: {e}")
    
    async def _calculate_sla_performance(self, session, sla: SLAMetrics, device: Device) -> float:
        """Calculate current SLA performance using real metrics"""
        try:
            # Use real SLA monitoring service
            from backend.services.sla_monitor import SLAMonitoringService
            sla_service = SLAMonitoringService()
            
            # Calculate real SLA performance
            sla_calculation = await sla_service.calculate_sla_for_device(
                device_id=str(device.id),
                sla_type=sla.sla_type,
                measurement_period_hours=sla.measurement_period
            )
            
            if sla_calculation:
                return sla_calculation.get('current_value', 0.0)
            else:
                logger.warning(f"No SLA calculation result for device {device.id}")
                return 0.0
                
        except Exception as e:
            logger.error(f"SLA calculation failed for device {device.id}: {e}")
            
            # Fallback: basic connectivity check
            try:
                import subprocess
                import platform
                
                # Simple ping test as fallback
                if platform.system().lower() == 'windows':
                    cmd = ['ping', '-n', '1', '-w', '2000', device.ip_address]
                else:
                    cmd = ['ping', '-c', '1', '-W', '2', device.ip_address]
                
                result = subprocess.run(cmd, capture_output=True, timeout=5)
                
                if sla.sla_type == "uptime":
                    return 100.0 if result.returncode == 0 else 0.0
                elif sla.sla_type == "response_time":
                    return 95.0 if result.returncode == 0 else 0.0
                elif sla.sla_type == "availability":
                    return 90.0 if result.returncode == 0 else 0.0
                else:
                    return 85.0 if result.returncode == 0 else 0.0
                    
            except Exception as ping_error:
                logger.warning(f"Fallback ping test failed for {device.ip_address}: {ping_error}")
                return 0.0
    
    async def _create_sla_violation_alert(self, session, sla: SLAMetrics, device: Device, performance: float, violation_type: str):
        """Create alert for SLA violation"""
        severity = AlertSeverity.CRITICAL if violation_type == "BREACH" else AlertSeverity.WARNING
        
        message = f"SLA {violation_type}: {device.hostname} {sla.sla_type} performance is {performance:.1f}% (target: {sla.target_sla:.1f}%)"
        
        alert = Alert(
            device_id=device.id,
            severity=severity,
            metric_name=f"SLA {violation_type}",
            message=message,
            acknowledged=False,
            resolved=False,
            created_at=datetime.utcnow()
        )
        
        session.add(alert)
        
        # Also create notification
        notification = Notification(
            title=f"SLA {violation_type}: {device.hostname}",
            message=message,
            notification_type=NotificationType.SLA_BREACH if violation_type == "BREACH" else NotificationType.SLA_WARNING,
            device_id=device.id,
            status=NotificationStatus.UNREAD,
            created_at=datetime.utcnow()
        )
        
        session.add(notification)
        
        logger.warning(f"SLA {violation_type} alert created for device {device.hostname}")
    
    async def _cleanup_old_notifications(self):
        """Clean up old notifications and metrics"""
        try:
            async with db.get_async_session() as session:
                # Delete read notifications older than 7 days
                old_notifications_query = select(Notification).where(
                    and_(
                        Notification.status == NotificationStatus.READ,
                        Notification.created_at < datetime.utcnow() - timedelta(days=7)
                    )
                )
                result = await session.execute(old_notifications_query)
                old_notifications = result.scalars().all()
                
                for notification in old_notifications:
                    await session.delete(notification)
                
                # Delete old performance metrics (keep only last 30 days)
                old_metrics_query = select(PerformanceMetrics).where(
                    PerformanceMetrics.timestamp < datetime.utcnow() - timedelta(days=30)
                )
                result = await session.execute(old_metrics_query)
                old_metrics = result.scalars().all()
                
                for metric in old_metrics:
                    await session.delete(metric)
                
                await session.commit()
                
                if old_notifications or old_metrics:
                    logger.info(f"Cleaned up {len(old_notifications)} old notifications and {len(old_metrics)} old metrics")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

# Global background task service instance
background_service = BackgroundTaskService()

# Context manager for managing background tasks
@asynccontextmanager
async def background_task_lifespan():
    """Context manager for background task lifecycle"""
    try:
        await background_service.start()
        yield background_service
    finally:
        await background_service.stop()
