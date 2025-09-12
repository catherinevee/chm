"""
Background Task Infrastructure for CHM
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from enum import Enum
import inspect
from functools import wraps

from sqlalchemy.ext.asyncio import AsyncSession
from backend.database.base import get_session
from backend.monitoring.snmp_handler import SNMPHandler
from backend.monitoring.ssh_handler import SSHHandler
from backend.services.metrics_service import MetricsService
from backend.services.alert_service import AlertService
from backend.services.device_service import DeviceService
from backend.services.notification_service import NotificationService
from backend.database.models import Device, DeviceMetric, Alert

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class BackgroundTask:
    """Represents a background task"""
    
    def __init__(
        self,
        name: str,
        func: Callable,
        args: tuple = (),
        kwargs: dict = None,
        interval: Optional[timedelta] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        max_retries: int = 3,
        retry_delay: float = 5.0
    ):
        self.id = uuid4()
        self.name = name
        self.func = func
        self.args = args
        self.kwargs = kwargs or {}
        self.interval = interval
        self.priority = priority
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.status = TaskStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.retry_count = 0
        self.result: Any = None
        self._cancel_event = asyncio.Event()
    
    async def execute(self):
        """Execute the task"""
        try:
            self.status = TaskStatus.RUNNING
            self.started_at = datetime.utcnow()
            
            # Check if function is async
            if inspect.iscoroutinefunction(self.func):
                self.result = await self.func(*self.args, **self.kwargs)
            else:
                # Run sync function in executor
                loop = asyncio.get_event_loop()
                self.result = await loop.run_in_executor(
                    None, self.func, *self.args, **self.kwargs
                )
            
            self.status = TaskStatus.COMPLETED
            self.completed_at = datetime.utcnow()
            return self.result
            
        except Exception as e:
            self.last_error = str(e)
            self.retry_count += 1
            
            if self.retry_count < self.max_retries:
                self.status = TaskStatus.PENDING
                await asyncio.sleep(self.retry_delay * self.retry_count)
                return await self.execute()
            else:
                self.status = TaskStatus.FAILED
                self.completed_at = datetime.utcnow()
                logger.error(f"Task {self.name} failed after {self.retry_count} retries: {e}")
                raise
    
    def cancel(self):
        """Cancel the task"""
        self._cancel_event.set()
        self.status = TaskStatus.CANCELLED
        self.completed_at = datetime.utcnow()
    
    @property
    def is_cancelled(self) -> bool:
        """Check if task is cancelled"""
        return self._cancel_event.is_set()


class TaskScheduler:
    """Manages background task scheduling and execution"""
    
    def __init__(self, max_workers: int = 10):
        self.max_workers = max_workers
        self.tasks: Dict[UUID, BackgroundTask] = {}
        self.periodic_tasks: Dict[str, BackgroundTask] = {}
        self.running_tasks: List[asyncio.Task] = []
        self._shutdown = False
        self._executor_task: Optional[asyncio.Task] = None
        self._task_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
    
    async def start(self):
        """Start the task scheduler"""
        if self._executor_task is None:
            self._executor_task = asyncio.create_task(self._task_executor())
            logger.info("Task scheduler started")
    
    async def stop(self):
        """Stop the task scheduler"""
        self._shutdown = True
        
        # Cancel all running tasks
        for task in self.running_tasks:
            task.cancel()
        
        # Wait for executor to finish
        if self._executor_task:
            await self._executor_task
        
        logger.info("Task scheduler stopped")
    
    async def _task_executor(self):
        """Main task executor loop"""
        workers = []
        
        try:
            while not self._shutdown:
                # Start workers up to max_workers
                while len(workers) < self.max_workers and not self._task_queue.empty():
                    try:
                        priority, task = await asyncio.wait_for(
                            self._task_queue.get(), timeout=0.1
                        )
                        
                        if not task.is_cancelled:
                            worker = asyncio.create_task(self._execute_task(task))
                            workers.append(worker)
                    except asyncio.TimeoutError:
                        break
                
                # Clean up completed workers
                workers = [w for w in workers if not w.done()]
                
                # Process periodic tasks
                await self._process_periodic_tasks()
                
                # Small delay to prevent busy loop
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Task executor error: {e}")
    
    async def _execute_task(self, task: BackgroundTask):
        """Execute a single task"""
        try:
            logger.info(f"Executing task: {task.name}")
            await task.execute()
            logger.info(f"Task completed: {task.name}")
        except Exception as e:
            logger.error(f"Task failed: {task.name} - {e}")
        finally:
            # Remove from active tasks
            if task.id in self.tasks:
                del self.tasks[task.id]
    
    async def _process_periodic_tasks(self):
        """Process periodic tasks"""
        current_time = datetime.utcnow()
        
        for name, task in list(self.periodic_tasks.items()):
            if task.interval and task.completed_at:
                next_run = task.completed_at + task.interval
                
                if current_time >= next_run:
                    # Create new task instance
                    new_task = BackgroundTask(
                        name=task.name,
                        func=task.func,
                        args=task.args,
                        kwargs=task.kwargs,
                        interval=task.interval,
                        priority=task.priority,
                        max_retries=task.max_retries,
                        retry_delay=task.retry_delay
                    )
                    
                    await self.submit_task(new_task)
    
    async def submit_task(
        self,
        task: BackgroundTask
    ) -> UUID:
        """Submit a task for execution"""
        self.tasks[task.id] = task
        
        # Add to priority queue (negative priority for max heap behavior)
        await self._task_queue.put((-task.priority.value, task))
        
        logger.info(f"Task submitted: {task.name} (ID: {task.id})")
        return task.id
    
    def schedule_periodic_task(
        self,
        name: str,
        func: Callable,
        interval: timedelta,
        args: tuple = (),
        kwargs: dict = None,
        priority: TaskPriority = TaskPriority.NORMAL
    ):
        """Schedule a periodic task"""
        task = BackgroundTask(
            name=name,
            func=func,
            args=args,
            kwargs=kwargs,
            interval=interval,
            priority=priority
        )
        
        self.periodic_tasks[name] = task
        logger.info(f"Periodic task scheduled: {name} (interval: {interval})")
    
    def cancel_task(self, task_id: UUID) -> bool:
        """Cancel a task"""
        if task_id in self.tasks:
            self.tasks[task_id].cancel()
            return True
        return False
    
    def get_task_status(self, task_id: UUID) -> Optional[TaskStatus]:
        """Get task status"""
        if task_id in self.tasks:
            return self.tasks[task_id].status
        
        # Return fallback task status when task not found
        fallback_data = FallbackData(
            data="unknown",
            source="task_status_fallback",
            confidence=0.0,
            metadata={"task_id": task_id, "reason": "Task not found"}
        )
        
        return create_failure_result(
            error=f"Task {task_id} not found",
            error_code="TASK_NOT_FOUND",
            fallback_data=fallback_data,
            suggestions=[
                "Task not found",
                "Check task ID",
                "Verify task exists",
                "Check task history"
            ]
        )


# Global task scheduler instance
task_scheduler = TaskScheduler()


# Predefined background tasks
async def monitor_device_health():
    """Monitor health of all devices with proper error handling and rate limiting"""
    session = None
    try:
        session = get_session()
        db = await session.__aenter__()
        
        device_service = DeviceService()
        metrics_service = MetricsService()
        alert_service = AlertService()
        
        # Get all devices in batches to avoid memory issues
        batch_size = 50
        skip = 0
        total_processed = 0
        total_errors = 0
        
        while True:
            try:
                devices = await device_service.get_devices(db, skip=skip, limit=batch_size)
                if not devices:
                    break
                
                # Process devices with concurrency control
                semaphore = asyncio.Semaphore(10)  # Max 10 concurrent device checks
                tasks = []
                
                for device in devices:
                    task = asyncio.create_task(
                        _monitor_single_device(semaphore, db, device, metrics_service, alert_service)
                    )
                    tasks.append(task)
                
                # Wait for all tasks with timeout
                try:
                    results = await asyncio.wait_for(
                        asyncio.gather(*tasks, return_exceptions=True),
                        timeout=300  # 5 minute timeout for batch
                    )
                    
                    # Count results
                    for result in results:
                        total_processed += 1
                        if isinstance(result, Exception):
                            total_errors += 1
                            logger.error(f"Device monitoring task failed: {result}")
                
                except asyncio.TimeoutError:
                    logger.warning(f"Device monitoring batch timed out after 5 minutes")
                    # Cancel remaining tasks
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    
                    total_errors += len([t for t in tasks if not t.done()])
                
                skip += batch_size
                
                # Small delay between batches to prevent overwhelming the system
                await asyncio.sleep(1)
            
            except Exception as e:
                logger.error(f"Error processing device batch starting at {skip}: {e}")
                total_errors += 1
                skip += batch_size  # Continue with next batch
        
        # Log summary
        logger.info(f"Device health monitoring completed: {total_processed} processed, {total_errors} errors")
        
        # Create system alert if error rate is high
        if total_processed > 0 and total_errors / total_processed > 0.1:  # More than 10% errors
            await alert_service.create_alert(
                db,
                {
                    'alert_type': 'system',
                    'severity': 'warning',
                    'message': f"High error rate in device monitoring: {total_errors}/{total_processed}",
                    'description': f"Device monitoring completed with {total_errors} errors out of {total_processed} devices"
                }
            )
                    
    except Exception as e:
        logger.error(f"Critical error in device health monitoring: {e}")
        # Try to create a critical system alert
        try:
            if session and db:
                alert_service = AlertService()
                await alert_service.create_alert(
                    db,
                    {
                        'alert_type': 'system',
                        'severity': 'critical',
                        'message': "Device health monitoring system failure",
                        'description': str(e)
                    }
                )
        except Exception as e:
            logger.debug(f"Exception caught: {e}")  # Avoid recursive errors
    
    finally:
        if session:
            try:
                await session.__aexit__(None, None, None)
            except Exception as e:
                logger.debug(f"Exception caught: {e}")


async def _monitor_single_device(
    semaphore: asyncio.Semaphore,
    db: AsyncSession,
    device: Device,
    metrics_service: MetricsService,
    alert_service: AlertService
) -> None:
    """Monitor a single device with rate limiting"""
    async with semaphore:
        device_start_time = time.time()
        device_errors = []
        
        try:
            from backend.monitoring.snmp_handler import SNMPHandler
            from backend.monitoring.ssh_handler import SSHHandler
            
            snmp_handler = SNMPHandler()
            ssh_handler = SSHHandler()
            
            metrics_data = []
            connection_successful = False
            
            # Try SNMP first if available
            if device.snmp_community:
                try:
                    # Use vendor-specific metrics if vendor is known
                    if device.vendor and device.vendor.lower() in ['cisco', 'juniper', 'arista']:
                        vendor_metrics = await snmp_handler.get_vendor_specific_metrics(
                            device.ip_address,
                            device.vendor,
                            device.snmp_community,
                            device.snmp_version or '2c'
                        )
                        
                        # Convert vendor metrics to standard format
                        for metric_name, value in vendor_metrics.items():
                            if isinstance(value, (int, float)) and value >= 0:
                                metrics_data.append({
                                    'device_id': device.id,
                                    'name': metric_name,
                                    'value': float(value),
                                    'unit': 'percent' if 'usage' in metric_name else 'bytes'
                                })
                    else:
                        # Standard SNMP metrics
                        cpu = await asyncio.wait_for(
                            snmp_handler.get_cpu_usage(
                                device.ip_address,
                                device.snmp_community,
                                device.snmp_version or '2c'
                            ),
                            timeout=30
                        )
                        
                        memory = await asyncio.wait_for(
                            snmp_handler.get_memory_usage(
                                device.ip_address,
                                device.snmp_community,
                                device.snmp_version or '2c'
                            ),
                            timeout=30
                        )
                        
                        if cpu > 0:
                            metrics_data.append({
                                'device_id': device.id,
                                'name': 'cpu_usage',
                                'value': cpu,
                                'unit': 'percent'
                            })
                        
                        if memory.get('percent', 0) > 0:
                            metrics_data.append({
                                'device_id': device.id,
                                'name': 'memory_usage',
                                'value': memory['percent'],
                                'unit': 'percent'
                            })
                    
                    connection_successful = True
                    
                except asyncio.TimeoutError:
                    error_msg = "SNMP connection timeout"
                    device_errors.append(error_msg)
                    logger.warning(f"Device {device.hostname}: {error_msg}")
                
                except Exception as e:
                    error_msg = f"SNMP error: {str(e)}"
                    device_errors.append(error_msg)
                    logger.debug(f"Device {device.hostname}: {error_msg}")
            
            # Try SSH if SNMP failed or is not configured
            if not connection_successful and device.ssh_username:
                try:
                    info = await asyncio.wait_for(
                        ssh_handler.get_device_info(
                            device.ip_address,
                            device.ssh_username,
                            device.ssh_password,
                            device.ssh_key_path
                        ),
                        timeout=45
                    )
                    
                    if 'cpu_usage' in info and isinstance(info['cpu_usage'], (int, float)):
                        metrics_data.append({
                            'device_id': device.id,
                            'name': 'cpu_usage',
                            'value': float(info['cpu_usage']),
                            'unit': 'percent'
                        })
                    
                    if 'memory' in info and isinstance(info['memory'], dict):
                        mem_data = info['memory']
                        if mem_data.get('total', 0) > 0:
                            percent = (mem_data.get('used', 0) / mem_data['total']) * 100
                            metrics_data.append({
                                'device_id': device.id,
                                'name': 'memory_usage',
                                'value': percent,
                                'unit': 'percent'
                            })
                    
                    connection_successful = True
                    
                except asyncio.TimeoutError:
                    error_msg = "SSH connection timeout"
                    device_errors.append(error_msg)
                    logger.warning(f"Device {device.hostname}: {error_msg}")
                
                except Exception as e:
                    error_msg = f"SSH error: {str(e)}"
                    device_errors.append(error_msg)
                    logger.debug(f"Device {device.hostname}: {error_msg}")
            
            # Store metrics if any were collected
            if metrics_data:
                try:
                    await metrics_service.bulk_create_metrics(db, metrics_data)
                except Exception as e:
                    error_msg = f"Failed to store metrics: {str(e)}"
                    device_errors.append(error_msg)
                    logger.error(f"Device {device.hostname}: {error_msg}")
            
            # Update device status
            current_time = datetime.utcnow()
            previous_state = device.current_state
            
            if connection_successful:
                device.current_state = 'active'
                device.last_seen = current_time
                
                # Clear any connectivity alerts if device is back up
                if previous_state in ['down', 'unknown']:
                    logger.info(f"Device {device.hostname} is back online")
            else:
                device.current_state = 'down'
                
                # Create connectivity alert only if state changed from active
                if previous_state == 'active':
                    await alert_service.create_alert(
                        db,
                        {
                            'device_id': device.id,
                            'alert_type': 'connectivity',
                            'severity': 'warning',
                            'message': f"Device {device.hostname} is unreachable",
                            'description': '; '.join(device_errors) if device_errors else "No specific error details",
                            'metadata': {
                                'previous_state': previous_state,
                                'errors': device_errors,
                                'monitoring_duration': time.time() - device_start_time
                            }
                        }
                    )
                    logger.warning(f"Device {device.hostname} went offline")
            
            # Commit device state changes
            await db.commit()
            
            # Log successful completion
            duration = time.time() - device_start_time
            if connection_successful:
                logger.debug(f"Monitored device {device.hostname} successfully in {duration:.2f}s")
            else:
                logger.warning(f"Failed to monitor device {device.hostname} after {duration:.2f}s: {'; '.join(device_errors)}")
        
        except Exception as e:
            # This catches any unexpected errors in the monitoring process
            error_msg = f"Unexpected error monitoring device {device.hostname}: {str(e)}"
            logger.error(error_msg)
            
            try:
                await alert_service.create_alert(
                    db,
                    {
                        'device_id': device.id,
                        'alert_type': 'system',
                        'severity': 'error',
                        'message': f"Monitoring system error for {device.hostname}",
                        'description': str(e)
                    }
                )
            except Exception as e:

                logger.debug(f"Exception: {e}")
                # Avoid recursive errors
                pass


async def cleanup_old_data():
    """Clean up old metrics and logs"""
    async with get_session() as db:
        try:
            metrics_service = MetricsService()
            
            # Delete metrics older than 90 days
            deleted_count = await metrics_service.delete_old_metrics(db, days=90)
            logger.info(f"Cleaned up {deleted_count} old metrics")
            
            # Clean up resolved alerts older than 30 days
            from sqlalchemy import delete
            cutoff = datetime.utcnow() - timedelta(days=30)
            
            stmt = delete(Alert).where(
                Alert.status == 'resolved',
                Alert.resolved_at < cutoff
            )
            
            result = await db.execute(stmt)
            await db.commit()
            
            logger.info(f"Cleaned up {result.rowcount} old alerts")
            
        except Exception as e:
            logger.error(f"Data cleanup error: {e}")


async def check_sla_compliance():
    """Check SLA compliance for all devices"""
    async with get_session() as db:
        try:
            from backend.services.sla_service import SLAService
            sla_service = SLAService()
            
            # Get all active SLAs
            slas = await sla_service.get_slas(db, status='active')
            
            for sla in slas:
                try:
                    # Check compliance
                    compliance = await sla_service.check_compliance(db, sla.id)
                    
                    # Create alert if not compliant
                    if not compliance['is_compliant']:
                        alert_service = AlertService()
                        await alert_service.create_alert(
                            db,
                            {
                                'device_id': sla.device_id,
                                'alert_type': 'sla_violation',
                                'severity': 'warning',
                                'message': f"SLA violation: {sla.name}",
                                'description': f"Compliance: {compliance['compliance_percentage']:.1f}%",
                                'metadata': compliance
                            }
                        )
                        
                except Exception as e:
                    logger.error(f"Error checking SLA {sla.name}: {e}")
                    
        except Exception as e:
            logger.error(f"SLA compliance check error: {e}")


async def generate_reports():
    """Generate scheduled reports"""
    async with get_session() as db:
        try:
            from backend.services.report_service import ReportService
            report_service = ReportService()
            notification_service = NotificationService()
            
            # Generate daily summary report
            report = await report_service.generate_summary_report(db)
            
            # Send notification
            await notification_service.broadcast_notification(
                db,
                title="Daily Network Report",
                message=f"Report generated with {report['total_devices']} devices monitored",
                notification_type='report',
                metadata=report
            )
            
            logger.info("Daily report generated successfully")
            
        except Exception as e:
            logger.error(f"Report generation error: {e}")


def schedule_default_tasks():
    """Schedule default background tasks"""
    # Monitor device health every 5 minutes
    task_scheduler.schedule_periodic_task(
        name="device_health_monitor",
        func=monitor_device_health,
        interval=timedelta(minutes=5),
        priority=TaskPriority.HIGH
    )
    
    # Clean up old data daily at midnight
    task_scheduler.schedule_periodic_task(
        name="data_cleanup",
        func=cleanup_old_data,
        interval=timedelta(days=1),
        priority=TaskPriority.LOW
    )
    
    # Check SLA compliance every hour
    task_scheduler.schedule_periodic_task(
        name="sla_compliance_check",
        func=check_sla_compliance,
        interval=timedelta(hours=1),
        priority=TaskPriority.NORMAL
    )
    
    # Generate reports daily
    task_scheduler.schedule_periodic_task(
        name="report_generation",
        func=generate_reports,
        interval=timedelta(days=1),
        priority=TaskPriority.NORMAL
    )
    
    logger.info("Default background tasks scheduled")