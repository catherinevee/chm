"""
Monitoring Tasks - Background tasks for device monitoring and metrics collection
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from uuid import UUID
import json

from celery import Task
from backend.tasks.celery_app import celery_app
from backend.database.base import get_session, AsyncSessionLocal
from backend.database.models import Device, DeviceMetric, Alert, NetworkInterface
from backend.protocols.snmp_client import SNMPPoller
from backend.protocols.ssh_client import DeviceSSHManager
from backend.services.metrics_service import MetricsService
from backend.services.alert_service import AlertService
from backend.services.device_service import DeviceService
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class DatabaseTask(Task):
    """Base task class with database session management"""
    
    _db: Optional[AsyncSession] = None
    
    @property
    def db(self) -> AsyncSession:
        if self._db is None:
            self._db = AsyncSessionLocal()
        return self._db
    
    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        """Clean up database session after task completion"""
        if self._db is not None:
            asyncio.run(self._db.close())
            self._db = None


@celery_app.task(base=DatabaseTask, bind=True, name='backend.tasks.monitoring_tasks.poll_device')
def poll_device(self, device_id: str) -> Dict[str, Any]:
    """
    Poll a single device for metrics
    
    Args:
        device_id: Device UUID
        
    Returns:
        Polling results
    """
    try:
        return asyncio.run(self._poll_device_async(device_id))
    except Exception as e:
        logger.error(f"Error polling device {device_id}: {str(e)}")
        raise self.retry(exc=e, countdown=60, max_retries=3)

async def _poll_device_async(self, device_id: str) -> Dict[str, Any]:
    """Async device polling implementation"""
    async with AsyncSessionLocal() as db:
        try:
            # Get device
            device = await db.get(Device, UUID(device_id))
            if not device:
                return {'error': f'Device {device_id} not found'}
            
            if not device.is_active:
                return {'error': f'Device {device_id} is not active'}
            
            results = {
                'device_id': device_id,
                'hostname': device.hostname,
                'timestamp': datetime.utcnow(),
                'metrics': {},
                'errors': []
            }
            
            # SNMP polling
            if device.snmp_community_encrypted:
                try:
                    snmp_metrics = await self._poll_snmp(device)
                    results['metrics']['snmp'] = snmp_metrics
                    
                    # Store metrics
                    await self._store_metrics(db, device.id, snmp_metrics)
                    
                except Exception as e:
                    logger.error(f"SNMP polling failed for {device.hostname}: {str(e)}")
                    results['errors'].append(f"SNMP: {str(e)}")
            
            # SSH polling
            if device.ssh_username and (device.ssh_password_encrypted or device.ssh_key_encrypted):
                try:
                    ssh_metrics = await self._poll_ssh(device)
                    results['metrics']['ssh'] = ssh_metrics
                    
                    # Store metrics
                    await self._store_metrics(db, device.id, ssh_metrics)
                    
                except Exception as e:
                    logger.error(f"SSH polling failed for {device.hostname}: {str(e)}")
                    results['errors'].append(f"SSH: {str(e)}")
            
            # ICMP ping check
            try:
                ping_result = await self._check_ping(device.ip_address)
                results['metrics']['ping'] = ping_result
                
                # Store availability metric
                await self._store_availability(db, device.id, ping_result['alive'])
                
            except Exception as e:
                logger.error(f"Ping check failed for {device.hostname}: {str(e)}")
                results['errors'].append(f"Ping: {str(e)}")
            
            # Update device status
            await self._update_device_status(db, device, results)
            
            # Check thresholds and create alerts
            await self._check_thresholds(db, device, results['metrics'])
            
            await db.commit()
            
            return results
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error in device polling: {str(e)}")
            return {'error': str(e)}


async def _poll_snmp(self, device: Device) -> Dict[str, Any]:
    """Poll device using SNMP"""
    from backend.common.security import credential_encryption
    
    # Decrypt SNMP community
    community = credential_encryption.decrypt_snmp_credential(
        device.snmp_community_encrypted
    )
    
    # Create SNMP poller
    poller = SNMPPoller()
    
    # Poll device
    device_config = {
        'ip_address': device.ip_address,
        'snmp_community': community,
        'snmp_version': device.snmp_version or 'v2c',
        'vendor': device.manufacturer or 'generic'
    }
    
    metrics = await poller.poll_device(device_config)
    
    # Clean up
    poller.cleanup()
    
    return metrics


async def _poll_ssh(self, device: Device) -> Dict[str, Any]:
    """Poll device using SSH"""
    from backend.common.security import credential_encryption
    
    # Prepare SSH credentials
    ssh_params = {
        'host': device.ip_address,
        'username': device.ssh_username,
        'vendor': device.manufacturer or 'generic'
    }
    
    # Decrypt password or key
    if device.ssh_password_encrypted:
        ssh_params['password'] = credential_encryption.decrypt_credential(
            device.ssh_password_encrypted
        )
    elif device.ssh_key_encrypted:
        ssh_params['private_key'] = credential_encryption.decrypt_credential(
            device.ssh_key_encrypted
        )
    
    # Create SSH manager
    manager = DeviceSSHManager()
    
    # Get device info
    device_info = await manager.get_device_info(ssh_params)
    
    # Get interfaces
    interfaces = await manager.get_interfaces(ssh_params)
    
    return {
        'device_info': device_info,
        'interfaces': interfaces
    }


async def _check_ping(self, ip_address: str) -> Dict[str, Any]:
    """Check device availability using ping"""
    import ping3
    
    response_time = ping3.ping(ip_address, timeout=2)
    
    return {
        'alive': response_time is not None,
        'response_time': response_time * 1000 if response_time else None,  # Convert to ms
        'timestamp': datetime.utcnow()
    }


async def _store_metrics(self, db: AsyncSession, device_id: UUID, metrics: Dict[str, Any]):
    """Store collected metrics in database"""
    metric_service = MetricsService()
    
    # Process SNMP metrics
    if 'cpu' in metrics:
        for key, value in metrics['cpu'].items():
            await metric_service.create_metric(
                db,
                device_id,
                {
                    'name': f'cpu_{key}',
                    'value': value,
                    'unit': 'percent',
                    'timestamp': datetime.utcnow()
                }
            )
    
    # Process memory metrics
    if 'memory' in metrics:
        memory = metrics['memory']
        if 'percent_used' in memory:
            await metric_service.create_metric(
                db,
                device_id,
                {
                    'name': 'memory_usage',
                    'value': memory['percent_used'],
                    'unit': 'percent',
                    'timestamp': datetime.utcnow()
                }
            )
    
    # Process interface metrics
    if 'interfaces' in metrics:
        for interface in metrics['interfaces']:
            # Store interface metrics
            await metric_service.create_metric(
                db,
                device_id,
                {
                    'name': f"interface_{interface.get('name', 'unknown')}_in_octets",
                    'value': interface.get('in_octets', 0),
                    'unit': 'bytes',
                    'timestamp': datetime.utcnow()
                }
            )
            
            await metric_service.create_metric(
                db,
                device_id,
                {
                    'name': f"interface_{interface.get('name', 'unknown')}_out_octets",
                    'value': interface.get('out_octets', 0),
                    'unit': 'bytes',
                    'timestamp': datetime.utcnow()
                }
            )


async def _store_availability(self, db: AsyncSession, device_id: UUID, is_alive: bool):
    """Store device availability metric"""
    metric_service = MetricsService()
    
    await metric_service.create_metric(
        db,
        device_id,
        {
            'name': 'availability',
            'value': 1 if is_alive else 0,
            'unit': 'boolean',
            'timestamp': datetime.utcnow()
        }
    )


async def _update_device_status(self, db: AsyncSession, device: Device, results: Dict[str, Any]):
    """Update device status based on polling results"""
    # Determine new state
    if results.get('errors'):
        if len(results['errors']) == len(results.get('metrics', {}).keys()):
            # All polling methods failed
            device.current_state = 'down'
            device.consecutive_failures += 1
        else:
            # Partial failure
            device.current_state = 'degraded'
    else:
        # Success
        device.current_state = 'up'
        device.consecutive_failures = 0
    
    # Update last poll time
    device.last_poll_time = datetime.utcnow()
    
    # Check circuit breaker
    if device.consecutive_failures >= 5:
        device.circuit_breaker_trips += 1
        device.is_active = False  # Disable polling temporarily
        
        # Create alert
        alert_service = AlertService()
        await alert_service.create_alert(
            db,
            {
                'device_id': device.id,
                'alert_type': 'circuit_breaker',
                'severity': 'error',
                'message': f'Device {device.hostname} circuit breaker triggered',
                'description': f'Device has failed {device.consecutive_failures} consecutive polls'
            }
        )


async def _check_thresholds(self, db: AsyncSession, device: Device, metrics: Dict[str, Any]):
    """Check metrics against thresholds and create alerts"""
    alert_service = AlertService()
    
    # Get device thresholds from configuration
    thresholds = device.configuration.get('thresholds', {}) if device.configuration else {}
    
    # Default thresholds if not configured
    if not thresholds:
        thresholds = {
            'cpu_usage': {'warning': 70, 'critical': 90},
            'memory_usage': {'warning': 80, 'critical': 95},
            'interface_errors': {'warning': 100, 'critical': 1000}
        }
    
    # Check CPU thresholds
    if 'snmp' in metrics and 'cpu' in metrics['snmp']:
        cpu_usage = metrics['snmp']['cpu'].get('5min', 0)
        if cpu_usage > thresholds.get('cpu_usage', {}).get('critical', 90):
            await alert_service.create_alert(
                db,
                {
                    'device_id': device.id,
                    'alert_type': 'threshold',
                    'severity': 'critical',
                    'message': f'CPU usage critical: {cpu_usage}%',
                    'metadata': {'metric': 'cpu_usage', 'value': cpu_usage}
                }
            )
        elif cpu_usage > thresholds.get('cpu_usage', {}).get('warning', 70):
            await alert_service.create_alert(
                db,
                {
                    'device_id': device.id,
                    'alert_type': 'threshold',
                    'severity': 'warning',
                    'message': f'CPU usage high: {cpu_usage}%',
                    'metadata': {'metric': 'cpu_usage', 'value': cpu_usage}
                }
            )


@celery_app.task(base=DatabaseTask, bind=True, name='backend.tasks.monitoring_tasks.poll_all_devices')
def poll_all_devices(self) -> Dict[str, Any]:
    """Poll all active devices"""
    try:
        return asyncio.run(self._poll_all_devices_async())
    except Exception as e:
        logger.error(f"Error polling all devices: {str(e)}")
        raise

async def _poll_all_devices_async(self) -> Dict[str, Any]:
    """Async implementation of poll all devices"""
    async with AsyncSessionLocal() as db:
        try:
            # Get all active devices
            result = await db.execute(
                select(Device).where(Device.is_active == True)
            )
            devices = result.scalars().all()
            
            logger.info(f"Starting poll for {len(devices)} devices")
            
            # Create tasks for each device
            poll_tasks = []
            for device in devices:
                # Queue individual device polling task
                task = poll_device.delay(str(device.id))
                poll_tasks.append(task)
            
            return {
                'devices_queued': len(devices),
                'timestamp': datetime.utcnow(),
                'task_ids': [task.id for task in poll_tasks]
            }
            
        except Exception as e:
            logger.error(f"Error queuing device polls: {str(e)}")
            return {'error': str(e)}


@celery_app.task(base=DatabaseTask, bind=True, name='backend.tasks.monitoring_tasks.check_device_health')
def check_device_health(self) -> Dict[str, Any]:
    """Check health status of all devices"""
    try:
        return asyncio.run(self._check_device_health_async())
    except Exception as e:
        logger.error(f"Error checking device health: {str(e)}")
        raise

async def _check_device_health_async(self) -> Dict[str, Any]:
    """Async implementation of device health check"""
    async with AsyncSessionLocal() as db:
        try:
            # Get devices that haven't been polled recently
            stale_time = datetime.utcnow() - timedelta(minutes=10)
            
            result = await db.execute(
                select(Device).where(
                    and_(
                        Device.is_active == True,
                        or_(
                            Device.last_poll_time < stale_time,
                            Device.last_poll_time.is_(None)
                        )
                    )
                )
            )
            stale_devices = result.scalars().all()
            
            # Create alerts for stale devices
            alert_service = AlertService()
            alerts_created = 0
            
            for device in stale_devices:
                await alert_service.create_alert(
                    db,
                    {
                        'device_id': device.id,
                        'alert_type': 'polling_failure',
                        'severity': 'warning',
                        'message': f'Device {device.hostname} has not been polled recently',
                        'metadata': {
                            'last_poll': device.last_poll_time.isoformat() if device.last_poll_time else None
                        }
                    }
                )
                alerts_created += 1
            
            await db.commit()
            
            return {
                'stale_devices': len(stale_devices),
                'alerts_created': alerts_created,
                'timestamp': datetime.utcnow()
            }
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error in health check: {str(e)}")
            return {'error': str(e)}


@celery_app.task(base=DatabaseTask, bind=True, name='backend.tasks.monitoring_tasks.aggregate_metrics')
def aggregate_metrics(self) -> Dict[str, Any]:
    """Aggregate metrics for reporting and analysis"""
    try:
        return asyncio.run(self._aggregate_metrics_async())
    except Exception as e:
        logger.error(f"Error aggregating metrics: {str(e)}")
        raise

async def _aggregate_metrics_async(self) -> Dict[str, Any]:
    """Async implementation of metric aggregation"""
    async with AsyncSessionLocal() as db:
        try:
            # Time ranges for aggregation
            now = datetime.utcnow()
            hour_ago = now - timedelta(hours=1)
            day_ago = now - timedelta(days=1)
            
            # Get all devices
            result = await db.execute(select(Device))
            devices = result.scalars().all()
            
            aggregated = {
                'hourly': {},
                'daily': {},
                'timestamp': now
            }
            
            for device in devices:
                # Get hourly metrics
                hourly_metrics = await db.execute(
                    select(DeviceMetric).where(
                        and_(
                            DeviceMetric.device_id == device.id,
                            DeviceMetric.timestamp >= hour_ago
                        )
                    )
                )
                
                # Calculate averages
                metrics_list = hourly_metrics.scalars().all()
                if metrics_list:
                    cpu_values = [m.value for m in metrics_list if 'cpu' in m.metric_type]
                    memory_values = [m.value for m in metrics_list if 'memory' in m.metric_type]
                    
                    aggregated['hourly'][str(device.id)] = {
                        'cpu_avg': sum(cpu_values) / len(cpu_values) if cpu_values else 0,
                        'memory_avg': sum(memory_values) / len(memory_values) if memory_values else 0,
                        'sample_count': len(metrics_list)
                    }
            
            logger.info(f"Aggregated metrics for {len(devices)} devices")
            
            return aggregated
            
        except Exception as e:
            logger.error(f"Error in metric aggregation: {str(e)}")
            return {'error': str(e)}


@celery_app.task(base=DatabaseTask, bind=True, name='backend.tasks.monitoring_tasks.check_certificates')
def check_certificates(self) -> Dict[str, Any]:
    """Check SSL certificate expiry for HTTPS-enabled devices"""
    try:
        return asyncio.run(self._check_certificates_async())
    except Exception as e:
        logger.error(f"Error checking certificates: {str(e)}")
        raise

async def _check_certificates_async(self) -> Dict[str, Any]:
    """Async implementation of certificate checking"""
    import ssl
    import socket
    from datetime import datetime
    
    async with AsyncSessionLocal() as db:
        try:
            # Get devices with HTTPS enabled
            result = await db.execute(
                select(Device).where(
                    and_(
                        Device.is_active == True,
                        Device.configuration['https_enabled'].astext == 'true'
                    )
                )
            )
            devices = result.scalars().all()
            
            expiring_soon = []
            expired = []
            
            for device in devices:
                try:
                    # Check certificate
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((device.ip_address, 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=device.ip_address) as ssock:
                            cert = ssock.getpeercert()
                            
                            if cert:
                                # Parse expiry date
                                not_after = datetime.strptime(
                                    cert['notAfter'],
                                    '%b %d %H:%M:%S %Y %Z'
                                )
                                
                                days_until_expiry = (not_after - datetime.utcnow()).days
                                
                                if days_until_expiry < 0:
                                    expired.append({
                                        'device': device.hostname,
                                        'expired_days_ago': abs(days_until_expiry)
                                    })
                                elif days_until_expiry < 30:
                                    expiring_soon.append({
                                        'device': device.hostname,
                                        'days_until_expiry': days_until_expiry
                                    })
                                    
                except Exception as e:
                    logger.debug(f"Could not check certificate for {device.hostname}: {str(e)}")
            
            # Create alerts for expiring certificates
            alert_service = AlertService()
            
            for cert_info in expired:
                await alert_service.create_alert(
                    db,
                    {
                        'alert_type': 'certificate_expired',
                        'severity': 'critical',
                        'message': f"SSL certificate expired for {cert_info['device']}",
                        'metadata': cert_info
                    }
                )
            
            for cert_info in expiring_soon:
                await alert_service.create_alert(
                    db,
                    {
                        'alert_type': 'certificate_expiring',
                        'severity': 'warning',
                        'message': f"SSL certificate expiring soon for {cert_info['device']}",
                        'metadata': cert_info
                    }
                )
            
            await db.commit()
            
            return {
                'devices_checked': len(devices),
                'expired': expired,
                'expiring_soon': expiring_soon,
                'timestamp': datetime.utcnow()
            }
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error in certificate check: {str(e)}")
            return {'error': str(e)}