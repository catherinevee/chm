"""
Main collector service that orchestrates device polling
Implements adaptive scheduling and emergency response
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import json

from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials
from backend.collector.protocols.snmp.oids import CiscoOIDs, OIDDefinition
from backend.storage.database import db
from backend.storage.models import Device, DeviceState, Alert, AlertSeverity
import os

logger = logging.getLogger(__name__)

@dataclass
class CollectorMetrics:
    """Metrics for collector service monitoring"""
    devices_polled: int = 0
    polls_successful: int = 0
    polls_failed: int = 0
    total_poll_time: float = 0.0
    alerts_generated: int = 0
    emergency_responses: int = 0
    
    def get_success_rate(self) -> float:
        total = self.polls_successful + self.polls_failed
        return (self.polls_successful / total * 100) if total > 0 else 0.0
    
    def get_average_poll_time(self) -> float:
        return (self.total_poll_time / self.devices_polled) if self.devices_polled > 0 else 0.0

class CollectorService:
    """
    Main collector service that manages device polling
    """
    
    def __init__(self):
        self.running = False
        self.device_sessions: Dict[str, SNMPSession] = {}
        self.metrics = CollectorMetrics()
        self.alert_queue = asyncio.Queue()
        self.metric_queue = asyncio.Queue()
        
        # Worker configuration
        self.num_workers = int(os.getenv("MAX_WORKERS", "10"))
        self.batch_size = int(os.getenv("BATCH_SIZE", "100"))
        
    async def initialize(self):
        """Initialize collector service"""
        logger.info("Initializing collector service...")
        
        # Connect to database
        await db.connect()
        
        # Load devices from database
        await self.load_devices()
        
        logger.info(f"Collector service initialized with {len(self.device_sessions)} devices")
    
    async def load_devices(self):
        """Load devices from database and create SNMP sessions"""
        async with db.get_session() as session:
            # Query active devices with their credentials
            query = """
                SELECT d.*, 
                       array_agg(
                           json_build_object(
                               'protocol', dc.protocol,
                               'version', dc.version,
                               'credentials', dc.credentials,
                               'priority', dc.priority
                           ) ORDER BY dc.priority
                       ) as credentials
                FROM devices d
                LEFT JOIN device_credentials dc ON d.id = dc.device_id
                WHERE d.is_active = true
                GROUP BY d.id
            """
            
            result = await session.execute(query)
            devices = result.fetchall()
            
            for device in devices:
                # Parse credentials
                snmp_creds = []
                for cred in device.credentials:
                    if cred['protocol'] == 'snmp':
                        # Decrypt credentials here
                        decrypted = self.decrypt_credentials(cred['credentials'])
                        
                        snmp_creds.append(SNMPCredentials(
                            version=cred['version'],
                            community=decrypted.get('community'),
                            username=decrypted.get('username'),
                            auth_protocol=decrypted.get('auth_protocol'),
                            auth_password=decrypted.get('auth_password'),
                            priv_protocol=decrypted.get('priv_protocol'),
                            priv_password=decrypted.get('priv_password')
                        ))
                
                # Create SNMP session
                if snmp_creds:
                    session = SNMPSession(device.ip_address, snmp_creds)
                    self.device_sessions[device.hostname] = session
            
            logger.info(f"Loaded {len(self.device_sessions)} devices for monitoring")
    
    def decrypt_credentials(self, encrypted: dict) -> dict:
        """Decrypt stored credentials"""
        # Implement actual decryption here
        # For now, return as-is (assuming they're not encrypted in dev)
        return encrypted
    
    async def poll_device(self, device: Device) -> Dict[str, Any]:
        """
        Poll a single device and collect metrics
        """
        hostname = device.hostname
        session = self.device_sessions.get(hostname)
        
        if not session:
            logger.error(f"No SNMP session for {hostname}")
            return {}
        
        logger.info(f"Polling {hostname} (state: {device.current_state})")
        
        start_time = datetime.now()
        metrics = {
            'timestamp': start_time.isoformat(),
            'hostname': hostname,
            'device_type': device.device_type.value,
            'state': device.current_state.value
        }
        
        try:
            # Get OIDs based on device type
            oid_groups = CiscoOIDs.get_oids_for_device_type(device.device_type.value)
            
            # Adaptive polling based on device state
            if device.current_state in [DeviceState.CRITICAL, DeviceState.DEGRADED]:
                # Limited polling for struggling devices
                oid_groups = {
                    'cpu': oid_groups.get('cpu', [])[:1],  # Only first CPU OID
                    'memory': oid_groups.get('memory', {}).get('processor_pool_free', [])[:1]
                }
            
            # Collect metrics based on device capabilities
            for category, oids in oid_groups.items():
                if category == 'system' and device.current_state == DeviceState.HEALTHY:
                    # Skip system OIDs for routine polls
                    continue
                
                for oid_def in oids:
                    if isinstance(oid_def, OIDDefinition):
                        value, response_time = await session.get(oid_def.oid)
                        
                        if value is not None:
                            # Apply unit conversion
                            if oid_def.multiplier != 1.0:
                                value = value * oid_def.multiplier
                            
                            metrics[oid_def.name] = {
                                'value': value,
                                'unit': oid_def.unit,
                                'response_time': response_time
                            }
                            
                            # Check thresholds
                            await self.check_threshold(device, oid_def.name, value)
                        
                        # Add delay for CPU-constrained devices
                        if device.gentle_mode:
                            await asyncio.sleep(int(os.getenv("GENTLE_MODE_DELAY", "2")))
            
            # Calculate overall poll time
            poll_time = (datetime.now() - start_time).total_seconds()
            metrics['poll_duration'] = poll_time
            
            # Update device state based on metrics
            await self.update_device_state(device, metrics, success=True)
            
            # Update collector metrics
            self.metrics.devices_polled += 1
            self.metrics.polls_successful += 1
            self.metrics.total_poll_time += poll_time
            
            # Queue metrics for storage
            await self.metric_queue.put(metrics)
            
            return metrics
            
        except Exception as e:
            logger.error(f"Error polling {hostname}: {e}")
            
            # Update failure state
            await self.update_device_state(device, {}, success=False)
            
            self.metrics.devices_polled += 1
            self.metrics.polls_failed += 1
            
            return {}
    
    async def check_threshold(self, device: Device, metric_name: str, value: float):
        """Check if metric exceeds configured thresholds"""
        async with db.get_session() as session:
            # Query thresholds for this device and metric
            query = """
                SELECT warning_value, critical_value, comparison
                FROM thresholds
                WHERE (device_id = :device_id OR 
                       (device_id IS NULL AND device_type = :device_type))
                  AND metric_name = :metric_name
                  AND is_active = true
                ORDER BY device_id DESC NULLS LAST
                LIMIT 1
            """
            
            result = await session.execute(
                query,
                {
                    'device_id': device.id,
                    'device_type': device.device_type,
                    'metric_name': metric_name
                }
            )
            
            threshold = result.fetchone()
            
            if threshold:
                severity = None
                message = None
                
                # Check critical threshold
                if threshold.critical_value is not None:
                    if self.compare_value(value, threshold.critical_value, threshold.comparison):
                        severity = AlertSeverity.CRITICAL
                        message = f"{metric_name} is {value} (critical threshold: {threshold.critical_value})"
                
                # Check warning threshold if not critical
                elif threshold.warning_value is not None:
                    if self.compare_value(value, threshold.warning_value, threshold.comparison):
                        severity = AlertSeverity.WARNING
                        message = f"{metric_name} is {value} (warning threshold: {threshold.warning_value})"
                
                # Generate alert if threshold exceeded
                if severity and message:
                    alert = {
                        'device_id': device.id,
                        'hostname': device.hostname,
                        'severity': severity,
                        'metric_name': metric_name,
                        'metric_value': value,
                        'threshold_value': threshold.critical_value or threshold.warning_value,
                        'message': message,
                        'timestamp': datetime.now()
                    }
                    
                    await self.alert_queue.put(alert)
                    self.metrics.alerts_generated += 1
                    
                    # Trigger emergency response for critical memory/CPU
                    if severity == AlertSeverity.CRITICAL:
                        if metric_name == 'ciscoMemoryPoolFree' and value < 2000000:  # < 2MB
                            await self.emergency_memory_response(device)
                        elif metric_name in ['cpmCPUTotal5secRev', 'avgBusy5'] and value > 95:
                            await self.emergency_cpu_response(device)
    
    def compare_value(self, value: float, threshold: float, comparison: str) -> bool:
        """Compare value against threshold based on comparison operator"""
        if comparison == 'greater':
            return value > threshold
        elif comparison == 'less':
            return value < threshold
        elif comparison == 'equal':
            return value == threshold
        elif comparison == 'greater_equal':
            return value >= threshold
        elif comparison == 'less_equal':
            return value <= threshold
        return False
    
    async def update_device_state(self, device: Device, metrics: Dict, success: bool):
        """Update device state based on polling results"""
        async with db.get_session() as session:
            if success:
                # Reset failure counter on success
                device.consecutive_failures = 0
                device.last_success_time = datetime.now()
                
                # Determine new state based on response times
                if metrics.get('poll_duration', 0) > 10:
                    device.current_state = DeviceState.DEGRADED
                else:
                    device.current_state = DeviceState.HEALTHY
            else:
                # Increment failure counter
                device.consecutive_failures += 1
                
                # Update state based on failure count
                if device.consecutive_failures >= 5:
                    device.current_state = DeviceState.UNREACHABLE
                    device.circuit_breaker_trips += 1
                elif device.consecutive_failures >= 3:
                    device.current_state = DeviceState.CRITICAL
                elif device.consecutive_failures >= 1:
                    device.current_state = DeviceState.DEGRADED
            
            device.last_poll_time = datetime.now()
            
            # Update in database
            await session.merge(device)
            await session.commit()
    
    async def emergency_memory_response(self, device: Device):
        """Execute emergency memory cleanup"""
        logger.critical(f"Executing emergency memory cleanup on {device.hostname}")
        
        # Import SSH handler
        from backend.collector.protocols.ssh.connection import SSHConnection
        
        try:
            # Get SSH credentials
            ssh_creds = await self.get_ssh_credentials(device)
            if not ssh_creds:
                logger.error(f"No SSH credentials for {device.hostname}")
                return
            
            # Connect via SSH
            ssh = SSHConnection(device.ip_address, ssh_creds)
            await ssh.connect()
            
            # Execute cleanup commands
            commands = [
                "clear mac address-table dynamic",
                "clear arp-cache",
                "clear logging",
                "clear cdp table",
                "clear spanning-tree detected-protocols"
            ]
            
            for cmd in commands:
                await ssh.execute_command(cmd)
                await asyncio.sleep(1)  # Don't overwhelm device
            
            await ssh.disconnect()
            
            self.metrics.emergency_responses += 1
            logger.info(f"Emergency memory cleanup completed on {device.hostname}")
            
        except Exception as e:
            logger.error(f"Emergency response failed: {e}")
    
    async def emergency_cpu_response(self, device: Device):
        """Respond to high CPU condition"""
        logger.critical(f"High CPU detected on {device.hostname}")
        
        # Immediately back off polling
        device.poll_interval = min(600, device.poll_interval * 3)
        
        # Update state to critical
        device.current_state = DeviceState.CRITICAL
        
        async with db.get_session() as session:
            await session.merge(device)
            await session.commit()
        
        self.metrics.emergency_responses += 1
    
    async def get_ssh_credentials(self, device: Device) -> Optional[Dict]:
        """Get SSH credentials for device"""
        async with db.get_session() as session:
            query = """
                SELECT credentials
                FROM device_credentials
                WHERE device_id = :device_id
                  AND protocol = 'ssh'
                ORDER BY priority
                LIMIT 1
            """
            
            result = await session.execute(query, {'device_id': device.id})
            cred = result.fetchone()
            
            if cred:
                return self.decrypt_credentials(cred.credentials)
            
            # Return fallback credentials when none found
            fallback_data = FallbackData(
                data={},
                source="credentials_fallback",
                confidence=0.0,
                metadata={"device_id": device.id, "reason": "No credentials found"}
            )
            
            return create_failure_result(
                error=f"No credentials found for device {device.id}",
                error_code="CREDENTIALS_NOT_FOUND",
                fallback_data=fallback_data,
                suggestions=[
                    "No credentials found for device",
                    "Check device configuration",
                    "Verify credential storage",
                    "Add device credentials"
                ]
            )
    
    async def run(self):
        """Main collector service loop"""
        self.running = True
        logger.info("Starting collector service...")
        
        # Start metric processor
        metric_task = asyncio.create_task(self.process_metrics())
        
        # Start alert processor
        alert_task = asyncio.create_task(self.process_alerts())
        
        # Main polling loop
        try:
            while self.running:
                # Get devices to poll
                async with db.get_session() as session:
                    # Get devices that need polling
                    query = """
                        SELECT * FROM devices 
                        WHERE is_active = true 
                        AND (last_poll_time IS NULL OR 
                             last_poll_time < NOW() - INTERVAL '1 minute' * poll_interval)
                        ORDER BY last_poll_time ASC NULLS FIRST
                        LIMIT 10
                    """
                    
                    result = await session.execute(query)
                    devices = result.fetchall()
                
                # Poll devices
                for device in devices:
                    await self.poll_device(device)
                    await asyncio.sleep(1)  # Small delay between devices
                
                # Periodic metrics reporting
                if self.metrics.devices_polled % 100 == 0 and self.metrics.devices_polled > 0:
                    logger.info(
                        f"Collector metrics - Devices: {self.metrics.devices_polled}, "
                        f"Success rate: {self.metrics.get_success_rate():.1f}%, "
                        f"Avg poll time: {self.metrics.get_average_poll_time():.2f}s, "
                        f"Alerts: {self.metrics.alerts_generated}"
                    )
                
                # Wait before next polling cycle
                await asyncio.sleep(30)
        
        except KeyboardInterrupt:
            logger.info("Collector service interrupted")
        finally:
            self.running = False
            
            # Cancel all tasks
            metric_task.cancel()
            alert_task.cancel()
            
            # Wait for tasks to complete
            await asyncio.gather(
                metric_task, alert_task,
                return_exceptions=True
            )
            
            # Cleanup
            await self.cleanup()
    
    async def process_metrics(self):
        """Process metrics from queue and store in database"""
        while self.running:
            try:
                # Batch process metrics
                metrics_batch = []
                
                # Collect batch
                for _ in range(self.batch_size):
                    try:
                        metric = await asyncio.wait_for(
                            self.metric_queue.get(),
                            timeout=1.0
                        )
                        metrics_batch.append(metric)
                    except asyncio.TimeoutError:
                        break
                
                if metrics_batch:
                    await self.store_metrics(metrics_batch)
                    
            except Exception as e:
                logger.error(f"Error processing metrics: {e}")
                await asyncio.sleep(1)
    
    async def store_metrics(self, metrics_batch: List[Dict]):
        """Store metrics in InfluxDB"""
        # For now, just log metrics
        # In production, this would write to InfluxDB
        for metrics in metrics_batch:
            logger.debug(f"Storing metrics for {metrics['hostname']}: {metrics}")
    
    async def process_alerts(self):
        """Process alerts from queue"""
        while self.running:
            try:
                alert = await self.alert_queue.get()
                await self.handle_alert(alert)
            except Exception as e:
                logger.error(f"Error processing alert: {e}")
    
    async def handle_alert(self, alert_data: Dict):
        """Handle alert generation and notification"""
        async with db.get_session() as session:
            # Create alert record
            alert = Alert(
                device_id=alert_data['device_id'],
                severity=alert_data['severity'],
                metric_name=alert_data['metric_name'],
                metric_value=alert_data['metric_value'],
                threshold_value=alert_data['threshold_value'],
                message=alert_data['message']
            )
            
            session.add(alert)
            await session.commit()
            
            # Send notifications
            await self.send_notifications(alert_data)
    
    async def send_notifications(self, alert: Dict):
        """Send alert notifications to configured channels"""
        # For now, just log the alert
        # In production, this would send to Slack, email, etc.
        logger.warning(f"ALERT: {alert['hostname']} - {alert['message']}")
    
    async def cleanup(self):
        """Cleanup resources"""
        logger.info("Cleaning up collector service...")
        
        # Close SNMP sessions
        for session in self.device_sessions.values():
            await session.close()
        
        # Disconnect from database
        await db.disconnect()
        
        logger.info("Collector service cleanup complete")

# Entry point
async def main():
    """Main entry point for collector service"""
    collector = CollectorService()
    await collector.initialize()
    await collector.run()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
