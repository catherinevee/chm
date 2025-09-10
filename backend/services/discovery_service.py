"""
Discovery Service - Business logic for network discovery
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID, uuid4
import asyncio
import ipaddress
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload

from backend.database.models import DiscoveryJob, Device
from backend.services.device_service import DeviceService
from backend.services.notification_service import NotificationService
from backend.common.exceptions import AppException
from backend.monitoring.snmp_handler import SNMPHandler
import logging

logger = logging.getLogger(__name__)

class DiscoveryService:
    """Service for network discovery operations"""
    
    @staticmethod
    async def start_discovery(
        db: AsyncSession,
        discovery_data: Dict[str, Any],
        user_id: UUID
    ) -> DiscoveryJob:
        """Start a new network discovery job"""
        try:
            # Validate IP range
            try:
                network = ipaddress.ip_network(discovery_data['ip_range'], strict=False)
            except ValueError as e:
                raise AppException(
                    status_code=400,
                    detail=f"Invalid IP range: {str(e)}"
                )
            
            # Create discovery job
            job = DiscoveryJob(
                id=uuid4(),
                name=discovery_data.get('name', f"Discovery {datetime.utcnow().isoformat()}"),
                ip_range=str(network),
                protocol=discovery_data.get('protocol', 'snmp'),
                credentials=discovery_data.get('credentials', {}),
                options=discovery_data.get('options', {}),
                status='pending',
                created_by=user_id,
                created_at=datetime.utcnow()
            )
            
            db.add(job)
            await db.commit()
            await db.refresh(job)
            
            # Start discovery in background
            asyncio.create_task(
                DiscoveryService._run_discovery(db, job)
            )
            
            return job
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error starting discovery: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to start discovery: {str(e)}"
            )
    
    @staticmethod
    async def get_discovery_jobs(
        db: AsyncSession,
        skip: int = 0,
        limit: int = 100,
        status: Optional[str] = None
    ) -> List[DiscoveryJob]:
        """Get discovery jobs with filtering"""
        try:
            query = select(DiscoveryJob)
            
            if status:
                query = query.where(DiscoveryJob.status == status)
            
            query = query.order_by(DiscoveryJob.created_at.desc())
            query = query.offset(skip).limit(limit)
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Error getting discovery jobs: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get discovery jobs: {str(e)}"
            )
    
    @staticmethod
    async def get_job_details(
        db: AsyncSession,
        job_id: UUID
    ) -> DiscoveryJob:
        """Get discovery job details"""
        try:
            job = await db.get(DiscoveryJob, job_id)
            if not job:
                raise AppException(
                    status_code=404,
                    detail=f"Discovery job {job_id} not found"
                )
            
            return job
            
        except AppException:
            raise
        except Exception as e:
            logger.error(f"Error getting job details: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get job details: {str(e)}"
            )
    
    @staticmethod
    async def cancel_job(
        db: AsyncSession,
        job_id: UUID
    ) -> DiscoveryJob:
        """Cancel a running discovery job"""
        try:
            job = await db.get(DiscoveryJob, job_id)
            if not job:
                raise AppException(
                    status_code=404,
                    detail=f"Discovery job {job_id} not found"
                )
            
            if job.status not in ['pending', 'running']:
                raise AppException(
                    status_code=400,
                    detail=f"Cannot cancel job with status: {job.status}"
                )
            
            job.status = 'cancelled'
            job.completed_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(job)
            
            return job
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error cancelling job: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to cancel job: {str(e)}"
            )
    
    @staticmethod
    async def get_job_results(
        db: AsyncSession,
        job_id: UUID
    ) -> Dict[str, Any]:
        """Get discovery job results"""
        try:
            job = await db.get(DiscoveryJob, job_id)
            if not job:
                raise AppException(
                    status_code=404,
                    detail=f"Discovery job {job_id} not found"
                )
            
            return {
                'job_id': str(job.id),
                'status': job.status,
                'devices_found': job.devices_found,
                'devices_added': job.devices_added,
                'errors': job.errors,
                'results': job.results,
                'started_at': job.started_at.isoformat() if job.started_at else None,
                'completed_at': job.completed_at.isoformat() if job.completed_at else None
            }
            
        except AppException:
            raise
        except Exception as e:
            logger.error(f"Error getting job results: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get job results: {str(e)}"
            )
    
    @staticmethod
    async def _run_discovery(
        db: AsyncSession,
        job: DiscoveryJob
    ) -> None:
        """Run the discovery process"""
        try:
            # Update job status
            job.status = 'running'
            job.started_at = datetime.utcnow()
            await db.commit()
            
            # Parse IP range
            network = ipaddress.ip_network(job.ip_range, strict=False)
            discovered_devices = []
            errors = []
            
            # Discover devices based on protocol
            if job.protocol == 'snmp':
                discovered_devices = await DiscoveryService._discover_snmp(
                    network, job.credentials, errors
                )
            elif job.protocol == 'icmp':
                discovered_devices = await DiscoveryService._discover_icmp(
                    network, errors
                )
            else:
                errors.append(f"Unsupported protocol: {job.protocol}")
            
            # Process discovered devices
            devices_added = 0
            device_service = DeviceService()
            
            for device_info in discovered_devices:
                try:
                    # Check if device already exists
                    existing = await db.execute(
                        select(Device).where(
                            Device.ip_address == device_info['ip_address']
                        )
                    )
                    
                    if not existing.scalar():
                        # Create new device
                        device_data = {
                            'hostname': device_info.get('hostname', device_info['ip_address']),
                            'ip_address': device_info['ip_address'],
                            'device_type': device_info.get('device_type', 'router'),
                            'vendor': device_info.get('vendor', 'Unknown'),
                            'model': device_info.get('model'),
                            'location': device_info.get('location'),
                            'snmp_community': job.credentials.get('community'),
                            'snmp_version': job.credentials.get('version', '2c'),
                            'configuration': {
                                'discovered': True,
                                'discovery_job_id': str(job.id)
                            }
                        }
                        
                        await device_service.create_device(db, device_data)
                        devices_added += 1
                        
                except Exception as e:
                    errors.append(f"Error adding device {device_info.get('ip_address')}: {str(e)}")
            
            # Update job with results
            job.status = 'completed'
            job.completed_at = datetime.utcnow()
            job.devices_found = len(discovered_devices)
            job.devices_added = devices_added
            job.errors = errors
            job.results = discovered_devices
            
            await db.commit()
            
            # Send notification
            notification_service = NotificationService()
            await notification_service.broadcast_notification(
                db,
                title=f"Discovery Completed: {job.name}",
                message=f"Found {job.devices_found} devices, added {job.devices_added} new devices",
                notification_type='discovery'
            )
            
        except Exception as e:
            logger.error(f"Error running discovery: {str(e)}")
            job.status = 'failed'
            job.completed_at = datetime.utcnow()
            job.errors = [str(e)]
            await db.commit()
    
    @staticmethod
    async def _discover_snmp(
        network: ipaddress.IPv4Network,
        credentials: Dict[str, Any],
        errors: List[str]
    ) -> List[Dict[str, Any]]:
        """Discover devices using SNMP"""
        discovered = []
        snmp_handler = SNMPHandler()
        
        # Limit to first 254 hosts for large networks
        hosts = list(network.hosts())[:254]
        
        for ip in hosts:
            try:
                device_info = await snmp_handler.get_device_info(
                    str(ip),
                    credentials.get('community', 'public'),
                    credentials.get('version', '2c')
                )
                
                if device_info:
                    discovered.append({
                        'ip_address': str(ip),
                        'hostname': device_info.get('sysName', str(ip)),
                        'vendor': device_info.get('vendor', 'Unknown'),
                        'model': device_info.get('model'),
                        'location': device_info.get('sysLocation'),
                        'device_type': DiscoveryService._determine_device_type(device_info)
                    })
                    
            except Exception as e:
                logger.debug(f"Failed to discover {ip}: {str(e)}")
                
        return discovered
    
    @staticmethod
    async def _discover_icmp(
        network: ipaddress.IPv4Network,
        errors: List[str]
    ) -> List[Dict[str, Any]]:
        """Discover devices using ICMP ping with raw sockets"""
        try:
            from backend.monitoring.icmp_handler import ICMPHandler
            
            icmp_handler = ICMPHandler(timeout=3.0)
            
            # Use the proper ICMP handler for discovery
            discovered_devices = await icmp_handler.discover_network(network, max_hosts=254)
            
            logger.info(f"ICMP discovery found {len(discovered_devices)} devices in {network}")
            return discovered_devices
            
        except Exception as e:
            error_msg = f"ICMP discovery error: {str(e)}"
            errors.append(error_msg)
            logger.error(error_msg)
            
            # Fallback to subprocess ping if raw socket fails
            logger.warning("Falling back to subprocess ping method")
            return await DiscoveryService._discover_icmp_fallback(network, errors)
    
    @staticmethod
    async def _discover_icmp_fallback(
        network: ipaddress.IPv4Network,
        errors: List[str]
    ) -> List[Dict[str, Any]]:
        """Fallback ICMP discovery using subprocess"""
        discovered = []
        
        # Limit to first 254 hosts for large networks
        hosts = list(network.hosts())[:254]
        
        # Use asyncio subprocess to run ping commands
        import platform
        import asyncio
        
        async def ping_host(ip: str) -> bool:
            """Ping a single host"""
            try:
                # Determine ping command based on OS
                if platform.system().lower() == 'windows':
                    cmd = ['ping', '-n', '1', '-w', '1000', str(ip)]
                else:
                    cmd = ['ping', '-c', '1', '-W', '1', str(ip)]
                
                # Run ping command
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL
                )
                
                # Wait for completion with timeout
                try:
                    returncode = await asyncio.wait_for(process.wait(), timeout=2.0)
                    return returncode == 0
                except asyncio.TimeoutError:
                    process.kill()
                    return False
                    
            except Exception as e:
                logger.debug(f"Ping error for {ip}: {str(e)}")
                return False
        
        # Create tasks for concurrent pinging
        tasks = []
        for ip in hosts:
            tasks.append(ping_host(str(ip)))
        
        # Run pings concurrently in batches to avoid overwhelming the system
        batch_size = 50
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            batch_hosts = hosts[i:i+batch_size]
            
            try:
                results = await asyncio.gather(*batch, return_exceptions=True)
                
                for ip, result in zip(batch_hosts, results):
                    if isinstance(result, bool) and result:
                        # Host responded to ping
                        discovered.append({
                            'ip_address': str(ip),
                            'hostname': str(ip),  # Will be resolved later
                            'device_type': 'unknown',
                            'discovery_method': 'icmp_fallback'
                        })
                        logger.debug(f"Discovered host via ICMP fallback: {ip}")
                    elif isinstance(result, Exception):
                        logger.debug(f"Ping exception for {ip}: {result}")
                        
            except Exception as e:
                errors.append(f"Batch ping error: {str(e)}")
                logger.error(f"Batch ping error: {str(e)}")
        
        # Try to resolve hostnames for discovered IPs
        for device in discovered:
            try:
                import socket
                hostname = socket.gethostbyaddr(device['ip_address'])[0]
                device['hostname'] = hostname
            except:
                pass  # Keep IP as hostname if resolution fails
                
        return discovered
    
    @staticmethod
    def _determine_device_type(device_info: Dict[str, Any]) -> str:
        """Determine device type from SNMP info"""
        sys_descr = device_info.get('sysDescr', '').lower()
        
        if 'router' in sys_descr or 'ios' in sys_descr:
            return 'router'
        elif 'switch' in sys_descr or 'catalyst' in sys_descr:
            return 'switch'
        elif 'firewall' in sys_descr or 'asa' in sys_descr:
            return 'firewall'
        elif 'server' in sys_descr or 'windows' in sys_descr or 'linux' in sys_descr:
            return 'server'
        else:
            return 'network_device'