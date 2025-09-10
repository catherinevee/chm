"""
Network discovery API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func
from pydantic import BaseModel, Field, IPvAnyAddress
import logging
import uuid

from backend.database.models import DiscoveryJob, Device
from backend.database.base import get_db
from backend.services.validation_service import ValidationService, ValidationError
from backend.api.dependencies.auth import (
    get_current_user,
    require_discovery_read,
    require_discovery_write,
    standard_rate_limit
)
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/discovery", tags=["discovery"])

# Database session dependency is imported from backend.database.base

class DiscoveryRequest(BaseModel):
    ip_range: str = Field(..., description="IP range in CIDR notation or range format")
    scan_type: str = Field(default="snmp", pattern="^(snmp|ssh|rest|auto)$")
    snmp_community: Optional[str] = Field(default="public")
    snmp_version: Optional[str] = Field(default="2c", pattern="^(1|2c|3)$")
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    ports: Optional[List[int]] = Field(default=[22, 23, 80, 443, 161])
    timeout: Optional[int] = Field(default=5, ge=1, le=30)
    parallel_scans: Optional[int] = Field(default=10, ge=1, le=50)

class DiscoveryJobResponse(BaseModel):
    id: str
    job_type: str
    status: str
    ip_range: str
    scan_type: str
    progress: int
    total_targets: int
    discovered_count: int
    error_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

class DiscoveryResult(BaseModel):
    job_id: str
    discovered_devices: List[Dict[str, Any]]
    failed_targets: List[str]
    summary: Dict[str, Any]

@router.post("/start", response_model=DiscoveryJobResponse, dependencies=[Depends(standard_rate_limit)])
async def start_discovery(
    discovery_request: DiscoveryRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_discovery_write),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Start a new network discovery job
    """
    try:
        # Validate IP range
        ip_range = ValidationService.validate_ip_range(discovery_request.ip_range)
        
        # Create discovery job
        job = DiscoveryJob(
            job_type="network_scan",
            status="pending",
            ip_range=ip_range,
            scan_type=discovery_request.scan_type,
            progress=0,
            total_targets=0,  # Will be calculated when job starts
            discovered_count=0,
            error_count=0,
            created_at=datetime.utcnow()
        )
        
        db_session.add(job)
        await db_session.commit()
        await db_session.refresh(job)
        
        # Start discovery in background
        background_tasks.add_task(
            run_discovery_job,
            str(job.id),
            discovery_request.dict(),
            str(current_user.id)
        )
        
        logger.info(f"Discovery job {job.id} started by user {current_user.username}")
        
        return DiscoveryJobResponse(
            id=str(job.id),
            job_type=job.job_type,
            status=job.status,
            ip_range=job.ip_range,
            scan_type=job.scan_type,
            progress=job.progress,
            total_targets=job.total_targets,
            discovered_count=job.discovered_count,
            error_count=job.error_count,
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_at=job.created_at
        )
        
    except ValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Error starting discovery: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to start discovery job"
        )

@router.get("", response_model=List[DiscoveryJobResponse])
async def list_discovery_jobs(
    status_filter: Optional[str] = None,
    limit: int = 50,
    current_user: User = Depends(require_discovery_read),
    db_session: AsyncSession = Depends(get_db)
):
    """
    List discovery jobs
    """
    try:
        query = select(DiscoveryJob).order_by(DiscoveryJob.created_at.desc())
        
        if status_filter:
            query = query.where(DiscoveryJob.status == status_filter)
        
        query = query.limit(limit)
        
        result = await db_session.execute(query)
        jobs = result.scalars().all()
        
        return [
            DiscoveryJobResponse(
                id=str(job.id),
                job_type=job.job_type,
                status=job.status,
                ip_range=job.ip_range,
                scan_type=job.scan_type,
                progress=job.progress,
                total_targets=job.total_targets,
                discovered_count=job.discovered_count,
                error_count=job.error_count,
                started_at=job.started_at,
                completed_at=job.completed_at,
                created_at=job.created_at
            )
            for job in jobs
        ]
        
    except Exception as e:
        logger.error(f"Error listing discovery jobs: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list discovery jobs"
        )

@router.get("/{job_id}", response_model=DiscoveryJobResponse)
async def get_discovery_job(
    job_id: str,
    current_user: User = Depends(require_discovery_read),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Get discovery job details
    """
    try:
        # Validate UUID
        try:
            uuid.UUID(job_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid job ID format"
            )
        
        result = await db_session.execute(
            select(DiscoveryJob).where(DiscoveryJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Discovery job not found"
            )
        
        return DiscoveryJobResponse(
            id=str(job.id),
            job_type=job.job_type,
            status=job.status,
            ip_range=job.ip_range,
            scan_type=job.scan_type,
            progress=job.progress,
            total_targets=job.total_targets,
            discovered_count=job.discovered_count,
            error_count=job.error_count,
            started_at=job.started_at,
            completed_at=job.completed_at,
            created_at=job.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting discovery job: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get discovery job"
        )

@router.post("/{job_id}/cancel")
async def cancel_discovery_job(
    job_id: str,
    current_user: User = Depends(require_discovery_write),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Cancel a running discovery job
    """
    try:
        result = await db_session.execute(
            select(DiscoveryJob).where(DiscoveryJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Discovery job not found"
            )
        
        if job.status not in ["pending", "running"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel job with status: {job.status}"
            )
        
        job.status = "cancelled"
        job.completed_at = datetime.utcnow()
        job.updated_at = datetime.utcnow()
        
        await db_session.commit()
        
        logger.info(f"Discovery job {job_id} cancelled by user {current_user.username}")
        
        return {"message": "Discovery job cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling discovery job: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to cancel discovery job"
        )

@router.get("/{job_id}/results", response_model=DiscoveryResult)
async def get_discovery_results(
    job_id: str,
    current_user: User = Depends(require_discovery_read),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Get results of a completed discovery job
    """
    try:
        # Get job
        result = await db_session.execute(
            select(DiscoveryJob).where(DiscoveryJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        
        if not job:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Discovery job not found"
            )
        
        if job.status not in ["completed", "failed"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Job not completed. Current status: {job.status}"
            )
        
        # Get discovered devices from this job
        # In a real implementation, you'd have a relationship or separate table
        # For now, we'll query devices created around the job time
        devices_result = await db_session.execute(
            select(Device).where(
                and_(
                    Device.created_at >= job.started_at,
                    Device.created_at <= (job.completed_at or datetime.utcnow())
                )
            )
        )
        devices = devices_result.scalars().all()
        
        discovered_devices = [
            {
                "id": str(device.id),
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "device_type": device.device_type,
                "manufacturer": device.manufacturer,
                "model": device.model,
                "discovery_protocol": device.discovery_protocol
            }
            for device in devices
        ]
        
        return DiscoveryResult(
            job_id=str(job.id),
            discovered_devices=discovered_devices,
            failed_targets=[],  # Would be tracked in real implementation
            summary={
                "total_targets": job.total_targets,
                "discovered": job.discovered_count,
                "failed": job.error_count,
                "duration_seconds": (
                    (job.completed_at - job.started_at).total_seconds()
                    if job.completed_at and job.started_at else 0
                )
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting discovery results: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get discovery results"
        )

# Background task function
async def run_discovery_job(job_id: str, config: dict, user_id: str):
    """
    Run discovery job in background
    """
    try:
        async with db.get_async_session() as session:
            # Update job status to running
            result = await session.execute(
                select(DiscoveryJob).where(DiscoveryJob.id == job_id)
            )
            job = result.scalar_one_or_none()
            
            if not job:
                logger.error(f"Discovery job {job_id} not found")
                return
            
            job.status = "running"
            job.started_at = datetime.utcnow()
            await session.commit()
            
            # Import discovery service
            from backend.discovery.service import DiscoveryService
            
            # Run discovery
            discovery_service = DiscoveryService()
            results = await discovery_service.discover_network(
                ip_range=config["ip_range"],
                scan_type=config["scan_type"],
                credentials={
                    "snmp_community": config.get("snmp_community"),
                    "snmp_version": config.get("snmp_version"),
                    "ssh_username": config.get("ssh_username"),
                    "ssh_password": config.get("ssh_password")
                },
                timeout=config.get("timeout", 5),
                parallel_scans=config.get("parallel_scans", 10),
                progress_callback=lambda p: update_job_progress(job_id, p)
            )
            
            # Update job with results
            job.status = "completed"
            job.completed_at = datetime.utcnow()
            job.discovered_count = len(results.get("discovered", []))
            job.error_count = len(results.get("failed", []))
            job.progress = 100
            
            await session.commit()
            
            logger.info(f"Discovery job {job_id} completed successfully")
            
    except Exception as e:
        logger.error(f"Error running discovery job {job_id}: {str(e)}")
        
        # Update job status to failed
        try:
            async with db.get_async_session() as session:
                result = await session.execute(
                    select(DiscoveryJob).where(DiscoveryJob.id == job_id)
                )
                job = result.scalar_one_or_none()
                if job:
                    job.status = "failed"
                    job.completed_at = datetime.utcnow()
                    await session.commit()
        except Exception as update_error:
            logger.error(f"Failed to update job status: {update_error}")

async def update_job_progress(job_id: str, progress: int):
    """Update discovery job progress"""
    try:
        async with db.get_async_session() as session:
            result = await session.execute(
                select(DiscoveryJob).where(DiscoveryJob.id == job_id)
            )
            job = result.scalar_one_or_none()
            if job:
                job.progress = progress
                job.updated_at = datetime.utcnow()
                await session.commit()
    except Exception as e:
        logger.error(f"Failed to update job progress: {e}")