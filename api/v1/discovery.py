"""
CHM Discovery API
Network discovery and device detection endpoints
"""

import asyncio
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.services.discovery_service import DiscoveryService
from core.database import get_db
from models.device import Device as DeviceModel
from models.discovery_job import DiscoveryJob as DiscoveryJobModel
from models.discovery_job import DiscoveryStatus, DiscoveryType

logger = logging.getLogger(__name__)

router = APIRouter()


# Pydantic models
class DiscoveryJob(BaseModel):
    id: int
    name: str
    network_range: str
    scan_type: str
    status: str
    progress: float
    created_at: str
    completed_at: Optional[str] = None


class DiscoveryResult(BaseModel):
    job_id: int
    device_id: int
    ip_address: str
    device_type: str
    vendor: Optional[str] = None
    model: Optional[str] = None
    discovered_at: str


# Discovery endpoints
@router.post("/start")
async def start_discovery(
    background_tasks: BackgroundTasks,
    name: str,
    network_ranges: List[str],
    discovery_types: List[str] = ["ping_sweep", "snmp"],
    db: AsyncSession = Depends(get_db),
):
    """Start network discovery job"""
    logger.info(f"Discovery start request: {name}, {network_ranges}")

    try:
        # Validate network ranges
        import ipaddress

        validated_ranges = []
        for network_range in network_ranges:
            try:
                ip_net = ipaddress.ip_network(network_range, strict=False)
                validated_ranges.append(network_range)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"Invalid network range '{network_range}': {str(e)}")

        # Convert discovery types
        discovery_type_enums = []
        for discovery_type in discovery_types:
            try:
                discovery_type_enums.append(DiscoveryType(discovery_type.upper()))
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid discovery type '{discovery_type}'. Valid types: {[t.value for t in DiscoveryType]}",
                )

        # Create discovery job
        new_job = DiscoveryJobModel(
            name=name,
            job_type=DiscoveryType.NETWORK_SCAN,
            target_networks=validated_ranges,
            status=DiscoveryStatus.PENDING,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )

        db.add(new_job)
        await db.commit()
        await db.refresh(new_job)

        # Start discovery in background
        background_tasks.add_task(run_discovery_job, new_job.id, validated_ranges, discovery_type_enums)

        logger.info(f"Created discovery job {new_job.id}: {name}")

        return DiscoveryJob(
            id=new_job.id,
            name=new_job.name,
            network_range=", ".join(validated_ranges),
            scan_type=", ".join(discovery_types),
            status=new_job.status.value,
            progress=0.0,
            created_at=new_job.created_at.isoformat(),
            completed_at=new_job.completed_at.isoformat() if new_job.completed_at else None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start discovery: {e}")
        raise HTTPException(status_code=500, detail="Failed to start discovery job")


@router.get("/", response_model=List[DiscoveryJob])
async def list_discovery_jobs(db: AsyncSession = Depends(get_db)):
    """List discovery jobs"""
    logger.info("Discovery jobs list request")

    try:
        jobs_query = select(DiscoveryJobModel).order_by(DiscoveryJobModel.created_at.desc())
        jobs_result = await db.execute(jobs_query)
        jobs = jobs_result.scalars().all()

        result = []
        for job in jobs:
            result.append(
                DiscoveryJob(
                    id=job.id,
                    name=job.name,
                    network_range=", ".join(job.target_networks) if job.target_networks else "",
                    scan_type=job.job_type.value if job.job_type else "unknown",
                    status=job.status.value if job.status else "unknown",
                    progress=job.progress_percentage or 0.0,
                    created_at=job.created_at.isoformat() if job.created_at else None,
                    completed_at=job.completed_at.isoformat() if job.completed_at else None,
                )
            )

        logger.info(f"Returning {len(result)} discovery jobs")
        return result

    except Exception as e:
        logger.error(f"Failed to list discovery jobs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve discovery jobs")


@router.get("/{job_id}", response_model=DiscoveryJob)
async def get_discovery_job(job_id: int, db: AsyncSession = Depends(get_db)):
    """Get discovery job details"""
    logger.info(f"Discovery job details request: {job_id}")

    try:
        job_query = select(DiscoveryJobModel).where(DiscoveryJobModel.id == job_id)
        job_result = await db.execute(job_query)
        job = job_result.scalar_one_or_none()

        if not job:
            raise HTTPException(status_code=404, detail="Discovery job not found")

        return DiscoveryJob(
            id=job.id,
            name=job.name,
            network_range=", ".join(job.target_networks) if job.target_networks else "",
            scan_type=job.job_type.value if job.job_type else "unknown",
            status=job.status.value if job.status else "unknown",
            progress=job.progress_percentage or 0.0,
            created_at=job.created_at.isoformat() if job.created_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get discovery job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve discovery job")


@router.post("/{job_id}/cancel")
async def cancel_discovery_job(job_id: int, db: AsyncSession = Depends(get_db)):
    """Cancel running discovery job"""
    logger.info(f"Discovery job cancellation request: {job_id}")

    try:
        job_query = select(DiscoveryJobModel).where(DiscoveryJobModel.id == job_id)
        job_result = await db.execute(job_query)
        job = job_result.scalar_one_or_none()

        if not job:
            raise HTTPException(status_code=404, detail="Discovery job not found")

        if job.status not in [DiscoveryStatus.PENDING, DiscoveryStatus.RUNNING]:
            raise HTTPException(status_code=400, detail=f"Cannot cancel job with status {job.status.value}")

        # Cancel the discovery task if it's running
        # TODO: Implement discovery job cancellation
        # discovery_service = DiscoveryService(db)
        # await discovery_service.cancel_job(job_id)

        # Update job status
        job.status = DiscoveryStatus.CANCELLED
        job.completed_at = datetime.utcnow()
        job.updated_at = datetime.utcnow()
        await db.commit()

        logger.info(f"Cancelled discovery job {job_id}")

        return {"message": "Discovery job cancelled successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to cancel discovery job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to cancel discovery job")


@router.get("/{job_id}/results", response_model=List[DiscoveryResult])
async def get_discovery_results(job_id: int, db: AsyncSession = Depends(get_db)):
    """Get discovery job results"""
    logger.info(f"Discovery results request: {job_id}")

    try:
        # Verify job exists
        job_query = select(DiscoveryJobModel).where(DiscoveryJobModel.id == job_id)
        job_result = await db.execute(job_query)
        job = job_result.scalar_one_or_none()
        if not job:
            raise HTTPException(status_code=404, detail="Discovery job not found")

        # Get devices discovered by this job (devices created around the job time)
        # Find devices that were likely discovered by this job
        # This is a simplified approach - in production, you'd have a direct relationship
        job_start_time = job.created_at
        job_end_time = job.completed_at or datetime.utcnow()

        devices_query = select(DeviceModel).where(
            DeviceModel.created_at >= job_start_time, DeviceModel.created_at <= job_end_time
        )
        devices_result = await db.execute(devices_query)
        discovered_devices = devices_result.scalars().all()

        result = []
        for device in discovered_devices:
            result.append(
                DiscoveryResult(
                    job_id=job_id,
                    device_id=device.id,
                    ip_address=device.ip_address,
                    device_type=device.device_type.value if device.device_type else "unknown",
                    vendor=device.vendor,
                    model=device.model,
                    discovered_at=device.created_at.isoformat() if device.created_at else None,
                )
            )

        logger.info(f"Returning {len(result)} discovery results for job {job_id}")
        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get discovery results for job {job_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve discovery results")


async def run_discovery_job(job_id: int, network_ranges: List[str], discovery_types: List[DiscoveryType]):
    """Background task to run discovery job"""
    logger.info(f"Starting discovery job: {job_id}")

    try:
        # Start the discovery job using the network discovery service
        # Start discovery job
        discovery_service = DiscoveryService(db)
        result = await discovery_service.discover_network(network_ranges[0] if network_ranges else "192.168.1.0/24")

        if result:
            logger.info(f"Discovery job {job_id} completed: found {len(result)} devices")
        else:
            logger.error(f"Discovery job {job_id} failed to find any devices")

    except Exception as e:
        logger.error(f"Discovery job {job_id} failed: {e}")

    logger.info(f"Discovery job {job_id} task completed")


__all__ = ["router"]
