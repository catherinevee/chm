"""
Notification management API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, update
from pydantic import BaseModel, Field
import logging
import uuid

from backend.database.models import Notification, Device
from backend.database.base import get_db
from backend.api.dependencies.auth import (
    get_current_user,
    standard_rate_limit
)
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/notifications", tags=["notifications"])

# Database session dependency is imported from backend.database.base

class NotificationCreate(BaseModel):
    notification_type: str = Field(..., description="Type of notification")
    title: str = Field(..., max_length=255)
    message: str
    severity: str = Field(default="info", pattern="^(info|warning|error|critical)$")
    device_id: Optional[str] = None

class NotificationUpdate(BaseModel):
    read: Optional[bool] = None

class NotificationResponse(BaseModel):
    id: str
    notification_type: str
    title: str
    message: str
    severity: str
    read: bool
    device_id: Optional[str]
    device_hostname: Optional[str]
    user_id: Optional[str]
    created_at: datetime
    read_at: Optional[datetime]

class NotificationListResponse(BaseModel):
    notifications: List[NotificationResponse]
    total: int
    unread_count: int
    page: int
    per_page: int

@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    unread_only: bool = False,
    severity: Optional[str] = None,
    notification_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    List notifications for the current user
    """
    try:
        # Build query - filter by user
        query = select(Notification).where(
            or_(
                Notification.user_id == str(current_user.id),
                Notification.user_id.is_(None)  # Global notifications
            )
        )
        
        # Apply filters
        filters = []
        if unread_only:
            filters.append(Notification.read == False)
        if severity:
            filters.append(Notification.severity == severity)
        if notification_type:
            filters.append(Notification.notification_type == notification_type)
        
        if filters:
            query = query.where(and_(*filters))
        
        # Order by creation date (newest first)
        query = query.order_by(Notification.created_at.desc())
        
        # Get total count
        count_query = select(func.count()).select_from(Notification).where(
            or_(
                Notification.user_id == str(current_user.id),
                Notification.user_id.is_(None)
            )
        )
        if filters:
            count_query = count_query.where(and_(*filters))
        total = await db_session.scalar(count_query)
        
        # Get unread count
        unread_count = await db_session.scalar(
            select(func.count()).select_from(Notification).where(
                and_(
                    or_(
                        Notification.user_id == str(current_user.id),
                        Notification.user_id.is_(None)
                    ),
                    Notification.read == False
                )
            )
        )
        
        # Apply pagination
        offset = (page - 1) * per_page
        query = query.offset(offset).limit(per_page)
        
        # Execute query
        result = await db_session.execute(query)
        notifications = result.scalars().all()
        
        # Build response
        notification_responses = []
        for notification in notifications:
            # Get device hostname if device_id exists
            device_hostname = None
            if notification.device_id:
                device_result = await db_session.execute(
                    select(Device.hostname).where(Device.id == notification.device_id)
                )
                device_hostname = device_result.scalar_one_or_none()
            
            notification_responses.append(NotificationResponse(
                id=str(notification.id),
                notification_type=notification.notification_type,
                title=notification.title,
                message=notification.message,
                severity=notification.severity,
                read=notification.read,
                device_id=str(notification.device_id) if notification.device_id else None,
                device_hostname=device_hostname,
                user_id=str(notification.user_id) if notification.user_id else None,
                created_at=notification.created_at,
                read_at=notification.read_at
            ))
        
        return NotificationListResponse(
            notifications=notification_responses,
            total=total,
            unread_count=unread_count,
            page=page,
            per_page=per_page
        )
        
    except Exception as e:
        logger.error(f"Error listing notifications: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list notifications"
        )

@router.get("/unread-count")
async def get_unread_count(
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Get count of unread notifications for current user
    """
    try:
        unread_count = await db_session.scalar(
            select(func.count()).select_from(Notification).where(
                and_(
                    or_(
                        Notification.user_id == str(current_user.id),
                        Notification.user_id.is_(None)
                    ),
                    Notification.read == False
                )
            )
        )
        
        # Get counts by severity
        severity_counts = await db_session.execute(
            select(
                Notification.severity,
                func.count().label("count")
            ).where(
                and_(
                    or_(
                        Notification.user_id == str(current_user.id),
                        Notification.user_id.is_(None)
                    ),
                    Notification.read == False
                )
            ).group_by(Notification.severity)
        )
        
        severity_breakdown = {
            row.severity: row.count
            for row in severity_counts
        }
        
        return {
            "unread_count": unread_count,
            "severity_breakdown": severity_breakdown,
            "has_critical": severity_breakdown.get("critical", 0) > 0
        }
        
    except Exception as e:
        logger.error(f"Error getting unread count: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get unread count"
        )

@router.post("/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Mark a notification as read
    """
    try:
        # Validate UUID
        try:
            uuid.UUID(notification_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid notification ID format"
            )
        
        # Get notification
        result = await db_session.execute(
            select(Notification).where(
                and_(
                    Notification.id == notification_id,
                    or_(
                        Notification.user_id == str(current_user.id),
                        Notification.user_id.is_(None)
                    )
                )
            )
        )
        notification = result.scalar_one_or_none()
        
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        # Mark as read
        notification.read = True
        notification.read_at = datetime.utcnow()
        
        await db_session.commit()
        
        return {"message": "Notification marked as read"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark notification as read"
        )

@router.post("/mark-all-read")
async def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Mark all notifications as read for current user
    """
    try:
        # Update all unread notifications for user
        result = await db_session.execute(
            update(Notification)
            .where(
                and_(
                    or_(
                        Notification.user_id == str(current_user.id),
                        Notification.user_id.is_(None)
                    ),
                    Notification.read == False
                )
            )
            .values(read=True, read_at=datetime.utcnow())
        )
        
        await db_session.commit()
        
        return {
            "message": "All notifications marked as read",
            "updated_count": result.rowcount
        }
        
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to mark all notifications as read"
        )

@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Delete a notification
    """
    try:
        # Get notification
        result = await db_session.execute(
            select(Notification).where(
                and_(
                    Notification.id == notification_id,
                    or_(
                        Notification.user_id == str(current_user.id),
                        Notification.user_id.is_(None)
                    )
                )
            )
        )
        notification = result.scalar_one_or_none()
        
        if not notification:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Notification not found"
            )
        
        # Delete notification
        await db_session.delete(notification)
        await db_session.commit()
        
        return {"message": "Notification deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting notification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete notification"
        )

@router.post("/test", dependencies=[Depends(standard_rate_limit)])
async def create_test_notification(
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Create a test notification for the current user
    """
    try:
        # Create test notification
        notification = Notification(
            notification_type="test",
            title="Test Notification",
            message=f"This is a test notification created at {datetime.utcnow().isoformat()}",
            severity="info",
            read=False,
            user_id=str(current_user.id),
            created_at=datetime.utcnow()
        )
        
        db_session.add(notification)
        await db_session.commit()
        await db_session.refresh(notification)
        
        # Broadcast via WebSocket if available
        try:
            from backend.api.websocket_manager import ws_manager
            await ws_manager.broadcast_notification({
                "id": str(notification.id),
                "type": notification.notification_type,
                "title": notification.title,
                "message": notification.message,
                "severity": notification.severity,
                "user_id": str(current_user.id)
            })
        except Exception as ws_error:
            logger.warning(f"Failed to broadcast notification via WebSocket: {ws_error}")
        
        return {
            "message": "Test notification created",
            "notification_id": str(notification.id)
        }
        
    except Exception as e:
        logger.error(f"Error creating test notification: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create test notification"
        )