"""
CHM Notifications API
User notification management endpoints
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import and_, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from core.auth_middleware import get_current_user
from core.database import get_db
from models.notification import Notification as NotificationModel
from models.notification import NotificationStatus, NotificationType
from models.user import User

logger = logging.getLogger(__name__)

router = APIRouter()

# Pydantic models
class NotificationResponse(BaseModel):
    id: int
    user_id: int
    title: str
    message: str
    notification_type: str
    status: str
    channel: str
    priority: str
    created_at: str
    sent_at: Optional[str] = None
    delivered_at: Optional[str] = None
    is_read: bool = False
    read_at: Optional[str] = None

# Notifications endpoints
@router.get("/", response_model=List[NotificationResponse])
async def list_notifications(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    is_read: Optional[bool] = None,
    notification_type: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List user notifications with filtering and pagination"""
    logger.info(f"Notifications list request: skip={skip}, limit={limit}")
    
    try:
        # Build query for user's notifications
        query = select(NotificationModel).where(
            and_(
                NotificationModel.user_id == current_user.id,
                NotificationModel.is_deleted == False
            )
        )
        
        # Apply filters
        if is_read is not None:
            if is_read:
                query = query.where(NotificationModel.delivered_at.isnot(None))
            else:
                query = query.where(NotificationModel.delivered_at.is_(None))
        
        if notification_type:
            try:
                notif_type = NotificationType(notification_type)
                query = query.where(NotificationModel.notification_type == notif_type)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid notification type: {notification_type}")
        
        # Apply pagination and ordering (newest first)
        query = query.order_by(NotificationModel.created_at.desc()).offset(skip).limit(limit)
        
        result = await db.execute(query)
        notifications = result.scalars().all()
        
        # Convert to response models
        response_notifications = []
        for notification in notifications:
            response_notifications.append(NotificationResponse(
                id=notification.id,
                user_id=notification.user_id,
                title=notification.title,
                message=notification.message,
                notification_type=notification.notification_type.value,
                status=notification.status.value,
                channel=notification.channel.value,
                priority=notification.priority.value,
                created_at=notification.created_at.isoformat(),
                sent_at=notification.sent_at.isoformat() if notification.sent_at else None,
                delivered_at=notification.delivered_at.isoformat() if notification.delivered_at else None,
                is_read=notification.delivered_at is not None,
                read_at=notification.delivered_at.isoformat() if notification.delivered_at else None
            ))
        
        logger.info(f"Returning {len(response_notifications)} notifications for user {current_user.id}")
        return response_notifications
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to list notifications: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve notifications")

@router.get("/unread-count")
async def get_unread_count(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get count of unread notifications"""
    logger.info("Unread notifications count request")
    
    try:
        # Count unread notifications for current user
        query = select(func.count(NotificationModel.id)).where(
            and_(
                NotificationModel.user_id == current_user.id,
                NotificationModel.is_deleted == False,
                NotificationModel.delivered_at.is_(None)
            )
        )
        
        result = await db.execute(query)
        unread_count = result.scalar()
        
        logger.info(f"User {current_user.id} has {unread_count} unread notifications")
        return {"unread_count": unread_count}
        
    except Exception as e:
        logger.error(f"Failed to get unread count: {e}")
        raise HTTPException(status_code=500, detail="Failed to get unread count")

@router.post("/{notification_id}/read")
async def mark_notification_read(
    notification_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark notification as read"""
    logger.info(f"Mark notification read request: {notification_id}")
    
    try:
        # Validate notification exists and belongs to user
        notification_query = select(NotificationModel).where(
            and_(
                NotificationModel.id == notification_id,
                NotificationModel.user_id == current_user.id,
                NotificationModel.is_deleted == False
            )
        )
        
        notification_result = await db.execute(notification_query)
        notification = notification_result.scalar_one_or_none()
        
        if not notification:
            raise HTTPException(status_code=404, detail="Notification not found")
        
        # Update read status
        notification.delivered_at = datetime.utcnow()
        notification.status = NotificationStatus.DELIVERED
        notification.updated_at = datetime.utcnow()
        
        await db.commit()
        
        logger.info(f"Marked notification {notification_id} as read for user {current_user.id}")
        return {"message": "Notification marked as read"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to mark notification as read: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to mark notification as read")

@router.post("/mark-all-read")
async def mark_all_notifications_read(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark all notifications as read"""
    logger.info("Mark all notifications read request")
    
    try:
        # Update all user's unread notifications
        update_query = update(NotificationModel).where(
            and_(
                NotificationModel.user_id == current_user.id,
                NotificationModel.is_deleted == False,
                NotificationModel.delivered_at.is_(None)
            )
        ).values(
            delivered_at=datetime.utcnow(),
            status=NotificationStatus.DELIVERED,
            updated_at=datetime.utcnow()
        )
        
        result = await db.execute(update_query)
        updated_count = result.rowcount
        
        await db.commit()
        
        logger.info(f"Marked {updated_count} notifications as read for user {current_user.id}")
        return {"message": f"All {updated_count} notifications marked as read"}
        
    except Exception as e:
        logger.error(f"Failed to mark all notifications as read: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to mark all notifications as read")

@router.delete("/{notification_id}")
async def delete_notification(
    notification_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Delete a notification"""
    logger.info(f"Notification deletion request: {notification_id}")
    
    try:
        # Validate notification exists and belongs to user
        notification_query = select(NotificationModel).where(
            and_(
                NotificationModel.id == notification_id,
                NotificationModel.user_id == current_user.id,
                NotificationModel.is_deleted == False
            )
        )
        
        notification_result = await db.execute(notification_query)
        notification = notification_result.scalar_one_or_none()
        
        if not notification:
            raise HTTPException(status_code=404, detail="Notification not found")
        
        # Soft delete the notification
        notification.is_deleted = True
        notification.deleted_at = datetime.utcnow()
        notification.deleted_by = current_user.id
        notification.updated_at = datetime.utcnow()
        
        await db.commit()
        
        logger.info(f"Deleted notification {notification_id} for user {current_user.id}")
        return {"message": "Notification deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete notification: {e}")
        await db.rollback()
        raise HTTPException(status_code=500, detail="Failed to delete notification")

__all__ = ["router"]
