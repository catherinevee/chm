"""
Notification Service - Business logic for user notifications
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_, func
from sqlalchemy.orm import selectinload

from backend.database.models import Notification
from backend.database.user_models import User
from backend.common.exceptions import AppException
from backend.api.websocket_manager import ws_manager as websocket_manager
import logging
import json

logger = logging.getLogger(__name__)

class NotificationService:
    """Service for managing user notifications"""
    
    @staticmethod
    async def create_notification(
        db: AsyncSession,
        user_id: UUID,
        title: str,
        message: str,
        notification_type: str = 'info',
        priority: str = 'normal',
        metadata: Optional[Dict[str, Any]] = None
    ) -> Notification:
        """Create a new notification for a user"""
        try:
            # Validate user exists
            user = await db.get(User, user_id)
            if not user:
                raise AppException(
                    status_code=404,
                    detail=f"User {user_id} not found"
                )
            
            # Create notification
            notification = Notification(
                id=uuid4(),
                user_id=user_id,
                title=title,
                message=message,
                notification_type=notification_type,
                severity=priority,
                read=False,
                notification_metadata=metadata,
                created_at=datetime.utcnow()
            )
            
            db.add(notification)
            await db.commit()
            await db.refresh(notification)
            
            # Send real-time notification via WebSocket
            await NotificationService._send_websocket_notification(
                user_id, notification
            )
            
            # Send email notification for high priority
            if priority == 'high':
                await NotificationService._send_email_notification(
                    user, notification
                )
            
            return notification
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error creating notification: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to create notification: {str(e)}"
            )
    
    @staticmethod
    async def get_user_notifications(
        db: AsyncSession,
        user_id: UUID,
        skip: int = 0,
        limit: int = 50,
        unread_only: bool = False,
        notification_type: Optional[str] = None
    ) -> List[Notification]:
        """Get notifications for a user"""
        try:
            query = select(Notification).where(
                Notification.user_id == user_id
            )
            
            # Apply filters
            if unread_only:
                query = query.where(Notification.read == False)
            
            if notification_type:
                query = query.where(Notification.notification_type == notification_type)
            
            # Order by created_at descending (newest first)
            query = query.order_by(Notification.created_at.desc())
            
            # Apply pagination
            query = query.offset(skip).limit(limit)
            
            result = await db.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Error getting notifications: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get notifications: {str(e)}"
            )
    
    @staticmethod
    async def mark_as_read(
        db: AsyncSession,
        notification_id: UUID,
        user_id: UUID
    ) -> Notification:
        """Mark a notification as read"""
        try:
            # Get notification
            query = select(Notification).where(
                and_(
                    Notification.id == notification_id,
                    Notification.user_id == user_id
                )
            )
            result = await db.execute(query)
            notification = result.scalar_one_or_none()
            
            if not notification:
                raise AppException(
                    status_code=404,
                    detail=f"Notification {notification_id} not found"
                )
            
            if notification.read:
                return notification  # Already read
            
            # Update notification
            notification.read = True
            notification.read_at = datetime.utcnow()
            
            await db.commit()
            await db.refresh(notification)
            
            # Send WebSocket update
            await NotificationService._send_websocket_update(
                user_id, {'unread_count': await NotificationService.get_unread_count(db, user_id)}
            )
            
            return notification
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error marking notification as read: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to mark notification as read: {str(e)}"
            )
    
    @staticmethod
    async def get_unread_count(
        db: AsyncSession,
        user_id: UUID
    ) -> int:
        """Get count of unread notifications for a user"""
        try:
            query = select(func.count(Notification.id)).where(
                and_(
                    Notification.user_id == user_id,
                    Notification.read == False
                )
            )
            
            result = await db.execute(query)
            return result.scalar() or 0
            
        except Exception as e:
            logger.error(f"Error getting unread count: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to get unread count: {str(e)}"
            )
    
    @staticmethod
    async def mark_all_as_read(
        db: AsyncSession,
        user_id: UUID
    ) -> int:
        """Mark all notifications as read for a user"""
        try:
            # Update all unread notifications
            stmt = update(Notification).where(
                and_(
                    Notification.user_id == user_id,
                    Notification.read == False
                )
            ).values(
                read=True,
                read_at=datetime.utcnow()
            )
            
            result = await db.execute(stmt)
            await db.commit()
            
            # Send WebSocket update
            await NotificationService._send_websocket_update(
                user_id, {'unread_count': 0}
            )
            
            return result.rowcount
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error marking all as read: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to mark all as read: {str(e)}"
            )
    
    @staticmethod
    async def delete_notification(
        db: AsyncSession,
        notification_id: UUID,
        user_id: UUID
    ) -> bool:
        """Delete a notification"""
        try:
            # Get notification
            query = select(Notification).where(
                and_(
                    Notification.id == notification_id,
                    Notification.user_id == user_id
                )
            )
            result = await db.execute(query)
            notification = result.scalar_one_or_none()
            
            if not notification:
                raise AppException(
                    status_code=404,
                    detail=f"Notification {notification_id} not found"
                )
            
            await db.delete(notification)
            await db.commit()
            
            return True
            
        except AppException:
            raise
        except Exception as e:
            await db.rollback()
            logger.error(f"Error deleting notification: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to delete notification: {str(e)}"
            )
    
    @staticmethod
    async def delete_old_notifications(
        db: AsyncSession,
        days: int = 30
    ) -> int:
        """Delete notifications older than specified days"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            
            # Delete old read notifications
            query = select(Notification).where(
                and_(
                    Notification.created_at < cutoff_date,
                    Notification.read == True
                )
            )
            result = await db.execute(query)
            old_notifications = result.scalars().all()
            
            count = len(old_notifications)
            for notification in old_notifications:
                await db.delete(notification)
            
            await db.commit()
            
            logger.info(f"Deleted {count} old notifications")
            return count
            
        except Exception as e:
            await db.rollback()
            logger.error(f"Error deleting old notifications: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to delete old notifications: {str(e)}"
            )
    
    @staticmethod
    async def create_test_notification(
        db: AsyncSession,
        user_id: UUID
    ) -> Notification:
        """Create a test notification for testing purposes"""
        try:
            return await NotificationService.create_notification(
                db,
                user_id=user_id,
                title="Test Notification",
                message="This is a test notification to verify the system is working correctly.",
                notification_type='test',
                priority='normal',
                metadata={'test': True, 'timestamp': datetime.utcnow().isoformat()}
            )
            
        except Exception as e:
            logger.error(f"Error creating test notification: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to create test notification: {str(e)}"
            )
    
    @staticmethod
    async def broadcast_notification(
        db: AsyncSession,
        title: str,
        message: str,
        notification_type: str = 'broadcast',
        target_roles: Optional[List[str]] = None
    ) -> int:
        """Broadcast notification to multiple users"""
        try:
            # Get target users
            query = select(User).where(User.is_active == True)
            
            if target_roles:
                # Filter by roles if specified
                query = query.join(User.roles).where(
                    User.roles.any(name=target_roles)
                )
            
            result = await db.execute(query)
            users = result.scalars().all()
            
            # Create notifications for all users
            count = 0
            for user in users:
                await NotificationService.create_notification(
                    db,
                    user_id=user.id,
                    title=title,
                    message=message,
                    notification_type=notification_type,
                    priority='normal',
                    metadata={'broadcast': True}
                )
                count += 1
            
            logger.info(f"Broadcast notification sent to {count} users")
            return count
            
        except Exception as e:
            logger.error(f"Error broadcasting notification: {str(e)}")
            raise AppException(
                status_code=500,
                detail=f"Failed to broadcast notification: {str(e)}"
            )
    
    @staticmethod
    async def _send_websocket_notification(
        user_id: UUID,
        notification: Notification
    ) -> None:
        """Send real-time notification via WebSocket"""
        try:
            message = {
                'type': 'notification',
                'data': {
                    'id': str(notification.id),
                    'title': notification.title,
                    'message': notification.message,
                    'type': notification.notification_type,
                    'priority': notification.severity,
                    'created_at': notification.created_at.isoformat()
                }
            }
            
            await websocket_manager.send_to_user(
                str(user_id),
                json.dumps(message)
            )
            
        except Exception as e:
            logger.error(f"Error sending WebSocket notification: {str(e)}")
    
    @staticmethod
    async def _send_websocket_update(
        user_id: UUID,
        data: Dict[str, Any]
    ) -> None:
        """Send WebSocket update to user"""
        try:
            message = {
                'type': 'notification_update',
                'data': data
            }
            
            await websocket_manager.send_to_user(
                str(user_id),
                json.dumps(message)
            )
            
        except Exception as e:
            logger.error(f"Error sending WebSocket update: {str(e)}")
    
    @staticmethod
    async def _send_email_notification(
        user: User,
        notification: Notification
    ) -> None:
        """Send email notification for high priority notifications."""
        try:
            # This would integrate with email service
            # For now, just log
            logger.info(
                f"Would send email to {user.email}: "
                f"{notification.title} - {notification.message}"
            )
            
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
