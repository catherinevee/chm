import React, { useState, useEffect } from 'react';
import apiService, { SystemNotification } from '../../services/api';

const NotificationCenter: React.FC = () => {
  const [notifications, setNotifications] = useState<SystemNotification[]>([]);
  const [unreadCount, setUnreadCount] = useState<number>(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDropdown, setShowDropdown] = useState(false);
  const [filter, setFilter] = useState<{
    status?: string;
    type?: string;
  }>({});

  const loadNotifications = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await apiService.getNotifications();
      
      setNotifications(response.notifications);
    } catch (err) {
      setError('Failed to load notifications');
      console.error('Error loading notifications:', err);
    } finally {
      setLoading(false);
    }
  };

  const loadUnreadCount = async () => {
    try {
      // Count unread notifications from the current list
      const unreadNotifications = notifications.filter(n => !n.read);
      setUnreadCount(unreadNotifications.length);
    } catch (err) {
      console.error('Error loading unread count:', err);
    }
  };

  useEffect(() => {
    loadNotifications();
    loadUnreadCount();
    
    // Poll for updates every 30 seconds
    const interval = setInterval(() => {
      loadUnreadCount();
      if (showDropdown) {
        loadNotifications();
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [showDropdown, filter, loadUnreadCount]);

  const markAsRead = async (notificationId: string) => {
    try {
      await apiService.markNotificationRead(notificationId);
      
      // Update local state
      setNotifications(prevNotifications =>
        prevNotifications.map(notification =>
          notification.id === notificationId
            ? { ...notification, status: 'read', read_at: new Date().toISOString() }
            : notification
        )
      );
      
      // Update unread count
      setUnreadCount(prev => Math.max(0, prev - 1));
    } catch (err) {
      console.error('Error marking notification as read:', err);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'emergency':
        return 'text-error';
      case 'warning':
        return 'text-warning';
      case 'info':
        return 'text-info';
      default:
        return 'text-base-content';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'emergency':
        return '';
      case 'warning':
        return '';
      case 'info':
        return '';
      default:
        return '';
    }
  };

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'alert':
        return '';
      case 'device_status':
        return '';
      case 'discovery':
        return '';
      case 'sla_breach':
        return '';
      case 'maintenance':
        return '';
      default:
        return '';
    }
  };

  const formatTimeAgo = (timestamp: string) => {
    const now = new Date();
    const time = new Date(timestamp);
    const diffInSeconds = Math.floor((now.getTime() - time.getTime()) / 1000);

    if (diffInSeconds < 60) {
      return 'Just now';
    } else if (diffInSeconds < 3600) {
      const minutes = Math.floor(diffInSeconds / 60);
      return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    } else if (diffInSeconds < 86400) {
      const hours = Math.floor(diffInSeconds / 3600);
      return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    } else {
      const days = Math.floor(diffInSeconds / 86400);
      return `${days} day${days > 1 ? 's' : ''} ago`;
    }
  };

  const handleNotificationClick = (notification: SystemNotification) => {
    // Mark as read if unread
    if (!notification.read) {
      markAsRead(notification.id);
    }

    // Handle notification click - could add navigation logic here in the future
  };

  return (
    <div className="relative">
      {/* Notification Bell */}
      <button
        className="btn btn-ghost btn-circle relative"
        onClick={() => setShowDropdown(!showDropdown)}
      >
        <div className="indicator">
          <svg
            xmlns="http://www.w3.org/2000/svg"
            className="h-5 w-5"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"
            />
          </svg>
          {unreadCount > 0 && (
            <span className="badge badge-xs badge-primary indicator-item">
              {unreadCount > 99 ? '99+' : unreadCount}
            </span>
          )}
        </div>
      </button>

      {/* Notification Dropdown */}
      {showDropdown && (
        <div className="absolute right-0 mt-2 w-96 bg-base-100 rounded-lg shadow-xl border z-50 max-h-96 overflow-hidden">
          {/* Header */}
          <div className="p-4 border-b">
            <div className="flex justify-between items-center mb-2">
              <h3 className="font-semibold text-lg">Notifications</h3>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setShowDropdown(false)}
              >
                
              </button>
            </div>
            
            {/* Filter Options */}
            <div className="flex gap-2">
              <select
                className="select select-xs select-bordered"
                value={filter.status || ''}
                onChange={(e) => setFilter({ ...filter, status: e.target.value || undefined })}
              >
                <option value="">All Status</option>
                <option value="unread">Unread</option>
                <option value="read">Read</option>
              </select>
              
              <select
                className="select select-xs select-bordered"
                value={filter.type || ''}
                onChange={(e) => setFilter({ ...filter, type: e.target.value || undefined })}
              >
                <option value="">All Types</option>
                <option value="alert">Alerts</option>
                <option value="device_status">Device Status</option>
                <option value="discovery">Discovery</option>
                <option value="sla_breach">SLA Breach</option>
                <option value="maintenance">Maintenance</option>
              </select>
            </div>
          </div>

          {/* Notifications List */}
          <div className="max-h-80 overflow-y-auto">
            {loading ? (
              <div className="flex justify-center p-4">
                <span className="loading loading-spinner loading-md"></span>
              </div>
            ) : error ? (
              <div className="p-4 text-center text-error">
                {error}
              </div>
            ) : notifications.length === 0 ? (
              <div className="p-4 text-center text-gray-500">
                No notifications found
              </div>
            ) : (
              <div className="divide-y">
                {notifications.map((notification) => (
                  <div
                    key={notification.id}
                    className={`p-3 hover:bg-base-200 cursor-pointer transition-colors ${
                      !notification.read ? 'bg-base-200/50' : ''
                    }`}
                    onClick={() => handleNotificationClick(notification)}
                  >
                    <div className="flex items-start gap-3">
                      {/* Icon */}
                      <div className="flex-shrink-0 text-lg">
                        {getTypeIcon(notification.notification_type)}
                      </div>
                      
                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between gap-2">
                          <h4 className="font-medium text-sm truncate">
                            {notification.title}
                          </h4>
                          <div className="flex items-center gap-1">
                            <span className={`text-xs ${getSeverityColor(notification.severity)}`}>
                              {getSeverityIcon(notification.severity)}
                            </span>
                            {!notification.read && (
                              <div className="w-2 h-2 bg-primary rounded-full"></div>
                            )}
                          </div>
                        </div>
                        
                        <p className="text-xs text-gray-600 mt-1 line-clamp-2">
                          {notification.message}
                        </p>
                        
                        <div className="flex items-center justify-between mt-2">
                          <span className="text-xs text-gray-500">
                            {formatTimeAgo(notification.created_at)}
                          </span>
                          

                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-3 border-t bg-base-50">
            <button
              className="btn btn-sm btn-ghost w-full"
              onClick={() => {
                // Navigate to full notifications page
                window.location.href = '/notifications';
              }}
            >
              View All Notifications
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

export default NotificationCenter;
