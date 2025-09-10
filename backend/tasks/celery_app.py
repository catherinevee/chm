"""
Celery Application - Background task processing for CHM
"""

import os
from celery import Celery
from celery.schedules import crontab
from kombu import Exchange, Queue
from backend.config import settings

# Create Celery instance
celery_app = Celery(
    'chm',
    broker=settings.CELERY_BROKER_URL or 'redis://localhost:6379/0',
    backend=settings.CELERY_RESULT_BACKEND or 'redis://localhost:6379/1',
    include=[
        'backend.tasks.device_tasks',
        'backend.tasks.discovery_tasks',
        'backend.tasks.monitoring_tasks',
        'backend.tasks.alert_tasks',
        'backend.tasks.maintenance_tasks',
        'backend.tasks.reporting_tasks'
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task execution settings
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    result_expires=3600,
    timezone='UTC',
    enable_utc=True,
    
    # Task routing
    task_routes={
        'backend.tasks.monitoring_tasks.*': {'queue': 'monitoring'},
        'backend.tasks.discovery_tasks.*': {'queue': 'discovery'},
        'backend.tasks.alert_tasks.*': {'queue': 'alerts'},
        'backend.tasks.device_tasks.*': {'queue': 'devices'},
        'backend.tasks.maintenance_tasks.*': {'queue': 'maintenance'},
        'backend.tasks.reporting_tasks.*': {'queue': 'reports'}
    },
    
    # Queue configuration
    task_queues=(
        Queue('default', Exchange('default'), routing_key='default'),
        Queue('monitoring', Exchange('monitoring'), routing_key='monitoring', priority=10),
        Queue('discovery', Exchange('discovery'), routing_key='discovery', priority=5),
        Queue('alerts', Exchange('alerts'), routing_key='alerts', priority=9),
        Queue('devices', Exchange('devices'), routing_key='devices', priority=7),
        Queue('maintenance', Exchange('maintenance'), routing_key='maintenance', priority=3),
        Queue('reports', Exchange('reports'), routing_key='reports', priority=1)
    ),
    
    # Worker settings
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    worker_disable_rate_limits=False,
    
    # Task execution limits
    task_soft_time_limit=300,  # 5 minutes
    task_time_limit=600,  # 10 minutes
    
    # Result backend settings
    result_backend_transport_options={
        'master_name': 'mymaster',
        'visibility_timeout': 3600,
        'fanout_prefix': True,
        'fanout_patterns': True
    },
    
    # Beat schedule for periodic tasks
    beat_schedule={
        # Device polling - every 5 minutes
        'poll-all-devices': {
            'task': 'backend.tasks.monitoring_tasks.poll_all_devices',
            'schedule': crontab(minute='*/5'),
            'options': {'queue': 'monitoring', 'priority': 10}
        },
        
        # Check device health - every 2 minutes
        'check-device-health': {
            'task': 'backend.tasks.monitoring_tasks.check_device_health',
            'schedule': crontab(minute='*/2'),
            'options': {'queue': 'monitoring', 'priority': 9}
        },
        
        # Alert escalation check - every minute
        'check-alert-escalation': {
            'task': 'backend.tasks.alert_tasks.check_escalations',
            'schedule': crontab(minute='*/1'),
            'options': {'queue': 'alerts', 'priority': 10}
        },
        
        # Metric aggregation - every 15 minutes
        'aggregate-metrics': {
            'task': 'backend.tasks.monitoring_tasks.aggregate_metrics',
            'schedule': crontab(minute='*/15'),
            'options': {'queue': 'monitoring', 'priority': 5}
        },
        
        # Network discovery - daily at 2 AM
        'daily-network-discovery': {
            'task': 'backend.tasks.discovery_tasks.run_scheduled_discovery',
            'schedule': crontab(hour=2, minute=0),
            'options': {'queue': 'discovery', 'priority': 5}
        },
        
        # Cleanup old data - daily at 3 AM
        'cleanup-old-data': {
            'task': 'backend.tasks.maintenance_tasks.cleanup_old_data',
            'schedule': crontab(hour=3, minute=0),
            'options': {'queue': 'maintenance', 'priority': 1}
        },
        
        # Generate daily reports - daily at 6 AM
        'generate-daily-reports': {
            'task': 'backend.tasks.reporting_tasks.generate_daily_reports',
            'schedule': crontab(hour=6, minute=0),
            'options': {'queue': 'reports', 'priority': 3}
        },
        
        # Check for updates - weekly on Sunday at 1 AM
        'check-system-updates': {
            'task': 'backend.tasks.maintenance_tasks.check_updates',
            'schedule': crontab(hour=1, minute=0, day_of_week=0),
            'options': {'queue': 'maintenance', 'priority': 1}
        },
        
        # Backup database - daily at 4 AM
        'backup-database': {
            'task': 'backend.tasks.maintenance_tasks.backup_database',
            'schedule': crontab(hour=4, minute=0),
            'options': {'queue': 'maintenance', 'priority': 2}
        },
        
        # Certificate expiry check - daily at 9 AM
        'check-certificate-expiry': {
            'task': 'backend.tasks.monitoring_tasks.check_certificates',
            'schedule': crontab(hour=9, minute=0),
            'options': {'queue': 'monitoring', 'priority': 5}
        }
    },
    
    # Beat scheduler settings
    beat_scheduler='celery.beat:PersistentScheduler',
    beat_schedule_filename='celerybeat-schedule.db',
    
    # Error handling
    task_reject_on_worker_lost=True,
    task_ignore_result=False,
    task_track_started=True,
    task_acks_late=True,
    
    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True
)

# Task error handlers
@celery_app.task(bind=True, max_retries=3)
def error_handler(self, uuid):
    """Handle task errors"""
    result = self.AsyncResult(uuid)
    exc = result.get(propagate=False)
    print(f'Task {uuid} raised exception: {exc}\n{result.traceback}')

# Initialize Celery app
def create_celery_app():
    """Create and configure Celery app"""
    return celery_app

if __name__ == '__main__':
    celery_app.start()