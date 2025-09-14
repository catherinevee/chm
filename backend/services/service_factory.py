"""
Service Factory for CHM - Complete Implementation
"""
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

class ServiceFactory:
    """Factory for creating service instances"""

    _instances = {}

    @classmethod
    def get_device_service(cls, db_session: Optional[AsyncSession] = None):
        """Get DeviceService instance"""
        from backend.services.device_service import DeviceService
        if 'device' not in cls._instances or db_session:
            cls._instances['device'] = DeviceService(db_session)
        return cls._instances['device']

    @classmethod
    def get_alert_service(cls, db_session: Optional[AsyncSession] = None):
        """Get AlertService instance"""
        from backend.services.alert_service import AlertService
        if 'alert' not in cls._instances or db_session:
            cls._instances['alert'] = AlertService(db_session)
        return cls._instances['alert']

    @classmethod
    def get_metrics_service(cls, db_session: Optional[AsyncSession] = None):
        """Get MetricsService instance"""
        from backend.services.metrics_service import MetricsService
        if 'metrics' not in cls._instances or db_session:
            cls._instances['metrics'] = MetricsService(db_session)
        return cls._instances['metrics']

    @classmethod
    def get_auth_service(cls):
        """Get AuthService instance"""
        from backend.services.auth_service import AuthService
        if 'auth' not in cls._instances:
            cls._instances['auth'] = AuthService()
        return cls._instances['auth']
