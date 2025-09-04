"""
Services package - Business logic layer
"""

# Import services conditionally to avoid import errors during development
__all__ = []

import logging
logger = logging.getLogger(__name__)

# Core services that should always be available
try:
    from backend.services.validation_service import ValidationService
    __all__.append('ValidationService')
except ImportError as e:
    logger.warning(f"Could not import ValidationService: {e}")
    ValidationService = None

try:
    from backend.services.device_service import DeviceService
    __all__.append('DeviceService')
except ImportError as e:
    logger.warning(f"Could not import DeviceService: {e}")
    DeviceService = None

try:
    from backend.services.metrics_service import MetricsService
    __all__.append('MetricsService')
except ImportError as e:
    logger.warning(f"Could not import MetricsService: {e}")
    MetricsService = None

try:
    from backend.services.alert_service import AlertService
    __all__.append('AlertService')
except ImportError as e:
    logger.warning(f"Could not import AlertService: {e}")
    AlertService = None

try:
    from backend.services.notification_service import NotificationService
    __all__.append('NotificationService')
except ImportError as e:
    logger.warning(f"Could not import NotificationService: {e}")
    NotificationService = None

try:
    from backend.services.discovery_service import DiscoveryService
    __all__.append('DiscoveryService')
except ImportError as e:
    logger.warning(f"Could not import DiscoveryService: {e}")
    DiscoveryService = None

try:
    from backend.services.sla_service import SLAService
    __all__.append('SLAService')
except ImportError as e:
    logger.warning(f"Could not import SLAService: {e}")
    SLAService = None

# Auth service might have additional dependencies
try:
    from backend.services.auth_service import AuthService
    __all__.append('AuthService')
except ImportError as e:
    logger.warning(f"Could not import AuthService: {e}")
    AuthService = None