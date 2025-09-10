"""
Centralized import management to prevent circular dependencies
Uses lazy loading pattern for all services and components
"""

from typing import TYPE_CHECKING, Optional, Any
import importlib
import logging

logger = logging.getLogger(__name__)

class LazyImporter:
    """Lazy importer for preventing circular dependencies"""
    
    def __init__(self):
        self._cache = {}
    
    def get_service(self, service_name: str) -> Any:
        """Get a service class using lazy loading"""
        cache_key = f"service_{service_name}"
        
        if cache_key not in self._cache:
            try:
                module_path = f"backend.services.{service_name.lower()}_service"
                module = importlib.import_module(module_path)
                service_class = getattr(module, f"{service_name}Service")
                self._cache[cache_key] = service_class
                logger.debug(f"Loaded {service_name}Service from {module_path}")
            except (ImportError, AttributeError) as e:
                logger.error(f"Failed to import {service_name}Service: {e}")
                self._cache[cache_key] = None
        
        return self._cache[cache_key]
    
    def get_model(self, model_name: str) -> Any:
        """Get a database model using lazy loading"""
        cache_key = f"model_{model_name}"
        
        if cache_key not in self._cache:
            try:
                # Try to import from the main models file first
                module = importlib.import_module("backend.database.models")
                model_class = getattr(module, model_name)
                self._cache[cache_key] = model_class
                logger.debug(f"Loaded {model_name} from backend.database.models")
            except (ImportError, AttributeError):
                # Try individual model files
                try:
                    module_path = f"backend.database.models.{model_name.lower()}"
                    module = importlib.import_module(module_path)
                    model_class = getattr(module, model_name)
                    self._cache[cache_key] = model_class
                    logger.debug(f"Loaded {model_name} from {module_path}")
                except (ImportError, AttributeError) as e:
                    logger.error(f"Failed to import {model_name}: {e}")
                    self._cache[cache_key] = None
        
        return self._cache[cache_key]
    
    def get_auth_component(self, component_name: str) -> Any:
        """Get an authentication component using lazy loading"""
        cache_key = f"auth_{component_name}"
        
        if cache_key not in self._cache:
            try:
                module = importlib.import_module("backend.services.auth_service")
                component = getattr(module, component_name)
                self._cache[cache_key] = component
                logger.debug(f"Loaded {component_name} from auth_service")
            except (ImportError, AttributeError) as e:
                logger.error(f"Failed to import {component_name}: {e}")
                self._cache[cache_key] = None
        
        return self._cache[cache_key]
    
    def clear_cache(self):
        """Clear the import cache"""
        self._cache.clear()
        logger.debug("Import cache cleared")

# Global lazy importer instance
lazy_import = LazyImporter()

# Convenience functions
def get_device_service():
    """Get DeviceService class"""
    return lazy_import.get_service("Device")

def get_auth_service():
    """Get AuthService class"""
    return lazy_import.get_service("Auth")

def get_metrics_service():
    """Get MetricsService class"""
    return lazy_import.get_service("Metrics")

def get_alert_service():
    """Get AlertService class"""
    return lazy_import.get_service("Alert")

def get_notification_service():
    """Get NotificationService class"""
    return lazy_import.get_service("Notification")

def get_discovery_service():
    """Get DiscoveryService class"""
    return lazy_import.get_service("Discovery")

# Model getters
def get_device_model():
    """Get Device model"""
    return lazy_import.get_model("Device")

def get_user_model():
    """Get User model"""
    return lazy_import.get_model("User")

def get_metric_model():
    """Get DeviceMetric model"""
    return lazy_import.get_model("DeviceMetric")

def get_alert_model():
    """Get Alert model"""
    return lazy_import.get_model("Alert")

# Auth component getters
def get_auth_manager():
    """Get AuthenticationManager"""
    return lazy_import.get_auth_component("AuthenticationManager")

def get_jwt_manager():
    """Get JWTManager"""
    return lazy_import.get_auth_component("JWTManager")

def get_password_manager():
    """Get PasswordManager"""
    return lazy_import.get_auth_component("PasswordManager")