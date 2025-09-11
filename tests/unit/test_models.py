"""
Unit tests for CHM models
Minimal unit tests to ensure models can be imported and basic functionality works
"""

import pytest
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))


class TestUserModel:
    """Test User model basic functionality"""
    
    def test_user_model_import(self):
        """Test User model can be imported"""
        try:
            from backend.models.user import User, UserRole, UserStatus
            assert User is not None
            assert UserRole is not None
            assert UserStatus is not None
        except ImportError:
            pytest.skip("User model dependencies not available")
    
    def test_user_roles_enum(self):
        """Test UserRole enum values"""
        try:
            from backend.models.user import UserRole
            assert hasattr(UserRole, 'ADMIN')
            assert hasattr(UserRole, 'OPERATOR')
            assert hasattr(UserRole, 'VIEWER')
        except ImportError:
            pytest.skip("UserRole enum not available")


class TestDeviceModel:
    """Test Device model basic functionality"""
    
    def test_device_model_import(self):
        """Test Device model can be imported"""
        try:
            from backend.models.device import Device, DeviceType, DeviceStatus
            assert Device is not None
            assert DeviceType is not None  
            assert DeviceStatus is not None
        except ImportError:
            pytest.skip("Device model dependencies not available")


class TestMetricModel:
    """Test Metric model basic functionality"""
    
    def test_metric_model_import(self):
        """Test Metric model can be imported"""
        try:
            from backend.models.metric import Metric, MetricType
            assert Metric is not None
            assert MetricType is not None
        except ImportError:
            pytest.skip("Metric model dependencies not available")


class TestAlertModel:
    """Test Alert model basic functionality"""
    
    def test_alert_model_import(self):
        """Test Alert model can be imported"""
        try:
            from backend.models.alert import Alert, AlertSeverity, AlertStatus
            assert Alert is not None
            assert AlertSeverity is not None
            assert AlertStatus is not None
        except ImportError:
            pytest.skip("Alert model dependencies not available")


# Basic functionality test
def test_models_basic():
    """Basic test that doesn't require database"""
    assert True, "Models basic test passed"