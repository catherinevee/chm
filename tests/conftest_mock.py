"""
Test configuration for CHM
Basic pytest configuration for minimal test coverage
"""

import pytest
import sys
import os
from pathlib import Path

# Add project root to Python path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Set test environment variables
os.environ.setdefault("TESTING", "true")
os.environ.setdefault("LOG_LEVEL", "ERROR")  # Reduce noise during testing
os.environ.setdefault("DATABASE_URL", "sqlite:///test.db")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret")


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Setup test environment"""
    # Set environment for testing
    os.environ["TESTING"] = "true"
    yield
    # Cleanup after tests
    pass


@pytest.fixture
def mock_database():
    """Mock database fixture for tests that need it"""
    return "mock_db"


@pytest.fixture  
def sample_user_data():
    """Sample user data for testing"""
    return {
        "username": "testuser",
        "email": "test@example.com", 
        "password": "TestPassword123!",
        "full_name": "Test User"
    }


@pytest.fixture
def sample_device_data():
    """Sample device data for testing"""
    return {
        "name": "test-device",
        "ip_address": "192.168.1.100",
        "device_type": "router",
        "vendor": "cisco"
    }