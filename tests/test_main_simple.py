"""
Simple main.py tests for CI compatibility 
"""
import os

# Set environment before any imports
os.environ.update({
    'TESTING': 'true',
    'DATABASE_URL': 'sqlite+aiosqlite:///:memory:',
    'JWT_SECRET_KEY': 'test-secret',
    'SECRET_KEY': 'test-secret',
    'DEBUG': 'true'
})

import pytest
from fastapi.testclient import TestClient


def test_main_import():
    """Test main.py can be imported"""
    import main
    assert main.app is not None
    assert hasattr(main.app, 'title')

def test_create_app_function():
    """Test create_app function"""
    from main import create_app
    app = create_app()
    assert app.title == "CHM API"
    assert app.version == "2.0.0"

def test_health_endpoints():
    """Test health endpoints"""
    from main import app
    client = TestClient(app)
    
    # Test root endpoint
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    
    # Test health endpoint
    response = client.get("/health")
    assert response.status_code == 200
    
    # Test API status
    response = client.get("/api/status")
    assert response.status_code == 200
    data = response.json()
    assert data["api_version"] == "v1"

def test_middleware_execution():
    """Test middleware adds headers"""
    from main import app
    client = TestClient(app)
    
    response = client.get("/health")
    assert response.status_code == 200
    # Check for process time header from RequestLoggingMiddleware
    assert "X-Process-Time" in response.headers