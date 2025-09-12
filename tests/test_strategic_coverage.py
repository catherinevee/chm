"""
Simple strategic tests to boost coverage from 48% to 65%
Focus on main.py and middleware functionality
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test environment
os.environ.update({
    'TESTING': 'true',
    'DATABASE_URL': 'sqlite+aiosqlite:///:memory:',
    'JWT_SECRET_KEY': 'test-secret',
    'SECRET_KEY': 'test-secret',
    'DEBUG': 'true'
})

import pytest
from fastapi.testclient import TestClient


class TestMainApp:
    """Test main.py application"""
    
    def test_main_import(self):
        """Test main.py can be imported"""
        import main
        assert main.app is not None
        assert hasattr(main, 'create_app')
        
    def test_create_app(self):
        """Test create_app function"""
        from main import create_app
        app = create_app()
        assert app.title == "CHM API"
        assert app.version == "2.0.0"
        
    def test_health_endpoints(self):
        """Test health endpoints work"""
        from main import app
        client = TestClient(app)
        
        # Test root
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        
        # Test health
        response = client.get("/health")
        assert response.status_code == 200
        
        # Test API status
        response = client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert data["api_version"] == "v1"


class TestCoreMiddleware:
    """Test core middleware functionality"""
    
    def test_middleware_import(self):
        """Test middleware can be imported"""
        from core import middleware
        assert hasattr(middleware, 'RequestLoggingMiddleware')
        
    def test_request_logging_middleware(self):
        """Test RequestLoggingMiddleware"""
        from core.middleware import RequestLoggingMiddleware
        from starlette.applications import Starlette
        from starlette.responses import Response
        
        async def app(scope, receive, send):
            response = Response("OK", status_code=200)
            await response(scope, receive, send)
            
        middleware = RequestLoggingMiddleware(app)
        
        # Test it exists and can be instantiated
        assert middleware is not None
        assert hasattr(middleware, 'dispatch')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])