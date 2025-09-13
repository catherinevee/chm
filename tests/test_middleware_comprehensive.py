"""
Comprehensive tests for middleware components
Full coverage of RequestLoggingMiddleware, SecurityMiddleware, and RateLimitMiddleware
"""
import os
import sys
import time
import asyncio
from pathlib import Path

# Setup environment
sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ.update({
    'TESTING': 'true',
    'DATABASE_URL': 'sqlite+aiosqlite:///:memory:',
    'JWT_SECRET_KEY': 'test-secret',
    'SECRET_KEY': 'test-secret',
    'DEBUG': 'true'
})

import pytest
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse


class TestRequestLoggingMiddleware:
    """Comprehensive tests for RequestLoggingMiddleware"""
    
    def test_middleware_import_and_instantiation(self):
        """Test middleware can be imported and instantiated"""
        from core.middleware import RequestLoggingMiddleware
        
        # Create mock app
        mock_app = Mock()
        middleware = RequestLoggingMiddleware(mock_app)
        
        assert middleware is not None
        assert hasattr(middleware, 'app')
        assert hasattr(middleware, 'dispatch')
    
    @pytest.mark.asyncio
    async def test_dispatch_method_execution(self):
        """Test dispatch method processes requests correctly"""
        from core.middleware import RequestLoggingMiddleware
        
        # Create a simple test app
        app = FastAPI()
        
        @app.get("/test")
        async def test_endpoint():
            return {"message": "test"}
        
        # Add middleware
        app.add_middleware(RequestLoggingMiddleware)
        
        # Test with client
        client = TestClient(app)
        response = client.get("/test")
        
        assert response.status_code == 200
        assert "X-Process-Time" in response.headers
    
    @pytest.mark.asyncio
    async def test_process_time_calculation(self):
        """Test that process time is calculated correctly"""
        from core.middleware import RequestLoggingMiddleware
        
        # Create app with delay
        app = FastAPI()
        
        @app.get("/slow")
        async def slow_endpoint():
            await asyncio.sleep(0.1)  # 100ms delay
            return {"message": "slow"}
        
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/slow")
        
        assert response.status_code == 200
        process_time = float(response.headers["X-Process-Time"])
        assert process_time >= 0.1  # Should be at least 100ms
        assert process_time < 1.0  # But not too slow
    
    @pytest.mark.asyncio
    async def test_logging_functionality(self):
        """Test that middleware logs requests and responses"""
        from core.middleware import RequestLoggingMiddleware
        import logging
        
        # Setup logging capture
        with patch('core.middleware.logger') as mock_logger:
            app = FastAPI()
            
            @app.get("/logged")
            async def logged_endpoint():
                return {"status": "ok"}
            
            app.add_middleware(RequestLoggingMiddleware)
            
            client = TestClient(app)
            response = client.get("/logged")
            
            # Verify logging calls were made
            assert mock_logger.info.called
            
            # Check log messages contain expected information
            log_calls = mock_logger.info.call_args_list
            assert any("Request:" in str(call) for call in log_calls)
            assert any("Response:" in str(call) for call in log_calls)
    
    @pytest.mark.asyncio
    async def test_error_handling_in_middleware(self):
        """Test middleware handles errors gracefully"""
        from core.middleware import RequestLoggingMiddleware
        
        app = FastAPI()
        
        @app.get("/error")
        async def error_endpoint():
            raise Exception("Test error")
        
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/error")
        
        # Should still have process time header even with error
        assert "X-Process-Time" in response.headers
        assert response.status_code == 500


class TestSecurityMiddleware:
    """Comprehensive tests for SecurityMiddleware"""
    
    def test_security_middleware_import(self):
        """Test SecurityMiddleware can be imported"""
        from core.middleware import SecurityMiddleware
        
        mock_app = Mock()
        middleware = SecurityMiddleware(mock_app)
        
        assert middleware is not None
        assert hasattr(middleware, 'dispatch')
    
    @pytest.mark.asyncio
    async def test_security_headers_added(self):
        """Test that security headers are added to responses"""
        from core.middleware import SecurityMiddleware
        
        app = FastAPI()
        
        @app.get("/secure")
        async def secure_endpoint():
            return {"secure": True}
        
        app.add_middleware(SecurityMiddleware)
        
        client = TestClient(app)
        response = client.get("/secure")
        
        assert response.status_code == 200
        
        # Check security headers
        assert "X-Content-Type-Options" in response.headers
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        
        assert "X-Frame-Options" in response.headers
        assert response.headers["X-Frame-Options"] == "DENY"
        
        assert "X-XSS-Protection" in response.headers
        assert response.headers["X-XSS-Protection"] == "1; mode=block"
        
        assert "Referrer-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        
        assert "Permissions-Policy" in response.headers
    
    @pytest.mark.asyncio
    async def test_security_headers_on_error_responses(self):
        """Test security headers are added even on error responses"""
        from core.middleware import SecurityMiddleware
        
        app = FastAPI()
        
        @app.get("/secure-error")
        async def secure_error():
            raise ValueError("Security test error")
        
        app.add_middleware(SecurityMiddleware)
        
        client = TestClient(app)
        response = client.get("/secure-error")
        
        # Should still have security headers on error
        assert "X-Content-Type-Options" in response.headers
        assert "X-Frame-Options" in response.headers
    
    @pytest.mark.asyncio
    async def test_multiple_middleware_interaction(self):
        """Test SecurityMiddleware works with other middleware"""
        from core.middleware import SecurityMiddleware, RequestLoggingMiddleware
        
        app = FastAPI()
        
        @app.get("/multi")
        async def multi_endpoint():
            return {"test": "multi"}
        
        app.add_middleware(SecurityMiddleware)
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/multi")
        
        assert response.status_code == 200
        # Should have headers from both middleware
        assert "X-Process-Time" in response.headers
        assert "X-Content-Type-Options" in response.headers


class TestRateLimitMiddleware:
    """Comprehensive tests for RateLimitMiddleware"""
    
    def test_rate_limit_middleware_import(self):
        """Test RateLimitMiddleware can be imported and configured"""
        from core.middleware import RateLimitMiddleware
        
        mock_app = Mock()
        
        # Test with default settings
        middleware = RateLimitMiddleware(mock_app)
        assert middleware.requests_per_minute == 60
        
        # Test with custom settings
        middleware = RateLimitMiddleware(mock_app, requests_per_minute=100)
        assert middleware.requests_per_minute == 100
    
    @pytest.mark.asyncio
    async def test_rate_limiting_enforcement(self):
        """Test that rate limiting is enforced"""
        from core.middleware import RateLimitMiddleware
        
        app = FastAPI()
        
        @app.get("/limited")
        async def limited_endpoint():
            return {"status": "ok"}
        
        # Use very low limit for testing
        app.add_middleware(RateLimitMiddleware, requests_per_minute=5)
        
        client = TestClient(app)
        
        # Make requests up to limit
        for i in range(5):
            response = client.get("/limited")
            assert response.status_code == 200
        
        # Next request should be rate limited
        response = client.get("/limited")
        assert response.status_code == 429
        assert response.text == "Rate limit exceeded"
    
    @pytest.mark.asyncio
    async def test_rate_limit_cleanup(self):
        """Test that old rate limit entries are cleaned up"""
        from core.middleware import RateLimitMiddleware
        
        app = FastAPI()
        
        @app.get("/cleanup")
        async def cleanup_endpoint():
            return {"status": "ok"}
        
        middleware = RateLimitMiddleware(app, requests_per_minute=60)
        
        # Add some old entries
        old_time = time.time() - 61  # More than 60 seconds ago
        middleware.request_counts["old_ip"] = (10, old_time)
        middleware.request_counts["current_ip"] = (5, time.time())
        
        # Create request to trigger cleanup
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/cleanup',
            'client': ('new_ip', 12345)
        }
        
        async def receive():
            return {'type': 'http.request', 'body': b''}
        
        messages = []
        async def send(message):
            messages.append(message)
        
        await middleware(scope, receive, send)
        
        # Old entry should be cleaned up
        assert "old_ip" not in middleware.request_counts
        assert "current_ip" in middleware.request_counts
    
    @pytest.mark.asyncio
    async def test_rate_limit_per_client(self):
        """Test that rate limiting is per-client IP"""
        from core.middleware import RateLimitMiddleware
        
        app = FastAPI()
        
        @app.get("/per-client")
        async def per_client_endpoint():
            return {"status": "ok"}
        
        app.add_middleware(RateLimitMiddleware, requests_per_minute=2)
        
        # Test with different client IPs
        client1 = TestClient(app)
        client1.headers = {"X-Forwarded-For": "192.168.1.1"}
        
        client2 = TestClient(app)
        client2.headers = {"X-Forwarded-For": "192.168.1.2"}
        
        # Client 1 makes 2 requests (at limit)
        for _ in range(2):
            response = client1.get("/per-client")
            assert response.status_code == 200
        
        # Client 1's next request is blocked
        response = client1.get("/per-client")
        assert response.status_code == 429
        
        # But client 2 can still make requests
        response = client2.get("/per-client")
        assert response.status_code == 200
    
    @pytest.mark.asyncio
    async def test_rate_limit_with_unknown_client(self):
        """Test rate limiting handles unknown client gracefully"""
        from core.middleware import RateLimitMiddleware
        
        mock_app = AsyncMock()
        middleware = RateLimitMiddleware(mock_app, requests_per_minute=10)
        
        # Scope without client info
        scope = {
            'type': 'http',
            'method': 'GET',
            'path': '/test',
            'client': None  # No client info
        }
        
        async def receive():
            return {'type': 'http.request'}
        
        messages = []
        async def send(message):
            messages.append(message)
        
        # Should handle gracefully
        await middleware(scope, receive, send)
        
        # Check it tracked as "unknown"
        assert "unknown" in middleware.request_counts


class TestMiddlewareIntegration:
    """Test all middleware working together"""
    
    @pytest.mark.asyncio
    async def test_all_middleware_together(self):
        """Test all middleware components work together"""
        from core.middleware import (
            RequestLoggingMiddleware,
            SecurityMiddleware,
            RateLimitMiddleware
        )
        
        app = FastAPI()
        
        @app.get("/integrated")
        async def integrated_endpoint():
            return {"test": "integrated"}
        
        # Add all middleware
        app.add_middleware(RateLimitMiddleware, requests_per_minute=100)
        app.add_middleware(SecurityMiddleware)
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/integrated")
        
        assert response.status_code == 200
        
        # Check headers from all middleware
        assert "X-Process-Time" in response.headers  # RequestLogging
        assert "X-Content-Type-Options" in response.headers  # Security
        
        # Make many requests to test rate limiting
        for _ in range(99):
            response = client.get("/integrated")
            assert response.status_code == 200
        
        # 101st request should be rate limited
        response = client.get("/integrated")
        assert response.status_code == 429
    
    @pytest.mark.asyncio
    async def test_middleware_error_propagation(self):
        """Test that errors propagate through middleware stack correctly"""
        from core.middleware import (
            RequestLoggingMiddleware,
            SecurityMiddleware
        )
        
        app = FastAPI()
        
        @app.get("/error-prop")
        async def error_prop_endpoint():
            raise ValueError("Test error propagation")
        
        app.add_middleware(SecurityMiddleware)
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/error-prop")
        
        # Error should propagate, but middleware should still add headers
        assert response.status_code == 500
        assert "X-Process-Time" in response.headers
        assert "X-Content-Type-Options" in response.headers


class TestMiddlewareEdgeCases:
    """Test edge cases and error conditions in middleware"""
    
    @pytest.mark.asyncio
    async def test_middleware_with_streaming_response(self):
        """Test middleware handles streaming responses"""
        from core.middleware import RequestLoggingMiddleware
        from fastapi.responses import StreamingResponse
        import io
        
        app = FastAPI()
        
        @app.get("/stream")
        async def stream_endpoint():
            def generate():
                yield b"chunk1"
                yield b"chunk2"
            
            return StreamingResponse(generate(), media_type="text/plain")
        
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/stream")
        
        assert response.status_code == 200
        assert "X-Process-Time" in response.headers
        assert response.content == b"chunk1chunk2"
    
    @pytest.mark.asyncio
    async def test_middleware_with_background_tasks(self):
        """Test middleware with background tasks"""
        from core.middleware import RequestLoggingMiddleware
        from fastapi import BackgroundTasks
        
        app = FastAPI()
        
        task_executed = False
        
        def background_task():
            nonlocal task_executed
            task_executed = True
        
        @app.get("/background")
        async def background_endpoint(background_tasks: BackgroundTasks):
            background_tasks.add_task(background_task)
            return {"status": "task scheduled"}
        
        app.add_middleware(RequestLoggingMiddleware)
        
        client = TestClient(app)
        response = client.get("/background")
        
        assert response.status_code == 200
        assert "X-Process-Time" in response.headers
        # Background task should execute
        assert task_executed


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])