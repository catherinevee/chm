"""
REST API Client
Provides REST API connectivity for modern network devices
"""

import aiohttp
import json
from typing import Dict, Any, Optional, List
import logging
from dataclasses import dataclass
from datetime import datetime
import base64

from ...common.result_objects import (
    ProtocolResult, FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

@dataclass
class RESTResult:
    success: bool
    data: Optional[Dict[str, Any]] = None
    status_code: Optional[int] = None
    error: Optional[str] = None
    response_time: Optional[float] = None

class RESTClient:
    def __init__(self, base_url: str, username: str, password: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.session = None
        self.auth_token = None
        
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    async def connect(self) -> bool:
        """Establish REST API connection and authenticate"""
        try:
            # Create session
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            self.session = aiohttp.ClientSession(connector=connector)
            
            # Authenticate
            await self._authenticate()
            return True
            
        except Exception as e:
            logger.error(f"REST connection failed to {self.base_url}: {e}")
            return False
    
    async def disconnect(self):
        """Close REST API connection"""
        if self.session:
            await self.session.close()
            self.session = None
            self.auth_token = None
    
    async def _authenticate(self):
        """Authenticate with the REST API"""
        try:
            # Try different authentication methods
            auth_methods = [
                self._auth_basic,
                self._auth_token,
                self._auth_cookie
            ]
            
            for auth_method in auth_methods:
                if await auth_method():
                    return True
            
            raise Exception("All authentication methods failed")
            
        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise
    
    async def _auth_basic(self) -> bool:
        """Basic authentication"""
        try:
            auth = aiohttp.BasicAuth(self.username, self.password)
            async with self.session.get(f"{self.base_url}/api/system/info", auth=auth) as response:
                if response.status == 200:
                    logger.info("Basic authentication successful")
                    return True
        except:
            pass
        return False
    
    async def _auth_token(self) -> bool:
        """Token-based authentication"""
        try:
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            async with self.session.post(
                f"{self.base_url}/api/auth/login",
                json=auth_data
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    self.auth_token = data.get('token') or data.get('access_token')
                    if self.auth_token:
                        logger.info("Token authentication successful")
                        return True
        except:
            pass
        return False
    
    async def _auth_cookie(self) -> bool:
        """Cookie-based authentication"""
        try:
            auth_data = {
                "username": self.username,
                "password": self.password
            }
            
            async with self.session.post(
                f"{self.base_url}/api/auth/login",
                json=auth_data
            ) as response:
                if response.status == 200:
                    # Check if we got a session cookie
                    if 'session' in response.cookies or 'auth' in response.cookies:
                        logger.info("Cookie authentication successful")
                        return True
        except:
            pass
        return False
    
    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication"""
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        
        return headers
    
    async def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> RESTResult:
        """Make GET request"""
        start_time = datetime.now()
        
        try:
            url = f"{self.base_url}{endpoint}"
            headers = self._get_headers()
            
            async with self.session.get(url, headers=headers, params=params) as response:
                response_time = (datetime.now() - start_time).total_seconds()
                
                if response.status == 200:
                    data = await response.json()
                    return RESTResult(
                        success=True,
                        data=data,
                        status_code=response.status,
                        response_time=response_time
                    )
                else:
                    error_text = await response.text()
                    return RESTResult(
                        success=False,
                        status_code=response.status,
                        error=f"HTTP {response.status}: {error_text}",
                        response_time=response_time
                    )
                    
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return RESTResult(
                success=False,
                error=f"Request failed: {str(e)}",
                response_time=response_time
            )
    
    async def post(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> RESTResult:
        """Make POST request"""
        start_time = datetime.now()
        
        try:
            url = f"{self.base_url}{endpoint}"
            headers = self._get_headers()
            
            async with self.session.post(url, headers=headers, json=data) as response:
                response_time = (datetime.now() - start_time).total_seconds()
                
                if response.status in [200, 201]:
                    response_data = await response.json()
                    return RESTResult(
                        success=True,
                        data=response_data,
                        status_code=response.status,
                        response_time=response_time
                    )
                else:
                    error_text = await response.text()
                    return RESTResult(
                        success=False,
                        status_code=response.status,
                        error=f"HTTP {response.status}: {error_text}",
                        response_time=response_time
                    )
                    
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return RESTResult(
                success=False,
                error=f"Request failed: {str(e)}",
                response_time=response_time
            )
    
    async def put(self, endpoint: str, data: Optional[Dict[str, Any]] = None) -> RESTResult:
        """Make PUT request"""
        start_time = datetime.now()
        
        try:
            url = f"{self.base_url}{endpoint}"
            headers = self._get_headers()
            
            async with self.session.put(url, headers=headers, json=data) as response:
                response_time = (datetime.now() - start_time).total_seconds()
                
                if response.status in [200, 201, 204]:
                    response_data = await response.json() if response.status != 204 else None
                    return RESTResult(
                        success=True,
                        data=response_data,
                        status_code=response.status,
                        response_time=response_time
                    )
                else:
                    error_text = await response.text()
                    return RESTResult(
                        success=False,
                        status_code=response.status,
                        error=f"HTTP {response.status}: {error_text}",
                        response_time=response_time
                    )
                    
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return RESTResult(
                success=False,
                error=f"Request failed: {str(e)}",
                response_time=response_time
            )
    
    async def delete(self, endpoint: str) -> RESTResult:
        """Make DELETE request"""
        start_time = datetime.now()
        
        try:
            url = f"{self.base_url}{endpoint}"
            headers = self._get_headers()
            
            async with self.session.delete(url, headers=headers) as response:
                response_time = (datetime.now() - start_time).total_seconds()
                
                if response.status in [200, 204]:
                    return RESTResult(
                        success=True,
                        status_code=response.status,
                        response_time=response_time
                    )
                else:
                    error_text = await response.text()
                    return RESTResult(
                        success=False,
                        status_code=response.status,
                        error=f"HTTP {response.status}: {error_text}",
                        response_time=response_time
                    )
                    
        except Exception as e:
            response_time = (datetime.now() - start_time).total_seconds()
            return RESTResult(
                success=False,
                error=f"Request failed: {str(e)}",
                response_time=response_time
            )
    
    # Device-specific methods
    async def get_system_info(self) -> Optional[Dict[str, Any]]:
        """Get system information"""
        result = await self.get("/api/system/info")
        if result.success:
            return result.data
        
        # Return fallback system info when REST API fails
        fallback_data = FallbackData(
            data={
                'hostname': 'unknown-device',
                'model': 'unknown',
                'vendor': 'unknown',
                'serial_number': 'unknown',
                'firmware_version': 'unknown'
            },
            source="fallback_defaults",
            confidence=0.1,
            metadata={"reason": "REST API system info failed", "endpoint": "/api/system/info"}
        )
        
        return create_partial_success_result(
            data=fallback_data.data,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="REST API system info failed, using default values",
                fallback_available=True
            ),
            suggestions=[
                "REST API system info endpoint failed",
                "Check if the device supports REST API",
                "Verify authentication credentials",
                "Check network connectivity to the device",
                "Consider alternative monitoring methods"
            ]
        )
    
    async def get_interfaces(self) -> List[Dict[str, Any]]:
        """Get interface information"""
        result = await self.get("/api/interfaces")
        if result.success:
            return result.data.get('interfaces', [])
        return []
    
    async def get_interface_stats(self, interface_id: str) -> Optional[Dict[str, Any]]:
        """Get interface statistics"""
        result = await self.get(f"/api/interfaces/{interface_id}/stats")
        if result.success:
            return result.data
        
        # Return fallback interface stats when REST API fails
        fallback_data = FallbackData(
            data={
                'interface_id': interface_id,
                'status': 'unknown',
                'speed': 0,
                'in_octets': 0,
                'out_octets': 0,
                'in_errors': 0,
                'out_errors': 0
            },
            source="fallback_defaults",
            confidence=0.1,
            metadata={"reason": "REST API interface stats failed", "interface_id": interface_id, "endpoint": f"/api/interfaces/{interface_id}/stats"}
        )
        
        return create_partial_success_result(
            data=fallback_data.data,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="REST API interface stats failed, using default values",
                fallback_available=True
            ),
            suggestions=[
                f"REST API interface stats failed for interface {interface_id}",
                "Check if the interface exists on the device",
                "Verify REST API endpoint availability",
                "Check authentication and permissions",
                "Consider alternative interface monitoring methods"
            ]
        )
    
    async def get_cpu_usage(self) -> Optional[float]:
        """Get CPU usage percentage"""
        result = await self.get("/api/system/cpu")
        if result.success:
            return result.data.get('usage_percent')
        
        # Return fallback CPU usage when REST API fails
        fallback_data = FallbackData(
            data=0.0,  # Default CPU usage
            source="fallback_defaults",
            confidence=0.1,
            metadata={"reason": "REST API CPU usage failed", "endpoint": "/api/system/cpu"}
        )
        
        return create_partial_success_result(
            data=0.0,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="REST API CPU usage failed, using default value",
                fallback_available=True
            ),
            suggestions=[
                "REST API CPU usage endpoint failed",
                "Check if the device supports CPU monitoring via REST",
                "Verify REST API endpoint availability",
                "Check authentication and permissions",
                "Consider alternative CPU monitoring methods"
            ]
        )
    
    async def get_memory_usage(self) -> Optional[Dict[str, Any]]:
        """Get memory usage information"""
        result = await self.get("/api/system/memory")
        if result.success:
            return result.data
        
        # Return fallback memory usage when REST API fails
        fallback_data = FallbackData(
            data={
                'total': 0,
                'used': 0,
                'free': 0,
                'usage_percent': 0.0
            },
            source="fallback_defaults",
            confidence=0.1,
            metadata={"reason": "REST API memory usage failed", "endpoint": "/api/system/memory"}
        )
        
        return create_partial_success_result(
            data=fallback_data.data,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="REST API memory usage failed, using default values",
                fallback_available=True
            ),
            suggestions=[
                "REST API memory usage endpoint failed",
                "Check if the device supports memory monitoring via REST",
                "Verify REST API endpoint availability",
                "Check authentication and permissions",
                "Consider alternative memory monitoring methods"
            ]
        )
    
    async def get_temperature(self) -> Optional[float]:
        """Get device temperature"""
        result = await self.get("/api/system/temperature")
        if result.success:
            return result.data.get('temperature')
        
        # Return fallback temperature when REST API fails
        fallback_data = FallbackData(
            data=25.0,  # Default room temperature
            source="fallback_defaults",
            confidence=0.1,
            metadata={"reason": "REST API temperature failed", "endpoint": "/api/system/temperature"}
        )
        
        return create_partial_success_result(
            data=25.0,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="REST API temperature failed, using default value",
                fallback_available=True
            ),
            suggestions=[
                "REST API temperature endpoint failed",
                "Check if the device supports temperature monitoring via REST",
                "Verify REST API endpoint availability",
                "Check authentication and permissions",
                "Consider alternative temperature monitoring methods"
            ]
        )
    
    async def get_configuration(self) -> Optional[str]:
        """Get device configuration"""
        result = await self.get("/api/config/running")
        if result.success:
            return result.data.get('config')
        
        # Return fallback configuration when REST API fails
        fallback_data = FallbackData(
            data="Configuration retrieval failed",
            source="fallback_defaults",
            confidence=0.0,
            metadata={"reason": "REST API configuration failed", "endpoint": "/api/config/running"}
        )
        
        return create_failure_result(
            error="REST API configuration retrieval failed",
            error_code="REST_CONFIG_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "REST API configuration endpoint failed",
                "Check if the device supports configuration retrieval via REST",
                "Verify REST API endpoint availability",
                "Check authentication and permissions",
                "Consider alternative configuration methods"
            ]
        )
    
    async def update_configuration(self, config: str) -> bool:
        """Update device configuration"""
        result = await self.put("/api/config/running", {"config": config})
        return result.success
    
    async def test_connectivity(self) -> bool:
        """Test basic connectivity"""
        result = await self.get("/api/system/health")
        return result.success and result.status_code == 200

class RESTManager:
    """Manages multiple REST API connections"""
    
    def __init__(self):
        self.clients: Dict[str, RESTClient] = {}
    
    async def get_client(self, device_id: str, config: Dict[str, Any]) -> Optional[RESTClient]:
        """Get or create REST client for a device"""
        if device_id in self.clients:
            return self.clients[device_id]
        
        # Create new client
        client = RESTClient(
            base_url=config['base_url'],
            username=config['username'],
            password=config['password'],
            verify_ssl=config.get('verify_ssl', False)
        )
        
        if await client.connect():
            self.clients[device_id] = client
            return client
        
        # Return fallback client data when REST connection fails
        fallback_data = FallbackData(
            data=None,
            source="connection_fallback",
            confidence=0.0,
            metadata={"reason": "REST connection failed", "device_id": device_id}
        )
        
        return create_failure_result(
            error="REST connection failed",
            error_code="REST_CONNECTION_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Check network connectivity to the device",
                "Verify REST API is enabled on the device",
                "Check base URL and port configuration",
                "Verify username and password credentials",
                "Check SSL/TLS configuration",
                "Consider alternative connection methods"
            ]
        )
    
    async def close_client(self, device_id: str):
        """Close REST client for a device"""
        if device_id in self.clients:
            await self.clients[device_id].disconnect()
            del self.clients[device_id]
    
    async def close_all_clients(self):
        """Close all REST clients"""
        for device_id in list(self.clients.keys()):
            await self.close_client(device_id)

# Global REST manager instance
rest_manager = RESTManager()
