"""
SSH Protocol Client
Provides SSH connectivity for network devices
"""

import asyncio
import asyncssh
from typing import Dict, Any, Optional, List
import logging
from dataclasses import dataclass
from datetime import datetime

from ...common.result_objects import (
    ProtocolResult, FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

@dataclass
class SSHResult:
    success: bool
    output: str
    error: Optional[str] = None
    execution_time: Optional[float] = None

class SSHClient:
    def __init__(self, host: str, username: str, password: str, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.connection = None
        self.connected = False
    
    async def connect(self) -> bool:
        """Establish SSH connection"""
        try:
            self.connection = await asyncio.wait_for(
                asyncssh.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    known_hosts=None,  # In production, use proper host key verification
                    client_keys=None
                ),
                timeout=10.0
            )
            self.connected = True
            logger.info(f"SSH connection established to {self.host}")
            return True
            
        except Exception as e:
            logger.error(f"SSH connection failed to {self.host}: {e}")
            self.connected = False
            return False
    
    async def disconnect(self):
        """Close SSH connection"""
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()
            self.connected = False
            logger.info(f"SSH connection closed to {self.host}")
    
    async def execute_command(self, command: str, timeout: float = 30.0) -> SSHResult:
        """Execute a command via SSH"""
        start_time = datetime.now()
        
        if not self.connected:
            if not await self.connect():
                return SSHResult(
                    success=False,
                    output="",
                    error="Failed to establish SSH connection"
                )
        
        try:
            result = await asyncio.wait_for(
                self.connection.run(command),
                timeout=timeout
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            return SSHResult(
                success=result.exit_status == 0,
                output=result.stdout,
                error=result.stderr if result.stderr else None,
                execution_time=execution_time
            )
            
        except asyncio.TimeoutError:
            return SSHResult(
                success=False,
                output="",
                error=f"Command timed out after {timeout} seconds"
            )
        except Exception as e:
            return SSHResult(
                success=False,
                output="",
                error=f"SSH command execution failed: {str(e)}"
            )
    
    async def get_device_info(self) -> Dict[str, Any]:
        """Get basic device information via SSH"""
        info = {}
        
        # Get hostname
        result = await self.execute_command("hostname")
        if result.success:
            info['hostname'] = result.output.strip()
        
        # Get system information
        result = await self.execute_command("show version")
        if result.success:
            info['version_info'] = result.output
        
        # Get interface information
        result = await self.execute_command("show interfaces")
        if result.success:
            info['interfaces'] = result.output
        
        return info
    
    async def get_cpu_usage(self) -> Optional[float]:
        """Get CPU usage percentage"""
        result = await self.execute_command("show processes cpu")
        if result.success:
            # Parse CPU usage from output
            lines = result.output.split('\n')
            for line in lines:
                if 'CPU utilization' in line:
                    # Extract percentage from line like "CPU utilization for five seconds: 5%; one minute: 3%; five minutes: 2%"
                    try:
                        parts = line.split(';')
                        current_usage = parts[0].split(':')[1].strip().replace('%', '')
                        return float(current_usage)
                    except Exception as e:
                        logger.debug(f"Failed to parse value: {e}")
        # Return fallback CPU usage data when parsing fails
        fallback_data = FallbackData(
            data=0.0,  # Default CPU usage
            source="parsing_fallback",
            confidence=0.1,
            metadata={"reason": "CPU usage parsing failed", "output": result.output}
        )
        
        return create_partial_success_result(
            data=0.0,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="CPU usage parsing failed, using default value",
                fallback_available=True
            ),
            suggestions=[
                "CPU usage parsing failed, check command output format",
                "Verify 'show processes cpu' command is supported",
                "Check if device is under load",
                "Consider alternative CPU monitoring methods"
            ]
        )
    
    async def get_memory_usage(self) -> Optional[Dict[str, Any]]:
        """Get memory usage information"""
        result = await self.execute_command("show memory statistics")
        if result.success:
            # Parse memory information
            memory_info = {}
            lines = result.output.split('\n')
            
            for line in lines:
                if 'Total' in line and 'Used' in line and 'Free' in line:
                    try:
                        parts = line.split()
                        memory_info['total'] = int(parts[1])
                        memory_info['used'] = int(parts[2])
                        memory_info['free'] = int(parts[3])
                        memory_info['usage_percent'] = (memory_info['used'] / memory_info['total']) * 100
                        return memory_info
                    except Exception as e:
                        logger.debug(f"Failed to parse value: {e}")
        # Return fallback memory data when parsing fails
        fallback_data = FallbackData(
            data={
                'total': 0,
                'used': 0,
                'free': 0,
                'usage_percent': 0.0
            },
            source="parsing_fallback",
            confidence=0.1,
            metadata={"reason": "Memory usage parsing failed", "output": result.output}
        )
        
        return create_partial_success_result(
            data=fallback_data.data,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="Memory usage parsing failed, using default values",
                fallback_available=True
            ),
            suggestions=[
                "Memory usage parsing failed, check command output format",
                "Verify 'show memory statistics' command is supported",
                "Check device memory configuration",
                "Consider alternative memory monitoring methods"
            ]
        )
    
    async def get_temperature(self) -> Optional[float]:
        """Get device temperature"""
        result = await self.execute_command("show environment temperature")
        if result.success:
            # Parse temperature from output
            lines = result.output.split('\n')
            for line in lines:
                if 'Temperature' in line and 'Celsius' in line:
                    try:
                        # Extract temperature value
                        temp_str = line.split('Temperature:')[1].split('Celsius')[0].strip()
                        return float(temp_str)
                    except Exception as e:
                        logger.debug(f"Failed to parse value: {e}")
        # Return fallback temperature data when parsing fails
        fallback_data = FallbackData(
            data=25.0,  # Default room temperature
            source="parsing_fallback",
            confidence=0.1,
            metadata={"reason": "Temperature parsing failed", "output": result.output}
        )
        
        return create_partial_success_result(
            data=25.0,
            fallback_data=fallback_data,
            health_status=HealthStatus(
                status=HealthLevel.DEGRADED,
                degradation_reason="Temperature parsing failed, using default value",
                fallback_available=True
            ),
            suggestions=[
                "Temperature parsing failed, check command output format",
                "Verify 'show environment temperature' command is supported",
                "Check if device has temperature sensors",
                "Consider alternative temperature monitoring methods"
            ]
        )
    
    async def get_interface_stats(self) -> List[Dict[str, Any]]:
        """Get interface statistics"""
        result = await self.execute_command("show interfaces")
        if result.success:
            interfaces = []
            current_interface = {}
            
            for line in result.output.split('\n'):
                line = line.strip()
                if line.startswith('Interface'):
                    if current_interface:
                        interfaces.append(current_interface)
                    current_interface = {'name': line.split()[1]}
                elif 'input rate' in line and current_interface:
                    try:
                        # Parse input rate
                        input_parts = line.split('input rate')[1].split(',')[0].strip()
                        current_interface['input_rate'] = input_parts
                    except Exception as e:
                        logger.debug(f"Failed to parse value: {e}")
                elif 'output rate' in line and current_interface:
                    try:
                        # Parse output rate
                        output_parts = line.split('output rate')[1].split(',')[0].strip()
                        current_interface['output_rate'] = output_parts
                    except Exception as e:
                        logger.debug(f"Failed to parse value: {e}")
            
            if current_interface:
                interfaces.append(current_interface)
            
            return interfaces
        
        return []
    
    async def backup_configuration(self) -> Optional[str]:
        """Backup device configuration"""
        result = await self.execute_command("show running-config")
        if result.success:
            return result.output
        # Return fallback configuration data when backup fails
        fallback_data = FallbackData(
            data="Configuration backup failed",
            source="backup_fallback",
            confidence=0.0,
            metadata={"reason": "Configuration backup failed", "error": result.error}
        )
        
        return create_failure_result(
            error="Configuration backup failed",
            error_code="CONFIG_BACKUP_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Check SSH connection to the device",
                "Verify 'show running-config' command is supported",
                "Check user permissions for configuration access",
                "Try alternative backup methods if available"
            ]
        )
    
    async def test_connectivity(self) -> bool:
        """Test basic connectivity"""
        result = await self.execute_command("ping 8.8.8.8 count 1")
        return result.success and "Success rate is 100 percent" in result.output

class SSHManager:
    """Manages multiple SSH connections"""
    
    def __init__(self):
        self.connections: Dict[str, SSHClient] = {}
    
    async def get_connection(self, device_id: str, credentials: Dict[str, Any]) -> Optional[SSHClient]:
        """Get or create SSH connection for a device"""
        if device_id in self.connections:
            client = self.connections[device_id]
            if client.connected:
                return client
        
        # Create new connection
        client = SSHClient(
            host=credentials['host'],
            username=credentials['username'],
            password=credentials['password'],
            port=credentials.get('port', 22)
        )
        
        if await client.connect():
            self.connections[device_id] = client
            return client
        
        # Return fallback connection data when SSH connection fails
        fallback_data = FallbackData(
            data=None,
            source="connection_fallback",
            confidence=0.0,
            metadata={"reason": "SSH connection failed", "device_id": device_id}
        )
        
        return create_failure_result(
            error="SSH connection failed",
            error_code="SSH_CONNECTION_FAILED",
            fallback_data=fallback_data,
            suggestions=[
                "Check network connectivity to the device",
                "Verify SSH is enabled on the device",
                "Check username and password credentials",
                "Verify SSH port is accessible",
                "Check firewall rules for SSH"
            ]
        )
    
    async def close_connection(self, device_id: str):
        """Close SSH connection for a device"""
        if device_id in self.connections:
            await self.connections[device_id].disconnect()
            del self.connections[device_id]
    
    async def close_all_connections(self):
        """Close all SSH connections"""
        for device_id in list(self.connections.keys()):
            await self.close_connection(device_id)

# Global SSH manager instance
ssh_manager = SSHManager()
