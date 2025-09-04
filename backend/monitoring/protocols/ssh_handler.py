"""
SSH Handler for device monitoring and management
"""

from typing import Dict, Any, Optional, List, Tuple
import asyncio
import asyncssh
import logging
import re
from datetime import datetime

from backend.common.exceptions import CHMException
from backend.common.utils import retry, circuit_breaker, timeout
from backend.monitoring.connection_pool import ssh_pool
from backend.monitoring.ssh_parsers import ssh_parser, ParsedSystemInfo

logger = logging.getLogger(__name__)

class SSHConnectionException(CHMException):
    """SSH connection specific exception"""
    def __init__(self, host: str, error: str):
        super().__init__(
            message=f"SSH connection failed to {host}: {error}",
            error_code="SSH_CONNECTION_FAILED",
            details={"host": host, "error": error}
        )

class SSHHandler:
    """Handles SSH operations for device management"""
    
    def __init__(self):
        self.connections: Dict[str, asyncssh.SSHClientConnection] = {}
    
    @retry(max_attempts=3, delay=2.0, backoff=2.0, exceptions=(SSHConnectionException, asyncio.TimeoutError))
    @circuit_breaker(failure_threshold=5, recovery_timeout=120)
    async def connect(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        timeout: int = 30
    ) -> asyncssh.SSHClientConnection:
        """Establish SSH connection to a device"""
        try:
            # Check if already connected
            conn_key = f"{host}:{port}"
            if conn_key in self.connections:
                # Test if connection is still alive
                try:
                    await asyncio.wait_for(
                        self.connections[conn_key].run('echo test'),
                        timeout=2
                    )
                    return self.connections[conn_key]
                except:
                    # Connection is dead, remove it
                    del self.connections[conn_key]
            
            # Prepare connection parameters
            connect_params = {
                'host': host,
                'port': port,
                'username': username,
                'known_hosts': None,  # Skip host key verification for now
                'connect_timeout': timeout
            }
            
            if password:
                connect_params['password'] = password
            elif key_path:
                connect_params['client_keys'] = [key_path]
            
            # Establish connection
            conn = await asyncssh.connect(**connect_params)
            self.connections[conn_key] = conn
            
            logger.info(f"SSH connection established to {host}:{port}")
            return conn
            
        except asyncio.TimeoutError:
            raise SSHConnectionException(host, "Connection timeout")
        except asyncssh.Error as e:
            raise SSHConnectionException(host, str(e))
        except Exception as e:
            raise SSHConnectionException(host, f"Unexpected error: {str(e)}")
    
    async def execute_command(
        self,
        connection: asyncssh.SSHClientConnection,
        command: str,
        timeout: int = 30
    ) -> Tuple[str, str, int]:
        """Execute a command on the remote device"""
        try:
            result = await asyncio.wait_for(
                connection.run(command),
                timeout=timeout
            )
            
            stdout = result.stdout if result.stdout else ""
            stderr = result.stderr if result.stderr else ""
            exit_status = result.exit_status if hasattr(result, 'exit_status') else 0
            
            return stdout, stderr, exit_status
            
        except asyncio.TimeoutError:
            logger.error(f"Command timeout: {command}")
            return "", "Command execution timeout", 1
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return "", str(e), 1
    
    async def get_device_info(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22
    ) -> Dict[str, Any]:
        """Get comprehensive device information using structured parsing"""
        try:
            # Use connection from pool
            async with ssh_pool.acquire(host, port, username, password, key_path) as conn:
                device_info = {
                    'hostname': host,
                    'connection_type': 'ssh',
                    'port': port,
                    'discovery_timestamp': datetime.now().isoformat()
                }
                
                # Collect parsed outputs from multiple commands
                parsed_outputs = []
                device_type = None
                
                # Try multiple detection commands and parse their outputs
                detection_commands = [
                    ('show version', 'cisco_ios'),
                    ('show version | json', 'arista_eos'),
                    ('display version', 'hp_comware'),
                    ('show version | display json', 'juniper_junos'),
                    ('get system status', 'fortinet'),
                    ('uname -a', 'linux')
                ]
                
                for command, expected_type in detection_commands:
                    stdout, stderr, exit_code = await self.execute_command(conn, command, timeout=15)
                    
                    if exit_code == 0 and stdout.strip():
                        # Parse command output
                        parsed_result = ssh_parser.parse_command_output(command, stdout, expected_type)
                        
                        if parsed_result.get('parsed', False):
                            parsed_outputs.append(parsed_result)
                            
                            # Determine device type from successful parsing
                            if not device_type:
                                if 'cisco' in stdout.lower() or expected_type == 'cisco_ios':
                                    device_type = 'cisco_ios'
                                    device_info['vendor'] = 'Cisco'
                                elif 'arista' in stdout.lower() or expected_type == 'arista_eos':
                                    device_type = 'arista_eos'
                                    device_info['vendor'] = 'Arista'
                                elif 'hp' in stdout.lower() or 'comware' in stdout.lower() or expected_type == 'hp_comware':
                                    device_type = 'hp_comware'
                                    device_info['vendor'] = 'HP/HPE'
                                elif 'junos' in stdout.lower() or expected_type == 'juniper_junos':
                                    device_type = 'juniper_junos'
                                    device_info['vendor'] = 'Juniper'
                                elif 'fortigate' in stdout.lower() or expected_type == 'fortinet':
                                    device_type = 'fortinet'
                                    device_info['vendor'] = 'Fortinet'
                                elif 'linux' in stdout.lower() or expected_type == 'linux':
                                    device_type = 'linux'
                                    device_info['os'] = 'Linux'
                            
                            # Stop after first successful detection
                            break
                
                device_info['device_type'] = device_type or 'unknown'
                
                # Get additional information based on detected device type
                if device_type:
                    additional_commands = self._get_additional_commands(device_type)
                    
                    for command in additional_commands:
                        stdout, stderr, exit_code = await self.execute_command(conn, command, timeout=15)
                        
                        if exit_code == 0 and stdout.strip():
                            parsed_result = ssh_parser.parse_command_output(command, stdout, device_type)
                            if parsed_result.get('parsed', False):
                                parsed_outputs.append(parsed_result)
                
                # Extract system information from all parsed outputs
                system_info = ssh_parser.extract_system_info(parsed_outputs)
                
                # Merge system info into device info
                device_info.update({
                    'hostname': system_info.hostname if system_info.hostname != 'unknown' else device_info['hostname'],
                    'model': system_info.model,
                    'serial_number': system_info.serial_number,
                    'software_version': system_info.software_version,
                    'uptime': system_info.uptime,
                    'cpu_usage': system_info.cpu_usage,
                    'memory_usage': system_info.memory_usage,
                    'temperature': system_info.temperature
                })
                
                # Add raw parsed outputs for detailed analysis
                device_info['parsed_outputs'] = parsed_outputs
                device_info['parsing_summary'] = {
                    'total_commands': len(parsed_outputs),
                    'successful_parses': len([p for p in parsed_outputs if p.get('parsed', False)]),
                    'parsers_attempted': list(set(p.get('parser_used', 'unknown') for p in parsed_outputs))
                }
                
                return device_info
            
        except Exception as e:
            logger.error(f"Failed to get device info via SSH for {host}: {e}")
            raise
    
    def _get_additional_commands(self, device_type: str) -> List[str]:
        """Get additional commands to run based on device type"""
        command_map = {
            'cisco_ios': [
                'show ip interface brief',
                'show processes cpu',
                'show memory summary',
                'show environment all',
                'show inventory'
            ],
            'arista_eos': [
                'show interfaces status',
                'show processes top once',
                'show system environment cooling',
                'show version detail'
            ],
            'juniper_junos': [
                'show interfaces terse',
                'show system information',
                'show chassis hardware',
                'show system uptime'
            ],
            'hp_comware': [
                'display interface brief',
                'display cpu-usage',
                'display memory-usage',
                'display device'
            ],
            'fortinet': [
                'get system interface physical',
                'get system performance status',
                'get hardware status'
            ],
            'linux': [
                'free -h',
                'top -bn1 | head -20',
                'ip addr show',
                'cat /proc/cpuinfo | head -20',
                'df -h'
            ]
        }
        
        return command_map.get(device_type, [])
    
    async def execute_commands_batch(
        self,
        connection: asyncssh.SSHClientConnection,
        commands: List[str],
        device_type: Optional[str] = None,
        timeout: int = 30
    ) -> List[Dict[str, Any]]:
        """Execute multiple commands and return parsed results"""
        results = []
        
        for command in commands:
            try:
                stdout, stderr, exit_code = await self.execute_command(
                    connection, command, timeout
                )
                
                if exit_code == 0 and stdout.strip():
                    parsed_result = ssh_parser.parse_command_output(
                        command, stdout, device_type
                    )
                    parsed_result['exit_code'] = exit_code
                    parsed_result['stderr'] = stderr
                    results.append(parsed_result)
                else:
                    # Still record failed commands
                    results.append({
                        'command': command,
                        'parsed': False,
                        'exit_code': exit_code,
                        'stdout': stdout,
                        'stderr': stderr,
                        'error': f"Command failed with exit code {exit_code}"
                    })
                    
            except Exception as e:
                logger.warning(f"Failed to execute command '{command}': {e}")
                results.append({
                    'command': command,
                    'parsed': False,
                    'error': str(e),
                    'exception': True
                })
        
        return results
    
    async def get_device_metrics(
        self,
        host: str,
        username: str,
        password: Optional[str] = None,
        key_path: Optional[str] = None,
        port: int = 22,
        device_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get current device performance metrics using structured parsing"""
        try:
            async with ssh_pool.acquire(host, port, username, password, key_path) as conn:
                metrics_commands = self._get_metrics_commands(device_type or 'unknown')
                
                # Execute metrics commands
                parsed_results = await self.execute_commands_batch(
                    conn, metrics_commands, device_type, timeout=15
                )
                
                # Extract metrics from parsed results
                metrics = {
                    'timestamp': datetime.now().isoformat(),
                    'host': host,
                    'device_type': device_type,
                    'cpu_usage': None,
                    'memory_usage': None,
                    'temperature': None,
                    'interface_stats': [],
                    'raw_outputs': parsed_results
                }
                
                # Extract specific metrics from parsed outputs
                for result in parsed_results:
                    if not result.get('parsed', False):
                        continue
                    
                    # CPU metrics
                    if 'cpu_5sec' in result:
                        metrics['cpu_usage'] = result['cpu_5sec']
                    elif 'cpu' in result and isinstance(result['cpu'], dict):
                        metrics['cpu_usage'] = result['cpu'].get('usage')
                    
                    # Memory metrics
                    if 'memory_pools' in result:
                        for pool in result['memory_pools']:
                            if pool.get('name', '').lower() == 'processor':
                                total = pool.get('total_bytes', 0)
                                used = pool.get('used_bytes', 0)
                                if total > 0:
                                    metrics['memory_usage'] = (used / total) * 100
                    elif 'memory' in result and isinstance(result['memory'], dict):
                        memory = result['memory']
                        total = memory.get('total', 0)
                        if total > 0:
                            used = memory.get('used', 0)
                            if 'available' in memory:
                                used = total - memory['available']
                            metrics['memory_usage'] = (used / total) * 100
                    
                    # Temperature metrics
                    if 'sensors' in result:
                        temps = []
                        for sensor in result['sensors']:
                            if 'temperature_c' in sensor:
                                temps.append(sensor['temperature_c'])
                        if temps:
                            metrics['temperature'] = sum(temps) / len(temps)
                    
                    # Interface statistics
                    if 'interfaces' in result:
                        metrics['interface_stats'] = result['interfaces']
                
                return metrics
                
        except Exception as e:
            logger.error(f"Failed to get device metrics for {host}: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'host': host,
                'error': str(e)
            }
    
    def _get_metrics_commands(self, device_type: str) -> List[str]:
        """Get performance monitoring commands based on device type"""
        command_map = {
            'cisco_ios': [
                'show processes cpu',
                'show memory summary',
                'show environment all'
            ],
            'arista_eos': [
                'show processes top once',
                'show system environment cooling'
            ],
            'juniper_junos': [
                'show chassis routing-engine',
                'show chassis environment'
            ],
            'hp_comware': [
                'display cpu-usage',
                'display memory-usage'
            ],
            'fortinet': [
                'get system performance status'
            ],
            'linux': [
                'top -bn1 | head -5',
                'free -m'
            ]
        }
        
        return command_map.get(device_type, ['echo "Unknown device type"'])
    
    # Legacy parsing methods removed - now using structured ssh_parser
    # These methods are kept for backward compatibility but deprecated
    
    def _parse_cisco_interfaces(self, output: str) -> List[Dict[str, Any]]:
        """Deprecated: Use ssh_parser instead"""
        logger.warning("_parse_cisco_interfaces is deprecated. Use ssh_parser.parse_command_output instead.")
        return ssh_parser.parse_command_output('show ip interface brief', output, 'cisco_ios').get('interfaces', [])
    
    def _parse_cisco_memory(self, output: str) -> Dict[str, Any]:
        """Deprecated: Use ssh_parser instead"""
        logger.warning("_parse_cisco_memory is deprecated. Use ssh_parser.parse_command_output instead.")
        result = ssh_parser.parse_command_output('show memory summary', output, 'cisco_ios')
        return result.get('memory_pools', [{}])[0] if result.get('memory_pools') else {}
    
    def _parse_linux_memory(self, output: str) -> Dict[str, Any]:
        """Deprecated: Use ssh_parser instead"""
        logger.warning("_parse_linux_memory is deprecated. Use ssh_parser.parse_command_output instead.")
        return ssh_parser.parse_command_output('free', output, 'linux').get('memory', {})
    
    def _parse_linux_interfaces(self, output: str) -> List[Dict[str, Any]]:
        """Deprecated: Use ssh_parser instead"""
        logger.warning("_parse_linux_interfaces is deprecated. Use ssh_parser.parse_command_output instead.")
        return ssh_parser.parse_command_output('ip addr show', output, 'linux').get('interfaces', [])
    
    def _parse_juniper_interfaces(self, output: str) -> List[Dict[str, Any]]:
        """Deprecated: Use ssh_parser instead"""
        logger.warning("_parse_juniper_interfaces is deprecated. Use ssh_parser.parse_command_output instead.")
        return ssh_parser.parse_command_output('show interfaces terse', output, 'juniper_junos').get('interfaces', [])
    
    # Legacy device-specific methods removed - functionality moved to structured parsing
    # These methods have been replaced by the comprehensive ssh_parser system
    
    async def disconnect(self, host: str, port: int = 22):
        """Disconnect SSH connection"""
        conn_key = f"{host}:{port}"
        if conn_key in self.connections:
            try:
                self.connections[conn_key].close()
                await self.connections[conn_key].wait_closed()
            except Exception as e:
                logger.debug(f"Error closing SSH connection to {host}:{port}: {e}")
            del self.connections[conn_key]
            logger.info(f"SSH connection closed to {host}:{port}")
    
    async def disconnect_all(self):
        """Disconnect all SSH connections"""
        for conn_key in list(self.connections.keys()):
            host, port = conn_key.split(':')
            await self.disconnect(host, int(port))
    
    def __del__(self):
        """Cleanup connections on deletion"""
        if hasattr(self, 'connections'):
            # Schedule cleanup in event loop if available
            try:
                loop = asyncio.get_event_loop()
                if not loop.is_closed():
                    loop.create_task(self.disconnect_all())
            except:
                pass