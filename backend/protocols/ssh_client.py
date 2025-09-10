"""
SSH Client - Comprehensive SSH implementation for device management
"""

import asyncio
import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Union
from datetime import datetime
import paramiko
from paramiko import SSHClient, AutoAddPolicy, RSAKey, Ed25519Key, ECDSAKey
from paramiko.ssh_exception import SSHException, AuthenticationException
import io
import json

logger = logging.getLogger(__name__)

class AsyncSSHClient:
    """
    Asynchronous SSH client for device management and monitoring
    """
    
    def __init__(self,
                 host: str,
                 port: int = 22,
                 username: str = None,
                 password: str = None,
                 private_key: str = None,
                 timeout: int = 30,
                 look_for_keys: bool = False,
                 allow_agent: bool = False):
        """
        Initialize SSH client
        
        Args:
            host: Target device IP address or hostname
            port: SSH port (default: 22)
            username: SSH username
            password: SSH password
            private_key: Private key string or path
            timeout: Connection timeout in seconds
            look_for_keys: Look for SSH keys in default locations
            allow_agent: Allow SSH agent for authentication
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        self.timeout = timeout
        self.look_for_keys = look_for_keys
        self.allow_agent = allow_agent
        self.client = None
        self.shell = None
        self.connected = False
        
    async def connect(self) -> bool:
        """
        Establish SSH connection
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            loop = asyncio.get_event_loop()
            
            # Run connection in thread pool to avoid blocking
            connected = await loop.run_in_executor(
                None,
                self._connect_sync
            )
            
            return connected
            
        except Exception as e:
            logger.error(f"SSH connection failed to {self.host}: {str(e)}")
            return False
    
    def _connect_sync(self) -> bool:
        """
        Synchronous connection method for thread execution
        
        Returns:
            True if connection successful
        """
        try:
            self.client = SSHClient()
            self.client.set_missing_host_key_policy(AutoAddPolicy())
            
            # Setup authentication
            connect_kwargs = {
                'hostname': self.host,
                'port': self.port,
                'username': self.username,
                'timeout': self.timeout,
                'look_for_keys': self.look_for_keys,
                'allow_agent': self.allow_agent
            }
            
            # Add password or key authentication
            if self.private_key:
                key = self._load_private_key(self.private_key)
                connect_kwargs['pkey'] = key
            elif self.password:
                connect_kwargs['password'] = self.password
            
            # Connect
            self.client.connect(**connect_kwargs)
            self.connected = True
            
            logger.info(f"SSH connection established to {self.host}")
            return True
            
        except AuthenticationException:
            logger.error(f"SSH authentication failed for {self.host}")
            return False
        except SSHException as e:
            logger.error(f"SSH error connecting to {self.host}: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error connecting to {self.host}: {str(e)}")
            return False
    
    def _load_private_key(self, key_data: str) -> Union[RSAKey, Ed25519Key, ECDSAKey]:
        """
        Load private key from string or file
        
        Args:
            key_data: Private key string or file path
            
        Returns:
            Loaded private key object
        """
        try:
            # Try as file path first
            try:
                with open(key_data, 'r') as f:
                    key_string = f.read()
            except:
                # Assume it's already a key string
                key_string = key_data
            
            # Try different key types
            key_file = io.StringIO(key_string)
            
            # Try RSA
            try:
                return RSAKey.from_private_key(key_file)
            except:
                key_file.seek(0)
            
            # Try Ed25519
            try:
                return Ed25519Key.from_private_key(key_file)
            except:
                key_file.seek(0)
            
            # Try ECDSA
            try:
                return ECDSAKey.from_private_key(key_file)
            except:
                raise ValueError("Unable to load private key")
                
        except Exception as e:
            logger.error(f"Error loading private key: {str(e)}")
            raise
    
    async def execute_command(self, 
                             command: str,
                             timeout: int = None) -> Tuple[str, str, int]:
        """
        Execute a command on the remote device
        
        Args:
            command: Command to execute
            timeout: Command timeout (uses connection timeout if not specified)
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        if not self.connected:
            raise RuntimeError("Not connected to SSH server")
        
        try:
            loop = asyncio.get_event_loop()
            
            # Run command in thread pool
            result = await loop.run_in_executor(
                None,
                self._execute_command_sync,
                command,
                timeout or self.timeout
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing command '{command}': {str(e)}")
            raise
    
    def _execute_command_sync(self, 
                             command: str,
                             timeout: int) -> Tuple[str, str, int]:
        """
        Synchronous command execution for thread pool
        
        Args:
            command: Command to execute
            timeout: Command timeout
            
        Returns:
            Tuple of (stdout, stderr, exit_code)
        """
        try:
            stdin, stdout, stderr = self.client.exec_command(
                command,
                timeout=timeout
            )
            
            # Read output
            stdout_data = stdout.read().decode('utf-8')
            stderr_data = stderr.read().decode('utf-8')
            exit_code = stdout.channel.recv_exit_status()
            
            return stdout_data, stderr_data, exit_code
            
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            raise
    
    async def execute_commands(self,
                              commands: List[str]) -> List[Dict[str, Any]]:
        """
        Execute multiple commands sequentially
        
        Args:
            commands: List of commands to execute
            
        Returns:
            List of command results
        """
        results = []
        
        for command in commands:
            try:
                stdout, stderr, exit_code = await self.execute_command(command)
                results.append({
                    'command': command,
                    'stdout': stdout,
                    'stderr': stderr,
                    'exit_code': exit_code,
                    'success': exit_code == 0
                })
            except Exception as e:
                results.append({
                    'command': command,
                    'error': str(e),
                    'success': False
                })
        
        return results
    
    async def get_shell(self) -> 'InteractiveShell':
        """
        Get an interactive shell session
        
        Returns:
            InteractiveShell instance
        """
        if not self.connected:
            raise RuntimeError("Not connected to SSH server")
        
        if not self.shell:
            self.shell = InteractiveShell(self.client)
            await self.shell.initialize()
        
        return self.shell
    
    async def disconnect(self):
        """Disconnect SSH connection"""
        try:
            if self.shell:
                await self.shell.close()
                self.shell = None
            
            if self.client:
                self.client.close()
                self.client = None
            
            self.connected = False
            logger.info(f"SSH connection closed to {self.host}")
            
        except Exception as e:
            logger.error(f"Error disconnecting SSH: {str(e)}")
    
    async def __aenter__(self):
        """Context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        await self.disconnect()


class InteractiveShell:
    """
    Interactive SSH shell for complex device interactions
    """
    
    def __init__(self, ssh_client: SSHClient):
        """
        Initialize interactive shell
        
        Args:
            ssh_client: Connected SSH client instance
        """
        self.client = ssh_client
        self.channel = None
        self.prompt_pattern = None
        
    async def initialize(self):
        """Initialize the shell channel"""
        try:
            loop = asyncio.get_event_loop()
            
            # Get shell in thread pool
            await loop.run_in_executor(
                None,
                self._initialize_sync
            )
            
        except Exception as e:
            logger.error(f"Error initializing shell: {str(e)}")
            raise
    
    def _initialize_sync(self):
        """Synchronous shell initialization"""
        self.channel = self.client.invoke_shell()
        self.channel.settimeout(0.5)
        
        # Wait for initial prompt
        self._wait_for_prompt()
        
        # Detect prompt pattern
        self.prompt_pattern = self._detect_prompt()
    
    def _wait_for_prompt(self, timeout: int = 10):
        """Wait for command prompt"""
        buffer = ""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < timeout:
            try:
                chunk = self.channel.recv(1024).decode('utf-8')
                buffer += chunk
                
                # Check for common prompts
                if re.search(r'[>#$]\s*$', buffer):
                    break
            except:
                pass
        
        return buffer
    
    def _detect_prompt(self) -> str:
        """Detect the device prompt pattern"""
        # Send empty line and capture prompt
        self.channel.send('\n')
        output = self._wait_for_prompt()
        
        # Extract prompt pattern
        lines = output.strip().split('\n')
        if lines:
            last_line = lines[-1]
            # Create regex pattern for prompt
            prompt = re.escape(last_line.strip())
            return f"{prompt}\\s*$"
        
        # Default prompt pattern
        return r'[>#$]\s*$'
    
    async def send_command(self,
                          command: str,
                          wait_for_prompt: bool = True,
                          timeout: int = 30) -> str:
        """
        Send command to shell and get output
        
        Args:
            command: Command to send
            wait_for_prompt: Wait for prompt after command
            timeout: Command timeout
            
        Returns:
            Command output
        """
        try:
            loop = asyncio.get_event_loop()
            
            result = await loop.run_in_executor(
                None,
                self._send_command_sync,
                command,
                wait_for_prompt,
                timeout
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Error sending command '{command}': {str(e)}")
            raise
    
    def _send_command_sync(self,
                          command: str,
                          wait_for_prompt: bool,
                          timeout: int) -> str:
        """Synchronous command sending"""
        # Send command
        self.channel.send(f"{command}\n")
        
        if not wait_for_prompt:
            return ""
        
        # Collect output
        output = ""
        start_time = datetime.now()
        
        while (datetime.now() - start_time).seconds < timeout:
            try:
                chunk = self.channel.recv(4096).decode('utf-8')
                output += chunk
                
                # Check for prompt
                if self.prompt_pattern and re.search(self.prompt_pattern, output):
                    break
            except:
                pass
        
        # Remove command echo and prompt
        lines = output.split('\n')
        if lines and command in lines[0]:
            lines = lines[1:]  # Remove command echo
        if lines and re.search(self.prompt_pattern or r'[>#$]\s*$', lines[-1]):
            lines = lines[:-1]  # Remove prompt
        
        return '\n'.join(lines)
    
    async def close(self):
        """Close the shell channel"""
        if self.channel:
            self.channel.close()
            self.channel = None


class DeviceSSHManager:
    """
    High-level SSH manager for different device types
    """
    
    def __init__(self):
        self.vendor_handlers = {
            'cisco': CiscoSSHHandler(),
            'juniper': JuniperSSHHandler(),
            'arista': AristaSSHHandler(),
            'generic': GenericSSHHandler()
        }
    
    async def get_device_info(self,
                             connection_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Get device information based on vendor
        
        Args:
            connection_params: Connection parameters including vendor
            
        Returns:
            Device information dictionary
        """
        vendor = connection_params.get('vendor', 'generic').lower()
        handler = self.vendor_handlers.get(vendor, self.vendor_handlers['generic'])
        
        async with AsyncSSHClient(**connection_params) as client:
            return await handler.get_device_info(client)
    
    async def get_configuration(self,
                               connection_params: Dict[str, Any]) -> str:
        """
        Get device configuration
        
        Args:
            connection_params: Connection parameters
            
        Returns:
            Device configuration text
        """
        vendor = connection_params.get('vendor', 'generic').lower()
        handler = self.vendor_handlers.get(vendor, self.vendor_handlers['generic'])
        
        async with AsyncSSHClient(**connection_params) as client:
            return await handler.get_configuration(client)
    
    async def get_interfaces(self,
                            connection_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get interface information
        
        Args:
            connection_params: Connection parameters
            
        Returns:
            List of interface dictionaries
        """
        vendor = connection_params.get('vendor', 'generic').lower()
        handler = self.vendor_handlers.get(vendor, self.vendor_handlers['generic'])
        
        async with AsyncSSHClient(**connection_params) as client:
            return await handler.get_interfaces(client)


class BaseSSHHandler:
    """Base class for vendor-specific SSH handlers"""
    
    async def get_device_info(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get basic device information"""
        raise NotImplementedError
    
    async def get_configuration(self, client: AsyncSSHClient) -> str:
        """Get device configuration"""
        raise NotImplementedError
    
    async def get_interfaces(self, client: AsyncSSHClient) -> List[Dict[str, Any]]:
        """Get interface information"""
        raise NotImplementedError
    
    async def get_cpu_usage(self, client: AsyncSSHClient) -> Dict[str, float]:
        """Get CPU usage"""
        raise NotImplementedError
    
    async def get_memory_usage(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get memory usage"""
        raise NotImplementedError


class CiscoSSHHandler(BaseSSHHandler):
    """Cisco-specific SSH handler"""
    
    async def get_device_info(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get Cisco device information"""
        shell = await client.get_shell()
        
        # Get version info
        version_output = await shell.send_command("show version")
        
        # Parse output
        info = {
            'vendor': 'Cisco',
            'hostname': '',
            'model': '',
            'version': '',
            'serial': '',
            'uptime': ''
        }
        
        # Parse hostname
        hostname_match = re.search(r'(\S+)\s+uptime', version_output)
        if hostname_match:
            info['hostname'] = hostname_match.group(1)
        
        # Parse model
        model_match = re.search(r'cisco\s+(\S+)', version_output, re.IGNORECASE)
        if model_match:
            info['model'] = model_match.group(1)
        
        # Parse version
        version_match = re.search(r'Version\s+([^\s,]+)', version_output)
        if version_match:
            info['version'] = version_match.group(1)
        
        # Parse serial
        serial_match = re.search(r'Processor board ID\s+(\S+)', version_output)
        if serial_match:
            info['serial'] = serial_match.group(1)
        
        # Parse uptime
        uptime_match = re.search(r'uptime is\s+(.+)', version_output)
        if uptime_match:
            info['uptime'] = uptime_match.group(1)
        
        return info
    
    async def get_configuration(self, client: AsyncSSHClient) -> str:
        """Get Cisco running configuration"""
        shell = await client.get_shell()
        
        # Enter enable mode if needed
        await shell.send_command("enable")
        
        # Get running config
        config = await shell.send_command("show running-config", timeout=60)
        
        return config
    
    async def get_interfaces(self, client: AsyncSSHClient) -> List[Dict[str, Any]]:
        """Get Cisco interface information"""
        shell = await client.get_shell()
        
        # Get interface status
        output = await shell.send_command("show ip interface brief")
        
        interfaces = []
        lines = output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                interface = {
                    'name': parts[0],
                    'ip_address': parts[1] if parts[1] != 'unassigned' else None,
                    'status': parts[4],
                    'protocol': parts[5]
                }
                interfaces.append(interface)
        
        # Get detailed interface info
        for interface in interfaces:
            detail = await shell.send_command(f"show interface {interface['name']}")
            
            # Parse bandwidth
            bw_match = re.search(r'BW\s+(\d+)\s+Kbit', detail)
            if bw_match:
                interface['bandwidth'] = int(bw_match.group(1)) * 1000
            
            # Parse MTU
            mtu_match = re.search(r'MTU\s+(\d+)', detail)
            if mtu_match:
                interface['mtu'] = int(mtu_match.group(1))
            
            # Parse errors
            in_errors_match = re.search(r'(\d+)\s+input errors', detail)
            if in_errors_match:
                interface['input_errors'] = int(in_errors_match.group(1))
            
            out_errors_match = re.search(r'(\d+)\s+output errors', detail)
            if out_errors_match:
                interface['output_errors'] = int(out_errors_match.group(1))
        
        return interfaces
    
    async def get_cpu_usage(self, client: AsyncSSHClient) -> Dict[str, float]:
        """Get Cisco CPU usage"""
        shell = await client.get_shell()
        
        output = await shell.send_command("show processes cpu")
        
        cpu_data = {}
        
        # Parse CPU usage
        cpu_match = re.search(
            r'CPU utilization for five seconds:\s+(\d+)%.*'
            r'one minute:\s+(\d+)%.*'
            r'five minutes:\s+(\d+)%',
            output
        )
        
        if cpu_match:
            cpu_data['5sec'] = float(cpu_match.group(1))
            cpu_data['1min'] = float(cpu_match.group(2))
            cpu_data['5min'] = float(cpu_match.group(3))
        
        return cpu_data
    
    async def get_memory_usage(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get Cisco memory usage"""
        shell = await client.get_shell()
        
        output = await shell.send_command("show memory statistics")
        
        memory_data = {}
        
        # Parse memory usage
        proc_match = re.search(
            r'Processor\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',
            output
        )
        
        if proc_match:
            total = int(proc_match.group(1))
            used = int(proc_match.group(2))
            free = int(proc_match.group(3))
            
            memory_data = {
                'total': total,
                'used': used,
                'free': free,
                'percent_used': (used / total * 100) if total > 0 else 0
            }
        
        return memory_data


class JuniperSSHHandler(BaseSSHHandler):
    """Juniper-specific SSH handler"""
    
    async def get_device_info(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get Juniper device information"""
        # Get version in JSON format
        stdout, _, _ = await client.execute_command(
            "show version | display json"
        )
        
        try:
            version_data = json.loads(stdout)
            
            info = {
                'vendor': 'Juniper',
                'hostname': version_data.get('hostname', ''),
                'model': version_data.get('model', ''),
                'version': version_data.get('version', ''),
                'serial': version_data.get('serial-number', ''),
            }
        except:
            # Fallback to text parsing
            stdout, _, _ = await client.execute_command("show version")
            info = self._parse_juniper_version(stdout)
        
        return info
    
    def _parse_juniper_version(self, output: str) -> Dict[str, Any]:
        """Parse Juniper version output"""
        info = {'vendor': 'Juniper'}
        
        # Parse hostname
        hostname_match = re.search(r'Hostname:\s+(\S+)', output)
        if hostname_match:
            info['hostname'] = hostname_match.group(1)
        
        # Parse model
        model_match = re.search(r'Model:\s+(\S+)', output)
        if model_match:
            info['model'] = model_match.group(1)
        
        # Parse version
        version_match = re.search(r'Junos:\s+(\S+)', output)
        if version_match:
            info['version'] = version_match.group(1)
        
        return info
    
    async def get_configuration(self, client: AsyncSSHClient) -> str:
        """Get Juniper configuration"""
        stdout, _, _ = await client.execute_command(
            "show configuration | no-more"
        )
        return stdout
    
    async def get_interfaces(self, client: AsyncSSHClient) -> List[Dict[str, Any]]:
        """Get Juniper interface information"""
        stdout, _, _ = await client.execute_command(
            "show interfaces terse"
        )
        
        interfaces = []
        lines = stdout.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 3:
                interface = {
                    'name': parts[0],
                    'admin_status': parts[1],
                    'link_status': parts[2]
                }
                
                # Get IP if present
                if len(parts) > 3 and '/' in parts[3]:
                    interface['ip_address'] = parts[3]
                
                interfaces.append(interface)
        
        return interfaces


class AristaSSHHandler(BaseSSHHandler):
    """Arista-specific SSH handler"""
    
    async def get_device_info(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get Arista device information"""
        # Arista supports JSON output
        stdout, _, _ = await client.execute_command(
            "show version | json"
        )
        
        try:
            version_data = json.loads(stdout)
            
            info = {
                'vendor': 'Arista',
                'hostname': version_data.get('hostname', ''),
                'model': version_data.get('modelName', ''),
                'version': version_data.get('version', ''),
                'serial': version_data.get('serialNumber', ''),
                'uptime': version_data.get('uptime', 0)
            }
        except:
            info = {'vendor': 'Arista'}
        
        return info
    
    async def get_configuration(self, client: AsyncSSHClient) -> str:
        """Get Arista running configuration"""
        stdout, _, _ = await client.execute_command(
            "show running-config"
        )
        return stdout
    
    async def get_interfaces(self, client: AsyncSSHClient) -> List[Dict[str, Any]]:
        """Get Arista interface information"""
        stdout, _, _ = await client.execute_command(
            "show interfaces status | json"
        )
        
        try:
            data = json.loads(stdout)
            interfaces = []
            
            for name, details in data.get('interfaceStatuses', {}).items():
                interface = {
                    'name': name,
                    'description': details.get('description', ''),
                    'status': details.get('linkStatus', ''),
                    'vlan': details.get('vlanInformation', {}).get('vlanId'),
                    'bandwidth': details.get('bandwidth', 0),
                    'duplex': details.get('duplex', '')
                }
                interfaces.append(interface)
            
            return interfaces
        except:
            return []


class GenericSSHHandler(BaseSSHHandler):
    """Generic SSH handler for unknown devices"""
    
    async def get_device_info(self, client: AsyncSSHClient) -> Dict[str, Any]:
        """Get generic device information"""
        info = {'vendor': 'Unknown'}
        
        # Try common commands
        commands = [
            ('hostname', 'hostname'),
            ('uname', 'uname -a'),
            ('version', 'cat /etc/os-release 2>/dev/null || cat /etc/issue')
        ]
        
        for key, command in commands:
            try:
                stdout, _, exit_code = await client.execute_command(command)
                if exit_code == 0 and stdout:
                    info[key] = stdout.strip()
            except:
                pass
        
        return info
    
    async def get_configuration(self, client: AsyncSSHClient) -> str:
        """Get generic configuration"""
        # Try to get network configuration
        stdout, _, _ = await client.execute_command(
            "ip addr show 2>/dev/null || ifconfig"
        )
        return stdout
    
    async def get_interfaces(self, client: AsyncSSHClient) -> List[Dict[str, Any]]:
        """Get generic interface information"""
        interfaces = []
        
        # Try ip command first
        stdout, _, exit_code = await client.execute_command("ip -j link show")
        
        if exit_code == 0:
            try:
                data = json.loads(stdout)
                for item in data:
                    interface = {
                        'name': item.get('ifname'),
                        'status': item.get('operstate'),
                        'mtu': item.get('mtu'),
                        'mac': item.get('address')
                    }
                    interfaces.append(interface)
            except:
                pass
        
        # Fallback to ifconfig
        if not interfaces:
            stdout, _, _ = await client.execute_command("ifconfig -a")
            # Parse ifconfig output
            current_interface = None
            
            for line in stdout.split('\n'):
                if line and not line[0].isspace():
                    # New interface
                    parts = line.split()
                    if parts:
                        current_interface = {'name': parts[0].rstrip(':')}
                        interfaces.append(current_interface)
                elif current_interface and 'inet' in line:
                    # IP address line
                    match = re.search(r'inet\s+(\S+)', line)
                    if match:
                        current_interface['ip_address'] = match.group(1)
        
        return interfaces