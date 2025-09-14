"""
SSH Service for device connectivity and command execution in CHM.

This module provides comprehensive SSH functionality including:
- Secure SSH connections with multiple authentication methods
- Command execution and output parsing
- Interactive shell sessions
- File transfer (SCP/SFTP)
- Multi-vendor device support
- Connection pooling and session management
- Async operations for scalability
"""

import asyncio
import json
import re
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
import tempfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import asyncssh
from asyncssh import SSHClientConnection, SSHClientSession
import paramiko
from pydantic import BaseModel, Field, validator

from backend.config import settings
import logging
logger = logging.getLogger(__name__)
from backend.common.exceptions import (
    DeviceConnectionError, SSHError,
    TimeoutError, ValidationError,
    AuthenticationError
)
# Cache manager not yet implemented
cache_manager = None




class DeviceVendor(str, Enum):
    """Supported device vendors."""
    CISCO = "cisco"
    JUNIPER = "juniper"
    ARISTA = "arista"
    HP = "hp"
    HUAWEI = "huawei"
    FORTINET = "fortinet"
    PALOALTO = "paloalto"
    F5 = "f5"
    LINUX = "linux"
    GENERIC = "generic"


class AuthMethod(str, Enum):
    """SSH authentication methods."""
    PASSWORD = "password"
    PUBLIC_KEY = "public_key"
    KEYBOARD_INTERACTIVE = "keyboard_interactive"
    MULTI_FACTOR = "multi_factor"


class CommandMode(str, Enum):
    """Device command modes."""
    USER = "user"
    PRIVILEGED = "privileged"
    CONFIGURE = "configure"
    INTERFACE = "interface"
    ROUTER = "router"
    VLAN = "vlan"


@dataclass
class SSHCredentials:
    """SSH connection credentials."""
    host: str
    username: str
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    port: int = 22
    timeout: int = 30
    auth_method: AuthMethod = AuthMethod.PASSWORD
    enable_password: Optional[str] = None
    vendor: DeviceVendor = DeviceVendor.GENERIC


@dataclass
class CommandResult:
    """Result from command execution."""
    success: bool
    command: str
    output: str
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DevicePrompts:
    """Device prompt patterns."""
    user_prompt: str = r">\s*$"
    privileged_prompt: str = r"#\s*$"
    configure_prompt: str = r"\(config\)#\s*$"
    interface_prompt: str = r"\(config-if\)#\s*$"
    router_prompt: str = r"\(config-router\)#\s*$"
    vlan_prompt: str = r"\(config-vlan\)#\s*$"
    password_prompt: str = r"[Pp]assword:\s*$"
    enable_prompt: str = r"[Pp]assword:\s*$"
    question_prompt: str = r"\?\s*$"
    continue_prompt: str = r"--More--|\(more\)"


class SSHConfig(BaseModel):
    """SSH service configuration."""
    max_connections: int = 100
    connection_timeout: int = 30
    command_timeout: int = 60
    retry_count: int = 3
    retry_delay: int = 5
    keepalive_interval: int = 30
    thread_pool_size: int = 10
    cache_ttl: int = 300
    known_hosts_file: Optional[str] = None
    strict_host_checking: bool = False


class VendorCommands:
    """Vendor-specific command mappings."""
    
    ENABLE_COMMANDS = {
        DeviceVendor.CISCO: "enable",
        DeviceVendor.JUNIPER: "",  # Already in operational mode
        DeviceVendor.ARISTA: "enable",
        DeviceVendor.HP: "enable",
        DeviceVendor.HUAWEI: "system-view",
        DeviceVendor.FORTINET: "",  # Already privileged
        DeviceVendor.LINUX: "sudo -i",
        DeviceVendor.GENERIC: "enable"
    }
    
    CONFIG_COMMANDS = {
        DeviceVendor.CISCO: "configure terminal",
        DeviceVendor.JUNIPER: "configure",
        DeviceVendor.ARISTA: "configure terminal",
        DeviceVendor.HP: "configure terminal",
        DeviceVendor.HUAWEI: "system-view",
        DeviceVendor.FORTINET: "config system",
        DeviceVendor.LINUX: "",
        DeviceVendor.GENERIC: "configure"
    }
    
    EXIT_COMMANDS = {
        DeviceVendor.CISCO: "exit",
        DeviceVendor.JUNIPER: "exit",
        DeviceVendor.ARISTA: "exit",
        DeviceVendor.HP: "exit",
        DeviceVendor.HUAWEI: "quit",
        DeviceVendor.FORTINET: "end",
        DeviceVendor.LINUX: "exit",
        DeviceVendor.GENERIC: "exit"
    }
    
    SAVE_COMMANDS = {
        DeviceVendor.CISCO: "copy running-config startup-config",
        DeviceVendor.JUNIPER: "commit",
        DeviceVendor.ARISTA: "copy running-config startup-config",
        DeviceVendor.HP: "save",
        DeviceVendor.HUAWEI: "save",
        DeviceVendor.FORTINET: "execute backup config",
        DeviceVendor.LINUX: "",
        DeviceVendor.GENERIC: "save"
    }
    
    SHOW_RUN_COMMANDS = {
        DeviceVendor.CISCO: "show running-config",
        DeviceVendor.JUNIPER: "show configuration",
        DeviceVendor.ARISTA: "show running-config",
        DeviceVendor.HP: "display current-configuration",
        DeviceVendor.HUAWEI: "display current-configuration",
        DeviceVendor.FORTINET: "show full-configuration",
        DeviceVendor.LINUX: "",
        DeviceVendor.GENERIC: "show running-config"
    }


class SSHService:
    """Service for SSH operations."""
    
    def __init__(self, config: Optional[SSHConfig] = None):
        """Initialize SSH service."""
        self.config = config or SSHConfig()
        self.connection_pool: Dict[str, SSHClientConnection] = {}
        self.command_cache: Dict[str, CommandResult] = {}
        self._executor = ThreadPoolExecutor(max_workers=self.config.thread_pool_size)
        self.vendor_commands = VendorCommands()
        self._prompts = self._initialize_prompts()
    
    def _initialize_prompts(self) -> Dict[DeviceVendor, DevicePrompts]:
        """Initialize vendor-specific prompts."""
        return {
            DeviceVendor.CISCO: DevicePrompts(
                user_prompt=r">\s*$",
                privileged_prompt=r"#\s*$",
                configure_prompt=r"\(config\)#\s*$"
            ),
            DeviceVendor.JUNIPER: DevicePrompts(
                user_prompt=r">\s*$",
                privileged_prompt=r"#\s*$",
                configure_prompt=r"#\s*$"
            ),
            DeviceVendor.ARISTA: DevicePrompts(
                user_prompt=r">\s*$",
                privileged_prompt=r"#\s*$",
                configure_prompt=r"\(config\)#\s*$"
            ),
            DeviceVendor.LINUX: DevicePrompts(
                user_prompt=r"\$\s*$",
                privileged_prompt=r"#\s*$",
                configure_prompt=r"#\s*$"
            ),
            DeviceVendor.GENERIC: DevicePrompts()
        }
    
    @asynccontextmanager
    async def connect(self, credentials: SSHCredentials) -> SSHClientConnection:
        """Establish SSH connection with context manager."""
        conn_key = f"{credentials.host}:{credentials.port}:{credentials.username}"
        
        # Check if connection exists in pool
        if conn_key in self.connection_pool:
            conn = self.connection_pool[conn_key]
            if conn and not conn.is_closing():
                yield conn
                return
        
        try:
            # Build connection options
            connect_options = {
                "host": credentials.host,
                "port": credentials.port,
                "username": credentials.username,
                "known_hosts": self.config.known_hosts_file,
                "connect_timeout": credentials.timeout,
                "keepalive_interval": self.config.keepalive_interval
            }
            
            # Add authentication
            if credentials.auth_method == AuthMethod.PASSWORD:
                connect_options["password"] = credentials.password
            elif credentials.auth_method == AuthMethod.PUBLIC_KEY:
                if credentials.private_key:
                    # Handle private key
                    if credentials.private_key.startswith("-----"):
                        # Key content provided directly
                        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                            f.write(credentials.private_key)
                            key_path = f.name
                    else:
                        # Key file path provided
                        key_path = credentials.private_key
                    
                    connect_options["client_keys"] = [key_path]
                    if credentials.private_key_passphrase:
                        connect_options["passphrase"] = credentials.private_key_passphrase
            
            # Establish connection
            conn = await asyncssh.connect(**connect_options)
            
            # Store in pool
            self.connection_pool[conn_key] = conn
            
            logger.info(f"SSH connection established to {credentials.host}")
            
            yield conn
            
        except asyncssh.Error as e:
            logger.error(f"SSH connection failed to {credentials.host}: {e}")
            raise SSHError(f"SSH connection failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error connecting to {credentials.host}: {e}")
            raise
        finally:
            # Don't close connection here - let pool manage it
            pass
    
    async def execute_command(
        self,
        credentials: SSHCredentials,
        command: str,
        timeout: Optional[int] = None
    ) -> CommandResult:
        """Execute a single command on device."""
        start_time = time.time()
        timeout = timeout or self.config.command_timeout
        
        # Check cache
        cache_key = f"{credentials.host}:{command}"
        if cache_key in self.command_cache:
            cached = self.command_cache[cache_key]
            if (datetime.utcnow() - cached.timestamp).seconds < self.config.cache_ttl:
                return cached
        
        try:
            async with self.connect(credentials) as conn:
                # Execute command
                result = await asyncio.wait_for(
                    conn.run(command),
                    timeout=timeout
                )
                
                execution_time = time.time() - start_time
                
                if result.exit_status == 0:
                    command_result = CommandResult(
                        success=True,
                        command=command,
                        output=result.stdout,
                        execution_time=execution_time
                    )
                else:
                    command_result = CommandResult(
                        success=False,
                        command=command,
                        output=result.stdout,
                        error=result.stderr,
                        execution_time=execution_time
                    )
                
                # Cache result for read-only commands
                if command.startswith(("show", "display", "get")):
                    self.command_cache[cache_key] = command_result
                
                return command_result
                
        except asyncio.TimeoutError:
            logger.error(f"Command timeout on {credentials.host}: {command}")
            return CommandResult(
                success=False,
                command=command,
                output="",
                error="Command execution timeout",
                execution_time=time.time() - start_time
            )
        except Exception as e:
            logger.error(f"Command execution failed on {credentials.host}: {e}")
            return CommandResult(
                success=False,
                command=command,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    async def execute_commands(
        self,
        credentials: SSHCredentials,
        commands: List[str],
        stop_on_error: bool = False
    ) -> List[CommandResult]:
        """Execute multiple commands on device."""
        results = []
        
        async with self.connect(credentials) as conn:
            for command in commands:
                result = await self.execute_command_on_connection(
                    conn, command, credentials.vendor
                )
                results.append(result)
                
                if stop_on_error and not result.success:
                    break
        
        return results
    
    async def execute_command_on_connection(
        self,
        conn: SSHClientConnection,
        command: str,
        vendor: DeviceVendor = DeviceVendor.GENERIC
    ) -> CommandResult:
        """Execute command on existing connection."""
        start_time = time.time()
        
        try:
            result = await conn.run(command)
            
            return CommandResult(
                success=result.exit_status == 0,
                command=command,
                output=result.stdout,
                error=result.stderr if result.exit_status != 0 else None,
                execution_time=time.time() - start_time
            )
            
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return CommandResult(
                success=False,
                command=command,
                output="",
                error=str(e),
                execution_time=time.time() - start_time
            )
    
    async def interactive_shell(
        self,
        credentials: SSHCredentials,
        commands: List[str]
    ) -> List[CommandResult]:
        """Execute commands in interactive shell session."""
        results = []
        
        try:
            async with self.connect(credentials) as conn:
                # Create interactive shell
                process = await conn.create_process(
                    term_type='vt100',
                    term_size=(80, 24)
                )
                
                # Get vendor prompts
                prompts = self._prompts.get(credentials.vendor, DevicePrompts())
                
                # Wait for initial prompt
                output = await self._read_until_prompt(process, prompts)
                
                # Enter privileged mode if needed
                if credentials.enable_password:
                    enable_cmd = self.vendor_commands.ENABLE_COMMANDS.get(
                        credentials.vendor, "enable"
                    )
                    if enable_cmd:
                        await self._send_command(process, enable_cmd)
                        output = await self._read_until_prompt(process, prompts)
                        
                        if re.search(prompts.password_prompt, output):
                            await self._send_command(process, credentials.enable_password)
                            output = await self._read_until_prompt(process, prompts)
                
                # Execute commands
                for command in commands:
                    start_time = time.time()
                    
                    # Send command
                    await self._send_command(process, command)
                    
                    # Read output
                    output = await self._read_until_prompt(process, prompts)
                    
                    # Handle pagination
                    full_output = output
                    while re.search(prompts.continue_prompt, output):
                        await self._send_command(process, " ")
                        output = await self._read_until_prompt(process, prompts)
                        full_output += output
                    
                    results.append(CommandResult(
                        success=True,
                        command=command,
                        output=self._clean_output(full_output, command),
                        execution_time=time.time() - start_time
                    ))
                
                # Exit cleanly
                exit_cmd = self.vendor_commands.EXIT_COMMANDS.get(
                    credentials.vendor, "exit"
                )
                await self._send_command(process, exit_cmd)
                
                return results
                
        except Exception as e:
            logger.error(f"Interactive shell failed: {e}")
            return results
    
    async def get_configuration(
        self,
        credentials: SSHCredentials
    ) -> Optional[str]:
        """Get device configuration."""
        show_run_cmd = self.vendor_commands.SHOW_RUN_COMMANDS.get(
            credentials.vendor, "show running-config"
        )
        
        if not show_run_cmd:
            logger.warning(f"No show run command for vendor {credentials.vendor}")
            raise NotImplementedError("Function not yet implemented")
        
        result = await self.execute_command(credentials, show_run_cmd)
        
        if result.success:
            return result.output
        else:
            logger.error(f"Failed to get configuration: {result.error}")
            raise NotImplementedError("Function not yet implemented")
    
    async def save_configuration(
        self,
        credentials: SSHCredentials
    ) -> bool:
        """Save device configuration."""
        save_cmd = self.vendor_commands.SAVE_COMMANDS.get(
            credentials.vendor, "save"
        )
        
        if not save_cmd:
            logger.warning(f"No save command for vendor {credentials.vendor}")
            return False
        
        result = await self.execute_command(credentials, save_cmd)
        return result.success
    
    async def configure_device(
        self,
        credentials: SSHCredentials,
        config_commands: List[str],
        save_config: bool = True
    ) -> List[CommandResult]:
        """Configure device with multiple commands."""
        results = []
        
        try:
            # Build command sequence
            commands = []
            
            # Enter config mode
            config_cmd = self.vendor_commands.CONFIG_COMMANDS.get(
                credentials.vendor, "configure"
            )
            if config_cmd:
                commands.append(config_cmd)
            
            # Add configuration commands
            commands.extend(config_commands)
            
            # Exit config mode
            exit_cmd = self.vendor_commands.EXIT_COMMANDS.get(
                credentials.vendor, "exit"
            )
            if exit_cmd:
                commands.append(exit_cmd)
            
            # Save configuration if requested
            if save_config:
                save_cmd = self.vendor_commands.SAVE_COMMANDS.get(
                    credentials.vendor
                )
                if save_cmd:
                    commands.append(save_cmd)
            
            # Execute commands
            results = await self.interactive_shell(credentials, commands)
            
            return results
            
        except Exception as e:
            logger.error(f"Device configuration failed: {e}")
            return results
    
    async def transfer_file(
        self,
        credentials: SSHCredentials,
        local_path: str,
        remote_path: str,
        direction: str = "upload"
    ) -> bool:
        """Transfer file via SCP/SFTP."""
        try:
            async with self.connect(credentials) as conn:
                async with conn.start_sftp_client() as sftp:
                    if direction == "upload":
                        await sftp.put(local_path, remote_path)
                        logger.info(f"Uploaded {local_path} to {remote_path}")
                    else:  # download
                        await sftp.get(remote_path, local_path)
                        logger.info(f"Downloaded {remote_path} to {local_path}")
                    
                    return True
                    
        except Exception as e:
            logger.error(f"File transfer failed: {e}")
            return False
    
    async def test_connectivity(
        self,
        credentials: SSHCredentials
    ) -> Dict[str, Any]:
        """Test SSH connectivity to device."""
        start_time = time.time()
        
        try:
            async with self.connect(credentials) as conn:
                # Test with simple command
                result = await conn.run("echo test")
                
                return {
                    "success": True,
                    "host": credentials.host,
                    "port": credentials.port,
                    "username": credentials.username,
                    "response_time": time.time() - start_time,
                    "vendor": credentials.vendor.value
                }
                
        except Exception as e:
            return {
                "success": False,
                "host": credentials.host,
                "port": credentials.port,
                "username": credentials.username,
                "error": str(e),
                "response_time": time.time() - start_time
            }
    
    async def get_device_info(
        self,
        credentials: SSHCredentials
    ) -> Dict[str, Any]:
        """Get basic device information."""
        info = {
            "host": credentials.host,
            "vendor": credentials.vendor.value
        }
        
        # Vendor-specific commands to gather info
        info_commands = {
            DeviceVendor.CISCO: [
                ("hostname", "show running-config | include hostname"),
                ("version", "show version"),
                ("model", "show inventory"),
                ("interfaces", "show ip interface brief")
            ],
            DeviceVendor.JUNIPER: [
                ("hostname", "show configuration system host-name"),
                ("version", "show version"),
                ("model", "show chassis hardware"),
                ("interfaces", "show interfaces terse")
            ],
            DeviceVendor.LINUX: [
                ("hostname", "hostname"),
                ("version", "uname -a"),
                ("model", "dmidecode -t system"),
                ("interfaces", "ip addr show")
            ]
        }
        
        commands = info_commands.get(credentials.vendor, [])
        
        for key, command in commands:
            result = await self.execute_command(credentials, command)
            if result.success:
                info[key] = result.output
        
        return info
    
    def close_connection(self, host: str, port: int = 22, username: str = None):
        """Close specific connection from pool."""
        if username:
            conn_key = f"{host}:{port}:{username}"
        else:
            # Close all connections to host
            conn_keys = [k for k in self.connection_pool.keys() if k.startswith(f"{host}:{port}")]
            for conn_key in conn_keys:
                self._close_connection_by_key(conn_key)
            return
        
        self._close_connection_by_key(conn_key)
    
    def close_all_connections(self):
        """Close all connections in pool."""
        for conn_key in list(self.connection_pool.keys()):
            self._close_connection_by_key(conn_key)
    
    # Private helper methods
    
    def _close_connection_by_key(self, conn_key: str):
        """Close connection by key."""
        if conn_key in self.connection_pool:
            conn = self.connection_pool[conn_key]
            if conn and not conn.is_closing():
                conn.close()
            del self.connection_pool[conn_key]
            logger.info(f"Closed connection: {conn_key}")
    
    async def _send_command(self, process, command: str):
        """Send command to process."""
        process.stdin.write(f"{command}\n")
        await process.stdin.drain()
    
    async def _read_until_prompt(
        self,
        process,
        prompts: DevicePrompts,
        timeout: int = 30
    ) -> str:
        """Read output until prompt is detected."""
        output = ""
        prompt_patterns = [
            prompts.user_prompt,
            prompts.privileged_prompt,
            prompts.configure_prompt,
            prompts.password_prompt,
            prompts.continue_prompt
        ]
        
        combined_pattern = "|".join(prompt_patterns)
        
        try:
            while True:
                chunk = await asyncio.wait_for(
                    process.stdout.read(1024),
                    timeout=timeout
                )
                
                if not chunk:
                    break
                
                output += chunk
                
                if re.search(combined_pattern, output):
                    break
            
            return output
            
        except asyncio.TimeoutError:
            logger.warning("Timeout waiting for prompt")
            return output
    
    def _clean_output(self, output: str, command: str) -> str:
        """Clean command output."""
        # Remove command echo
        lines = output.split('\n')
        cleaned_lines = []
        
        skip_next = False
        for line in lines:
            # Skip command echo
            if command in line:
                skip_next = True
                continue
            
            if skip_next:
                skip_next = False
                continue
            
            # Skip prompts
            if re.search(r"[>#$]\s*$", line):
                continue
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines).strip()


# Create singleton instance
ssh_service = SSHService()