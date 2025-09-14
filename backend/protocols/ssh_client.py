"""
SSH Protocol Client for CHM
"""
from typing import Dict, Any, List, Optional
import asyncio
import asyncssh
import logging

logger = logging.getLogger(__name__)

class AsyncSSHClient:
    """Async SSH client for device communication"""

    def __init__(self):
        self.connection = None

    async def connect(self, host: str, username: str, password: str, port: int = 22):
        """Connect to device via SSH"""
        try:
            self.connection = await asyncssh.connect(
                host,
                port=port,
                username=username,
                password=password,
                known_hosts=None
            )
            return True
        except Exception as e:
            logger.error(f"SSH connection failed: {e}")
            return False

    async def execute_command(self, command: str) -> str:
        """Execute command on device"""
        if not self.connection:
            raise RuntimeError("Not connected")

        try:
            result = await self.connection.run(command)
            return result.stdout
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise

    async def disconnect(self):
        """Disconnect from device"""
        if self.connection:
            self.connection.close()
            await self.connection.wait_closed()
            self.connection = None

class DeviceSSHManager:
    """Manager for device-specific SSH operations"""

    async def get_device_info(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get device information via SSH"""
        client = AsyncSSHClient()

        try:
            await client.connect(
                params['host'],
                params['username'],
                params.get('password', '')
            )

            # Get hostname
            hostname_output = await client.execute_command("hostname")

            # Get version (generic)
            version_output = await client.execute_command("uname -a")

            return {
                "hostname": hostname_output.strip(),
                "version": version_output.strip(),
                "vendor": "Generic",
                "model": "Unknown"
            }

        finally:
            await client.disconnect()

    async def get_interfaces(self, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get interface information via SSH"""
        client = AsyncSSHClient()

        try:
            await client.connect(
                params['host'],
                params['username'],
                params.get('password', '')
            )

            # Get interfaces (Linux example)
            output = await client.execute_command("ip addr show")

            # Parse output (simplified)
            interfaces = []
            lines = output.split('\n')
            for line in lines:
                if ':' in line and 'mtu' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        interfaces.append({
                            "name": parts[1].strip(),
                            "status": "up" if "UP" in line else "down"
                        })

            return interfaces

        finally:
            await client.disconnect()

    async def get_configuration(self, params: Dict[str, Any]) -> str:
        """Get device configuration via SSH"""
        client = AsyncSSHClient()

        try:
            await client.connect(
                params['host'],
                params['username'],
                params.get('password', '')
            )

            # Get configuration (example)
            config = await client.execute_command("cat /etc/hostname")

            return config

        finally:
            await client.disconnect()
