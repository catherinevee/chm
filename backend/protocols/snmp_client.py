"""
SNMP Protocol Client for CHM
"""
from typing import Dict, Any, List, Optional, Tuple
import asyncio
from backend.services.snmp_service import SNMPService, SNMPCredentials, SNMPVersion

class SNMPClient:
    """SNMP client for device communication"""

    def __init__(self, host: str):
        self.host = host
        self.service = SNMPService()

    async def test_connectivity(self, community: str = "public") -> bool:
        """Test SNMP connectivity"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        result = await self.service.get(
            self.host,
            "1.3.6.1.2.1.1.1.0",  # sysDescr
            credentials
        )

        return result.success

    async def get_system_info(self, community: str = "public") -> Dict[str, Any]:
        """Get system information"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        return await self.service.get_system_info(self.host, credentials)

    async def get_interfaces(self, community: str = "public") -> List[Dict[str, Any]]:
        """Get interface information"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        return await self.service.get_interface_stats(self.host, credentials)

    async def get_cpu_usage(self, community: str = "public") -> float:
        """Get CPU usage"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        # Cisco CPU OID
        result = await self.service.get(
            self.host,
            "1.3.6.1.4.1.9.9.109.1.1.1.1.5",
            credentials
        )

        return float(result.value) if result.success and result.value else 0.0

    async def get_memory_usage(self, community: str = "public") -> Dict[str, int]:
        """Get memory usage"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        # Get used and free memory
        used_result = await self.service.get(
            self.host,
            "1.3.6.1.4.1.9.9.48.1.1.1.5",
            credentials
        )

        free_result = await self.service.get(
            self.host,
            "1.3.6.1.4.1.9.9.48.1.1.1.6",
            credentials
        )

        return {
            "used": int(used_result.value) if used_result.success else 0,
            "free": int(free_result.value) if free_result.success else 0
        }

    async def get_environment_sensors(self, community: str = "public") -> List[Dict[str, Any]]:
        """Get environment sensor data"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        # Walk sensor table (Cisco specific)
        results = await self.service.walk(
            self.host,
            "1.3.6.1.4.1.9.9.13.1.3",
            credentials
        )

        sensors = []
        for result in results:
            if result.success:
                sensors.append({
                    "oid": result.oid,
                    "value": result.value
                })

        return sensors

    async def walk(self, community: str, base_oid: str) -> List[Tuple[str, Any]]:
        """Walk SNMP tree"""
        credentials = SNMPCredentials(
            version=SNMPVersion.V2C,
            community=community
        )

        results = await self.service.walk(
            self.host,
            base_oid,
            credentials
        )

        return [(r.oid, r.value) for r in results if r.success]

    def close(self):
        """Close SNMP client"""
        pass  # Cleanup if needed
