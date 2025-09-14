"""
Device Polling Service for CHM
"""
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class DevicePollingService:
    """Service for continuous device polling"""

    def __init__(self):
        self.polling_tasks = {}
        self.polling_intervals = {
            "critical": 60,    # 1 minute
            "normal": 300,     # 5 minutes
            "low": 900         # 15 minutes
        }

    async def start_polling(self, device_id: int, priority: str = "normal"):
        """Start polling a device"""
        if device_id in self.polling_tasks:
            logger.warning(f"Device {device_id} already being polled")
            return

        interval = self.polling_intervals.get(priority, 300)
        task = asyncio.create_task(self._poll_device_loop(device_id, interval))
        self.polling_tasks[device_id] = task

        logger.info(f"Started polling device {device_id} with {priority} priority")

    async def stop_polling(self, device_id: int):
        """Stop polling a device"""
        if device_id in self.polling_tasks:
            self.polling_tasks[device_id].cancel()
            del self.polling_tasks[device_id]
            logger.info(f"Stopped polling device {device_id}")

    async def _poll_device_loop(self, device_id: int, interval: int):
        """Main polling loop for a device"""
        while True:
            try:
                await self._poll_device(device_id)
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Polling error for device {device_id}: {e}")
                await asyncio.sleep(interval)

    async def _poll_device(self, device_id: int):
        """Poll a single device"""
        logger.debug(f"Polling device {device_id}")

        # Get device details from database
        # Collect metrics via SNMP/SSH
        # Store metrics in database
        # Check thresholds and create alerts

        # This is where the actual polling logic would go
        # It would use the monitoring_engine to collect metrics

        timestamp = datetime.utcnow()
        logger.debug(f"Device {device_id} polled at {timestamp}")

    async def get_polling_status(self) -> Dict[str, Any]:
        """Get status of all polling tasks"""
        return {
            "active_devices": len(self.polling_tasks),
            "device_ids": list(self.polling_tasks.keys()),
            "status": "running" if self.polling_tasks else "idle"
        }

# Global instance
device_polling_service = DevicePollingService()
