"""
ICMP Handler using raw sockets for network discovery
"""

import asyncio
import socket
import struct
import time
import logging
from typing import List, Tuple, Optional, Dict, Any
import ipaddress
from dataclasses import dataclass
import platform
import os
from datetime import datetime

from ...common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)


@dataclass
class PingResult:
    """Result of a ping operation"""
    host: str
    success: bool
    rtt: Optional[float] = None  # Round trip time in milliseconds
    error: Optional[str] = None
    packet_loss: float = 0.0
    packets_sent: int = 1
    packets_received: int = 0


class ICMPHandler:
    """Handles ICMP ping operations using raw sockets"""
    
    def __init__(self, timeout: float = 3.0, packet_size: int = 56):
        self.timeout = timeout
        self.packet_size = packet_size
        self.sequence = 0
        self._use_raw_socket = self._can_use_raw_socket()
        self._semaphore = asyncio.Semaphore(100)  # Limit concurrent pings
        
    def _can_use_raw_socket(self) -> bool:
        """Check if raw sockets are available"""
        try:
            # On Windows, raw sockets require admin privileges
            # On Unix, raw sockets require root or CAP_NET_RAW
            if platform.system().lower() == 'windows':
                # Try to create a raw socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.close()
                return True
            else:
                # Check if we have proper permissions
                return os.geteuid() == 0 or os.access('/proc/sys/net/ipv4/ping_group_range', os.R_OK)
        except (OSError, PermissionError):
            logger.warning("Raw sockets not available, falling back to subprocess ping")
            return False
    
    def _checksum(self, data: bytes) -> int:
        """Calculate RFC 1071 compliant ICMP checksum"""
        # Pad data to even length
        if len(data) % 2:
            data += b'\x00'
        
        # Sum all 16-bit words
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                word = (data[i] << 8) + data[i + 1]
            else:
                word = data[i] << 8
            checksum += word
        
        # Handle carry bits
        while checksum >> 16:
            checksum = (checksum & 0xFFFF) + (checksum >> 16)
        
        # One's complement
        return ~checksum & 0xFFFF
    
    def _create_icmp_packet(self, packet_id: int, sequence: int) -> bytes:
        """Create an ICMP echo request packet"""
        # ICMP header: type(8), code(8), checksum(16), id(16), sequence(16)
        icmp_type = 8  # Echo request
        icmp_code = 0
        icmp_checksum = 0
        
        # Pack header without checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, packet_id, sequence)
        
        # Data payload with timestamp
        timestamp = struct.pack('!d', time.time())
        data = timestamp + b'A' * (self.packet_size - 8)  # Fill to desired size
        
        # Calculate checksum
        packet = header + data
        icmp_checksum = self._checksum(packet)
        
        # Repack with correct checksum
        header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, packet_id, sequence)
        return header + data
    
    def _parse_icmp_reply(self, packet: bytes, packet_id: int):
        """Parse ICMP echo reply and return RTT with proper validation"""
        try:
            if len(packet) < 20:  # Minimum IP header size
                # Return fallback RTT when packet is too short
                fallback_data = FallbackData(
                    data=999.0,  # High latency to indicate failure
                    source="packet_length_fallback",
                    confidence=0.0,
                    metadata={"reason": "Packet too short", "packet_length": len(packet), "minimum_required": 20}
                )
                
                return create_failure_result(
                    error="ICMP packet too short",
                    error_code="ICMP_PACKET_TOO_SHORT",
                    fallback_data=fallback_data,
                    suggestions=[
                        "Received ICMP packet is too short",
                        "Check network configuration and packet routing",
                        "Verify target device ICMP implementation",
                        "Check for packet corruption or fragmentation",
                        "Consider alternative ping methods"
                    ]
                )
            
            # Parse IP header to get proper header length
            version_ihl = packet[0]
            version = (version_ihl >> 4) & 0x0F
            if version != 4:  # Only IPv4 supported
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=999.0,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="IPv6 packet received",
                            details=f"Received IPv6 packet (version {version}), only IPv4 supported",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="IPV6_NOT_SUPPORTED",
                    error_message="IPv6 packets not supported",
                    details=f"Received IPv6 packet (version {version}), only IPv4 supported",
                    suggestions=["Use IPv4 addresses", "Configure network for IPv4", "Check routing configuration"]
                )
                
            ihl = version_ihl & 0x0F
            ip_header_len = ihl * 4
            
            if ip_header_len < 20 or len(packet) < ip_header_len + 8:
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=999.0,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="Invalid IP header length",
                            details=f"IP header length {ip_header_len} is invalid or packet too short",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="INVALID_IP_HEADER",
                    error_message="Invalid IP header length",
                    details=f"IP header length {ip_header_len} is invalid or packet too short",
                    suggestions=["Check network configuration", "Verify packet integrity", "Check for packet corruption"]
                )
            
            # Extract ICMP packet
            icmp_packet = packet[ip_header_len:]
            
            if len(icmp_packet) < 8:
                return create_failure_result(
                    fallback_data=FallbackData(
                        data=999.0,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="ICMP packet too short",
                            details=f"ICMP packet length {len(icmp_packet)} is less than minimum 8 bytes",
                            timestamp=datetime.now().isoformat()
                        )
                    ),
                    error_code="ICMP_PACKET_TOO_SHORT",
                    error_message="ICMP packet too short",
                    details=f"ICMP packet length {len(icmp_packet)} is less than minimum 8 bytes",
                    suggestions=["Check network configuration", "Verify packet integrity", "Check for packet corruption"]
                )
            
            # Parse ICMP header
            icmp_type, icmp_code, icmp_checksum, reply_id, sequence = struct.unpack('!BBHHH', icmp_packet[:8])
            
            # Validate this is an echo reply for our packet
            if icmp_type == 0 and icmp_code == 0 and reply_id == packet_id:
                # Verify checksum
                icmp_data = icmp_packet[8:]
                checksum_packet = icmp_packet[:2] + b'\x00\x00' + icmp_packet[4:]
                calculated_checksum = self._checksum(checksum_packet)
                
                # Some systems don't verify checksums, so log but don't fail
                if calculated_checksum != icmp_checksum:
                    logger.debug(f"ICMP checksum mismatch: expected {icmp_checksum}, got {calculated_checksum}")
                
                # Extract timestamp from data payload
                if len(icmp_data) >= 8:
                    try:
                        timestamp = struct.unpack('!d', icmp_data[:8])[0]
                        current_time = time.time()
                        
                        # Validate timestamp is reasonable (not in future, not too old)
                        if timestamp <= current_time and (current_time - timestamp) < 60:
                            rtt = (current_time - timestamp) * 1000  # Convert to milliseconds
                            return max(0, rtt)  # Ensure non-negative
                    except struct.error:
                        logger.debug("Failed to parse timestamp from ICMP payload")
            
            return create_failure_result(
                fallback_data=FallbackData(
                    data=999.0,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="Invalid ICMP reply",
                        details="ICMP reply validation failed or packet format invalid",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="INVALID_ICMP_REPLY",
                error_message="Invalid ICMP reply",
                details="ICMP reply validation failed or packet format invalid",
                suggestions=["Check network configuration", "Verify packet integrity", "Check for packet corruption"]
            )
            
        except (struct.error, IndexError, ValueError) as e:
            logger.debug(f"Error parsing ICMP reply: {e}")
            return create_failure_result(
                fallback_data=FallbackData(
                    data=999.0,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="ICMP parsing error",
                        details=f"Error parsing ICMP reply: {e}",
                        timestamp=datetime.now().isoformat()
                    )
                ),
                error_code="ICMP_PARSING_ERROR",
                error_message="ICMP parsing error",
                details=f"Error parsing ICMP reply: {e}",
                suggestions=["Check network configuration", "Verify packet integrity", "Check for packet corruption"]
            )
    
    async def _ping_raw_socket(self, host: str, packet_id: int, count: int = 1) -> PingResult:
        """Ping using raw sockets"""
        try:
            # Resolve hostname
            try:
                target_addr = socket.gethostbyname(host)
            except socket.gaierror as e:
                return PingResult(host, False, error=f"Name resolution failed: {e}")
            
            # Create raw socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(self.timeout)
            
            packets_sent = 0
            packets_received = 0
            rtts = []
            
            for i in range(count):
                try:
                    # Create and send ICMP packet
                    self.sequence += 1
                    packet = self._create_icmp_packet(packet_id, self.sequence)
                    sock.sendto(packet, (target_addr, 0))
                    packets_sent += 1
                    
                    # Wait for reply
                    start_time = time.time()
                    while time.time() - start_time < self.timeout:
                        try:
                            reply, addr = sock.recvfrom(1024)
                            if addr[0] == target_addr:
                                rtt = self._parse_icmp_reply(reply, packet_id)
                                if rtt is not None:
                                    rtts.append(rtt)
                                    packets_received += 1
                                    break
                        except socket.timeout:
                            break
                    
                    # Small delay between packets
                    if i < count - 1:
                        await asyncio.sleep(0.1)
                
                except Exception as e:
                    logger.debug(f"ICMP packet send failed for {host}: {e}")
            
            sock.close()
            
            # Calculate results
            success = packets_received > 0
            avg_rtt = sum(rtts) / len(rtts) if rtts else None
            packet_loss = ((packets_sent - packets_received) / packets_sent * 100) if packets_sent > 0 else 100
            
            return PingResult(
                host=host,
                success=success,
                rtt=avg_rtt,
                packets_sent=packets_sent,
                packets_received=packets_received,
                packet_loss=packet_loss
            )
            
        except Exception as e:
            return PingResult(host, False, error=str(e))
    
    async def _ping_subprocess(self, host: str) -> PingResult:
        """Fallback ping using subprocess (from original implementation)"""
        try:
            import platform
            
            # Determine ping command based on OS
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', '1000', host]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', host]
            
            # Run ping command
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            
            # Wait for completion with timeout
            try:
                returncode = await asyncio.wait_for(process.wait(), timeout=self.timeout)
                success = returncode == 0
                return PingResult(host, success)
            except asyncio.TimeoutError:
                process.kill()
                return PingResult(host, False, error="Timeout")
        
        except Exception as e:
            return PingResult(host, False, error=str(e))
    
    async def ping_single(self, host: str, count: int = 1) -> PingResult:
        """Ping a single host"""
        async with self._semaphore:
            packet_id = os.getpid() & 0xFFFF  # Use process ID as packet ID
            
            if self._use_raw_socket:
                return await self._ping_raw_socket(host, packet_id, count)
            else:
                return await self._ping_subprocess(host)
    
    async def ping_multiple(
        self,
        hosts: List[str],
        batch_size: int = 50,
        count: int = 1
    ) -> List[PingResult]:
        """Ping multiple hosts concurrently"""
        results = []
        
        # Process hosts in batches to avoid overwhelming the system
        for i in range(0, len(hosts), batch_size):
            batch = hosts[i:i + batch_size]
            
            # Create tasks for concurrent pinging
            tasks = [self.ping_single(host, count) for host in batch]
            
            try:
                # Run batch with timeout
                batch_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=self.timeout * 2  # Double timeout for batch
                )
                
                # Process results
                for result in batch_results:
                    if isinstance(result, Exception):
                        logger.error(f"Ping task failed: {result}")
                        results.append(PingResult("unknown", False, error=str(result)))
                    else:
                        results.append(result)
            
            except asyncio.TimeoutError:
                logger.warning(f"Ping batch timed out")
                # Add failed results for timed out batch
                for host in batch:
                    results.append(PingResult(host, False, error="Batch timeout"))
            
            # Small delay between batches
            if i + batch_size < len(hosts):
                await asyncio.sleep(0.5)
        
        return results
    
    async def discover_network(
        self,
        network: ipaddress.IPv4Network,
        max_hosts: int = 254
    ) -> List[Dict[str, Any]]:
        """Discover active hosts in a network using ICMP ping"""
        try:
            # Get list of host IPs (limit to avoid overwhelming)
            hosts = list(network.hosts())[:max_hosts]
            host_strings = [str(ip) for ip in hosts]
            
            logger.info(f"Starting ICMP discovery of {len(host_strings)} hosts in {network}")
            
            # Ping all hosts
            results = await self.ping_multiple(host_strings)
            
            # Filter successful pings and format as device info
            discovered_devices = []
            successful_pings = sum(1 for r in results if r.success)
            
            for result in results:
                if result.success:
                    device_info = {
                        'ip_address': result.host,
                        'hostname': result.host,  # Will be resolved later if needed
                        'device_type': 'unknown',
                        'discovery_method': 'icmp',
                        'rtt': result.rtt,
                        'packet_loss': result.packet_loss,
                        'response_time': result.rtt
                    }
                    
                    # Try to resolve hostname
                    try:
                        hostname = socket.gethostbyaddr(result.host)[0]
                        device_info['hostname'] = hostname
                    except Exception as e:
                        logger.debug(f"Could not resolve hostname for {result.host}: {e}")
                        # Keep IP as hostname if resolution fails
                    
                    discovered_devices.append(device_info)
            
            logger.info(f"ICMP discovery completed: {successful_pings}/{len(host_strings)} hosts responded")
            return discovered_devices
            
        except Exception as e:
            logger.error(f"ICMP network discovery failed: {e}")
            return []
    
    def get_stats(self) -> Dict[str, Any]:
        """Get ping handler statistics"""
        return {
            'timeout': self.timeout,
            'packet_size': self.packet_size,
            'sequence': self.sequence,
            'use_raw_socket': self._use_raw_socket,
            'max_concurrent': self._semaphore._value,
            'platform': platform.system(),
            'can_use_raw_socket': self._can_use_raw_socket()
        }