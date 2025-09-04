"""
Real-time Network Topology Service
Provides dynamic topology updates, real-time status monitoring, and topology visualization
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from sqlalchemy import select, and_, or_, func, distinct
from sqlalchemy.orm import selectinload

from backend.storage.database import db
from backend.storage.models import (
    Device, DeviceRelationship, NetworkInterface, DeviceStatus, DeviceType,
    PerformanceMetrics, NetworkDiscovery
)
from backend.services.notification_service import notification_service
from backend.discovery.protocol_discovery import enhanced_discovery
from backend.common.result_objects import (
    FallbackData, HealthStatus, HealthLevel,
    create_success_result, create_failure_result, create_partial_success_result
)

logger = logging.getLogger(__name__)

@dataclass
class TopologyNode:
    """Network topology node representation"""
    id: str
    hostname: str
    ip_address: str
    device_type: str
    status: str
    location: Optional[str] = None
    interfaces: List[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    last_seen: Optional[datetime] = None
    performance_summary: Optional[Dict[str, Any]] = None

@dataclass
class TopologyEdge:
    """Network topology edge/relationship representation"""
    id: str
    source_id: str
    target_id: str
    relationship_type: str
    source_interface: Optional[str] = None
    target_interface: Optional[str] = None
    bandwidth: Optional[float] = None
    latency: Optional[float] = None
    status: str = "active"
    discovery_protocol: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    last_updated: Optional[datetime] = None

@dataclass
class TopologyGraph:
    """Complete network topology graph"""
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]
    metadata: Dict[str, Any]
    last_updated: datetime

class RealTimeTopologyService:
    """Service for real-time network topology management and visualization"""
    
    def __init__(self):
        self.topology_cache = None
        self.cache_expiry = None
        self.cache_duration = 300  # 5 minutes
        self.monitoring_active = False
        self.monitoring_task = None
        self.update_interval = 60  # Update every minute
        self.subscribers = []  # WebSocket subscribers for real-time updates
    
    async def start_real_time_monitoring(self):
        """Start real-time topology monitoring"""
        
        if self.monitoring_active:
            logger.warning("Topology monitoring already active")
            return
        
        self.monitoring_active = True
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("Real-time topology monitoring started")
    
    async def stop_real_time_monitoring(self):
        """Stop real-time topology monitoring"""
        
        self.monitoring_active = False
        
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Real-time topology monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main topology monitoring loop"""
        
        try:
            while self.monitoring_active:
                try:
                    # Update topology data
                    await self._update_topology_status()
                    
                    # Check for topology changes
                    await self._detect_topology_changes()
                    
                    # Broadcast updates to subscribers
                    await self._broadcast_topology_updates()
                    
                except Exception as e:
                    logger.error(f"Error in topology monitoring loop: {e}")
                
                await asyncio.sleep(self.update_interval)
        
        except asyncio.CancelledError:
            logger.info("Topology monitoring loop cancelled")
        except Exception as e:
            logger.error(f"Topology monitoring loop error: {e}")
            self.monitoring_active = False
    
    async def get_network_topology(self, force_refresh: bool = False) -> TopologyGraph:
        """Get current network topology with caching"""
        
        # Check cache
        if not force_refresh and self._is_cache_valid():
            return self.topology_cache
        
        try:
            # Build topology from database
            topology = await self._build_topology_graph()
            
            # Update cache
            self.topology_cache = topology
            self.cache_expiry = datetime.utcnow() + timedelta(seconds=self.cache_duration)
            
            return topology
        
        except Exception as e:
            logger.error(f"Failed to get network topology: {e}")
            raise
    
    def _is_cache_valid(self) -> bool:
        """Check if topology cache is still valid"""
        return (
            self.topology_cache is not None and 
            self.cache_expiry is not None and 
            datetime.utcnow() < self.cache_expiry
        )
    
    async def _build_topology_graph(self) -> TopologyGraph:
        """Build complete topology graph from database"""
        
        try:
            # Get all devices with their interfaces
            devices_query = select(Device).options(
                selectinload(Device.interfaces),
                selectinload(Device.parent_relationships),
                selectinload(Device.child_relationships)
            ).where(Device.is_active == True)
            
            devices_result = await db.execute(devices_query)
            devices = devices_result.scalars().all()
            
            # Get all device relationships
            relationships_query = select(DeviceRelationship).options(
                selectinload(DeviceRelationship.parent_device),
                selectinload(DeviceRelationship.child_device)
            )
            relationships_result = await db.execute(relationships_query)
            relationships = relationships_result.scalars().all()
            
            # Build nodes
            nodes = []
            for device in devices:
                # Get performance summary
                perf_summary = await self._get_device_performance_summary(device.id)
                
                # Build interfaces list
                interfaces = []
                for interface in device.interfaces:
                    interfaces.append({
                        "id": str(interface.id),
                        "name": interface.interface_name,
                        "type": interface.interface_type,
                        "ip_address": interface.ip_address,
                        "mac_address": interface.mac_address,
                        "status": interface.status,
                        "speed": interface.speed,
                        "in_octets": interface.in_octets,
                        "out_octets": interface.out_octets,
                        "in_errors": interface.in_errors,
                        "out_errors": interface.out_errors
                    })
                
                node = TopologyNode(
                    id=str(device.id),
                    hostname=device.hostname,
                    ip_address=device.ip_address,
                    device_type=device.device_type.value if device.device_type else "other",
                    status=device.current_state.value if device.current_state else "unknown",
                    location=device.location,
                    interfaces=interfaces,
                    last_seen=device.last_poll_time,
                    performance_summary=perf_summary,
                    metadata={
                        "manufacturer": device.manufacturer,
                        "model": device.model,
                        "serial_number": device.serial_number,
                        "firmware_version": device.firmware_version,
                        "os_version": device.os_version,
                        "discovery_protocol": device.discovery_protocol,
                        "last_discovery": device.last_discovery.isoformat() if device.last_discovery else None
                    }
                )
                nodes.append(node)
            
            # Build edges
            edges = []
            for relationship in relationships:
                # Get bandwidth and latency from recent metrics
                bandwidth, latency = await self._get_relationship_metrics(relationship)
                
                # Determine relationship status
                status = await self._get_relationship_status(relationship)
                
                edge = TopologyEdge(
                    id=str(relationship.id),
                    source_id=str(relationship.parent_device_id),
                    target_id=str(relationship.child_device_id),
                    relationship_type=relationship.relationship_type,
                    source_interface=relationship.parent_interface,
                    target_interface=relationship.child_interface,
                    bandwidth=bandwidth,
                    latency=latency,
                    status=status,
                    discovery_protocol=relationship.discovery_protocol,
                    last_updated=relationship.updated_at,
                    metadata={
                        "discovery_method": relationship.discovery_protocol,
                        "metadata": relationship.metadata
                    }
                )
                edges.append(edge)
            
            # Calculate topology statistics
            metadata = await self._calculate_topology_metadata(nodes, edges)
            
            return TopologyGraph(
                nodes=nodes,
                edges=edges,
                metadata=metadata,
                last_updated=datetime.utcnow()
            )
        
        except Exception as e:
            logger.error(f"Failed to build topology graph: {e}")
            raise
    
    async def _get_device_performance_summary(self, device_id: str) -> Dict[str, Any]:
        """Get performance summary for a device"""
        
        try:
            # Get recent performance metrics
            since_time = datetime.utcnow() - timedelta(hours=1)
            
            metrics_query = select(
                PerformanceMetrics.metric_type,
                func.avg(PerformanceMetrics.metric_value).label('avg_value'),
                func.max(PerformanceMetrics.metric_value).label('max_value'),
                PerformanceMetrics.metric_unit
            ).where(
                and_(
                    PerformanceMetrics.device_id == device_id,
                    PerformanceMetrics.timestamp >= since_time
                )
            ).group_by(
                PerformanceMetrics.metric_type,
                PerformanceMetrics.metric_unit
            )
            
            result = await db.execute(metrics_query)
            metrics_data = result.all()
            
            summary = {}
            for metric in metrics_data:
                summary[metric.metric_type] = {
                    "average": float(metric.avg_value),
                    "maximum": float(metric.max_value),
                    "unit": metric.metric_unit
                }
            
            return summary
        
        except Exception as e:
            logger.error(f"Failed to get performance summary for device {device_id}: {e}")
            return {}
    
    async def _get_relationship_metrics(self, relationship: DeviceRelationship) -> Tuple[Optional[float], Optional[float]]:
        """Get bandwidth and latency metrics for a relationship"""
        
        try:
            # Get recent interface metrics for bandwidth
            bandwidth = None
            if relationship.parent_interface:
                since_time = datetime.utcnow() - timedelta(minutes=5)
                
                bandwidth_query = select(func.avg(PerformanceMetrics.metric_value)).where(
                    and_(
                        PerformanceMetrics.device_id == relationship.parent_device_id,
                        PerformanceMetrics.interface_name == relationship.parent_interface,
                        PerformanceMetrics.metric_type == "bandwidth",
                        PerformanceMetrics.timestamp >= since_time
                    )
                )
                
                bandwidth_result = await db.execute(bandwidth_query)
                bandwidth = bandwidth_result.scalar()
            
            # Get latency from ping metrics
            latency = None
            latency_query = select(func.avg(PerformanceMetrics.metric_value)).where(
                and_(
                    PerformanceMetrics.device_id == relationship.child_device_id,
                    PerformanceMetrics.metric_type == "latency",
                    PerformanceMetrics.timestamp >= datetime.utcnow() - timedelta(minutes=5)
                )
            )
            
            latency_result = await db.execute(latency_query)
            latency = latency_result.scalar()
            
            return bandwidth, latency
        
        except Exception as e:
            logger.error(f"Failed to get relationship metrics: {e}")
            
            # Return fallback relationship metrics when retrieval fails
            fallback_data = FallbackData(
                data=(0.0, 0.0),
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Relationship metrics retrieval failed",
                    details=f"Failed to get relationship metrics: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to get relationship metrics",
                error_code="RELATIONSHIP_METRICS_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Relationship metrics retrieval failed",
                    "Check database connection",
                    "Verify metrics configuration",
                    "Use fallback values"
                ]
            ).data
    
    async def _get_relationship_status(self, relationship: DeviceRelationship) -> str:
        """Determine the status of a device relationship"""
        
        try:
            # Check if both devices are online
            parent_query = select(Device.current_state).where(Device.id == relationship.parent_device_id)
            child_query = select(Device.current_state).where(Device.id == relationship.child_device_id)
            
            parent_result = await db.execute(parent_query)
            child_result = await db.execute(child_query)
            
            parent_status = parent_result.scalar()
            child_status = child_result.scalar()
            
            if parent_status == DeviceStatus.ONLINE and child_status == DeviceStatus.ONLINE:
                return "active"
            elif parent_status == DeviceStatus.OFFLINE or child_status == DeviceStatus.OFFLINE:
                return "inactive"
            else:
                return "unknown"
        
        except Exception as e:
            logger.error(f"Failed to get relationship status: {e}")
            return "unknown"
    
    async def _calculate_topology_metadata(self, nodes: List[TopologyNode], edges: List[TopologyEdge]) -> Dict[str, Any]:
        """Calculate topology statistics and metadata"""
        
        try:
            # Basic counts
            total_devices = len(nodes)
            total_connections = len(edges)
            
            # Device status counts
            status_counts = {}
            device_type_counts = {}
            
            for node in nodes:
                status_counts[node.status] = status_counts.get(node.status, 0) + 1
                device_type_counts[node.device_type] = device_type_counts.get(node.device_type, 0) + 1
            
            # Connection status counts
            connection_status_counts = {}
            protocol_counts = {}
            
            for edge in edges:
                connection_status_counts[edge.status] = connection_status_counts.get(edge.status, 0) + 1
                if edge.discovery_protocol:
                    protocol_counts[edge.discovery_protocol] = protocol_counts.get(edge.discovery_protocol, 0) + 1
            
            # Calculate network health
            online_devices = status_counts.get("online", 0)
            active_connections = connection_status_counts.get("active", 0)
            
            device_health = (online_devices / total_devices * 100) if total_devices > 0 else 0
            connection_health = (active_connections / total_connections * 100) if total_connections > 0 else 0
            overall_health = (device_health + connection_health) / 2
            
            # Find central devices (most connections)
            connection_counts = {}
            for edge in edges:
                connection_counts[edge.source_id] = connection_counts.get(edge.source_id, 0) + 1
                connection_counts[edge.target_id] = connection_counts.get(edge.target_id, 0) + 1
            
            central_devices = sorted(connection_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            
            return {
                "total_devices": total_devices,
                "total_connections": total_connections,
                "device_status_counts": status_counts,
                "device_type_counts": device_type_counts,
                "connection_status_counts": connection_status_counts,
                "discovery_protocol_counts": protocol_counts,
                "network_health": {
                    "overall_health_percentage": round(overall_health, 2),
                    "device_health_percentage": round(device_health, 2),
                    "connection_health_percentage": round(connection_health, 2)
                },
                "central_devices": central_devices,
                "last_discovery": await self._get_last_discovery_time(),
                "topology_complexity": self._calculate_topology_complexity(nodes, edges)
            }
        
        except Exception as e:
            logger.error(f"Failed to calculate topology metadata: {e}")
            return {}
    
    def _calculate_topology_complexity(self, nodes: List[TopologyNode], edges: List[TopologyEdge]) -> str:
        """Calculate topology complexity level"""
        
        device_count = len(nodes)
        connection_count = len(edges)
        
        if device_count <= 5:
            return "simple"
        elif device_count <= 20:
            return "moderate"
        elif device_count <= 50:
            return "complex"
        else:
            return "enterprise"
    
    async def _get_last_discovery_time(self) -> Optional[str]:
        """Get the time of the last network discovery"""
        
        try:
            last_discovery_query = select(func.max(NetworkDiscovery.end_time)).where(
                NetworkDiscovery.status == "completed"
            )
            result = await db.execute(last_discovery_query)
            last_time = result.scalar()
            
            return last_time.isoformat() if last_time else None
        
        except Exception as e:
            logger.error(f"Failed to get last discovery time: {e}")
            
            # Return fallback discovery time when retrieval fails
            fallback_data = FallbackData(
                data="unknown",
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Last discovery time retrieval failed",
                    details=f"Failed to get last discovery time: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to get last discovery time",
                error_code="DISCOVERY_TIME_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Last discovery time retrieval failed",
                    "Check database connection",
                    "Verify discovery configuration",
                    "Use fallback value"
                ]
            ).data
    
    async def _update_topology_status(self):
        """Update topology status information"""
        
        try:
            # Invalidate cache to force refresh
            self.cache_expiry = None
            
            # Update device statuses based on recent metrics
            await self._update_device_statuses()
            
            # Update interface statuses
            await self._update_interface_statuses()
            
            logger.debug("Topology status updated")
        
        except Exception as e:
            logger.error(f"Failed to update topology status: {e}")
    
    async def _update_device_statuses(self):
        """Update device online/offline status based on recent activity"""
        
        try:
            # Get devices that haven't been seen recently
            stale_threshold = datetime.utcnow() - timedelta(minutes=10)
            
            stale_devices_query = select(Device).where(
                and_(
                    Device.current_state == DeviceStatus.ONLINE,
                    or_(
                        Device.last_poll_time < stale_threshold,
                        Device.last_poll_time.is_(None)
                    )
                )
            )
            
            result = await db.execute(stale_devices_query)
            stale_devices = result.scalars().all()
            
            for device in stale_devices:
                # Check if device has recent performance metrics
                recent_metrics_query = select(func.count(PerformanceMetrics.id)).where(
                    and_(
                        PerformanceMetrics.device_id == device.id,
                        PerformanceMetrics.timestamp >= stale_threshold
                    )
                )
                
                metrics_result = await db.execute(recent_metrics_query)
                recent_count = metrics_result.scalar()
                
                if recent_count == 0:
                    # Mark device as potentially offline
                    old_status = device.current_state.value
                    device.current_state = DeviceStatus.OFFLINE
                    
                    # Create notification for status change
                    await notification_service.create_device_status_notification(
                        device=device,
                        old_status=old_status,
                        new_status="offline"
                    )
            
            await db.commit()
        
        except Exception as e:
            logger.error(f"Failed to update device statuses: {e}")
            await db.rollback()
    
    async def _update_interface_statuses(self):
        """Update network interface statuses"""
        
        try:
            # Get interfaces with recent traffic data
            recent_threshold = datetime.utcnow() - timedelta(minutes=5)
            
            interfaces_query = select(NetworkInterface)
            result = await db.execute(interfaces_query)
            interfaces = result.scalars().all()
            
            for interface in interfaces:
                # Check for recent interface metrics
                metrics_query = select(PerformanceMetrics).where(
                    and_(
                        PerformanceMetrics.device_id == interface.device_id,
                        PerformanceMetrics.interface_name == interface.interface_name,
                        PerformanceMetrics.timestamp >= recent_threshold,
                        PerformanceMetrics.metric_type.in_(["bandwidth", "interface"])
                    )
                ).order_by(PerformanceMetrics.timestamp.desc()).limit(1)
                
                metrics_result = await db.execute(metrics_query)
                recent_metric = metrics_result.scalar_one_or_none()
                
                if recent_metric:
                    # Update interface status based on metric
                    if recent_metric.metric_type == "interface" and recent_metric.metric_value == 1:
                        interface.status = "up"
                    elif recent_metric.metric_type == "interface" and recent_metric.metric_value == 0:
                        interface.status = "down"
            
            await db.commit()
        
        except Exception as e:
            logger.error(f"Failed to update interface statuses: {e}")
            await db.rollback()
    
    async def _detect_topology_changes(self):
        """Detect changes in network topology"""
        
        try:
            # This would compare current topology with previous state
            # For now, we'll implement basic change detection
            
            current_time = datetime.utcnow()
            recent_threshold = current_time - timedelta(minutes=self.update_interval + 5)
            
            # Check for new devices
            new_devices_query = select(Device).where(
                Device.created_at >= recent_threshold
            )
            new_devices_result = await db.execute(new_devices_query)
            new_devices = new_devices_result.scalars().all()
            
            for device in new_devices:
                await notification_service.create_notification(
                    title="New Device Discovered",
                    message=f"New device {device.hostname} ({device.ip_address}) has been added to the network topology",
                    notification_type="device_status",
                    severity="info",
                    device_id=str(device.id),
                    action_url=f"/topology?highlight={device.id}"
                )
            
            # Check for new relationships
            new_relationships_query = select(DeviceRelationship).where(
                DeviceRelationship.created_at >= recent_threshold
            )
            new_relationships_result = await db.execute(new_relationships_query)
            new_relationships = new_relationships_result.scalars().all()
            
            for relationship in new_relationships:
                await notification_service.create_notification(
                    title="New Network Connection",
                    message=f"New {relationship.relationship_type} connection discovered between network devices",
                    notification_type="discovery",
                    severity="info",
                    action_url="/topology"
                )
            
        except Exception as e:
            logger.error(f"Failed to detect topology changes: {e}")
    
    async def _broadcast_topology_updates(self):
        """Broadcast topology updates to WebSocket subscribers"""
        
        try:
            if not self.subscribers:
                return
            
            # Get current topology summary for broadcast
            topology = await self.get_network_topology()
            
            update_message = {
                "type": "topology_update",
                "data": {
                    "total_devices": len(topology.nodes),
                    "total_connections": len(topology.edges),
                    "network_health": topology.metadata.get("network_health", {}),
                    "last_updated": topology.last_updated.isoformat()
                }
            }
            
            # Send to all subscribers
            disconnected = []
            for websocket in self.subscribers:
                try:
                    await websocket.send_json(update_message)
                except Exception as e:
                    logger.warning(f"Failed to send topology update via WebSocket: {e}")
                    disconnected.append(websocket)
            
            # Remove disconnected clients
            for websocket in disconnected:
                self.subscribers.remove(websocket)
        
        except Exception as e:
            logger.error(f"Failed to broadcast topology updates: {e}")
    
    async def trigger_topology_discovery(self, network_cidr: Optional[str] = None) -> Dict[str, Any]:
        """Trigger network discovery to update topology"""
        
        try:
            # Use enhanced discovery to find new devices and relationships
            if not network_cidr:
                # Auto-detect network ranges from existing devices
                network_cidr = await self._detect_network_ranges()
            
            if network_cidr:
                discovery = await enhanced_discovery.discover_network(
                    network_cidr=network_cidr,
                    protocols=["snmp", "cdp", "lldp", "arp"],
                    discovery_name=f"Topology_Update_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                )
                
                # Invalidate cache after discovery
                self.cache_expiry = None
                
                return {
                    "success": True,
                    "discovery_id": str(discovery.id),
                    "network_cidr": network_cidr,
                    "devices_found": discovery.devices_found,
                    "devices_added": discovery.devices_added,
                    "message": "Topology discovery completed successfully"
                }
            else:
                return {
                    "success": False,
                    "message": "No network range detected for discovery"
                }
        
        except Exception as e:
            logger.error(f"Failed to trigger topology discovery: {e}")
            raise
    
    async def _detect_network_ranges(self) -> Optional[str]:
        """Auto-detect network ranges from existing devices"""
        
        try:
            # Get all device IP addresses
            devices_query = select(Device.ip_address).where(Device.is_active == True)
            result = await db.execute(devices_query)
            ip_addresses = [row[0] for row in result.all()]
            
            if not ip_addresses:
                # Return fallback network range when no IP addresses
                fallback_data = FallbackData(
                    data="192.168.1.0/24",
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No IP addresses found",
                        details="No IP addresses found for network range detection",
                        timestamp=datetime.now().isoformat()
                    )
                )
                
                return create_partial_success_result(
                    data="192.168.1.0/24",
                    fallback_data=fallback_data,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No IP addresses found",
                        details="No IP addresses found for network range detection",
                        timestamp=datetime.now().isoformat()
                    ),
                    suggestions=[
                        "No IP addresses found",
                        "Check device configuration",
                        "Use fallback network range",
                        "Verify device discovery"
                    ]
                ).data
            
            # Simple network detection - find common subnet
            # This is a simplified implementation
            import ipaddress
            
            networks = set()
            for ip in ip_addresses:
                try:
                    network = ipaddress.ip_network(f"{ip}/24", strict=False)
                    networks.add(str(network))
                except:
                    continue
            
            # Return the most common network or the first one
            if networks:
                return list(networks)[0]
            
            # Return fallback network range when no networks detected
            fallback_data = FallbackData(
                data="192.168.1.0/24",
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No networks detected",
                    details="No networks detected from IP addresses",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_partial_success_result(
                data="192.168.1.0/24",
                fallback_data=fallback_data,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="No networks detected",
                    details="No networks detected from IP addresses",
                    timestamp=datetime.now().isoformat()
                ),
                suggestions=[
                    "No networks detected",
                    "Check IP address format",
                    "Use fallback network range",
                    "Verify network configuration"
                ]
            ).data
        
        except Exception as e:
            logger.error(f"Failed to detect network ranges: {e}")
            
            # Return fallback network range when detection fails
            fallback_data = FallbackData(
                data="192.168.1.0/24",
                health_status=HealthStatus(
                    level=HealthLevel.CRITICAL,
                    message="Network range detection failed",
                    details=f"Failed to detect network ranges: {e}",
                    timestamp=datetime.now().isoformat()
                )
            )
            
            return create_failure_result(
                error=f"Failed to detect network ranges",
                error_code="NETWORK_RANGE_DETECTION_FAILED",
                fallback_data=fallback_data,
                suggestions=[
                    "Network range detection failed",
                    "Check IP address format",
                    "Verify network configuration",
                    "Use fallback network range"
                ]
            ).data
    
    def add_subscriber(self, websocket):
        """Add WebSocket subscriber for real-time updates"""
        self.subscribers.append(websocket)
    
    def remove_subscriber(self, websocket):
        """Remove WebSocket subscriber"""
        if websocket in self.subscribers:
            self.subscribers.remove(websocket)

# Global topology service instance
topology_service = RealTimeTopologyService()
