"""
Topology Analysis Service for CHM

This service provides network topology analysis, path optimization,
health assessment, and topology recommendations.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict, deque
import networkx as nx

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from sqlalchemy.orm import joinedload

from ..models.network_topology import (
    NetworkTopology, NetworkInterface, NetworkPath, DeviceRelationship,
    TopologyType, InterfaceType, InterfaceStatus, PathStatus
)
from ..models.device import Device, DeviceStatus
from ..models.metric import Metric, MetricType, MetricCategory
from ..models.result_objects import OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class PathAnalysisResult:
    """Result of path analysis between two devices"""
    source_device_id: int
    destination_device_id: int
    path_exists: bool
    shortest_path: List[int]  # List of device IDs
    path_length: int
    total_latency: float
    total_bandwidth: float
    path_quality: float
    bottlenecks: List[Dict[str, Any]]
    alternative_paths: List[List[int]]
    recommendations: List[str]


@dataclass
class TopologyHealthResult:
    """Result of topology health assessment"""
    overall_health_score: float  # 0-100
    device_health: Dict[int, float]
    interface_health: Dict[int, float]
    path_health: Dict[int, float]
    critical_issues: List[Dict[str, Any]]
    warnings: List[Dict[str, Any]]
    recommendations: List[str]


@dataclass
class TopologyOptimizationResult:
    """Result of topology optimization analysis"""
    current_efficiency: float  # 0-100
    optimization_opportunities: List[Dict[str, Any]]
    capacity_planning: Dict[str, Any]
    redundancy_analysis: Dict[str, Any]
    cost_optimization: List[Dict[str, Any]]
    implementation_plan: List[Dict[str, Any]]


class TopologyAnalysisService:
    """Service for analyzing network topology and providing insights"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._topology_graphs: Dict[int, nx.Graph] = {}
        self._analysis_cache: Dict[str, Any] = {}
        self._cache_ttl = timedelta(minutes=15)
        self._last_cache_update: Dict[str, datetime] = {}
    
    async def analyze_path(
        self,
        topology_id: int,
        source_device_id: int,
        destination_device_id: int,
        use_cache: bool = True
    ) -> PathAnalysisResult:
        """Analyze network path between two devices"""
        try:
            cache_key = f"path_analysis_{topology_id}_{source_device_id}_{destination_device_id}"
            
            if use_cache and self._is_cache_valid(cache_key):
                return self._analysis_cache[cache_key]
            
            # Build topology graph
            graph = await self._build_topology_graph(topology_id)
            if not graph:
                return PathAnalysisResult(
                    source_device_id=source_device_id,
                    destination_device_id=destination_device_id,
                    path_exists=False,
                    shortest_path=[],
                    path_length=0,
                    total_latency=0.0,
                    total_bandwidth=0.0,
                    path_quality=0.0,
                    bottlenecks=[],
                    alternative_paths=[],
                    recommendations=["Topology graph not available"]
                )
            
            # Check if both devices exist in topology
            if source_device_id not in graph.nodes or destination_device_id not in graph.nodes:
                return PathAnalysisResult(
                    source_device_id=source_device_id,
                    destination_device_id=destination_device_id,
                    path_exists=False,
                    shortest_path=[],
                    path_length=0,
                    total_latency=0.0,
                    total_bandwidth=0.0,
                    path_quality=0.0,
                    bottlenecks=[],
                    alternative_paths=[],
                    recommendations=["One or both devices not found in topology"]
                )
            
            # Find shortest path
            try:
                shortest_path = nx.shortest_path(graph, source_device_id, destination_device_id, weight='latency')
                path_exists = True
            except nx.NetworkXNoPath:
                shortest_path = []
                path_exists = False
            
            # Analyze path characteristics
            path_analysis = await self._analyze_path_characteristics(
                topology_id, shortest_path, graph
            )
            
            # Find alternative paths
            alternative_paths = await self._find_alternative_paths(
                graph, source_device_id, destination_device_id, shortest_path
            )
            
            # Identify bottlenecks
            bottlenecks = await self._identify_bottlenecks(topology_id, shortest_path)
            
            # Generate recommendations
            recommendations = await self._generate_path_recommendations(
                path_exists, path_analysis, bottlenecks, alternative_paths
            )
            
            # Create result
            result = PathAnalysisResult(
                source_device_id=source_device_id,
                destination_device_id=destination_device_id,
                path_exists=path_exists,
                shortest_path=shortest_path,
                path_length=len(shortest_path) - 1 if shortest_path else 0,
                total_latency=path_analysis.get("total_latency", 0.0),
                total_bandwidth=path_analysis.get("total_bandwidth", 0.0),
                path_quality=path_analysis.get("path_quality", 0.0),
                bottlenecks=bottlenecks,
                alternative_paths=alternative_paths,
                recommendations=recommendations
            )
            
            # Cache result
            if use_cache:
                self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Path analysis failed: {str(e)}")
            raise
    
    async def assess_topology_health(
        self,
        topology_id: int,
        use_cache: bool = True
    ) -> TopologyHealthResult:
        """Assess overall health of network topology"""
        try:
            cache_key = f"topology_health_{topology_id}"
            
            if use_cache and self._is_cache_valid(cache_key):
                return self._analysis_cache[cache_key]
            
            # Get topology data
            topology = await self._get_topology(topology_id)
            if not topology:
                raise ValueError(f"Topology {topology_id} not found")
            
            # Assess device health
            device_health = await self._assess_device_health(topology_id)
            
            # Assess interface health
            interface_health = await self._assess_interface_health(topology_id)
            
            # Assess path health
            path_health = await self._assess_path_health(topology_id)
            
            # Calculate overall health score
            overall_health_score = self._calculate_overall_health_score(
                device_health, interface_health, path_health
            )
            
            # Identify critical issues and warnings
            critical_issues, warnings = await self._identify_health_issues(
                topology_id, device_health, interface_health, path_health
            )
            
            # Generate recommendations
            recommendations = await self._generate_health_recommendations(
                critical_issues, warnings, overall_health_score
            )
            
            # Create result
            result = TopologyHealthResult(
                overall_health_score=overall_health_score,
                device_health=device_health,
                interface_health=interface_health,
                path_health=path_health,
                critical_issues=critical_issues,
                warnings=warnings,
                recommendations=recommendations
            )
            
            # Cache result
            if use_cache:
                self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Topology health assessment failed: {str(e)}")
            raise
    
    async def optimize_topology(
        self,
        topology_id: int,
        optimization_goals: List[str],
        use_cache: bool = True
    ) -> TopologyOptimizationResult:
        """Analyze topology for optimization opportunities"""
        try:
            cache_key = f"topology_optimization_{topology_id}_{'_'.join(sorted(optimization_goals))}"
            
            if use_cache and self._is_cache_valid(cache_key):
                return self._analysis_cache[cache_key]
            
            # Get current topology efficiency
            current_efficiency = await self._calculate_topology_efficiency(topology_id)
            
            # Analyze optimization opportunities
            optimization_opportunities = await self._analyze_optimization_opportunities(
                topology_id, optimization_goals
            )
            
            # Capacity planning analysis
            capacity_planning = await self._analyze_capacity_planning(topology_id)
            
            # Redundancy analysis
            redundancy_analysis = await self._analyze_redundancy(topology_id)
            
            # Cost optimization analysis
            cost_optimization = await self._analyze_cost_optimization(topology_id)
            
            # Implementation plan
            implementation_plan = await self._create_implementation_plan(
                optimization_opportunities, capacity_planning, redundancy_analysis
            )
            
            # Create result
            result = TopologyOptimizationResult(
                current_efficiency=current_efficiency,
                optimization_opportunities=optimization_opportunities,
                capacity_planning=capacity_planning,
                redundancy_analysis=redundancy_analysis,
                cost_optimization=cost_optimization,
                implementation_plan=implementation_plan
            )
            
            # Cache result
            if use_cache:
                self._cache_result(cache_key, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Topology optimization analysis failed: {str(e)}")
            raise
    
    async def _build_topology_graph(self, topology_id: int) -> Optional[nx.Graph]:
        """Build NetworkX graph representation of topology"""
        try:
            # Check if graph is already built
            if topology_id in self._topology_graphs:
                return self._topology_graphs[topology_id]
            
            # Get topology relationships
            stmt = select(DeviceRelationship).where(
                and_(
                    DeviceRelationship.topology_id == topology_id,
                    DeviceRelationship.is_active == True
                )
            ).options(
                joinedload(DeviceRelationship.source_device),
                joinedload(DeviceRelationship.target_device),
                joinedload(DeviceRelationship.source_interface),
                joinedload(DeviceRelationship.target_interface)
            )
            
            result = await self.db_session.execute(stmt)
            relationships = result.scalars().all()
            
            if not relationships:
                logger.warning(f"No active relationships found for topology {topology_id}")
                return None
            
            # Build graph
            graph = nx.Graph()
            
            for rel in relationships:
                source_id = rel.source_device_id
                target_id = rel.target_device_id
                
                # Add nodes
                graph.add_node(source_id, device=rel.source_device)
                graph.add_node(target_id, device=rel.target_device)
                
                # Add edge with attributes
                edge_attrs = {
                    'relationship_id': rel.id,
                    'relationship_type': rel.relationship_type,
                    'latency': rel.latency or 1.0,  # Default latency
                    'bandwidth': rel.bandwidth or 1000.0,  # Default bandwidth
                    'reliability': rel.reliability or 95.0,  # Default reliability
                    'connection_quality': rel.connection_quality or 80.0
                }
                
                graph.add_edge(source_id, target_id, **edge_attrs)
            
            # Cache the graph
            self._topology_graphs[topology_id] = graph
            
            logger.info(f"Built topology graph for topology {topology_id} with {len(graph.nodes)} nodes and {len(graph.edges)} edges")
            return graph
            
        except Exception as e:
            logger.error(f"Failed to build topology graph: {str(e)}")
            return None
    
    async def _analyze_path_characteristics(
        self,
        topology_id: int,
        path: List[int],
        graph: nx.Graph
    ) -> Dict[str, Any]:
        """Analyze characteristics of a network path"""
        if not path or len(path) < 2:
            return {
                "total_latency": 0.0,
                "total_bandwidth": 0.0,
                "path_quality": 0.0,
                "hop_details": []
            }
        
        total_latency = 0.0
        total_bandwidth = float('inf')
        hop_details = []
        
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            
            edge_data = graph.get_edge_data(source, target)
            if edge_data:
                latency = edge_data.get('latency', 1.0)
                bandwidth = edge_data.get('bandwidth', 1000.0)
                reliability = edge_data.get('reliability', 95.0)
                
                total_latency += latency
                total_bandwidth = min(total_bandwidth, bandwidth)
                
                hop_details.append({
                    "source_device_id": source,
                    "target_device_id": target,
                    "latency": latency,
                    "bandwidth": bandwidth,
                    "reliability": reliability
                })
        
        # Calculate path quality (simplified scoring)
        path_quality = min(100.0, max(0.0, 100.0 - total_latency * 10))
        
        return {
            "total_latency": total_latency,
            "total_bandwidth": total_bandwidth if total_bandwidth != float('inf') else 0.0,
            "path_quality": path_quality,
            "hop_details": hop_details
        }
    
    async def _find_alternative_paths(
        self,
        graph: nx.Graph,
        source: int,
        target: int,
        primary_path: List[int]
    ) -> List[List[int]]:
        """Find alternative paths between source and target"""
        try:
            # Find k-shortest paths (excluding the primary path)
            k = 3  # Number of alternative paths to find
            
            # Remove primary path edges temporarily
            edges_to_remove = []
            for i in range(len(primary_path) - 1):
                edge = (primary_path[i], primary_path[i + 1])
                if graph.has_edge(*edge):
                    edges_to_remove.append(edge)
                    graph.remove_edge(*edge)
            
            # Find alternative paths
            alternative_paths = []
            try:
                # Find shortest path in modified graph
                alt_path = nx.shortest_path(graph, source, target, weight='latency')
                if alt_path and alt_path != primary_path:
                    alternative_paths.append(alt_path)
            except nx.NetworkXNoPath:
                pass
            
            # Restore primary path edges
            for edge in edges_to_remove:
                graph.add_edge(*edge[0], *edge[1])
            
            return alternative_paths
            
        except Exception as e:
            logger.error(f"Failed to find alternative paths: {str(e)}")
            return []
    
    async def _identify_bottlenecks(
        self,
        topology_id: int,
        path: List[int]
    ) -> List[Dict[str, Any]]:
        """Identify potential bottlenecks in a network path"""
        bottlenecks = []
        
        if not path or len(path) < 2:
            return bottlenecks
        
        try:
            # Get interface information for path
            for i in range(len(path) - 1):
                source_device_id = path[i]
                target_device_id = path[i + 1]
                
                # Get interfaces between these devices
                stmt = select(NetworkInterface).where(
                    and_(
                        NetworkInterface.device_id == source_device_id,
                        NetworkInterface.neighbor_device_id == target_device_id
                    )
                )
                
                result = await self.db_session.execute(stmt)
                interfaces = result.scalars().all()
                
                for interface in interfaces:
                    # Check for potential bottlenecks
                    if interface.bandwidth_mbps and interface.bandwidth_mbps < 1000:  # Less than 1Gbps
                        bottlenecks.append({
                            "device_id": source_device_id,
                            "interface_id": interface.id,
                            "interface_name": interface.name,
                            "bottleneck_type": "low_bandwidth",
                            "current_value": interface.bandwidth_mbps,
                            "threshold": 1000,
                            "severity": "medium",
                            "recommendation": f"Consider upgrading {interface.name} to higher bandwidth"
                        })
                    
                    if interface.current_utilization and interface.current_utilization > 80:
                        bottlenecks.append({
                            "device_id": source_device_id,
                            "interface_id": interface.id,
                            "interface_name": interface.name,
                            "bottleneck_type": "high_utilization",
                            "current_value": interface.current_utilization,
                            "threshold": 80,
                            "severity": "high",
                            "recommendation": f"Monitor {interface.name} utilization and consider load balancing"
                        })
                    
                    if interface.error_count and interface.error_count > 100:
                        bottlenecks.append({
                            "device_id": source_device_id,
                            "interface_id": interface.id,
                            "interface_name": interface.name,
                            "bottleneck_type": "high_error_rate",
                            "current_value": interface.error_count,
                            "threshold": 100,
                            "severity": "critical",
                            "recommendation": f"Investigate errors on {interface.name} immediately"
                        })
        
        except Exception as e:
            logger.error(f"Failed to identify bottlenecks: {str(e)}")
        
        return bottlenecks
    
    async def _assess_device_health(self, topology_id: int) -> Dict[int, float]:
        """Assess health of devices in topology"""
        device_health = {}
        
        try:
            # Get devices in topology
            stmt = select(Device).join(NetworkInterface).where(
                NetworkInterface.topology_id == topology_id
            ).distinct()
            
            result = await self.db_session.execute(stmt)
            devices = result.scalars().all()
            
            for device in devices:
                health_score = 100.0  # Start with perfect health
                
                # Deduct points for various issues
                if device.status != DeviceStatus.ONLINE:
                    health_score -= 30
                
                # Check recent metrics for performance issues
                recent_metrics = await self._get_recent_device_metrics(device.id)
                if recent_metrics:
                    # Analyze CPU, memory, etc.
                    if any(m.value > 90 for m in recent_metrics if m.metric_name == "cpu_usage"):
                        health_score -= 20
                    
                    if any(m.value > 90 for m in recent_metrics if m.metric_name == "memory_usage"):
                        health_score -= 20
                
                # Ensure health score is within bounds
                device_health[device.id] = max(0.0, min(100.0, health_score))
        
        except Exception as e:
            logger.error(f"Failed to assess device health: {str(e)}")
        
        return device_health
    
    async def _assess_interface_health(self, topology_id: int) -> Dict[int, float]:
        """Assess health of interfaces in topology"""
        interface_health = {}
        
        try:
            # Get interfaces in topology
            stmt = select(NetworkInterface).where(
                NetworkInterface.topology_id == topology_id
            )
            
            result = await self.db_session.execute(stmt)
            interfaces = result.scalars().all()
            
            for interface in interfaces:
                health_score = 100.0
                
                # Deduct points for various issues
                if interface.status != "up":
                    health_score -= 40
                
                if interface.current_utilization and interface.current_utilization > 80:
                    health_score -= 25
                
                if interface.error_count and interface.error_count > 100:
                    health_score -= 30
                
                if interface.packet_loss and interface.packet_loss > 5:
                    health_score -= 20
                
                # Ensure health score is within bounds
                interface_health[interface.id] = max(0.0, min(100.0, health_score))
        
        except Exception as e:
            logger.error(f"Failed to assess interface health: {str(e)}")
        
        return interface_health
    
    async def _assess_path_health(self, topology_id: int) -> Dict[int, float]:
        """Assess health of network paths in topology"""
        path_health = {}
        
        try:
            # Get paths in topology
            stmt = select(NetworkPath).where(NetworkPath.topology_id == topology_id)
            
            result = await self.db_session.execute(stmt)
            paths = result.scalars().all()
            
            for path in paths:
                health_score = 100.0
                
                # Deduct points for various issues
                if path.status != "active":
                    health_score -= 50
                
                if path.path_quality and path.path_quality < 80:
                    health_score -= (80 - path.path_quality) * 0.5
                
                if path.packet_loss and path.packet_loss > 5:
                    health_score -= 25
                
                if path.jitter and path.jitter > 50:
                    health_score -= 20
                
                # Ensure health score is within bounds
                path_health[path.id] = max(0.0, min(100.0, health_score))
        
        except Exception as e:
            logger.error(f"Failed to assess path health: {str(e)}")
        
        return path_health
    
    def _calculate_overall_health_score(
        self,
        device_health: Dict[int, float],
        interface_health: Dict[int, float],
        path_health: Dict[int, float]
    ) -> float:
        """Calculate overall topology health score"""
        if not device_health and not interface_health and not path_health:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        # Weight device health more heavily
        if device_health:
            device_avg = sum(device_health.values()) / len(device_health)
            total_score += device_avg * 0.4
            total_weight += 0.4
        
        if interface_health:
            interface_avg = sum(interface_health.values()) / len(interface_health)
            total_score += interface_avg * 0.35
            total_weight += 0.35
        
        if path_health:
            path_avg = sum(path_health.values()) / len(path_health)
            total_score += path_avg * 0.25
            total_weight += 0.25
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    async def _identify_health_issues(
        self,
        topology_id: int,
        device_health: Dict[int, float],
        interface_health: Dict[int, float],
        path_health: Dict[int, float]
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Identify critical issues and warnings"""
        critical_issues = []
        warnings = []
        
        # Check device health
        for device_id, health in device_health.items():
            if health < 30:
                critical_issues.append({
                    "type": "device_health",
                    "device_id": device_id,
                    "severity": "critical",
                    "message": f"Device health critically low: {health:.1f}%",
                    "recommendation": "Immediate investigation required"
                })
            elif health < 60:
                warnings.append({
                    "type": "device_health",
                    "device_id": device_id,
                    "severity": "warning",
                    "message": f"Device health below threshold: {health:.1f}%",
                    "recommendation": "Monitor closely and investigate if trend continues"
                })
        
        # Check interface health
        for interface_id, health in interface_health.items():
            if health < 30:
                critical_issues.append({
                    "type": "interface_health",
                    "interface_id": interface_id,
                    "severity": "critical",
                    "message": f"Interface health critically low: {health:.1f}%",
                    "recommendation": "Immediate investigation required"
                })
            elif health < 60:
                warnings.append({
                    "type": "interface_health",
                    "interface_id": interface_id,
                    "severity": "warning",
                    "message": f"Interface health below threshold: {health:.1f}%",
                    "recommendation": "Monitor closely and investigate if trend continues"
                })
        
        # Check path health
        for path_id, health in path_health.items():
            if health < 30:
                critical_issues.append({
                    "type": "path_health",
                    "path_id": path_id,
                    "severity": "critical",
                    "message": f"Path health critically low: {health:.1f}%",
                    "recommendation": "Immediate investigation required"
                })
            elif health < 60:
                warnings.append({
                    "type": "path_health",
                    "path_id": path_id,
                    "severity": "warning",
                    "message": f"Path health below threshold: {health:.1f}%",
                    "recommendation": "Monitor closely and investigate if trend continues"
                })
        
        return critical_issues, warnings
    
    async def _generate_path_recommendations(
        self,
        path_exists: bool,
        path_analysis: Dict[str, Any],
        bottlenecks: List[Dict[str, Any]],
        alternative_paths: List[List[int]]
    ) -> List[str]:
        """Generate recommendations for path optimization"""
        recommendations = []
        
        if not path_exists:
            recommendations.append("No path exists between source and destination devices")
            recommendations.append("Check network connectivity and routing configuration")
            return recommendations
        
        # Analyze path characteristics
        if path_analysis.get("total_latency", 0) > 100:
            recommendations.append("Path latency is high - consider optimizing routing or upgrading links")
        
        if path_analysis.get("total_bandwidth", 0) < 1000:
            recommendations.append("Path bandwidth is limited - consider upgrading to higher capacity links")
        
        if path_analysis.get("path_quality", 0) < 80:
            recommendations.append("Path quality is below optimal - investigate performance issues")
        
        # Address bottlenecks
        for bottleneck in bottlenecks:
            if bottleneck["severity"] == "critical":
                recommendations.append(f"CRITICAL: {bottleneck['recommendation']}")
            elif bottleneck["severity"] == "high":
                recommendations.append(f"HIGH PRIORITY: {bottleneck['recommendation']}")
            else:
                recommendations.append(bottleneck["recommendation"])
        
        # Alternative path recommendations
        if alternative_paths:
            recommendations.append(f"Found {len(alternative_paths)} alternative path(s) - consider load balancing")
        else:
            recommendations.append("No alternative paths available - consider adding redundancy")
        
        return recommendations
    
    async def _generate_health_recommendations(
        self,
        critical_issues: List[Dict[str, Any]],
        warnings: List[Dict[str, Any]],
        overall_health_score: float
    ) -> List[str]:
        """Generate recommendations for improving topology health"""
        recommendations = []
        
        if overall_health_score < 50:
            recommendations.append("Overall topology health is critically low - immediate action required")
        elif overall_health_score < 70:
            recommendations.append("Overall topology health needs improvement - prioritize critical issues")
        
        # Critical issue recommendations
        if critical_issues:
            recommendations.append(f"Address {len(critical_issues)} critical issue(s) immediately")
            for issue in critical_issues[:3]:  # Limit to first 3
                recommendations.append(f"- {issue['message']}")
        
        # Warning recommendations
        if warnings:
            recommendations.append(f"Monitor {len(warnings)} warning(s) closely")
            if len(warnings) > 5:
                recommendations.append("High number of warnings suggests systematic issues")
        
        # General recommendations
        if overall_health_score < 80:
            recommendations.append("Implement proactive monitoring and alerting")
            recommendations.append("Review and update network documentation")
            recommendations.append("Consider network infrastructure upgrades")
        
        return recommendations
    
    async def _calculate_topology_efficiency(self, topology_id: int) -> float:
        """Calculate current topology efficiency score"""
        try:
            # This is a simplified efficiency calculation
            # In production, this would consider multiple factors
            
            # Get topology statistics
            stmt = select(func.count(Device.id)).join(NetworkInterface).where(
                NetworkInterface.topology_id == topology_id
            )
            result = await self.db_session.execute(stmt)
            device_count = result.scalar() or 0
            
            if device_count == 0:
                return 0.0
            
            # Calculate efficiency based on various factors
            efficiency = 80.0  # Base efficiency
            
            # Adjust based on device count (more devices = more complex = lower efficiency)
            if device_count > 100:
                efficiency -= 20
            elif device_count > 50:
                efficiency -= 10
            
            # Adjust based on health scores
            health_result = await self.assess_topology_health(topology_id, use_cache=False)
            efficiency = (efficiency + health_result.overall_health_score) / 2
            
            return max(0.0, min(100.0, efficiency))
            
        except Exception as e:
            logger.error(f"Failed to calculate topology efficiency: {str(e)}")
            return 50.0
    
    async def _analyze_optimization_opportunities(
        self,
        topology_id: int,
        optimization_goals: List[str]
    ) -> List[Dict[str, Any]]:
        """Analyze topology for optimization opportunities"""
        opportunities = []
        
        try:
            # Get topology data
            topology = await self._get_topology(topology_id)
            if not topology:
                return opportunities
            
            # Analyze based on goals
            for goal in optimization_goals:
                if goal == "performance":
                    perf_opps = await self._analyze_performance_opportunities(topology_id)
                    opportunities.extend(perf_opps)
                
                elif goal == "reliability":
                    rel_opps = await self._analyze_reliability_opportunities(topology_id)
                    opportunities.extend(rel_opps)
                
                elif goal == "cost":
                    cost_opps = await self._analyze_cost_opportunities(topology_id)
                    opportunities.extend(cost_opps)
                
                elif goal == "scalability":
                    scale_opps = await self._analyze_scalability_opportunities(topology_id)
                    opportunities.extend(scale_opps)
        
        except Exception as e:
            logger.error(f"Failed to analyze optimization opportunities: {str(e)}")
        
        return opportunities
    
    async def _analyze_performance_opportunities(self, topology_id: int) -> List[Dict[str, Any]]:
        """Analyze performance optimization opportunities"""
        opportunities = []
        
        try:
            # Get interfaces with high utilization
            stmt = select(NetworkInterface).where(
                and_(
                    NetworkInterface.topology_id == topology_id,
                    NetworkInterface.current_utilization > 80
                )
            )
            
            result = await self.db_session.execute(stmt)
            high_util_interfaces = result.scalars().all()
            
            for interface in high_util_interfaces:
                opportunities.append({
                    "type": "performance",
                    "category": "bandwidth_upgrade",
                    "target_id": interface.id,
                    "target_type": "interface",
                    "description": f"Interface {interface.name} has high utilization",
                    "current_value": interface.current_utilization,
                    "recommended_action": "Upgrade to higher bandwidth or implement load balancing",
                    "estimated_impact": "high",
                    "estimated_cost": "medium"
                })
        
        except Exception as e:
            logger.error(f"Failed to analyze performance opportunities: {str(e)}")
        
        return opportunities
    
    async def _analyze_reliability_opportunities(self, topology_id: int) -> List[Dict[str, Any]]:
        """Analyze reliability optimization opportunities"""
        opportunities = []
        
        try:
            # Get devices without redundancy
            # This is a simplified analysis
            opportunities.append({
                "type": "reliability",
                "category": "redundancy",
                "target_id": topology_id,
                "target_type": "topology",
                "description": "Add redundant paths for critical connections",
                "current_value": "single_path",
                "recommended_action": "Implement redundant routing and backup links",
                "estimated_impact": "high",
                "estimated_cost": "high"
            })
        
        except Exception as e:
            logger.error(f"Failed to analyze reliability opportunities: {str(e)}")
        
        return opportunities
    
    async def _analyze_cost_opportunities(self, topology_id: int) -> List[Dict[str, Any]]:
        """Analyze cost optimization opportunities"""
        opportunities = []
        
        try:
            # Get underutilized interfaces
            stmt = select(NetworkInterface).where(
                and_(
                    NetworkInterface.topology_id == topology_id,
                    NetworkInterface.current_utilization < 20,
                    NetworkInterface.bandwidth_mbps > 1000
                )
            )
            
            result = await self.db_session.execute(stmt)
            underutilized_interfaces = result.scalars().all()
            
            for interface in underutilized_interfaces:
                opportunities.append({
                    "type": "cost",
                    "category": "rightsizing",
                    "target_id": interface.id,
                    "target_type": "interface",
                    "description": f"Interface {interface.name} is underutilized",
                    "current_value": interface.current_utilization,
                    "recommended_action": "Consider downgrading to lower bandwidth to reduce costs",
                    "estimated_impact": "medium",
                    "estimated_cost": "low"
                })
        
        except Exception as e:
            logger.error(f"Failed to analyze cost opportunities: {str(e)}")
        
        return opportunities
    
    async def _analyze_scalability_opportunities(self, topology_id: int) -> List[Dict[str, Any]]:
        """Analyze scalability optimization opportunities"""
        opportunities = []
        
        try:
            # Get topology statistics
            stmt = select(func.count(Device.id)).join(NetworkInterface).where(
                NetworkInterface.topology_id == topology_id
            )
            result = await self.db_session.execute(stmt)
            device_count = result.scalar() or 0
            
            if device_count > 100:
                opportunities.append({
                    "type": "scalability",
                    "category": "segmentation",
                    "target_id": topology_id,
                    "target_type": "topology",
                    "description": "Large topology may benefit from segmentation",
                    "current_value": device_count,
                    "recommended_action": "Consider implementing network segmentation and micro-segmentation",
                    "estimated_impact": "high",
                    "estimated_cost": "medium"
                })
        
        except Exception as e:
            logger.error(f"Failed to analyze scalability opportunities: {str(e)}")
        
        return opportunities
    
    async def _analyze_capacity_planning(self, topology_id: int) -> Dict[str, Any]:
        """Analyze capacity planning needs"""
        try:
            # Get current capacity metrics
            stmt = select(NetworkInterface).where(
                NetworkInterface.topology_id == topology_id
            )
            
            result = await self.db_session.execute(stmt)
            interfaces = result.scalars().all()
            
            total_bandwidth = sum(i.bandwidth_mbps or 0 for i in interfaces)
            avg_utilization = sum(i.current_utilization or 0 for i in interfaces) / max(len(interfaces), 1)
            
            # Capacity planning recommendations
            if avg_utilization > 70:
                growth_recommendation = "High utilization suggests need for capacity expansion"
                growth_timeline = "6-12 months"
            elif avg_utilization > 50:
                growth_recommendation = "Moderate utilization - plan for gradual expansion"
                growth_timeline = "12-24 months"
            else:
                growth_recommendation = "Low utilization - current capacity is sufficient"
                growth_timeline = "24+ months"
            
            return {
                "current_total_bandwidth": total_bandwidth,
                "average_utilization": avg_utilization,
                "growth_recommendation": growth_recommendation,
                "growth_timeline": growth_timeline,
                "capacity_planning_priority": "high" if avg_utilization > 70 else "medium" if avg_utilization > 50 else "low"
            }
        
        except Exception as e:
            logger.error(f"Failed to analyze capacity planning: {str(e)}")
            return {}
    
    async def _analyze_redundancy(self, topology_id: int) -> Dict[str, Any]:
        """Analyze redundancy in topology"""
        try:
            # Get topology graph
            graph = await self._build_topology_graph(topology_id)
            if not graph:
                return {"redundancy_level": "unknown", "recommendations": ["Unable to analyze redundancy"]}
            
            # Calculate redundancy metrics
            node_count = len(graph.nodes)
            edge_count = len(graph.edges)
            
            # Simple redundancy calculation
            if edge_count >= node_count * 2:
                redundancy_level = "high"
            elif edge_count >= node_count * 1.5:
                redundancy_level = "medium"
            else:
                redundancy_level = "low"
            
            recommendations = []
            if redundancy_level == "low":
                recommendations.append("Implement redundant paths for critical connections")
                recommendations.append("Add backup links between key network segments")
            elif redundancy_level == "medium":
                recommendations.append("Review redundancy for mission-critical paths")
                recommendations.append("Consider additional backup links for high-priority connections")
            else:
                recommendations.append("Good redundancy level - maintain current configuration")
            
            return {
                "redundancy_level": redundancy_level,
                "node_count": node_count,
                "edge_count": edge_count,
                "redundancy_ratio": edge_count / max(node_count, 1),
                "recommendations": recommendations
            }
        
        except Exception as e:
            logger.error(f"Failed to analyze redundancy: {str(e)}")
            return {}
    
    async def _create_implementation_plan(
        self,
        optimization_opportunities: List[Dict[str, Any]],
        capacity_planning: Dict[str, Any],
        redundancy_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Create implementation plan for optimizations"""
        implementation_plan = []
        
        try:
            # Prioritize opportunities by impact and cost
            prioritized_opps = sorted(
                optimization_opportunities,
                key=lambda x: (
                    {"high": 3, "medium": 2, "low": 1}.get(x.get("estimated_impact", "low"), 1),
                    {"low": 3, "medium": 2, "high": 1}.get(x.get("estimated_cost", "high"), 1)
                ),
                reverse=True
            )
            
            # Create implementation phases
            phase1 = []
            phase2 = []
            phase3 = []
            
            for opp in prioritized_opps[:5]:  # Top 5 opportunities
                if opp.get("estimated_impact") == "high" and opp.get("estimated_cost") in ["low", "medium"]:
                    phase1.append(opp)
                elif opp.get("estimated_impact") == "high":
                    phase2.append(opp)
                else:
                    phase3.append(opp)
            
            # Phase 1: Quick wins
            if phase1:
                implementation_plan.append({
                    "phase": 1,
                    "name": "Quick Wins",
                    "timeline": "1-2 weeks",
                    "opportunities": phase1,
                    "description": "High-impact, low-cost optimizations for immediate improvement"
                })
            
            # Phase 2: Strategic improvements
            if phase2:
                implementation_plan.append({
                    "phase": 2,
                    "name": "Strategic Improvements",
                    "timeline": "1-3 months",
                    "opportunities": phase2,
                    "description": "High-impact improvements requiring more resources"
                })
            
            # Phase 3: Long-term optimizations
            if phase3:
                implementation_plan.append({
                    "phase": 3,
                    "name": "Long-term Optimizations",
                    "timeline": "3-12 months",
                    "opportunities": phase3,
                    "description": "Gradual improvements for sustained optimization"
                })
            
            # Add capacity planning recommendations
            if capacity_planning.get("capacity_planning_priority") == "high":
                implementation_plan.append({
                    "phase": 1,
                    "name": "Capacity Planning",
                    "timeline": "Immediate",
                    "opportunities": [],
                    "description": "Urgent capacity planning required",
                    "special_notes": capacity_planning.get("growth_recommendation")
                })
            
            # Add redundancy improvements
            if redundancy_analysis.get("redundancy_level") == "low":
                implementation_plan.append({
                    "phase": 2,
                    "name": "Redundancy Improvements",
                    "timeline": "1-6 months",
                    "opportunities": [],
                    "description": "Implement critical redundancy for network resilience",
                    "special_notes": "Focus on mission-critical connections first"
                })
        
        except Exception as e:
            logger.error(f"Failed to create implementation plan: {str(e)}")
        
        return implementation_plan
    
    async def _get_recent_device_metrics(self, device_id: int, hours: int = 24) -> List[Metric]:
        """Get recent metrics for a device"""
        try:
            cutoff_time = datetime.now() - timedelta(hours=hours)
            
            stmt = select(Metric).where(
                and_(
                    Metric.device_id == device_id,
                    Metric.timestamp >= cutoff_time
                )
            ).order_by(Metric.timestamp.desc()).limit(100)
            
            result = await self.db_session.execute(stmt)
            return result.scalars().all()
        
        except Exception as e:
            logger.error(f"Failed to get recent device metrics: {str(e)}")
            return []
    
    async def _get_topology(self, topology_id: int) -> Optional[NetworkTopology]:
        """Get topology by ID"""
        try:
            stmt = select(NetworkTopology).where(NetworkTopology.id == topology_id)
            result = await self.db_session.execute(stmt)
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Failed to get topology {topology_id}: {str(e)}")
            return None
    
    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached result is still valid"""
        if cache_key not in self._last_cache_update:
            return False
        
        return datetime.now() - self._last_cache_update[cache_key] < self._cache_ttl
    
    def _cache_result(self, cache_key: str, result: Any):
        """Cache analysis result"""
        self._analysis_cache[cache_key] = result
        self._last_cache_update[cache_key] = datetime.now()
        
        # Clean up old cache entries
        if len(self._analysis_cache) > 100:
            # Remove oldest entries
            keys_to_remove = sorted(
                self._last_cache_update.keys(),
                key=lambda k: self._last_cache_update[k]
            )[:20]
            
            for key in keys_to_remove:
                del self._analysis_cache[key]
                del self._last_cache_update[key]
