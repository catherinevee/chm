"""
SNMP Monitoring Service
Provides comprehensive monitoring capabilities using essential MIBs
"""

import asyncio
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict

from .session import SNMPSession, DeviceMetrics, SNMPResult
from .oids import OIDManager, StandardMIBs, OIDCategory

logger = logging.getLogger(__name__)

@dataclass
class MonitoringThreshold:
    """Threshold configuration for monitoring"""
    metric_name: str
    warning_threshold: float
    critical_threshold: float
    operator: str = ">"  # >, <, >=, <=, ==, !=
    enabled: bool = True

@dataclass
class AlertCondition:
    """Alert condition for monitoring"""
    metric_name: str
    current_value: float
    threshold_value: float
    severity: str  # warning, critical
    message: str
    timestamp: datetime

class SNMPMonitor:
    """Comprehensive SNMP monitoring service"""
    
    def __init__(self):
        self.oid_manager = OIDManager()
        self.sessions: Dict[str, SNMPSession] = {}
        self.thresholds: Dict[str, List[MonitoringThreshold]] = defaultdict(list)
        self.metrics_history: Dict[str, List[DeviceMetrics]] = defaultdict(list)
        self.max_history_size = 1000  # Keep last 1000 data points
        
        # Initialize default thresholds
        self._setup_default_thresholds()
    
    def _setup_default_thresholds(self):
        """Setup default monitoring thresholds"""
        # CPU thresholds
        self.add_threshold("cpu_utilization", 70.0, 90.0, ">")
        
        # Memory thresholds
        self.add_threshold("memory_usage_percent", 80.0, 95.0, ">")
        
        # Temperature thresholds
        self.add_threshold("temperature", 60.0, 75.0, ">")
        
        # Interface error thresholds
        self.add_threshold("interface_error_rate", 1.0, 5.0, ">")
        
        # Buffer thresholds
        self.add_threshold("buffer_usage_percent", 80.0, 95.0, ">")
    
    def add_threshold(self, metric_name: str, warning_threshold: float, 
                     critical_threshold: float, operator: str = ">"):
        """Add monitoring threshold"""
        threshold = MonitoringThreshold(
            metric_name=metric_name,
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
            operator=operator
        )
        self.thresholds[metric_name].append(threshold)
    
    async def get_session(self, device_id: str, credentials: Dict[str, Any]) -> Optional[SNMPSession]:
        """Get or create SNMP session for a device"""
        if device_id not in self.sessions:
            session = SNMPSession(
                host=credentials['host'],
                community=credentials.get('community', 'public'),
                version=credentials.get('version', '2c'),
                port=credentials.get('port', 161),
                timeout=credentials.get('timeout', 10),  # Increased from 3 to 10 seconds
                retries=credentials.get('retries', 4)   # Increased from 3 to 4 retries
            )
            
            # Test connection
            if await session.connect():
                self.sessions[device_id] = session
            else:
                # Return fallback session data when connection fails
                fallback_data = FallbackData(
                    data=None,
                    source="session_connection_fallback",
                    confidence=0.0,
                    metadata={"device_id": device_id, "reason": "SNMP connection failed"}
                )
                
                return create_failure_result(
                    error=f"Failed to establish SNMP connection for device {device_id}",
                    error_code="SNMP_CONNECTION_FAILED",
                    fallback_data=fallback_data,
                    suggestions=[
                        "SNMP connection failed",
                        "Check SNMP credentials",
                        "Verify network connectivity",
                        "Check SNMP configuration on device"
                    ]
                )
        
        return self.sessions[device_id]
    
    async def monitor_device(self, device_id: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive device monitoring"""
        session = await self.get_session(device_id, credentials)
        if not session:
            return {"error": "Failed to establish SNMP connection"}
        
        try:
            # Get comprehensive metrics
            metrics = await session.get_comprehensive_metrics()
            
            # Store in history
            self._store_metrics_history(device_id, metrics)
            
            # Calculate derived metrics
            derived_metrics = self._calculate_derived_metrics(device_id, metrics)
            
            # Check thresholds and generate alerts
            alerts = self._check_thresholds(device_id, metrics, derived_metrics)
            
            # Prepare monitoring result
            result = {
                "device_id": device_id,
                "timestamp": datetime.now().isoformat(),
                "vendor": session.vendor,
                "device_type": session.device_type,
                "metrics": self._format_metrics(metrics),
                "derived_metrics": derived_metrics,
                "alerts": [self._format_alert(alert) for alert in alerts],
                "status": "healthy" if not alerts else "warning" if any(a.severity == "warning" for a in alerts) else "critical"
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Monitoring failed for device {device_id}: {e}")
            return {"error": str(e)}
    
    async def monitor_essential_metrics(self, device_id: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor only essential metrics for performance"""
        session = await self.get_session(device_id, credentials)
        if not session:
            return {"error": "Failed to establish SNMP connection"}
        
        try:
            # Get essential metrics only
            essential_metrics = {}
            
            # System uptime
            uptime_result = await session.get_system_uptime()
            if uptime_result.success:
                essential_metrics["system_uptime"] = uptime_result.value
            
            # CPU usage
            cpu_result = await session.get_cpu_usage()
            if cpu_result.success:
                essential_metrics["cpu_utilization"] = cpu_result.value
            
            # Memory usage
            memory_info = await session.get_memory_usage()
            if memory_info and 'error' not in memory_info:
                essential_metrics["memory"] = memory_info
            
            # Interface count
            if_count = await session.get_interface_count()
            if if_count.success:
                essential_metrics["interface_count"] = if_count.value
            
            # IP statistics (basic traffic)
            ip_stats = await session.get_ip_statistics()
            if ip_stats:
                essential_metrics["ip_statistics"] = ip_stats
            
            return {
                "device_id": device_id,
                "timestamp": datetime.now().isoformat(),
                "vendor": session.vendor,
                "device_type": session.device_type,
                "essential_metrics": essential_metrics,
                "status": "healthy"
            }
            
        except Exception as e:
            logger.error(f"Essential monitoring failed for device {device_id}: {e}")
            return {"error": str(e)}
    
    async def monitor_interface_performance(self, device_id: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor interface performance metrics"""
        session = await self.get_session(device_id, credentials)
        if not session:
            return {"error": "Failed to establish SNMP connection"}
        
        try:
            # Get interface statistics
            interface_stats = await session.get_interface_stats()
            interface_table = await session.get_interface_table()
            
            # Calculate interface performance metrics
            performance_metrics = {}
            
            for if_index, stats in interface_stats.items():
                if_info = interface_table.get(if_index, {})
                
                # Calculate error rates
                in_errors = stats.get('in_errors', 0)
                out_errors = stats.get('out_errors', 0)
                in_octets = stats.get('in_octets', 0)
                out_octets = stats.get('out_octets', 0)
                
                # Calculate utilization (if speed is available)
                speed = if_info.get('speed', 0)
                utilization = 0
                if speed > 0:
                    total_octets = in_octets + out_octets
                    utilization = (total_octets * 8) / (speed * 100)  # Convert to percentage
                
                performance_metrics[if_index] = {
                    "description": if_info.get('description', f"Interface {if_index}"),
                    "type": if_info.get('type', 'Unknown'),
                    "speed": speed,
                    "admin_status": if_info.get('admin_status', 'Unknown'),
                    "oper_status": if_info.get('oper_status', 'Unknown'),
                    "in_octets": in_octets,
                    "out_octets": out_octets,
                    "in_errors": in_errors,
                    "out_errors": out_errors,
                    "in_discards": stats.get('in_discards', 0),
                    "out_discards": stats.get('out_discards', 0),
                    "utilization_percent": utilization,
                    "error_rate": (in_errors + out_errors) / max(1, in_octets + out_octets) * 100
                }
            
            return {
                "device_id": device_id,
                "timestamp": datetime.now().isoformat(),
                "interface_performance": performance_metrics
            }
            
        except Exception as e:
            logger.error(f"Interface monitoring failed for device {device_id}: {e}")
            return {"error": str(e)}
    
    async def monitor_network_performance(self, device_id: str, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor network layer performance"""
        session = await self.get_session(device_id, credentials)
        if not session:
            return {"error": "Failed to establish SNMP connection"}
        
        try:
            # Get IP statistics
            ip_stats = await session.get_ip_statistics()
            
            # Get TCP statistics
            tcp_stats = await session.get_tcp_statistics()
            
            # Calculate network performance metrics
            network_metrics = {
                "ip_layer": {
                    "packets_received": ip_stats.get('ipInReceives', 0),
                    "packets_delivered": ip_stats.get('ipInDelivers', 0),
                    "packets_forwarded": ip_stats.get('ipForwDatagrams', 0),
                    "packets_sent": ip_stats.get('ipOutRequests', 0),
                    "error_rate": self._calculate_error_rate(
                        ip_stats.get('ipInErrors', 0),
                        ip_stats.get('ipInReceives', 0)
                    ),
                    "discard_rate": self._calculate_error_rate(
                        ip_stats.get('ipInDiscards', 0) + ip_stats.get('ipOutDiscards', 0),
                        ip_stats.get('ipInReceives', 0) + ip_stats.get('ipOutRequests', 0)
                    )
                },
                "tcp_layer": {
                    "active_connections": tcp_stats.get('tcpActiveOpens', 0),
                    "passive_connections": tcp_stats.get('tcpPassiveOpens', 0),
                    "current_connections": tcp_stats.get('tcpCurrEstab', 0),
                    "segments_received": tcp_stats.get('tcpInSegs', 0),
                    "segments_sent": tcp_stats.get('tcpOutSegs', 0),
                    "retransmission_rate": self._calculate_error_rate(
                        tcp_stats.get('tcpRetransSegs', 0),
                        tcp_stats.get('tcpOutSegs', 0)
                    ),
                    "error_rate": self._calculate_error_rate(
                        tcp_stats.get('tcpInErrs', 0),
                        tcp_stats.get('tcpInSegs', 0)
                    )
                }
            }
            
            return {
                "device_id": device_id,
                "timestamp": datetime.now().isoformat(),
                "network_performance": network_metrics
            }
            
        except Exception as e:
            logger.error(f"Network monitoring failed for device {device_id}: {e}")
            return {"error": str(e)}
    
    def _calculate_error_rate(self, errors: int, total: int) -> float:
        """Calculate error rate percentage"""
        if total == 0:
            return 0.0
        return (errors / total) * 100
    
    def _calculate_derived_metrics(self, device_id: str, metrics: DeviceMetrics) -> Dict[str, Any]:
        """Calculate derived metrics from raw SNMP data"""
        derived = {}
        
        # Memory usage percentage
        if metrics.memory_used is not None and metrics.memory_total is not None:
            derived["memory_usage_percent"] = (metrics.memory_used / metrics.memory_total) * 100
        
        # Interface error rates
        if metrics.interface_stats:
            total_errors = 0
            total_octets = 0
            for if_stats in metrics.interface_stats.values():
                total_errors += if_stats.get('in_errors', 0) + if_stats.get('out_errors', 0)
                total_octets += if_stats.get('in_octets', 0) + if_stats.get('out_octets', 0)
            
            if total_octets > 0:
                derived["interface_error_rate"] = (total_errors / total_octets) * 100
        
        # IP error rates
        if metrics.ip_in_receives and metrics.ip_in_errors:
            derived["ip_error_rate"] = (metrics.ip_in_errors / metrics.ip_in_receives) * 100
        
        # TCP retransmission rate
        if metrics.tcp_out_segs and metrics.tcp_retrans_segs:
            derived["tcp_retransmission_rate"] = (metrics.tcp_retrans_segs / metrics.tcp_out_segs) * 100
        
        return derived
    
    def _check_thresholds(self, device_id: str, metrics: DeviceMetrics, 
                         derived_metrics: Dict[str, Any]) -> List[AlertCondition]:
        """Check metrics against thresholds and generate alerts"""
        alerts = []
        
        # Check CPU utilization
        if metrics.cpu_utilization is not None:
            alerts.extend(self._check_metric_thresholds(
                "cpu_utilization", metrics.cpu_utilization, device_id
            ))
        
        # Check memory usage
        if "memory_usage_percent" in derived_metrics:
            alerts.extend(self._check_metric_thresholds(
                "memory_usage_percent", derived_metrics["memory_usage_percent"], device_id
            ))
        
        # Check temperature
        if metrics.temperature is not None:
            alerts.extend(self._check_metric_thresholds(
                "temperature", metrics.temperature, device_id
            ))
        
        # Check interface error rate
        if "interface_error_rate" in derived_metrics:
            alerts.extend(self._check_metric_thresholds(
                "interface_error_rate", derived_metrics["interface_error_rate"], device_id
            ))
        
        return alerts
    
    def _check_metric_thresholds(self, metric_name: str, value: float, 
                                device_id: str) -> List[AlertCondition]:
        """Check a specific metric against its thresholds"""
        alerts = []
        
        for threshold in self.thresholds[metric_name]:
            if not threshold.enabled:
                continue
            
            # Evaluate threshold condition
            condition_met = False
            if threshold.operator == ">":
                condition_met = value > threshold.critical_threshold
            elif threshold.operator == ">=":
                condition_met = value >= threshold.critical_threshold
            elif threshold.operator == "<":
                condition_met = value < threshold.critical_threshold
            elif threshold.operator == "<=":
                condition_met = value <= threshold.critical_threshold
            elif threshold.operator == "==":
                condition_met = value == threshold.critical_threshold
            elif threshold.operator == "!=":
                condition_met = value != threshold.critical_threshold
            
            if condition_met:
                severity = "critical"
                threshold_value = threshold.critical_threshold
            elif self._check_warning_threshold(value, threshold):
                severity = "warning"
                threshold_value = threshold.warning_threshold
            else:
                continue
            
            alert = AlertCondition(
                metric_name=metric_name,
                current_value=value,
                threshold_value=threshold_value,
                severity=severity,
                message=f"{metric_name} is {value} (threshold: {threshold_value})",
                timestamp=datetime.now()
            )
            alerts.append(alert)
        
        return alerts
    
    def _check_warning_threshold(self, value: float, threshold: MonitoringThreshold) -> bool:
        """Check if value exceeds warning threshold"""
        if threshold.operator == ">":
            return value > threshold.warning_threshold
        elif threshold.operator == ">=":
            return value >= threshold.warning_threshold
        elif threshold.operator == "<":
            return value < threshold.warning_threshold
        elif threshold.operator == "<=":
            return value <= threshold.warning_threshold
        elif threshold.operator == "==":
            return value == threshold.warning_threshold
        elif threshold.operator == "!=":
            return value != threshold.warning_threshold
        return False
    
    def _store_metrics_history(self, device_id: str, metrics: DeviceMetrics):
        """Store metrics in history"""
        self.metrics_history[device_id].append(metrics)
        
        # Keep only recent history
        if len(self.metrics_history[device_id]) > self.max_history_size:
            self.metrics_history[device_id] = self.metrics_history[device_id][-self.max_history_size:]
    
    def _format_metrics(self, metrics: DeviceMetrics) -> Dict[str, Any]:
        """Format metrics for JSON serialization"""
        return {
            "system": {
                "uptime": metrics.system_uptime,
                "name": metrics.system_name,
                "location": metrics.system_location
            },
            "performance": {
                "cpu_utilization": metrics.cpu_utilization,
                "memory_used": metrics.memory_used,
                "memory_free": metrics.memory_free,
                "temperature": metrics.temperature
            },
            "interfaces": {
                "count": metrics.interface_count,
                "stats": metrics.interface_stats
            },
            "traffic": {
                "ip_in_receives": metrics.ip_in_receives,
                "ip_in_delivers": metrics.ip_in_delivers,
                "ip_out_requests": metrics.ip_out_requests,
                "ip_in_errors": metrics.ip_in_errors,
                "ip_out_discards": metrics.ip_out_discards
            },
            "tcp": {
                "active_opens": metrics.tcp_active_opens,
                "passive_opens": metrics.tcp_passive_opens,
                "current_established": metrics.tcp_curr_estab,
                "in_segments": metrics.tcp_in_segs,
                "out_segments": metrics.tcp_out_segs,
                "retransmitted_segments": metrics.tcp_retrans_segs,
                "in_errors": metrics.tcp_in_errs
            },
            "vendor_specific": metrics.vendor_metrics
        }
    
    def _format_alert(self, alert: AlertCondition) -> Dict[str, Any]:
        """Format alert for JSON serialization"""
        return {
            "metric_name": alert.metric_name,
            "current_value": alert.current_value,
            "threshold_value": alert.threshold_value,
            "severity": alert.severity,
            "message": alert.message,
            "timestamp": alert.timestamp.isoformat()
        }
    
    def get_metrics_history(self, device_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get metrics history for a device"""
        if device_id not in self.metrics_history:
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        history = []
        
        for metrics in self.metrics_history[device_id]:
            # Note: This is a simplified check - in practice you'd store timestamps
            history.append(self._format_metrics(metrics))
        
        return history[-100:]  # Return last 100 entries
    
    def close_session(self, device_id: str):
        """Close SNMP session for a device"""
        if device_id in self.sessions:
            del self.sessions[device_id]
    
    def close_all_sessions(self):
        """Close all SNMP sessions"""
        self.sessions.clear()

# Global SNMP monitor instance
snmp_monitor = SNMPMonitor()
