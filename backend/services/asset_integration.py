"""
Asset-Monitoring Integration Service
Connects asset management with monitoring data for comprehensive device lifecycle management
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from sqlalchemy import select, and_, or_, func, desc
from sqlalchemy.orm import selectinload

from backend.storage.database import db
from backend.storage.models import (
    Device, PerformanceMetrics, Alert, SLAMetrics, DeviceStatus,
    AssetStatus, AlertSeverity
)
from backend.services.notification_service import notification_service
from backend.collector.performance_collector import performance_collector

logger = logging.getLogger(__name__)

@dataclass
class AssetHealthReport:
    """Asset health report with monitoring integration"""
    device_id: str
    hostname: str
    asset_tag: Optional[str]
    asset_status: str
    monitoring_status: str
    health_score: float
    performance_summary: Dict[str, Any]
    alerts_summary: Dict[str, Any]
    sla_summary: Dict[str, Any]
    maintenance_recommendations: List[str]
    cost_analysis: Dict[str, Any]
    last_updated: datetime

@dataclass
class MaintenanceRecommendation:
    """Maintenance recommendation based on monitoring data"""
    device_id: str
    recommendation_type: str
    priority: str
    description: str
    estimated_cost: Optional[float]
    projected_date: Optional[datetime]
    supporting_metrics: List[Dict[str, Any]]

class AssetMonitoringIntegration:
    """Service for integrating asset management with monitoring systems"""
    
    def __init__(self):
        self.health_cache = {}
        self.cache_duration = 300  # 5 minutes
    
    async def get_asset_health_report(self, device_id: str) -> AssetHealthReport:
        """Get comprehensive asset health report with monitoring data"""
        
        try:
            # Get device with asset information
            device_query = select(Device).options(
                selectinload(Device.sla_metrics),
                selectinload(Device.performance_metrics)
            ).where(Device.id == device_id)
            
            device_result = await db.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Get performance summary
            performance_summary = await self._get_performance_summary(device_id)
            
            # Get alerts summary
            alerts_summary = await self._get_alerts_summary(device_id)
            
            # Get SLA summary
            sla_summary = await self._get_sla_summary(device_id)
            
            # Calculate health score
            health_score = await self._calculate_health_score(device_id, performance_summary, alerts_summary, sla_summary)
            
            # Generate maintenance recommendations
            recommendations = await self._generate_maintenance_recommendations(device, performance_summary, alerts_summary)
            
            # Calculate cost analysis
            cost_analysis = await self._calculate_cost_analysis(device, performance_summary)
            
            return AssetHealthReport(
                device_id=device_id,
                hostname=device.hostname,
                asset_tag=device.asset_tag,
                asset_status=device.asset_status.value if device.asset_status else "unknown",
                monitoring_status=device.current_state.value if device.current_state else "unknown",
                health_score=health_score,
                performance_summary=performance_summary,
                alerts_summary=alerts_summary,
                sla_summary=sla_summary,
                maintenance_recommendations=recommendations,
                cost_analysis=cost_analysis,
                last_updated=datetime.utcnow()
            )
        
        except Exception as e:
            logger.error(f"Failed to get asset health report for {device_id}: {e}")
            raise
    
    async def _get_performance_summary(self, device_id: str) -> Dict[str, Any]:
        """Get performance metrics summary for asset analysis"""
        
        try:
            # Get recent performance metrics (last 24 hours)
            since_time = datetime.utcnow() - timedelta(hours=24)
            
            metrics_query = select(
                PerformanceMetrics.metric_type,
                func.avg(PerformanceMetrics.metric_value).label('avg_value'),
                func.max(PerformanceMetrics.metric_value).label('max_value'),
                func.min(PerformanceMetrics.metric_value).label('min_value'),
                func.count(PerformanceMetrics.id).label('sample_count'),
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
            
            summary = {
                "total_metrics": len(metrics_data),
                "monitoring_active": len(metrics_data) > 0,
                "metrics": {}
            }
            
            for metric in metrics_data:
                summary["metrics"][metric.metric_type] = {
                    "average": float(metric.avg_value),
                    "maximum": float(metric.max_value),
                    "minimum": float(metric.min_value),
                    "sample_count": metric.sample_count,
                    "unit": metric.metric_unit,
                    "health_status": self._assess_metric_health(metric.metric_type, metric.avg_value, metric.max_value)
                }
            
            return summary
        
        except Exception as e:
            logger.error(f"Failed to get performance summary for {device_id}: {e}")
            return {"total_metrics": 0, "monitoring_active": False, "metrics": {}}
    
    def _assess_metric_health(self, metric_type: str, avg_value: float, max_value: float) -> str:
        """Assess health status of a specific metric"""
        
        # Define health thresholds for different metric types
        thresholds = {
            "cpu": {"warning": 70, "critical": 90},
            "memory": {"warning": 80, "critical": 95},
            "disk": {"warning": 85, "critical": 95},
            "temperature": {"warning": 70, "critical": 85},
            "latency": {"warning": 100, "critical": 500},
            "packet_loss": {"warning": 1, "critical": 5}
        }
        
        if metric_type in thresholds:
            if max_value >= thresholds[metric_type]["critical"]:
                return "critical"
            elif avg_value >= thresholds[metric_type]["warning"]:
                return "warning"
            else:
                return "healthy"
        
        return "unknown"
    
    async def _get_alerts_summary(self, device_id: str) -> Dict[str, Any]:
        """Get alerts summary for asset analysis"""
        
        try:
            # Get alerts from last 30 days
            since_time = datetime.utcnow() - timedelta(days=30)
            
            alerts_query = select(Alert).where(
                and_(
                    Alert.device_id == device_id,
                    Alert.created_at >= since_time
                )
            ).order_by(desc(Alert.created_at))
            
            result = await db.execute(alerts_query)
            alerts = result.scalars().all()
            
            # Categorize alerts
            severity_counts = {"info": 0, "warning": 0, "critical": 0, "emergency": 0}
            status_counts = {"open": 0, "acknowledged": 0, "resolved": 0}
            recent_alerts = []
            
            for alert in alerts:
                severity_counts[alert.severity.value] += 1
                
                if alert.resolved:
                    status_counts["resolved"] += 1
                elif alert.acknowledged:
                    status_counts["acknowledged"] += 1
                else:
                    status_counts["open"] += 1
                
                # Include recent critical/emergency alerts
                if alert.severity in [AlertSeverity.CRITICAL, AlertSeverity.EMERGENCY] and len(recent_alerts) < 5:
                    recent_alerts.append({
                        "id": str(alert.id),
                        "severity": alert.severity.value,
                        "metric_name": alert.metric_name,
                        "message": alert.message,
                        "created_at": alert.created_at.isoformat(),
                        "acknowledged": alert.acknowledged,
                        "resolved": alert.resolved
                    })
            
            return {
                "total_alerts": len(alerts),
                "severity_counts": severity_counts,
                "status_counts": status_counts,
                "recent_critical_alerts": recent_alerts,
                "alert_rate": len(alerts) / 30,  # alerts per day
                "resolution_rate": (status_counts["resolved"] / len(alerts) * 100) if alerts else 0
            }
        
        except Exception as e:
            logger.error(f"Failed to get alerts summary for {device_id}: {e}")
            return {"total_alerts": 0, "severity_counts": {}, "status_counts": {}, "recent_critical_alerts": [], "alert_rate": 0, "resolution_rate": 0}
    
    async def _get_sla_summary(self, device_id: str) -> Dict[str, Any]:
        """Get SLA summary for asset analysis"""
        
        try:
            sla_query = select(SLAMetrics).where(
                and_(
                    SLAMetrics.device_id == device_id,
                    SLAMetrics.is_active == True
                )
            )
            
            result = await db.execute(sla_query)
            sla_metrics = result.scalars().all()
            
            summary = {
                "total_slas": len(sla_metrics),
                "sla_details": [],
                "overall_compliance": 0
            }
            
            if sla_metrics:
                compliant_count = 0
                
                for sla in sla_metrics:
                    sla_detail = {
                        "id": str(sla.id),
                        "name": sla.sla_name,
                        "type": sla.sla_type,
                        "target_value": sla.target_value,
                        "current_value": sla.current_value,
                        "status": sla.sla_status,
                        "uptime_percentage": sla.uptime_percentage,
                        "downtime_minutes": sla.downtime_minutes,
                        "total_outages": sla.total_outages,
                        "compliant": sla.sla_status == "met"
                    }
                    
                    summary["sla_details"].append(sla_detail)
                    
                    if sla.sla_status == "met":
                        compliant_count += 1
                
                summary["overall_compliance"] = (compliant_count / len(sla_metrics)) * 100
            
            return summary
        
        except Exception as e:
            logger.error(f"Failed to get SLA summary for {device_id}: {e}")
            return {"total_slas": 0, "sla_details": [], "overall_compliance": 0}
    
    async def _calculate_health_score(self, device_id: str, performance: Dict, alerts: Dict, sla: Dict) -> float:
        """Calculate overall asset health score (0-100)"""
        
        try:
            score = 100.0
            
            # Performance impact (40% weight)
            performance_score = 100.0
            if performance.get("monitoring_active") and performance.get("metrics"):
                critical_metrics = 0
                warning_metrics = 0
                total_metrics = 0
                
                for metric_type, metric_data in performance["metrics"].items():
                    total_metrics += 1
                    health_status = metric_data.get("health_status", "unknown")
                    
                    if health_status == "critical":
                        critical_metrics += 1
                    elif health_status == "warning":
                        warning_metrics += 1
                
                if total_metrics > 0:
                    performance_score = 100 - (critical_metrics * 30) - (warning_metrics * 15)
                    performance_score = max(0, performance_score)
            
            score *= (performance_score / 100) * 0.4 + 0.6  # 40% weight
            
            # Alerts impact (30% weight)
            alerts_score = 100.0
            if alerts.get("total_alerts", 0) > 0:
                critical_alerts = alerts.get("severity_counts", {}).get("critical", 0)
                emergency_alerts = alerts.get("severity_counts", {}).get("emergency", 0)
                warning_alerts = alerts.get("severity_counts", {}).get("warning", 0)
                
                alerts_score = 100 - (emergency_alerts * 25) - (critical_alerts * 15) - (warning_alerts * 5)
                alerts_score = max(0, alerts_score)
            
            score *= (alerts_score / 100) * 0.3 + 0.7  # 30% weight
            
            # SLA impact (30% weight)
            sla_score = sla.get("overall_compliance", 100)
            score *= (sla_score / 100) * 0.3 + 0.7  # 30% weight
            
            return round(max(0, min(100, score)), 2)
        
        except Exception as e:
            logger.error(f"Failed to calculate health score for {device_id}: {e}")
            return 50.0  # Default neutral score
    
    async def _generate_maintenance_recommendations(self, device: Device, performance: Dict, alerts: Dict) -> List[str]:
        """Generate maintenance recommendations based on monitoring data"""
        
        recommendations = []
        
        try:
            # Check performance metrics for maintenance needs
            if performance.get("metrics"):
                for metric_type, metric_data in performance["metrics"].items():
                    health_status = metric_data.get("health_status", "unknown")
                    avg_value = metric_data.get("average", 0)
                    
                    if health_status == "critical":
                        if metric_type == "cpu":
                            recommendations.append(f"Critical: CPU usage averaging {avg_value:.1f}% - Consider upgrading CPU or optimizing workload")
                        elif metric_type == "memory":
                            recommendations.append(f"Critical: Memory usage averaging {avg_value:.1f}% - Consider adding RAM or optimizing memory usage")
                        elif metric_type == "disk":
                            recommendations.append(f"Critical: Disk usage at {avg_value:.1f}% - Immediate disk cleanup or expansion required")
                        elif metric_type == "temperature":
                            recommendations.append(f"Critical: High temperature averaging {avg_value:.1f}°C - Check cooling systems and airflow")
                    
                    elif health_status == "warning":
                        if metric_type == "cpu":
                            recommendations.append(f"Warning: CPU usage trending high at {avg_value:.1f}% - Monitor for capacity planning")
                        elif metric_type == "memory":
                            recommendations.append(f"Warning: Memory usage at {avg_value:.1f}% - Plan for memory upgrade")
                        elif metric_type == "disk":
                            recommendations.append(f"Warning: Disk usage at {avg_value:.1f}% - Schedule cleanup or expansion")
            
            # Check alert patterns
            if alerts.get("total_alerts", 0) > 0:
                alert_rate = alerts.get("alert_rate", 0)
                if alert_rate > 5:  # More than 5 alerts per day
                    recommendations.append(f"High alert frequency ({alert_rate:.1f}/day) - Review monitoring thresholds and device stability")
                
                resolution_rate = alerts.get("resolution_rate", 0)
                if resolution_rate < 80:  # Less than 80% resolution rate
                    recommendations.append(f"Low alert resolution rate ({resolution_rate:.1f}%) - Review alert handling processes")
            
            # Asset age-based recommendations
            if device.purchase_date:
                age_years = (datetime.utcnow() - device.purchase_date).days / 365.25
                if age_years > 5:
                    recommendations.append(f"Device is {age_years:.1f} years old - Consider replacement planning")
                elif age_years > 3:
                    recommendations.append(f"Device is {age_years:.1f} years old - Schedule preventive maintenance")
            
            # Warranty recommendations
            if device.warranty_expiry:
                days_to_expiry = (device.warranty_expiry - datetime.utcnow()).days
                if days_to_expiry < 30:
                    recommendations.append(f"Warranty expires in {days_to_expiry} days - Consider renewal or replacement")
                elif days_to_expiry < 90:
                    recommendations.append(f"Warranty expires in {days_to_expiry} days - Plan for warranty renewal")
            
            # Generic recommendations if none specific
            if not recommendations:
                if performance.get("monitoring_active"):
                    recommendations.append("Device appears healthy - Continue regular monitoring")
                else:
                    recommendations.append("Enable comprehensive monitoring for better asset management")
            
        except Exception as e:
            logger.error(f"Failed to generate maintenance recommendations: {e}")
            recommendations.append("Unable to generate recommendations - Review monitoring configuration")
        
        return recommendations
    
    async def _calculate_cost_analysis(self, device: Device, performance: Dict) -> Dict[str, Any]:
        """Calculate cost analysis including operational costs"""
        
        try:
            analysis = {
                "initial_cost": device.cost or 0,
                "estimated_annual_operational_cost": 0,
                "estimated_maintenance_cost": 0,
                "total_cost_of_ownership": 0,
                "cost_per_uptime_hour": 0,
                "recommendations": []
            }
            
            # Estimate operational costs based on device type and performance
            base_annual_cost = 0
            if device.device_type:
                device_type = device.device_type.value
                if device_type in ["server", "router", "switch"]:
                    base_annual_cost = 500  # Network equipment
                elif device_type == "firewall":
                    base_annual_cost = 800  # Security equipment
                else:
                    base_annual_cost = 200  # Other devices
            
            # Adjust based on performance issues
            performance_multiplier = 1.0
            if performance.get("metrics"):
                critical_metrics = sum(1 for m in performance["metrics"].values() 
                                     if m.get("health_status") == "critical")
                if critical_metrics > 0:
                    performance_multiplier = 1.5  # Higher operational costs for problematic devices
            
            analysis["estimated_annual_operational_cost"] = base_annual_cost * performance_multiplier
            
            # Estimate maintenance costs
            if device.purchase_date:
                age_years = (datetime.utcnow() - device.purchase_date).days / 365.25
                # Maintenance costs increase with age
                maintenance_factor = min(age_years * 0.1, 0.5)  # Up to 50% of initial cost
                analysis["estimated_maintenance_cost"] = (device.cost or 0) * maintenance_factor
            
            # Calculate total cost of ownership
            analysis["total_cost_of_ownership"] = (
                analysis["initial_cost"] +
                analysis["estimated_annual_operational_cost"] +
                analysis["estimated_maintenance_cost"]
            )
            
            # Calculate cost per uptime hour (if we have uptime data)
            # This would require more sophisticated uptime tracking
            if analysis["total_cost_of_ownership"] > 0:
                estimated_annual_hours = 365 * 24 * 0.99  # Assume 99% uptime
                analysis["cost_per_uptime_hour"] = analysis["total_cost_of_ownership"] / estimated_annual_hours
            
            # Cost optimization recommendations
            if performance_multiplier > 1.2:
                analysis["recommendations"].append("High operational costs due to performance issues - Consider optimization or replacement")
            
            if device.cost and analysis["estimated_maintenance_cost"] > device.cost * 0.3:
                analysis["recommendations"].append("High maintenance costs - Evaluate replacement vs. continued maintenance")
            
            return analysis
        
        except Exception as e:
            logger.error(f"Failed to calculate cost analysis: {e}")
            return {"initial_cost": 0, "estimated_annual_operational_cost": 0, "estimated_maintenance_cost": 0, "total_cost_of_ownership": 0, "cost_per_uptime_hour": 0, "recommendations": []}
    
    async def sync_monitoring_to_assets(self) -> Dict[str, Any]:
        """Sync monitoring data to asset records"""
        
        try:
            # Get all devices with asset information
            devices_query = select(Device).where(Device.asset_tag.isnot(None))
            result = await db.execute(devices_query)
            devices = result.scalars().all()
            
            updated_count = 0
            error_count = 0
            
            for device in devices:
                try:
                    # Update asset status based on monitoring status
                    old_asset_status = device.asset_status
                    
                    if device.current_state == DeviceStatus.ONLINE:
                        device.asset_status = AssetStatus.ACTIVE
                    elif device.current_state == DeviceStatus.OFFLINE:
                        # Keep as active if recently seen, otherwise mark inactive
                        if device.last_poll_time and (datetime.utcnow() - device.last_poll_time).days < 7:
                            device.asset_status = AssetStatus.ACTIVE
                        else:
                            device.asset_status = AssetStatus.INACTIVE
                    elif device.current_state == DeviceStatus.MAINTENANCE:
                        device.asset_status = AssetStatus.ACTIVE  # Still active, just in maintenance
                    elif device.current_state == DeviceStatus.DECOMMISSIONED:
                        device.asset_status = AssetStatus.INACTIVE
                    
                    # Update last seen information
                    if device.last_poll_time:
                        device.updated_at = datetime.utcnow()
                    
                    # Create notification if asset status changed significantly
                    if old_asset_status != device.asset_status and old_asset_status:
                        await notification_service.create_notification(
                            title="Asset Status Updated",
                            message=f"Asset {device.asset_tag} ({device.hostname}) status changed from {old_asset_status.value} to {device.asset_status.value} based on monitoring data",
                            notification_type="system",
                            severity="info",
                            device_id=str(device.id),
                            action_url=f"/inventory?search={device.asset_tag}"
                        )
                    
                    updated_count += 1
                
                except Exception as e:
                    logger.error(f"Failed to sync monitoring data for device {device.hostname}: {e}")
                    error_count += 1
            
            await db.commit()
            
            return {
                "success": True,
                "devices_processed": len(devices),
                "devices_updated": updated_count,
                "errors": error_count,
                "message": f"Synchronized monitoring data for {updated_count} assets"
            }
        
        except Exception as e:
            logger.error(f"Failed to sync monitoring to assets: {e}")
            await db.rollback()
            raise
    
    async def trigger_asset_discovery(self, device_id: str) -> Dict[str, Any]:
        """Trigger comprehensive asset discovery including monitoring setup"""
        
        try:
            device_query = select(Device).where(Device.id == device_id)
            result = await db.execute(device_query)
            device = result.scalar_one_or_none()
            
            if not device:
                raise ValueError(f"Device {device_id} not found")
            
            # Collect comprehensive metrics
            metrics = await performance_collector.collect_all_metrics(device)
            latency_metrics = await performance_collector.calculate_latency_metrics(device)
            metrics.extend(latency_metrics)
            
            # Store metrics
            await performance_collector.store_metrics(device, metrics)
            
            # Update asset information based on discovered data
            if metrics:
                # Update device information from SNMP data
                for metric in metrics:
                    if metric.metadata:
                        if "sys_descr" in metric.metadata and not device.os_version:
                            device.os_version = metric.metadata["sys_descr"][:255]
                        
                        if "sensor_name" in metric.metadata and metric.metric_type == "temperature":
                            # Could update hardware component information
                            pass
            
            # Update discovery timestamp
            device.last_discovery = datetime.utcnow()
            device.discovery_status = "completed"
            
            await db.commit()
            
            # Generate asset health report
            health_report = await self.get_asset_health_report(device_id)
            
            return {
                "success": True,
                "device_id": device_id,
                "metrics_collected": len(metrics),
                "health_score": health_report.health_score,
                "recommendations": health_report.maintenance_recommendations,
                "message": f"Asset discovery completed for {device.hostname}"
            }
        
        except Exception as e:
            logger.error(f"Failed to trigger asset discovery for {device_id}: {e}")
            await db.rollback()
            raise

# Global asset integration service instance
asset_integration = AssetMonitoringIntegration()
