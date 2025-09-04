"""
Performance Analytics Service for CHM Advanced Analytics & Reporting System

This service provides comprehensive performance analysis capabilities including:
- Trend analysis and forecasting
- Anomaly detection using statistical methods
- Capacity planning and resource optimization
- Performance optimization recommendations
- Comparative analysis across devices and time periods
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import statistics
import math

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc
from sqlalchemy.orm import selectinload

from ..models.analytics import (
    PerformanceAnalysis, AnomalyDetection, CapacityPlanning, 
    TrendForecast, AnalyticsInsight, AnalysisType, AnomalySeverity
)
from ..models.metric import Metric, MetricType, MetricCategory
from ..models.device import Device, DeviceStatus
from ..models.result_objects import AnalyticsResult, OptimizationResult
from ..services.metrics_query import MetricsQueryService

logger = logging.getLogger(__name__)


@dataclass
class TrendAnalysisConfig:
    """Configuration for trend analysis"""
    min_data_points: int = 24  # Minimum data points for reliable analysis
    trend_threshold: float = 0.1  # Minimum change percentage to consider a trend
    confidence_interval: float = 0.95  # Statistical confidence interval
    seasonal_analysis: bool = True  # Enable seasonal pattern detection
    outlier_detection: bool = True  # Enable outlier detection


@dataclass
class AnomalyDetectionConfig:
    """Configuration for anomaly detection"""
    baseline_window_hours: int = 168  # 7 days for baseline calculation
    anomaly_threshold_std: float = 3.0  # Standard deviations for anomaly detection
    min_anomaly_duration_minutes: int = 5  # Minimum duration to consider anomaly
    correlation_window_minutes: int = 30  # Window for finding related anomalies
    false_positive_reduction: bool = True  # Enable false positive reduction


@dataclass
class CapacityPlanningConfig:
    """Configuration for capacity planning"""
    forecast_horizon_days: List[int] = None  # Days to forecast (default: 30, 90, 180, 365)
    utilization_thresholds: Dict[str, float] = None  # Resource-specific thresholds
    growth_rate_analysis: bool = True  # Analyze growth rates
    seasonal_adjustment: bool = True  # Apply seasonal adjustments to forecasts
    cost_optimization: bool = True  # Include cost considerations in recommendations
    
    def __post_init__(self):
        if self.forecast_horizon_days is None:
            self.forecast_horizon_days = [30, 90, 180, 365]
        if self.utilization_thresholds is None:
            self.utilization_thresholds = {
                'cpu': 80.0,
                'memory': 85.0,
                'disk': 90.0,
                'network': 75.0,
                'bandwidth': 80.0
            }


class PerformanceAnalyticsService:
    """Service for comprehensive performance analytics and insights"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.metrics_query = MetricsQueryService(db_session)
        self.trend_config = TrendAnalysisConfig()
        self.anomaly_config = AnomalyDetectionConfig()
        self.capacity_config = CapacityPlanningConfig()
    
    async def analyze_device_performance(
        self,
        device_id: int,
        analysis_type: AnalysisType,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        **kwargs
    ) -> AnalyticsResult:
        """Analyze device performance based on specified analysis type"""
        try:
            start_time = datetime.now()
            
            if analysis_type == AnalysisType.TREND_ANALYSIS:
                result = await self._analyze_trends(device_id, time_range, **kwargs)
            elif analysis_type == AnalysisType.ANOMALY_DETECTION:
                result = await self._detect_anomalies(device_id, time_range, **kwargs)
            elif analysis_type == AnalysisType.CAPACITY_PLANNING:
                result = await self._analyze_capacity(device_id, **kwargs)
            elif analysis_type == AnalysisType.PERFORMANCE_OPTIMIZATION:
                result = await self._optimize_performance(device_id, time_range, **kwargs)
            elif analysis_type == AnalysisType.FORECASTING:
                result = await self._generate_forecast(device_id, time_range, **kwargs)
            elif analysis_type == AnalysisType.COMPARATIVE_ANALYSIS:
                result = await self._compare_performance(device_id, time_range, **kwargs)
            else:
                return AnalyticsResult(
                    success=False,
                    error=f"Unsupported analysis type: {analysis_type}"
                )
            
            analysis_duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # Store analysis result if successful
            if result.success and hasattr(result, 'analysis_id'):
                await self._store_analysis_result(
                    device_id, analysis_type, result, analysis_duration
                )
            
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing device {device_id} performance: {str(e)}")
            return AnalyticsResult(
                success=False,
                error=str(e),
                fallback_data={"analysis_available": False}
            )
    
    async def _analyze_trends(
        self,
        device_id: int,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        metric_names: Optional[List[str]] = None
    ) -> AnalyticsResult:
        """Analyze performance trends for device metrics"""
        try:
            # Determine time range
            if time_range is None:
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=168)  # 7 days
            else:
                start_time, end_time = time_range
            
            # Get metrics data
            if metric_names is None:
                metric_names = ['cpu_utilization', 'memory_utilization', 'network_throughput']
            
            trend_results = {}
            insights = []
            recommendations = []
            
            for metric_name in metric_names:
                # Query metrics data
                metrics_data = await self.metrics_query.get_metrics(
                    device_id=device_id,
                    metric_name=metric_name,
                    start_time=start_time,
                    end_time=end_time,
                    limit=1000
                )
                
                if not metrics_data.success or not metrics_data.metrics:
                    continue
                
                # Analyze trend for this metric
                trend_analysis = await self._calculate_trend(
                    metrics_data.metrics, metric_name
                )
                
                if trend_analysis:
                    trend_results[metric_name] = trend_analysis
                    
                    # Generate insights and recommendations
                    metric_insights = await self._generate_trend_insights(
                        metric_name, trend_analysis
                    )
                    insights.extend(metric_insights)
                    
                    metric_recommendations = await self._generate_trend_recommendations(
                        metric_name, trend_analysis
                    )
                    recommendations.extend(metric_recommendations)
            
            if not trend_results:
                return AnalyticsResult(
                    success=False,
                    error="No trend data available for analysis"
                )
            
            # Calculate overall trend score
            overall_trend_score = self._calculate_overall_trend_score(trend_results)
            
            return AnalyticsResult(
                success=True,
                analysis_type=AnalysisType.TREND_ANALYSIS,
                data={
                    'trends': trend_results,
                    'overall_trend_score': overall_trend_score,
                    'time_range': {'start': start_time, 'end': end_time},
                    'insights': insights,
                    'recommendations': recommendations
                },
                metadata={
                    'device_id': device_id,
                    'metrics_analyzed': list(trend_results.keys()),
                    'data_points_total': sum(len(t['data_points']) for t in trend_results.values())
                }
            )
            
        except Exception as e:
            logger.error(f"Error analyzing trends for device {device_id}: {str(e)}")
            return AnalyticsResult(
                success=False,
                error=str(e),
                fallback_data={"trend_analysis": "unavailable"}
            )
    
    async def _calculate_trend(
        self,
        metrics: List[Metric],
        metric_name: str
    ) -> Optional[Dict[str, Any]]:
        """Calculate trend characteristics for a metric"""
        try:
            if len(metrics) < self.trend_config.min_data_points:
                return None
            
            # Extract values and timestamps
            values = [m.value for m in metrics]
            timestamps = [m.timestamp for m in metrics]
            
            # Calculate basic statistics
            mean_value = statistics.mean(values)
            std_dev = statistics.stdev(values) if len(values) > 1 else 0
            
            # Calculate trend using linear regression
            trend_slope, trend_intercept, trend_r_squared = self._linear_regression(
                timestamps, values
            )
            
            # Determine trend direction and strength
            trend_direction = self._determine_trend_direction(trend_slope)
            trend_strength = min(abs(trend_r_squared), 1.0)
            
            # Calculate change percentage
            if len(values) >= 2:
                change_percentage = ((values[-1] - values[0]) / values[0]) * 100
            else:
                change_percentage = 0
            
            # Detect seasonal patterns if enabled
            seasonal_info = None
            if self.trend_config.seasonal_analysis:
                seasonal_info = self._detect_seasonality(timestamps, values)
            
            # Detect outliers if enabled
            outliers = []
            if self.trend_config.outlier_detection:
                outliers = self._detect_outliers(values, mean_value, std_dev)
            
            return {
                'metric_name': metric_name,
                'data_points': len(metrics),
                'mean_value': mean_value,
                'std_dev': std_dev,
                'trend_slope': trend_slope,
                'trend_intercept': trend_intercept,
                'trend_r_squared': trend_r_squared,
                'trend_direction': trend_direction,
                'trend_strength': trend_strength,
                'change_percentage': change_percentage,
                'min_value': min(values),
                'max_value': max(values),
                'current_value': values[-1],
                'baseline_value': mean_value,
                'seasonal_info': seasonal_info,
                'outliers': outliers,
                'confidence_score': min(trend_r_squared * 0.8 + 0.2, 1.0)
            }
            
        except Exception as e:
            logger.error(f"Error calculating trend for {metric_name}: {str(e)}")
            return None
    
    def _linear_regression(
        self,
        timestamps: List[datetime],
        values: List[float]
    ) -> Tuple[float, float, float]:
        """Calculate linear regression for trend analysis"""
        try:
            # Convert timestamps to numeric values (hours since start)
            start_time = min(timestamps)
            x_values = [(t - start_time).total_seconds() / 3600 for t in timestamps]
            
            n = len(x_values)
            if n < 2:
                return 0.0, 0.0, 0.0
            
            # Calculate means
            x_mean = statistics.mean(x_values)
            y_mean = statistics.mean(values)
            
            # Calculate slope and intercept
            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
            denominator = sum((x - x_mean) ** 2 for x in x_values)
            
            if denominator == 0:
                return 0.0, y_mean, 0.0
            
            slope = numerator / denominator
            intercept = y_mean - slope * x_mean
            
            # Calculate R-squared
            y_pred = [slope * x + intercept for x in x_values]
            ss_res = sum((y - y_pred) ** 2 for y, y_pred in zip(values, y_pred))
            ss_tot = sum((y - y_mean) ** 2 for y in values)
            
            r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
            
            return slope, intercept, r_squared
            
        except Exception as e:
            logger.error(f"Error in linear regression: {str(e)}")
            return 0.0, 0.0, 0.0
    
    def _determine_trend_direction(self, slope: float) -> str:
        """Determine trend direction based on slope"""
        if abs(slope) < self.trend_config.trend_threshold:
            return "stable"
        elif slope > 0:
            return "increasing"
        else:
            return "decreasing"
    
    def _detect_seasonality(
        self,
        timestamps: List[datetime],
        values: List[float]
    ) -> Optional[Dict[str, Any]]:
        """Detect seasonal patterns in time series data"""
        try:
            if len(values) < 48:  # Need at least 48 data points for seasonality
                return None
            
            # Simple seasonality detection using autocorrelation
            # This is a simplified approach - production systems might use more sophisticated methods
            
            # Calculate hourly averages to detect daily patterns
            hourly_averages = {}
            for timestamp, value in zip(timestamps, values):
                hour = timestamp.hour
                if hour not in hourly_averages:
                    hourly_averages[hour] = []
                hourly_averages[hour].append(value)
            
            # Calculate variance in hourly patterns
            hourly_means = [statistics.mean(hourly_averages.get(h, [0])) for h in range(24)]
            hourly_variance = statistics.variance(hourly_means) if len(hourly_means) > 1 else 0
            
            # Determine if there's significant hourly variation
            overall_mean = statistics.mean(values)
            seasonal_strength = min(hourly_variance / (overall_mean ** 2) if overall_mean > 0 else 0, 1.0)
            
            if seasonal_strength > 0.1:  # Threshold for seasonality
                return {
                    'has_seasonality': True,
                    'seasonal_period': 24,  # hours
                    'seasonal_strength': seasonal_strength,
                    'hourly_pattern': hourly_means
                }
            
            return {
                'has_seasonality': False,
                'seasonal_strength': seasonal_strength
            }
            
        except Exception as e:
            logger.error(f"Error detecting seasonality: {str(e)}")
            return None
    
    def _detect_outliers(
        self,
        values: List[float],
        mean_value: float,
        std_dev: float
    ) -> List[Dict[str, Any]]:
        """Detect outliers using statistical methods"""
        try:
            outliers = []
            threshold = 2.5  # Standard deviations for outlier detection
            
            for i, value in enumerate(values):
                z_score = abs((value - mean_value) / std_dev) if std_dev > 0 else 0
                if z_score > threshold:
                    outliers.append({
                        'index': i,
                        'value': value,
                        'z_score': z_score,
                        'deviation_percentage': ((value - mean_value) / mean_value * 100) if mean_value > 0 else 0
                    })
            
            return outliers
            
        except Exception as e:
            logger.error(f"Error detecting outliers: {str(e)}")
            return []
    
    def _calculate_overall_trend_score(self, trend_results: Dict[str, Any]) -> float:
        """Calculate overall trend score across all metrics"""
        try:
            if not trend_results:
                return 0.0
            
            # Weight different aspects of trends
            trend_scores = []
            for metric_result in trend_results.values():
                # Base score from R-squared
                base_score = metric_result.get('trend_r_squared', 0)
                
                # Bonus for strong trends
                trend_strength = metric_result.get('trend_strength', 0)
                trend_bonus = trend_strength * 0.2
                
                # Penalty for negative trends
                direction_penalty = 0
                if metric_result.get('trend_direction') == 'decreasing':
                    direction_penalty = 0.1
                
                final_score = min(base_score + trend_bonus - direction_penalty, 1.0)
                trend_scores.append(final_score)
            
            return statistics.mean(trend_scores) if trend_scores else 0.0
            
        except Exception as e:
            logger.error(f"Error calculating overall trend score: {str(e)}")
            return 0.0
    
    async def _generate_trend_insights(
        self,
        metric_name: str,
        trend_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate insights from trend analysis"""
        insights = []
        
        try:
            trend_direction = trend_analysis.get('trend_direction', 'stable')
            change_percentage = trend_analysis.get('change_percentage', 0)
            trend_strength = trend_analysis.get('trend_strength', 0)
            
            # Trend direction insights
            if trend_direction == 'increasing' and change_percentage > 10:
                insights.append({
                    'type': 'trend_warning',
                    'title': f'{metric_name.replace("_", " ").title()} Increasing',
                    'description': f'{metric_name} shows a strong increasing trend of {change_percentage:.1f}%',
                    'severity': 'medium' if change_percentage < 25 else 'high',
                    'recommendation': 'Monitor closely and consider capacity planning'
                })
            elif trend_direction == 'decreasing' and change_percentage < -10:
                insights.append({
                    'type': 'trend_positive',
                    'title': f'{metric_name.replace("_", " ").title()} Improving',
                    'description': f'{metric_name} shows improvement with {abs(change_percentage):.1f}% decrease',
                    'severity': 'info',
                    'recommendation': 'Performance optimization efforts may be working'
                })
            
            # Seasonal pattern insights
            seasonal_info = trend_analysis.get('seasonal_info')
            if seasonal_info and seasonal_info.get('has_seasonality'):
                insights.append({
                    'type': 'seasonal_pattern',
                    'title': 'Seasonal Pattern Detected',
                    'description': f'{metric_name} shows daily seasonal patterns',
                    'severity': 'info',
                    'recommendation': 'Consider seasonal variations in capacity planning'
                })
            
            # Outlier insights
            outliers = trend_analysis.get('outliers', [])
            if outliers:
                insights.append({
                    'type': 'outlier_detection',
                    'title': f'{len(outliers)} Outliers Detected',
                    'description': f'Found {len(outliers)} unusual values in {metric_name}',
                    'severity': 'low',
                    'recommendation': 'Investigate outlier causes and consider alert thresholds'
                })
            
            return insights
            
        except Exception as e:
            logger.error(f"Error generating trend insights: {str(e)}")
            return []
    
    async def _generate_trend_recommendations(
        self,
        metric_name: str,
        trend_analysis: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Generate recommendations from trend analysis"""
        recommendations = []
        
        try:
            trend_direction = trend_analysis.get('trend_direction', 'stable')
            change_percentage = trend_analysis.get('change_percentage', 0)
            trend_strength = trend_analysis.get('trend_strength', 0)
            
            # Performance optimization recommendations
            if trend_direction == 'increasing' and change_percentage > 20:
                recommendations.append({
                    'type': 'capacity_planning',
                    'priority': 'high',
                    'title': 'Plan Capacity Upgrade',
                    'description': f'{metric_name} growth rate suggests capacity upgrade needed within 3-6 months',
                    'estimated_effort': 'medium',
                    'estimated_benefit': 'high'
                })
            
            # Monitoring recommendations
            if trend_strength > 0.7:
                recommendations.append({
                    'type': 'monitoring',
                    'priority': 'medium',
                    'title': 'Enhanced Monitoring',
                    'description': f'Strong trend in {metric_name} warrants enhanced monitoring and alerting',
                    'estimated_effort': 'low',
                    'estimated_benefit': 'medium'
                })
            
            # Alert threshold recommendations
            if trend_analysis.get('outliers'):
                recommendations.append({
                    'type': 'alerting',
                    'priority': 'medium',
                    'title': 'Adjust Alert Thresholds',
                    'description': f'Consider adjusting alert thresholds for {metric_name} based on trend analysis',
                    'estimated_effort': 'low',
                    'estimated_benefit': 'medium'
                })
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating trend recommendations: {str(e)}")
            return []
    
    async def _detect_anomalies(
        self,
        device_id: int,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        metric_names: Optional[List[str]] = None
    ) -> AnalyticsResult:
        """Detect anomalies in device metrics"""
        try:
            # Determine time range
            if time_range is None:
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=self.anomaly_config.baseline_window_hours)
            else:
                start_time, end_time = time_range
            
            # Get metrics data
            if metric_names is None:
                metric_names = ['cpu_utilization', 'memory_utilization', 'network_throughput']
            
            detected_anomalies = []
            
            for metric_name in metric_names:
                # Query metrics data
                metrics_data = await self.metrics_query.get_metrics(
                    device_id=device_id,
                    metric_name=metric_name,
                    start_time=start_time,
                    end_time=end_time,
                    limit=1000
                )
                
                if not metrics_data.success or not metrics_data.metrics:
                    continue
                
                # Detect anomalies for this metric
                metric_anomalies = await self._detect_metric_anomalies(
                    device_id, metric_name, metrics_data.metrics
                )
                
                detected_anomalies.extend(metric_anomalies)
            
            if not detected_anomalies:
                return AnalyticsResult(
                    success=True,
                    analysis_type=AnalysisType.ANOMALY_DETECTION,
                    data={
                        'anomalies': [],
                        'anomaly_count': 0,
                        'baseline_window': self.anomaly_config.baseline_window_hours
                    },
                    metadata={
                        'device_id': device_id,
                        'metrics_analyzed': metric_names,
                        'anomaly_detection_method': 'statistical'
                    }
                )
            
            # Correlate related anomalies
            correlated_anomalies = await self._correlate_anomalies(detected_anomalies)
            
            # Store anomaly detections
            for anomaly in detected_anomalies:
                await self._store_anomaly_detection(anomaly)
            
            return AnalyticsResult(
                success=True,
                analysis_type=AnalysisType.ANOMALY_DETECTION,
                data={
                    'anomalies': correlated_anomalies,
                    'anomaly_count': len(detected_anomalies),
                    'correlated_groups': len(set(a.get('correlation_group') for a in correlated_anomalies if a.get('correlation_group'))),
                    'baseline_window': self.anomaly_config.baseline_window_hours
                },
                metadata={
                    'device_id': device_id,
                    'metrics_analyzed': metric_names,
                    'anomaly_detection_method': 'statistical'
                }
            )
            
        except Exception as e:
            logger.error(f"Error detecting anomalies for device {device_id}: {str(e)}")
            return AnalyticsResult(
                success=False,
                error=str(e),
                fallback_data={"anomaly_detection": "unavailable"}
            )
    
    async def _detect_metric_anomalies(
        self,
        device_id: int,
        metric_name: str,
        metrics: List[Metric]
    ) -> List[Dict[str, Any]]:
        """Detect anomalies for a specific metric"""
        try:
            if len(metrics) < 10:  # Need minimum data points
                return []
            
            # Calculate baseline statistics
            values = [m.value for m in metrics]
            baseline_mean = statistics.mean(values)
            baseline_std = statistics.stdev(values) if len(values) > 1 else 0
            
            if baseline_std == 0:
                return []
            
            anomalies = []
            
            for metric in metrics:
                # Calculate z-score
                z_score = abs((metric.value - baseline_mean) / baseline_std)
                
                # Check if this is an anomaly
                if z_score > self.anomaly_config.anomaly_threshold_std:
                    # Determine anomaly type and severity
                    anomaly_type = self._classify_anomaly_type(metric.value, baseline_mean, z_score)
                    severity = self._classify_anomaly_severity(z_score)
                    
                    anomaly = {
                        'device_id': device_id,
                        'metric_name': metric_name,
                        'anomaly_type': anomaly_type,
                        'severity': severity,
                        'confidence_score': min(z_score / 5.0, 1.0),  # Normalize to 0-1
                        'detection_method': 'statistical',
                        'detection_algorithm': 'z_score_threshold',
                        'detection_threshold': self.anomaly_config.anomaly_threshold_std,
                        'baseline_value': baseline_mean,
                        'anomalous_value': metric.value,
                        'deviation_percentage': ((metric.value - baseline_mean) / baseline_mean * 100) if baseline_mean > 0 else 0,
                        'deviation_std_devs': z_score,
                        'detected_at': metric.timestamp,
                        'anomaly_start_time': metric.timestamp,
                        'status': 'active'
                    }
                    
                    anomalies.append(anomaly)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error detecting anomalies for metric {metric_name}: {str(e)}")
            return []
    
    def _classify_anomaly_type(
        self,
        value: float,
        baseline: float,
        z_score: float
    ) -> str:
        """Classify the type of anomaly"""
        if value > baseline:
            if z_score > 4.0:
                return "extreme_spike"
            elif z_score > 3.0:
                return "spike"
            else:
                return "elevated"
        else:
            if z_score > 4.0:
                return "extreme_drop"
            elif z_score > 3.0:
                return "drop"
            else:
                return "depressed"
    
    def _classify_anomaly_severity(self, z_score: float) -> str:
        """Classify anomaly severity based on z-score"""
        if z_score > 4.0:
            return AnomalySeverity.CRITICAL
        elif z_score > 3.5:
            return AnomalySeverity.HIGH
        elif z_score > 3.0:
            return AnomalySeverity.MEDIUM
        else:
            return AnomalySeverity.LOW
    
    async def _correlate_anomalies(
        self,
        anomalies: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Correlate related anomalies"""
        try:
            if not anomalies:
                return []
            
            # Group anomalies by time proximity
            correlation_window = timedelta(minutes=self.anomaly_config.correlation_window_minutes)
            correlated_groups = []
            processed_anomalies = set()
            
            for i, anomaly in enumerate(anomalies):
                if i in processed_anomalies:
                    continue
                
                # Start a new correlation group
                group = [anomaly]
                processed_anomalies.add(i)
                group_id = len(correlated_groups)
                
                # Find related anomalies
                for j, other_anomaly in enumerate(anomalies):
                    if j in processed_anomalies:
                        continue
                    
                    time_diff = abs(
                        anomaly['detected_at'] - other_anomaly['detected_at']
                    )
                    
                    if time_diff <= correlation_window:
                        # Check if they're related (same device, similar severity, etc.)
                        if self._are_anomalies_related(anomaly, other_anomaly):
                            other_anomaly['correlation_group'] = group_id
                            group.append(other_anomaly)
                            processed_anomalies.add(j)
                
                # Add correlation group info to all anomalies in the group
                for group_anomaly in group:
                    group_anomaly['correlation_group'] = group_id
                    group_anomaly['related_anomalies'] = [a['id'] for a in group if a != group_anomaly]
                
                correlated_groups.append(group)
            
            return anomalies
            
        except Exception as e:
            logger.error(f"Error correlating anomalies: {str(e)}")
            return anomalies
    
    def _are_anomalies_related(
        self,
        anomaly1: Dict[str, Any],
        anomaly2: Dict[str, Any]
    ) -> bool:
        """Determine if two anomalies are related"""
        try:
            # Same device
            if anomaly1['device_id'] != anomaly2['device_id']:
                return False
            
            # Similar severity
            severity1 = anomaly1['severity']
            severity2 = anomaly2['severity']
            
            severity_levels = {
                AnomalySeverity.CRITICAL: 4,
                AnomalySeverity.HIGH: 3,
                AnomalySeverity.MEDIUM: 2,
                AnomalySeverity.LOW: 1,
                AnomalySeverity.INFO: 0
            }
            
            if abs(severity_levels.get(severity1, 0) - severity_levels.get(severity2, 0)) > 1:
                return False
            
            # Similar metric types (e.g., both CPU-related)
            metric1 = anomaly1['metric_name']
            metric2 = anomaly2['metric_name']
            
            # Simple metric grouping
            cpu_metrics = ['cpu_utilization', 'cpu_load', 'cpu_temperature']
            memory_metrics = ['memory_utilization', 'memory_available', 'swap_usage']
            network_metrics = ['network_throughput', 'network_errors', 'network_latency']
            
            if any(m in cpu_metrics for m in [metric1, metric2]) and any(m in cpu_metrics for m in [metric1, metric2]):
                return True
            elif any(m in memory_metrics for m in [metric1, metric2]) and any(m in memory_metrics for m in [metric1, metric2]):
                return True
            elif any(m in network_metrics for m in [metric1, metric2]) and any(m in network_metrics for m in [metric1, metric2]):
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error checking anomaly relationship: {str(e)}")
            return False
    
    async def _store_analysis_result(
        self,
        device_id: int,
        analysis_type: AnalysisType,
        result: AnalyticsResult,
        duration_ms: int
    ) -> None:
        """Store analysis result in database"""
        try:
            if analysis_type == AnalysisType.TREND_ANALYSIS:
                await self._store_trend_analysis(device_id, result, duration_ms)
            elif analysis_type == AnalysisType.ANOMALY_DETECTION:
                # Anomalies are stored separately in _store_anomaly_detection
                pass
            
        except Exception as e:
            logger.error(f"Error storing analysis result: {str(e)}")
    
    async def _store_trend_analysis(
        self,
        device_id: int,
        result: AnalyticsResult,
        duration_ms: int
    ) -> None:
        """Store trend analysis results"""
        try:
            data = result.data
            trends = data.get('trends', {})
            
            for metric_name, trend_data in trends.items():
                analysis = PerformanceAnalysis(
                    device_id=device_id,
                    metric_name=metric_name,
                    analysis_type=AnalysisType.TREND_ANALYSIS,
                    time_range_start=data['time_range']['start'],
                    time_range_end=data['time_range']['end'],
                    analysis_window_hours=168,  # 7 days
                    baseline_value=trend_data.get('baseline_value'),
                    baseline_std_dev=trend_data.get('std_dev'),
                    current_value=trend_data.get('current_value'),
                    change_percentage=trend_data.get('change_percentage'),
                    trend_direction=trend_data.get('trend_direction'),
                    trend_strength=trend_data.get('trend_strength'),
                    min_value=trend_data.get('min_value'),
                    max_value=trend_data.get('max_value'),
                    mean_value=trend_data.get('mean_value'),
                    confidence_score=trend_data.get('confidence_score'),
                    data_points_analyzed=trend_data.get('data_points'),
                    analysis_duration_ms=duration_ms,
                    insights=data.get('insights'),
                    recommendations=data.get('recommendations')
                )
                
                self.db_session.add(analysis)
            
            await self.db_session.commit()
            
        except Exception as e:
            logger.error(f"Error storing trend analysis: {str(e)}")
            await self.db_session.rollback()
    
    async def _store_anomaly_detection(self, anomaly: Dict[str, Any]) -> None:
        """Store anomaly detection in database"""
        try:
            detection = AnomalyDetection(
                device_id=anomaly['device_id'],
                metric_name=anomaly['metric_name'],
                anomaly_type=anomaly['anomaly_type'],
                severity=anomaly['severity'],
                confidence_score=anomaly['confidence_score'],
                detection_method=anomaly['detection_method'],
                detection_algorithm=anomaly['detection_algorithm'],
                detection_threshold=anomaly['detection_threshold'],
                baseline_value=anomaly['baseline_value'],
                anomalous_value=anomaly['anomalous_value'],
                deviation_percentage=anomaly['deviation_percentage'],
                deviation_std_devs=anomaly['deviation_std_devs'],
                detected_at=anomaly['detected_at'],
                anomaly_start_time=anomaly['anomaly_start_time'],
                related_anomalies=anomaly.get('related_anomalies', []),
                status=anomaly['status']
            )
            
            self.db_session.add(detection)
            await self.db_session.commit()
            
            # Update the anomaly with the database ID
            anomaly['id'] = detection.id
            
        except Exception as e:
            logger.error(f"Error storing anomaly detection: {str(e)}")
            await self.db_session.rollback()
    
    async def _analyze_capacity(
        self,
        device_id: int,
        resource_types: Optional[List[str]] = None
    ) -> AnalyticsResult:
        """Analyze device capacity and generate planning recommendations"""
        # This is a placeholder for capacity planning analysis
        # Full implementation would include historical trend analysis,
        # forecasting, and upgrade recommendations
        return AnalyticsResult(
            success=True,
            analysis_type=AnalysisType.CAPACITY_PLANNING,
            data={"capacity_analysis": "placeholder"},
            metadata={"device_id": device_id}
        )
    
    async def _optimize_performance(
        self,
        device_id: int,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> OptimizationResult:
        """Generate performance optimization recommendations"""
        # This is a placeholder for performance optimization
        # Full implementation would analyze bottlenecks and suggest improvements
        return OptimizationResult(
            success=True,
            optimizations=[],
            estimated_improvement=0.0
        )
    
    async def _generate_forecast(
        self,
        device_id: int,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> AnalyticsResult:
        """Generate performance forecasts"""
        # This is a placeholder for forecasting
        # Full implementation would use time series forecasting models
        return AnalyticsResult(
            success=True,
            analysis_type=AnalysisType.FORECASTING,
            data={"forecast": "placeholder"},
            metadata={"device_id": device_id}
        )
    
    async def _compare_performance(
        self,
        device_id: int,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> AnalyticsResult:
        """Compare performance across time periods or devices"""
        # This is a placeholder for comparative analysis
        # Full implementation would compare performance across different dimensions
        return AnalyticsResult(
            success=True,
            analysis_type=AnalysisType.COMPARATIVE_ANALYSIS,
            data={"comparison": "placeholder"},
            metadata={"device_id": device_id}
        )
