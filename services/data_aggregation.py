"""
Data Aggregation & Insights Service for CHM Advanced Analytics & Reporting System

This service provides comprehensive data aggregation capabilities including:
- Multi-dimensional data aggregation
- Time-window based analysis
- Statistical aggregation functions
- Data quality assessment
- Insight generation
- Pattern recognition
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import statistics
import math
from collections import defaultdict, Counter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc, text, case
from sqlalchemy.orm import selectinload

from ..models.analytics import (
    AnalyticsInsight, PerformanceAnalysis, AnomalyDetection,
    CapacityPlanning, TrendForecast
)
from ..models.metric import Metric, MetricType, MetricCategory, MetricQuality
from ..models.device import Device, DeviceStatus
from ..models.alert import Alert, AlertSeverity, AlertStatus
from ..models.result_objects import CollectionResult, OptimizationResult
from ..services.metrics_query import MetricsQueryService

logger = logging.getLogger(__name__)


@dataclass
class AggregationConfig:
    """Configuration for data aggregation"""
    time_window: str = "1h"  # 1m, 5m, 15m, 1h, 6h, 1d, 1w, 1M
    aggregation_functions: List[str] = None  # mean, min, max, sum, count, std, median, p95, p99
    quality_threshold: float = 0.8  # Minimum quality score for inclusion
    max_data_points: int = 10000  # Maximum data points to process
    enable_outlier_detection: bool = True
    enable_trend_analysis: bool = True
    enable_correlation_analysis: bool = True
    
    def __post_init__(self):
        if self.aggregation_functions is None:
            self.aggregation_functions = ['mean', 'min', 'max', 'count', 'std']


@dataclass
class AggregationResult:
    """Result of data aggregation operation"""
    success: bool
    aggregated_data: Dict[str, Any]
    metadata: Dict[str, Any]
    quality_score: float
    insights: List[Dict[str, Any]]
    error: Optional[str] = None


@dataclass
class InsightConfig:
    """Configuration for insight generation"""
    min_confidence: float = 0.7  # Minimum confidence for insights
    max_insights: int = 50  # Maximum insights to generate
    insight_types: List[str] = None  # performance, anomaly, capacity, trend, correlation
    enable_ml_insights: bool = False  # Enable machine learning insights
    enable_business_insights: bool = True  # Enable business-focused insights
    
    def __post_init__(self):
        if self.insight_types is None:
            self.insight_types = ['performance', 'anomaly', 'capacity', 'trend', 'correlation']


class DataAggregationService:
    """Service for comprehensive data aggregation and insights generation"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.metrics_query = MetricsQueryService(db_session)
        self.agg_config = AggregationConfig()
        self.insight_config = InsightConfig()
    
    async def aggregate_metrics(
        self,
        device_ids: Optional[List[int]] = None,
        metric_names: Optional[List[str]] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None,
        aggregation_config: Optional[AggregationConfig] = None
    ) -> AggregationResult:
        """Aggregate metrics data with comprehensive analysis"""
        try:
            if aggregation_config is None:
                aggregation_config = self.agg_config
            
            # Determine time range
            if time_range is None:
                end_time = datetime.now()
                start_time = end_time - timedelta(hours=24)  # Default to 24 hours
            else:
                start_time, end_time = time_range
            
            # Get metrics data
            metrics_data = await self._get_metrics_for_aggregation(
                device_ids, metric_names, start_time, end_time
            )
            
            if not metrics_data.success or not metrics_data.metrics:
                return AggregationResult(
                    success=False,
                    aggregated_data={},
                    metadata={'error': 'No metrics data available'},
                    quality_score=0.0,
                    insights=[],
                    error="No metrics data available for aggregation"
                )
            
            # Perform multi-dimensional aggregation
            aggregated_data = await self._perform_multi_dimensional_aggregation(
                metrics_data.metrics, aggregation_config
            )
            
            # Calculate quality score
            quality_score = await self._calculate_aggregation_quality(
                metrics_data.metrics, aggregated_data
            )
            
            # Generate insights
            insights = await self._generate_aggregation_insights(
                aggregated_data, quality_score
            )
            
            # Prepare metadata
            metadata = {
                'device_count': len(set(m.device_id for m in metrics_data.metrics)),
                'metric_count': len(set(m.metric_name for m in metrics_data.metrics)),
                'data_points': len(metrics_data.metrics),
                'time_range': {'start': start_time, 'end': end_time},
                'aggregation_window': aggregation_config.time_window,
                'aggregation_functions': aggregation_config.aggregation_functions
            }
            
            return AggregationResult(
                success=True,
                aggregated_data=aggregated_data,
                metadata=metadata,
                quality_score=quality_score,
                insights=insights
            )
            
        except Exception as e:
            logger.error(f"Error aggregating metrics: {str(e)}")
            return AggregationResult(
                success=False,
                aggregated_data={},
                metadata={},
                quality_score=0.0,
                insights=[],
                error=str(e)
            )
    
    async def _get_metrics_for_aggregation(
        self,
        device_ids: Optional[List[int]],
        metric_names: Optional[List[str]],
        start_time: datetime,
        end_time: datetime
    ) -> CollectionResult:
        """Get metrics data for aggregation"""
        try:
            # Build query parameters
            query_params = {
                'start_time': start_time,
                'end_time': end_time,
                'limit': self.agg_config.max_data_points
            }
            
            if device_ids:
                query_params['device_ids'] = device_ids
            
            if metric_names:
                query_params['metric_names'] = metric_names
            
            # Get metrics data
            return await self.metrics_query.get_metrics(**query_params)
            
        except Exception as e:
            logger.error(f"Error getting metrics for aggregation: {str(e)}")
            return CollectionResult(
                success=False,
                error=str(e),
                metrics=[],
                total_count=0
            )
    
    async def _perform_multi_dimensional_aggregation(
        self,
        metrics: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Perform multi-dimensional aggregation of metrics data"""
        try:
            aggregated_data = {
                'by_device': {},
                'by_metric': {},
                'by_time': {},
                'by_category': {},
                'cross_analysis': {},
                'statistical_summary': {}
            }
            
            # Group metrics by device
            device_groups = defaultdict(list)
            for metric in metrics:
                device_groups[metric.device_id].append(metric)
            
            # Aggregate by device
            for device_id, device_metrics in device_groups.items():
                aggregated_data['by_device'][device_id] = await self._aggregate_device_metrics(
                    device_metrics, config
                )
            
            # Group metrics by metric name
            metric_groups = defaultdict(list)
            for metric in metrics:
                metric_groups[metric.metric_name].append(metric)
            
            # Aggregate by metric
            for metric_name, metric_data in metric_groups.items():
                aggregated_data['by_metric'][metric_name] = await self._aggregate_metric_data(
                    metric_data, config
                )
            
            # Group metrics by time window
            time_groups = await self._group_by_time_window(metrics, config.time_window)
            for time_key, time_metrics in time_groups.items():
                aggregated_data['by_time'][time_key] = await self._aggregate_time_metrics(
                    time_metrics, config
                )
            
            # Group metrics by category
            category_groups = defaultdict(list)
            for metric in metrics:
                category = metric.category or 'unknown'
                category_groups[category].append(metric)
            
            # Aggregate by category
            for category, category_metrics in category_groups.items():
                aggregated_data['by_category'][category] = await self._aggregate_category_metrics(
                    category_metrics, config
                )
            
            # Cross-dimensional analysis
            aggregated_data['cross_analysis'] = await self._perform_cross_analysis(
                metrics, config
            )
            
            # Overall statistical summary
            aggregated_data['statistical_summary'] = await self._calculate_overall_statistics(
                metrics, config
            )
            
            return aggregated_data
            
        except Exception as e:
            logger.error(f"Error performing multi-dimensional aggregation: {str(e)}")
            return {}
    
    async def _aggregate_device_metrics(
        self,
        device_metrics: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Aggregate metrics for a specific device"""
        try:
            if not device_metrics:
                return {}
            
            # Group by metric name
            metric_groups = defaultdict(list)
            for metric in device_metrics:
                metric_groups[metric.metric_name].append(metric)
            
            device_aggregation = {}
            
            for metric_name, metric_data in metric_groups.items():
                device_aggregation[metric_name] = await self._calculate_aggregation_functions(
                    metric_data, config.aggregation_functions
                )
            
            # Calculate device-level statistics
            all_values = [m.value for m in device_metrics]
            device_aggregation['overall'] = {
                'total_metrics': len(device_metrics),
                'unique_metrics': len(metric_groups),
                'value_range': {'min': min(all_values), 'max': max(all_values)},
                'quality_score': statistics.mean([m.quality_score for m in device_metrics if m.quality_score])
            }
            
            return device_aggregation
            
        except Exception as e:
            logger.error(f"Error aggregating device metrics: {str(e)}")
            return {}
    
    async def _aggregate_metric_data(
        self,
        metric_data: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Aggregate data for a specific metric across devices"""
        try:
            if not metric_data:
                return {}
            
            # Group by device
            device_groups = defaultdict(list)
            for metric in metric_data:
                device_groups[metric.device_id].append(metric)
            
            metric_aggregation = {}
            
            # Aggregate by device
            for device_id, device_metrics in device_groups.items():
                metric_aggregation[f"device_{device_id}"] = await self._calculate_aggregation_functions(
                    device_metrics, config.aggregation_functions
                )
            
            # Calculate metric-level statistics
            all_values = [m.value for m in metric_data]
            metric_aggregation['overall'] = {
                'total_measurements': len(metric_data),
                'device_count': len(device_groups),
                'value_range': {'min': min(all_values), 'max': max(all_values)},
                'quality_score': statistics.mean([m.quality_score for m in metric_data if m.quality_score])
            }
            
            # Trend analysis if enabled
            if config.enable_trend_analysis:
                metric_aggregation['trend'] = await self._analyze_metric_trend(metric_data)
            
            return metric_aggregation
            
        except Exception as e:
            logger.error(f"Error aggregating metric data: {str(e)}")
            return {}
    
    async def _aggregate_time_metrics(
        self,
        time_metrics: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Aggregate metrics for a specific time window"""
        try:
            if not time_metrics:
                return {}
            
            # Group by metric name
            metric_groups = defaultdict(list)
            for metric in time_metrics:
                metric_groups[metric.metric_name].append(metric)
            
            time_aggregation = {}
            
            for metric_name, metric_data in metric_groups.items():
                time_aggregation[metric_name] = await self._calculate_aggregation_functions(
                    metric_data, config.aggregation_functions
                )
            
            # Calculate time-window statistics
            all_values = [m.value for m in time_metrics]
            time_aggregation['overall'] = {
                'total_measurements': len(time_metrics),
                'unique_metrics': len(metric_groups),
                'value_range': {'min': min(all_values), 'max': max(all_values)},
                'quality_score': statistics.mean([m.quality_score for m in time_metrics if m.quality_score])
            }
            
            return time_aggregation
            
        except Exception as e:
            logger.error(f"Error aggregating time metrics: {str(e)}")
            return {}
    
    async def _aggregate_category_metrics(
        self,
        category_metrics: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Aggregate metrics for a specific category"""
        try:
            if not category_metrics:
                return {}
            
            # Group by metric name
            metric_groups = defaultdict(list)
            for metric in category_metrics:
                metric_groups[metric.metric_name].append(metric)
            
            category_aggregation = {}
            
            for metric_name, metric_data in metric_groups.items():
                category_aggregation[metric_name] = await self._calculate_aggregation_functions(
                    metric_data, config.aggregation_functions
                )
            
            # Calculate category-level statistics
            all_values = [m.value for m in category_metrics]
            category_aggregation['overall'] = {
                'total_measurements': len(category_metrics),
                'unique_metrics': len(metric_groups),
                'value_range': {'min': min(all_values), 'max': max(all_values)},
                'quality_score': statistics.mean([m.quality_score for m in category_metrics if m.quality_score])
            }
            
            return category_aggregation
            
        except Exception as e:
            logger.error(f"Error aggregating category metrics: {str(e)}")
            return {}
    
    async def _calculate_aggregation_functions(
        self,
        metrics: List[Metric],
        functions: List[str]
    ) -> Dict[str, float]:
        """Calculate aggregation functions for a set of metrics"""
        try:
            if not metrics:
                return {}
            
            values = [m.value for m in metrics]
            results = {}
            
            for func_name in functions:
                try:
                    if func_name == 'mean':
                        results['mean'] = statistics.mean(values)
                    elif func_name == 'min':
                        results['min'] = min(values)
                    elif func_name == 'max':
                        results['max'] = max(values)
                    elif func_name == 'sum':
                        results['sum'] = sum(values)
                    elif func_name == 'count':
                        results['count'] = len(values)
                    elif func_name == 'std':
                        results['std'] = statistics.stdev(values) if len(values) > 1 else 0
                    elif func_name == 'median':
                        results['median'] = statistics.median(values)
                    elif func_name == 'p95':
                        results['p95'] = self._percentile(values, 95)
                    elif func_name == 'p99':
                        results['p99'] = self._percentile(values, 99)
                except Exception as e:
                    logger.warning(f"Error calculating {func_name}: {str(e)}")
                    results[func_name] = None
            
            return results
            
        except Exception as e:
            logger.error(f"Error calculating aggregation functions: {str(e)}")
            return {}
    
    def _percentile(self, values: List[float], percentile: int) -> float:
        """Calculate percentile of values"""
        try:
            if not values:
                return 0.0
            
            sorted_values = sorted(values)
            index = (percentile / 100) * (len(sorted_values) - 1)
            
            if index.is_integer():
                return sorted_values[int(index)]
            else:
                lower = sorted_values[int(index)]
                upper = sorted_values[int(index) + 1]
                return lower + (upper - lower) * (index - int(index))
                
        except Exception as e:
            logger.error(f"Error calculating percentile: {str(e)}")
            return 0.0
    
    async def _group_by_time_window(
        self,
        metrics: List[Metric],
        time_window: str
    ) -> Dict[str, List[Metric]]:
        """Group metrics by time window"""
        try:
            time_groups = defaultdict(list)
            
            # Parse time window
            if time_window.endswith('m'):
                minutes = int(time_window[:-1])
                window_seconds = minutes * 60
            elif time_window.endswith('h'):
                hours = int(time_window[:-1])
                window_seconds = hours * 3600
            elif time_window.endswith('d'):
                days = int(time_window[:-1])
                window_seconds = days * 86400
            elif time_window.endswith('w'):
                weeks = int(time_window[:-1])
                window_seconds = weeks * 604800
            elif time_window.endswith('M'):
                months = int(time_window[:-1])
                window_seconds = months * 2592000  # Approximate
            else:
                window_seconds = 3600  # Default to 1 hour
            
            # Group metrics by time window
            for metric in metrics:
                timestamp = metric.timestamp
                window_start = timestamp.replace(
                    second=timestamp.second - (timestamp.second % (window_seconds // 60)),
                    microsecond=0
                )
                time_key = window_start.isoformat()
                time_groups[time_key].append(metric)
            
            return dict(time_groups)
            
        except Exception as e:
            logger.error(f"Error grouping by time window: {str(e)}")
            return {}
    
    async def _analyze_metric_trend(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze trend for a set of metrics"""
        try:
            if len(metrics) < 2:
                return {'trend': 'insufficient_data'}
            
            # Sort by timestamp
            sorted_metrics = sorted(metrics, key=lambda x: x.timestamp)
            values = [m.value for m in sorted_metrics]
            
            # Calculate trend using linear regression
            n = len(values)
            x_values = list(range(n))
            
            # Calculate means
            x_mean = statistics.mean(x_values)
            y_mean = statistics.mean(values)
            
            # Calculate slope
            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(x_values, values))
            denominator = sum((x - x_mean) ** 2 for x in x_values)
            
            if denominator == 0:
                slope = 0
            else:
                slope = numerator / denominator
            
            # Determine trend direction
            if abs(slope) < 0.01:
                trend = 'stable'
            elif slope > 0:
                trend = 'increasing'
            else:
                trend = 'decreasing'
            
            # Calculate change percentage
            if values[0] != 0:
                change_percentage = ((values[-1] - values[0]) / values[0]) * 100
            else:
                change_percentage = 0
            
            return {
                'trend': trend,
                'slope': slope,
                'change_percentage': change_percentage,
                'data_points': n
            }
            
        except Exception as e:
            logger.error(f"Error analyzing metric trend: {str(e)}")
            return {'trend': 'error'}
    
    async def _perform_cross_analysis(
        self,
        metrics: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Perform cross-dimensional analysis"""
        try:
            cross_analysis = {}
            
            if config.enable_correlation_analysis:
                cross_analysis['correlations'] = await self._analyze_metric_correlations(metrics)
            
            if config.enable_outlier_detection:
                cross_analysis['outliers'] = await self._detect_cross_metric_outliers(metrics)
            
            # Performance patterns
            cross_analysis['performance_patterns'] = await self._analyze_performance_patterns(metrics)
            
            return cross_analysis
            
        except Exception as e:
            logger.error(f"Error performing cross analysis: {str(e)}")
            return {}
    
    async def _analyze_metric_correlations(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze correlations between different metrics"""
        try:
            # Group metrics by device and time
            device_time_groups = defaultdict(lambda: defaultdict(list))
            for metric in metrics:
                device_time_groups[metric.device_id][metric.timestamp].append(metric)
            
            correlations = {}
            
            # Find metrics that have data at the same timestamps
            for device_id, time_groups in device_time_groups.items():
                device_correlations = {}
                
                # Get all unique timestamps for this device
                all_timestamps = set(time_groups.keys())
                
                # Find metrics with sufficient overlap
                metric_coverage = defaultdict(int)
                for timestamp, timestamp_metrics in time_groups.items():
                    for metric in timestamp_metrics:
                        metric_coverage[metric.metric_name] += 1
                
                # Only analyze metrics with sufficient data
                sufficient_metrics = [
                    name for name, count in metric_coverage.items()
                    if count >= len(all_timestamps) * 0.5  # At least 50% coverage
                ]
                
                if len(sufficient_metrics) >= 2:
                    # Calculate correlations between pairs of metrics
                    for i, metric1 in enumerate(sufficient_metrics):
                        for metric2 in sufficient_metrics[i+1:]:
                            correlation = await self._calculate_metric_correlation(
                                device_id, metric1, metric2, time_groups
                            )
                            if correlation is not None:
                                key = f"{metric1}_vs_{metric2}"
                                device_correlations[key] = correlation
                
                if device_correlations:
                    correlations[f"device_{device_id}"] = device_correlations
            
            return correlations
            
        except Exception as e:
            logger.error(f"Error analyzing metric correlations: {str(e)}")
            return {}
    
    async def _calculate_metric_correlation(
        self,
        device_id: int,
        metric1: str,
        metric2: str,
        time_groups: Dict[datetime, List[Metric]]
    ) -> Optional[float]:
        """Calculate correlation between two metrics"""
        try:
            # Extract values for both metrics at common timestamps
            metric1_values = []
            metric2_values = []
            
            for timestamp, timestamp_metrics in time_groups.items():
                metric1_data = [m for m in timestamp_metrics if m.metric_name == metric1]
                metric2_data = [m for m in timestamp_metrics if m.metric_name == metric2]
                
                if metric1_data and metric2_data:
                    metric1_values.append(metric1_data[0].value)
                    metric2_values.append(metric2_data[0].value)
            
            if len(metric1_values) < 3:  # Need at least 3 points for correlation
                return None
            
            # Calculate Pearson correlation
            n = len(metric1_values)
            x_mean = statistics.mean(metric1_values)
            y_mean = statistics.mean(metric2_values)
            
            numerator = sum((x - x_mean) * (y - y_mean) for x, y in zip(metric1_values, metric2_values))
            x_std = math.sqrt(sum((x - x_mean) ** 2 for x in metric1_values))
            y_std = math.sqrt(sum((y - y_mean) ** 2 for y in metric2_values))
            
            if x_std == 0 or y_std == 0:
                return None
            
            correlation = numerator / (x_std * y_std)
            return correlation
            
        except Exception as e:
            logger.error(f"Error calculating metric correlation: {str(e)}")
            return None
    
    async def _detect_cross_metric_outliers(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Detect outliers across multiple metrics"""
        try:
            outliers = {}
            
            # Group by device and metric
            device_metric_groups = defaultdict(lambda: defaultdict(list))
            for metric in metrics:
                device_metric_groups[metric.device_id][metric.metric_name].append(metric)
            
            for device_id, metric_groups in device_metric_groups.items():
                device_outliers = {}
                
                for metric_name, metric_data in metric_groups.items():
                    if len(metric_data) < 10:  # Need sufficient data
                        continue
                    
                    values = [m.value for m in metric_data]
                    mean_value = statistics.mean(values)
                    std_value = statistics.stdev(values) if len(values) > 1 else 0
                    
                    if std_value == 0:
                        continue
                    
                    # Detect outliers (beyond 3 standard deviations)
                    metric_outliers = []
                    for metric in metric_data:
                        z_score = abs((metric.value - mean_value) / std_value)
                        if z_score > 3:
                            metric_outliers.append({
                                'timestamp': metric.timestamp.isoformat(),
                                'value': metric.value,
                                'z_score': z_score,
                                'deviation': (metric.value - mean_value) / mean_value * 100 if mean_value != 0 else 0
                            })
                    
                    if metric_outliers:
                        device_outliers[metric_name] = metric_outliers
                
                if device_outliers:
                    outliers[f"device_{device_id}"] = device_outliers
            
            return outliers
            
        except Exception as e:
            logger.error(f"Error detecting cross metric outliers: {str(e)}")
            return {}
    
    async def _analyze_performance_patterns(self, metrics: List[Metric]) -> Dict[str, Any]:
        """Analyze performance patterns across metrics"""
        try:
            patterns = {}
            
            # Group by device
            device_groups = defaultdict(list)
            for metric in metrics:
                device_groups[metric.device_id].append(metric)
            
            for device_id, device_metrics in device_groups.items():
                device_patterns = {}
                
                # Analyze metric categories
                category_groups = defaultdict(list)
                for metric in device_metrics:
                    category = metric.category or 'unknown'
                    category_groups[category].append(metric)
                
                for category, category_metrics in category_groups.items():
                    if len(category_metrics) < 5:  # Need sufficient data
                        continue
                    
                    values = [m.value for m in category_metrics]
                    device_patterns[category] = {
                        'count': len(category_metrics),
                        'mean': statistics.mean(values),
                        'std': statistics.stdev(values) if len(values) > 1 else 0,
                        'range': {'min': min(values), 'max': max(values)}
                    }
                
                if device_patterns:
                    patterns[f"device_{device_id}"] = device_patterns
            
            return patterns
            
        except Exception as e:
            logger.error(f"Error analyzing performance patterns: {str(e)}")
            return {}
    
    async def _calculate_overall_statistics(
        self,
        metrics: List[Metric],
        config: AggregationConfig
    ) -> Dict[str, Any]:
        """Calculate overall statistics for all metrics"""
        try:
            if not metrics:
                return {}
            
            all_values = [m.value for m in metrics]
            quality_scores = [m.quality_score for m in metrics if m.quality_score]
            
            overall_stats = {
                'total_measurements': len(metrics),
                'unique_devices': len(set(m.device_id for m in metrics)),
                'unique_metrics': len(set(m.metric_name for m in metrics)),
                'unique_categories': len(set(m.category for m in metrics if m.category)),
                'value_statistics': {
                    'mean': statistics.mean(all_values),
                    'median': statistics.median(all_values),
                    'min': min(all_values),
                    'max': max(all_values),
                    'std': statistics.stdev(all_values) if len(all_values) > 1 else 0
                },
                'quality_statistics': {
                    'mean': statistics.mean(quality_scores) if quality_scores else 0,
                    'min': min(quality_scores) if quality_scores else 0,
                    'max': max(quality_scores) if quality_scores else 0
                } if quality_scores else {}
            }
            
            return overall_stats
            
        except Exception as e:
            logger.error(f"Error calculating overall statistics: {str(e)}")
            return {}
    
    async def _calculate_aggregation_quality(
        self,
        metrics: List[Metric],
        aggregated_data: Dict[str, Any]
    ) -> float:
        """Calculate quality score for aggregation results"""
        try:
            if not metrics:
                return 0.0
            
            quality_factors = []
            
            # Data completeness
            total_expected = len(metrics)
            total_actual = len(metrics)
            completeness = total_actual / total_expected if total_expected > 0 else 0
            quality_factors.append(completeness)
            
            # Data quality scores
            quality_scores = [m.quality_score for m in metrics if m.quality_score]
            if quality_scores:
                avg_quality = statistics.mean(quality_scores)
                quality_factors.append(avg_quality)
            
            # Aggregation coverage
            if aggregated_data:
                coverage = len(aggregated_data.get('by_device', {})) / max(len(set(m.device_id for m in metrics)), 1)
                quality_factors.append(coverage)
            
            # Calculate overall quality score
            if quality_factors:
                return statistics.mean(quality_factors)
            else:
                return 0.0
                
        except Exception as e:
            logger.error(f"Error calculating aggregation quality: {str(e)}")
            return 0.0
    
    async def _generate_aggregation_insights(
        self,
        aggregated_data: Dict[str, Any],
        quality_score: float
    ) -> List[Dict[str, Any]]:
        """Generate insights from aggregated data"""
        try:
            insights = []
            
            # Quality insights
            if quality_score < 0.5:
                insights.append({
                    'type': 'data_quality',
                    'title': 'Low Data Quality Detected',
                    'description': f'Overall data quality score is {quality_score:.2f}, indicating potential data collection issues',
                    'impact_level': 'medium',
                    'priority_score': 0.7,
                    'recommendation': 'Investigate data collection processes and improve monitoring coverage'
                })
            
            # Performance insights
            if 'by_device' in aggregated_data:
                device_count = len(aggregated_data['by_device'])
                if device_count > 10:
                    insights.append({
                        'type': 'performance',
                        'title': 'Large Device Fleet Detected',
                        'description': f'Monitoring {device_count} devices, consider implementing automated scaling',
                        'impact_level': 'low',
                        'priority_score': 0.4,
                        'recommendation': 'Implement automated scaling and load balancing for large device fleets'
                    })
            
            # Metric insights
            if 'by_metric' in aggregated_data:
                metric_count = len(aggregated_data['by_metric'])
                if metric_count > 50:
                    insights.append({
                        'type': 'monitoring',
                        'title': 'High Metric Complexity',
                        'description': f'Tracking {metric_count} different metrics, consider metric consolidation',
                        'impact_level': 'medium',
                        'priority_score': 0.6,
                        'recommendation': 'Review and consolidate metrics to reduce complexity and improve performance'
                    })
            
            # Time-based insights
            if 'by_time' in aggregated_data:
                time_windows = len(aggregated_data['by_time'])
                if time_windows > 100:
                    insights.append({
                        'type': 'temporal',
                        'title': 'Extended Time Analysis',
                        'description': f'Analyzing {time_windows} time windows, consider data retention optimization',
                        'impact_level': 'low',
                        'priority_score': 0.3,
                        'recommendation': 'Implement data retention policies and archival strategies'
                    })
            
            return insights[:self.insight_config.max_insights]
            
        except Exception as e:
            logger.error(f"Error generating aggregation insights: {str(e)}")
            return []
