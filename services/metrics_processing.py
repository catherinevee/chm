"""
CHM Metrics Processing Service
Data validation, aggregation, transformation, and quality assessment
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import statistics
from collections import defaultdict
import json

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, text
from sqlalchemy.orm import selectinload

from ..models import Metric, Device, CollectionMethod, MetricQuality
from ..models.result_objects import StorageResult, OperationStatus
from ..core.database import Base

logger = logging.getLogger(__name__)

@dataclass
class ProcessingConfig:
    """Configuration for metrics processing"""
    enable_validation: bool = True
    enable_aggregation: bool = True
    enable_transformation: bool = True
    enable_quality_assessment: bool = True
    validation_rules: Dict[str, Any] = None
    aggregation_windows: List[int] = None  # Seconds
    quality_thresholds: Dict[str, float] = None
    outlier_detection_enabled: bool = True
    outlier_threshold_std: float = 3.0

@dataclass
class ValidationResult:
    """Result of metric validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    confidence_score: float
    suggested_corrections: List[str]

@dataclass
class AggregationResult:
    """Result of metric aggregation"""
    original_count: int
    aggregated_count: int
    aggregation_window: int
    metrics: List[Metric]
    statistics: Dict[str, float]

@dataclass
class QualityAssessment:
    """Quality assessment of a metric"""
    overall_score: float
    data_quality: float
    collection_quality: float
    freshness_quality: float
    consistency_quality: float
    recommendations: List[str]

class MetricsProcessingService:
    """Service for processing and enhancing collected metrics"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.config = ProcessingConfig()
        
        # Initialize default validation rules
        if self.config.validation_rules is None:
            self.config.validation_rules = {
                "cpu_usage": {"min": 0.0, "max": 100.0, "unit": "percent"},
                "memory_usage": {"min": 0.0, "max": 100.0, "unit": "percent"},
                "disk_usage": {"min": 0.0, "max": 100.0, "unit": "percent"},
                "interface_in_octets": {"min": 0.0, "max": None, "unit": "bytes"},
                "interface_out_octets": {"min": 0.0, "max": None, "unit": "bytes"},
                "system_uptime": {"min": 0.0, "max": None, "unit": "seconds"},
                "load_average": {"min": 0.0, "max": None, "unit": "load"},
                "process_count": {"min": 0, "max": None, "unit": "count"}
            }
        
        # Initialize default aggregation windows
        if self.config.aggregation_windows is None:
            self.config.aggregation_windows = [300, 900, 3600, 86400]  # 5min, 15min, 1hr, 1day
        
        # Initialize default quality thresholds
        if self.config.quality_thresholds is None:
            self.config.quality_thresholds = {
                "excellent": 0.9,
                "good": 0.7,
                "fair": 0.5,
                "poor": 0.3
            }
    
    async def process_metrics(
        self, 
        metrics: List[Metric], 
        device_id: Optional[int] = None
    ) -> List[Metric]:
        """Process a list of metrics through the full pipeline"""
        if not metrics:
            return []
        
        processed_metrics = []
        
        for metric in metrics:
            try:
                # Validate metric
                if self.config.enable_validation:
                    validation_result = await self._validate_metric(metric)
                    if not validation_result.is_valid:
                        metric.is_valid = False
                        metric.validation_errors = validation_result.errors
                        metric.confidence = validation_result.confidence_score
                        logger.warning(f"Metric {metric.name} validation failed: {validation_result.errors}")
                    else:
                        metric.is_valid = True
                        metric.confidence = validation_result.confidence_score
                
                # Transform metric if needed
                if self.config.enable_transformation:
                    await self._transform_metric(metric)
                
                # Assess quality
                if self.config.enable_quality_assessment:
                    quality_assessment = await self._assess_metric_quality(metric)
                    metric.quality_score = quality_assessment.overall_score
                    metric.update_quality_score(quality_assessment.overall_score)
                
                processed_metrics.append(metric)
                
            except Exception as e:
                logger.error(f"Failed to process metric {metric.name}: {str(e)}")
                metric.is_valid = False
                metric.validation_errors = [str(e)]
                processed_metrics.append(metric)
        
        return processed_metrics
    
    async def _validate_metric(self, metric: Metric) -> ValidationResult:
        """Validate a single metric"""
        errors = []
        warnings = []
        confidence_score = 1.0
        
        # Check if metric name has validation rules
        if metric.name in self.config.validation_rules:
            rules = self.config.validation_rules[metric.name]
            
            # Check value range
            if "min" in rules and rules["min"] is not None:
                if metric.value < rules["min"]:
                    errors.append(f"Value {metric.value} below minimum {rules['min']}")
                    confidence_score *= 0.5
            
            if "max" in rules and rules["max"] is not None:
                if metric.value > rules["max"]:
                    errors.append(f"Value {metric.value} above maximum {rules['max']}")
                    confidence_score *= 0.5
            
            # Check unit consistency
            if "unit" in rules and metric.unit:
                if rules["unit"] != metric.unit:
                    warnings.append(f"Unit mismatch: expected {rules['unit']}, got {metric.unit}")
                    confidence_score *= 0.9
        
        # Check for outliers if enabled
        if self.config.outlier_detection_enabled:
            outlier_score = await self._detect_outliers(metric)
            if outlier_score < 0.5:
                warnings.append("Value appears to be an outlier")
                confidence_score *= outlier_score
        
        # Check timestamp validity
        if metric.timestamp > datetime.now():
            errors.append("Timestamp is in the future")
            confidence_score *= 0.3
        
        if metric.timestamp < datetime.now() - timedelta(days=365):
            warnings.append("Timestamp is very old")
            confidence_score *= 0.8
        
        # Check collection method consistency
        if metric.collection_method and metric.collection_source:
            if metric.collection_method == CollectionMethod.SNMP and not metric.collection_source.startswith("1.3.6.1"):
                warnings.append("SNMP method with non-standard OID format")
                confidence_score *= 0.9
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            confidence_score=max(0.0, min(1.0, confidence_score)),
            suggested_corrections=[]
        )
    
    async def _detect_outliers(self, metric: Metric) -> float:
        """Detect if a metric value is an outlier"""
        try:
            # Get recent metrics of the same type from the same device
            recent_metrics = await self._get_recent_metrics(
                device_id=metric.device_id,
                metric_name=metric.name,
                hours=24
            )
            
            if len(recent_metrics) < 3:
                return 1.0  # Not enough data to detect outliers
            
            values = [m.value for m in recent_metrics]
            mean = statistics.mean(values)
            std = statistics.stdev(values) if len(values) > 1 else 0
            
            if std == 0:
                return 1.0
            
            # Calculate z-score
            z_score = abs(metric.value - mean) / std
            
            if z_score > self.config.outlier_threshold_std:
                return 0.3  # Strong outlier
            elif z_score > self.config.outlier_threshold_std * 0.7:
                return 0.7  # Moderate outlier
            else:
                return 1.0  # No outlier
                
        except Exception as e:
            logger.warning(f"Outlier detection failed for metric {metric.name}: {str(e)}")
            return 1.0
    
    async def _transform_metric(self, metric: Metric):
        """Transform metric data if needed"""
        try:
            # Convert units if needed
            if metric.unit == "bytes" and metric.value > 1024:
                # Convert to appropriate unit
                if metric.value > 1024**3:
                    metric.value = metric.value / (1024**3)
                    metric.unit = "GB"
                elif metric.value > 1024**2:
                    metric.value = metric.value / (1024**2)
                    metric.unit = "MB"
                elif metric.value > 1024:
                    metric.value = metric.value / 1024
                    metric.unit = "KB"
            
            # Normalize percentage values
            if metric.unit == "percent" and metric.value > 1.0:
                metric.value = metric.value / 100.0
            
            # Add derived fields
            if metric.previous_value is not None:
                metric.change_rate = (metric.value - metric.previous_value) / 60.0  # Per minute
                
                if metric.change_rate > 0:
                    metric.trend_direction = "increasing"
                elif metric.change_rate < 0:
                    metric.trend_direction = "decreasing"
                else:
                    metric.trend_direction = "stable"
            
            # Add context tags
            if not metric.tags:
                metric.tags = []
            
            # Add performance context
            if metric.category.value == "performance":
                if metric.value > 80:
                    metric.tags.append("high_performance")
                elif metric.value < 20:
                    metric.tags.append("low_performance")
            
            # Add time context
            hour = metric.timestamp.hour
            if 6 <= hour <= 18:
                metric.tags.append("business_hours")
            else:
                metric.tags.append("off_hours")
                
        except Exception as e:
            logger.warning(f"Metric transformation failed for {metric.name}: {str(e)}")
    
    async def _assess_metric_quality(self, metric: Metric) -> QualityAssessment:
        """Assess the overall quality of a metric"""
        try:
            # Data quality (value validity, unit consistency)
            data_quality = 1.0
            if not metric.is_valid:
                data_quality *= 0.3
            if metric.validation_errors:
                data_quality *= 0.5
            if metric.unit is None:
                data_quality *= 0.8
            
            # Collection quality (method, source, duration)
            collection_quality = 1.0
            if metric.collection_duration_ms:
                if metric.collection_duration_ms > 5000:
                    collection_quality *= 0.6
                elif metric.collection_duration_ms > 1000:
                    collection_quality *= 0.8
            
            if metric.collection_retries > 0:
                collection_quality *= 0.9
            
            # Freshness quality (how recent is the data)
            freshness_quality = 1.0
            age_hours = (datetime.now() - metric.timestamp).total_seconds() / 3600
            if age_hours > 24:
                freshness_quality *= 0.5
            elif age_hours > 1:
                freshness_quality *= 0.8
            
            # Consistency quality (how consistent with historical data)
            consistency_quality = 1.0
            if metric.confidence is not None:
                consistency_quality *= metric.confidence
            
            # Calculate overall score
            overall_score = (
                data_quality * 0.4 +
                collection_quality * 0.3 +
                freshness_quality * 0.2 +
                consistency_quality * 0.1
            )
            
            # Generate recommendations
            recommendations = []
            if data_quality < 0.8:
                recommendations.append("Improve data validation")
            if collection_quality < 0.8:
                recommendations.append("Optimize collection method")
            if freshness_quality < 0.8:
                recommendations.append("Reduce collection intervals")
            if consistency_quality < 0.8:
                recommendations.append("Check data consistency")
            
            return QualityAssessment(
                overall_score=overall_score,
                data_quality=data_quality,
                collection_quality=collection_quality,
                freshness_quality=freshness_quality,
                consistency_quality=consistency_quality,
                recommendations=recommendations
            )
            
        except Exception as e:
            logger.error(f"Quality assessment failed for metric {metric.name}: {str(e)}")
            return QualityAssessment(
                overall_score=0.5,
                data_quality=0.5,
                collection_quality=0.5,
                freshness_quality=0.5,
                consistency_quality=0.5,
                recommendations=["Quality assessment failed"]
            )
    
    async def aggregate_metrics(
        self, 
        device_id: int, 
        metric_name: str, 
        window_seconds: int,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> AggregationResult:
        """Aggregate metrics over a time window"""
        try:
            # Set default time range if not provided
            if not end_time:
                end_time = datetime.now()
            if not start_time:
                start_time = end_time - timedelta(seconds=window_seconds)
            
            # Get metrics in the time range
            metrics = await self._get_metrics_in_range(
                device_id=device_id,
                metric_name=metric_name,
                start_time=start_time,
                end_time=end_time
            )
            
            if not metrics:
                return AggregationResult(
                    original_count=0,
                    aggregated_count=0,
                    aggregation_window=window_seconds,
                    metrics=[],
                    statistics={}
                )
            
            # Perform aggregation
            aggregated_metrics = await self._perform_aggregation(
                metrics, window_seconds, start_time, end_time
            )
            
            # Calculate statistics
            statistics = self._calculate_aggregation_statistics(metrics)
            
            return AggregationResult(
                original_count=len(metrics),
                aggregated_count=len(aggregated_metrics),
                aggregation_window=window_seconds,
                metrics=aggregated_metrics,
                statistics=statistics
            )
            
        except Exception as e:
            logger.error(f"Metric aggregation failed: {str(e)}")
            return AggregationResult(
                original_count=0,
                aggregated_count=0,
                aggregation_window=window_seconds,
                metrics=[],
                statistics={}
            )
    
    async def _perform_aggregation(
        self, 
        metrics: List[Metric], 
        window_seconds: int,
        start_time: datetime,
        end_time: datetime
    ) -> List[Metric]:
        """Perform the actual aggregation"""
        aggregated_metrics = []
        
        # Group metrics by time windows
        window_groups = defaultdict(list)
        
        for metric in metrics:
            # Calculate which window this metric belongs to
            time_diff = (metric.timestamp - start_time).total_seconds()
            window_index = int(time_diff / window_seconds)
            window_groups[window_index].append(metric)
        
        # Aggregate each window
        for window_index, window_metrics in window_groups.items():
            if not window_metrics:
                continue
            
            # Calculate window start time
            window_start = start_time + timedelta(seconds=window_index * window_seconds)
            
            # Create aggregated metric
            aggregated_metric = await self._create_aggregated_metric(
                window_metrics, window_start, window_seconds
            )
            
            aggregated_metrics.append(aggregated_metric)
        
        return aggregated_metrics
    
    async def _create_aggregated_metric(
        self, 
        metrics: List[Metric], 
        window_start: datetime,
        window_seconds: int
    ) -> Metric:
        """Create an aggregated metric from a group of metrics"""
        # Use the first metric as a template
        template = metrics[0]
        
        # Calculate aggregated values
        values = [m.value for m in metrics if m.value is not None]
        if not values:
            values = [0.0]
        
        # Create aggregated metric
        aggregated_metric = Metric(
            device_id=template.device_id,
            name=f"{template.name}_aggregated",
            value=statistics.mean(values),
            unit=template.unit,
            metric_type=template.metric_type,
            category=template.category,
            timestamp=window_start,
            collection_method=template.collection_method,
            collection_source=f"aggregation_{window_seconds}s",
            metadata={
                "aggregation_window": window_seconds,
                "original_count": len(metrics),
                "aggregation_method": "mean",
                "min_value": min(values),
                "max_value": max(values),
                "std_dev": statistics.stdev(values) if len(values) > 1 else 0
            },
            tags=["aggregated", f"window_{window_seconds}s"]
        )
        
        return aggregated_metric
    
    def _calculate_aggregation_statistics(self, metrics: List[Metric]) -> Dict[str, float]:
        """Calculate statistics for a group of metrics"""
        values = [m.value for m in metrics if m.value is not None]
        
        if not values:
            return {}
        
        return {
            "count": len(values),
            "mean": statistics.mean(values),
            "median": statistics.median(values),
            "min": min(values),
            "max": max(values),
            "std_dev": statistics.stdev(values) if len(values) > 1 else 0,
            "variance": statistics.variance(values) if len(values) > 1 else 0
        }
    
    async def _get_metrics_in_range(
        self, 
        device_id: int, 
        metric_name: str,
        start_time: datetime,
        end_time: datetime
    ) -> List[Metric]:
        """Get metrics within a time range"""
        try:
            result = await self.db_session.execute(
                select(Metric).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.name == metric_name,
                        Metric.timestamp >= start_time,
                        Metric.timestamp <= end_time,
                        Metric.is_deleted == False
                    )
                ).order_by(Metric.timestamp.asc())
            )
            
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get metrics in range: {str(e)}")
            return []
    
    async def _get_recent_metrics(
        self, 
        device_id: int, 
        metric_name: str,
        hours: int = 24
    ) -> List[Metric]:
        """Get recent metrics for a device and metric name"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            result = await self.db_session.execute(
                select(Metric).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.name == metric_name,
                        Metric.timestamp >= since,
                        Metric.is_deleted == False
                    )
                ).order_by(Metric.timestamp.desc())
            )
            
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get recent metrics: {str(e)}")
            return []
    
    def update_config(self, config: ProcessingConfig):
        """Update processing configuration"""
        self.config = config
        logger.info(f"Updated metrics processing config: {config}")
    
    async def get_processing_stats(self, device_id: int, hours: int = 24) -> Dict[str, Any]:
        """Get processing statistics for a device"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            # Get processed metrics
            result = await self.db_session.execute(
                select(Metric).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.processed_at >= since,
                        Metric.is_deleted == False
                    )
                )
            )
            
            metrics = result.scalars().all()
            
            if not metrics:
                return {
                    "total_processed": 0,
                    "valid_metrics": 0,
                    "invalid_metrics": 0,
                    "average_quality": 0.0,
                    "average_confidence": 0.0
                }
            
            # Calculate statistics
            total_processed = len(metrics)
            valid_metrics = sum(1 for m in metrics if m.is_valid)
            invalid_metrics = total_processed - valid_metrics
            
            quality_scores = [m.quality_score for m in metrics if m.quality_score is not None]
            average_quality = sum(quality_scores) / len(quality_scores) if quality_scores else 0
            
            confidence_scores = [m.confidence for m in metrics if m.confidence is not None]
            average_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
            
            return {
                "total_processed": total_processed,
                "valid_metrics": valid_metrics,
                "invalid_metrics": invalid_metrics,
                "average_quality": round(average_quality, 3),
                "average_confidence": round(average_confidence, 3),
                "time_range_hours": hours
            }
            
        except Exception as e:
            logger.error(f"Failed to get processing stats: {str(e)}")
            return {
                "total_processed": 0,
                "valid_metrics": 0,
                "invalid_metrics": 0,
                "average_quality": 0.0,
                "average_confidence": 0.0
            }
