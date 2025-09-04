"""
Tests for CHM Advanced Analytics & Reporting System

This module tests the functionality of:
- Performance Analytics Service
- Advanced Reporting Service  
- Data Aggregation Service
- Analytics Models
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from typing import List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.analytics import (
    PerformanceAnalysis, AnomalyDetection, CapacityPlanning, 
    TrendForecast, AnalyticsReport, AnalyticsInsight,
    AnalysisType, AnomalySeverity, ReportType, ReportFormat
)
from ..models.metric import Metric, MetricType, MetricCategory
from ..models.device import Device, DeviceStatus
from ..models.result_objects import AnalyticsResult, ReportResult, CollectionResult
from ..services.performance_analytics import PerformanceAnalyticsService
from ..services.advanced_reporting import AdvancedReportingService, ReportConfig
from ..services.data_aggregation import DataAggregationService, AggregationConfig


class TestPerformanceAnalyticsService:
    """Test Performance Analytics Service"""
    
    @pytest.fixture
    def analytics_service(self, db_session):
        return PerformanceAnalyticsService(db_session)
    
    @pytest.fixture
    def sample_metrics(self):
        """Create sample metrics for testing"""
        base_time = datetime.now()
        metrics = []
        
        # Create CPU utilization metrics with increasing trend
        for i in range(24):
            timestamp = base_time + timedelta(hours=i)
            value = 50 + (i * 2) + (i % 3)  # Increasing trend with some noise
            metrics.append(Metric(
                id=i+1,
                device_id=1,
                metric_name="cpu_utilization",
                value=value,
                timestamp=timestamp,
                category=MetricCategory.PERFORMANCE,
                quality_score=0.9
            ))
        
        # Create memory utilization metrics with stable trend
        for i in range(24):
            timestamp = base_time + timedelta(hours=i)
            value = 75 + (i % 5)  # Stable around 75%
            metrics.append(Metric(
                id=i+25,
                device_id=1,
                metric_name="memory_utilization",
                value=value,
                timestamp=timestamp,
                category=MetricCategory.PERFORMANCE,
                quality_score=0.85
            ))
        
        return metrics
    
    @pytest.mark.asyncio
    async def test_analyze_device_performance_trend_analysis(self, analytics_service, sample_metrics):
        """Test trend analysis for device performance"""
        # Mock metrics query service
        with patch.object(analytics_service.metrics_query, 'get_metrics') as mock_get_metrics:
            mock_get_metrics.return_value = CollectionResult(
                success=True,
                metrics=sample_metrics,
                total_count=len(sample_metrics)
            )
            
            # Test trend analysis
            result = await analytics_service.analyze_device_performance(
                device_id=1,
                analysis_type=AnalysisType.TREND_ANALYSIS
            )
            
            assert result.success is True
            assert result.analysis_type == AnalysisType.TREND_ANALYSIS
            assert 'trends' in result.data
            assert 'cpu_utilization' in result.data['trends']
            assert 'memory_utilization' in result.data['trends']
            assert 'overall_trend_score' in result.data
            assert 'insights' in result.data
            assert 'recommendations' in result.data
    
    @pytest.mark.asyncio
    async def test_analyze_device_performance_anomaly_detection(self, analytics_service, sample_metrics):
        """Test anomaly detection for device performance"""
        # Add some anomalous values
        anomalous_metrics = sample_metrics.copy()
        anomalous_metrics.append(Metric(
            id=50,
            device_id=1,
            metric_name="cpu_utilization",
            value=150,  # Anomalously high
            timestamp=datetime.now(),
            category=MetricCategory.PERFORMANCE,
            quality_score=0.9
        ))
        
        with patch.object(analytics_service.metrics_query, 'get_metrics') as mock_get_metrics:
            mock_get_metrics.return_value = CollectionResult(
                success=True,
                metrics=anomalous_metrics,
                total_count=len(anomalous_metrics)
            )
            
            # Test anomaly detection
            result = await analytics_service.analyze_device_performance(
                device_id=1,
                analysis_type=AnalysisType.ANOMALY_DETECTION
            )
            
            assert result.success is True
            assert result.analysis_type == AnalysisType.ANOMALY_DETECTION
            assert 'anomalies' in result.data
            assert result.data['anomaly_count'] > 0
    
    @pytest.mark.asyncio
    async def test_calculate_trend(self, analytics_service, sample_metrics):
        """Test trend calculation for metrics"""
        cpu_metrics = [m for m in sample_metrics if m.metric_name == "cpu_utilization"]
        
        trend_analysis = await analytics_service._calculate_trend(cpu_metrics, "cpu_utilization")
        
        assert trend_analysis is not None
        assert trend_analysis['metric_name'] == "cpu_utilization"
        assert trend_analysis['trend_direction'] == "increasing"
        assert trend_analysis['trend_strength'] > 0
        assert trend_analysis['change_percentage'] > 0
        assert 'seasonal_info' in trend_analysis
        assert 'outliers' in trend_analysis
    
    @pytest.mark.asyncio
    async def test_detect_metric_anomalies(self, analytics_service, sample_metrics):
        """Test anomaly detection for specific metrics"""
        # Add anomalous values
        anomalous_metrics = sample_metrics.copy()
        anomalous_metrics.append(Metric(
            id=51,
            device_id=1,
            metric_name="cpu_utilization",
            value=200,  # Very high anomaly
            timestamp=datetime.now(),
            category=MetricCategory.PERFORMANCE,
            quality_score=0.9
        ))
        
        anomalies = await analytics_service._detect_metric_anomalies(
            device_id=1,
            metric_name="cpu_utilization",
            metrics=anomalous_metrics
        )
        
        assert len(anomalies) > 0
        assert anomalies[0]['anomaly_type'] in ['spike', 'extreme_spike']
        assert anomalies[0]['severity'] in [AnomalySeverity.HIGH, AnomalySeverity.CRITICAL]
    
    @pytest.mark.asyncio
    async def test_correlate_anomalies(self, analytics_service):
        """Test anomaly correlation"""
        anomalies = [
            {
                'device_id': 1,
                'metric_name': 'cpu_utilization',
                'detected_at': datetime.now(),
                'severity': AnomalySeverity.HIGH
            },
            {
                'device_id': 1,
                'metric_name': 'memory_utilization',
                'detected_at': datetime.now() + timedelta(minutes=5),
                'severity': AnomalySeverity.MEDIUM
            }
        ]
        
        correlated = await analytics_service._correlate_anomalies(anomalies)
        
        assert len(correlated) == 2
        assert any('correlation_group' in a for a in correlated)
    
    @pytest.mark.asyncio
    async def test_generate_trend_insights(self, analytics_service):
        """Test trend insight generation"""
        trend_analysis = {
            'trend_direction': 'increasing',
            'change_percentage': 25.0,
            'trend_strength': 0.8,
            'outliers': [{'value': 100}],
            'seasonal_info': {'has_seasonality': True}
        }
        
        insights = await analytics_service._generate_trend_insights(
            'cpu_utilization', trend_analysis
        )
        
        assert len(insights) > 0
        assert any(i['type'] == 'trend_warning' for i in insights)
        assert any(i['type'] == 'seasonal_pattern' for i in insights)
        assert any(i['type'] == 'outlier_detection' for i in insights)
    
    @pytest.mark.asyncio
    async def test_generate_trend_recommendations(self, analytics_service):
        """Test trend recommendation generation"""
        trend_analysis = {
            'trend_direction': 'increasing',
            'change_percentage': 30.0,
            'trend_strength': 0.9,
            'outliers': [{'value': 100}]
        }
        
        recommendations = await analytics_service._generate_trend_recommendations(
            'cpu_utilization', trend_analysis
        )
        
        assert len(recommendations) > 0
        assert any(r['type'] == 'capacity_planning' for r in recommendations)
        assert any(r['type'] == 'monitoring' for r in recommendations)
        assert any(r['type'] == 'alerting' for r in recommendations)


class TestAdvancedReportingService:
    """Test Advanced Reporting Service"""
    
    @pytest.fixture
    def reporting_service(self, db_session):
        return AdvancedReportingService(db_session)
    
    @pytest.fixture
    def sample_report_config(self):
        """Create sample report configuration"""
        return ReportConfig(
            report_type=ReportType.PERFORMANCE_SUMMARY,
            time_range=(datetime.now() - timedelta(hours=24), datetime.now()),
            device_ids=[1, 2, 3],
            metric_names=['cpu_utilization', 'memory_utilization'],
            format=ReportFormat.HTML
        )
    
    @pytest.mark.asyncio
    async def test_generate_report(self, reporting_service, sample_report_config):
        """Test report generation"""
        with patch.object(reporting_service, '_get_device_performance_summary') as mock_device_summary:
            mock_device_summary.return_value = [{"device_id": 1, "status": "healthy"}]
            
            with patch.object(reporting_service, '_get_metric_trends') as mock_trends:
                mock_trends.return_value = {"trends": "sample_trends"}
                
                with patch.object(reporting_service, '_get_alerts_summary') as mock_alerts:
                    mock_alerts.return_value = {"alerts": "sample_alerts"}
                    
                    result = await reporting_service.generate_report(
                        config=sample_report_config,
                        user_id=1
                    )
                    
                    assert result.success is True
                    assert result.report_id is not None
                    assert result.report_file is not None
                    assert result.report_summary is not None
                    assert result.generation_duration_ms > 0
    
    @pytest.mark.asyncio
    async def test_generate_performance_summary(self, reporting_service, sample_report_config):
        """Test performance summary report generation"""
        with patch.object(reporting_service, '_get_device_performance_summary') as mock_device_summary:
            mock_device_summary.return_value = [{"device_id": 1, "status": "healthy"}]
            
            with patch.object(reporting_service, '_get_metric_trends') as mock_trends:
                mock_trends.return_value = {"trends": "sample_trends"}
                
                with patch.object(reporting_service, '_get_alerts_summary') as mock_alerts:
                    mock_alerts.return_value = {"alerts": "sample_alerts"}
                    
                    content = await reporting_service._generate_performance_summary(sample_report_config)
                    
                    assert 'sections' in content
                    assert 'data_summary' in content
                    assert len(content['sections']) > 0
    
    @pytest.mark.asyncio
    async def test_generate_anomaly_report(self, reporting_service, sample_report_config):
        """Test anomaly report generation"""
        with patch.object(reporting_service, '_get_anomalies_summary') as mock_anomalies:
            mock_anomalies.return_value = {
                "total_count": 5,
                "critical_count": 2,
                "type_breakdown": {"spike": 3, "drop": 2}
            }
            
            with patch.object(reporting_service, '_get_anomaly_trends') as mock_trends:
                mock_trends.return_value = {"trends": "anomaly_trends"}
                
                with patch.object(reporting_service, '_get_device_anomaly_breakdown') as mock_breakdown:
                    mock_breakdown.return_value = {"breakdown": "device_breakdown"}
                    
                    content = await reporting_service._generate_anomaly_report(sample_report_config)
                    
                    assert 'sections' in content
                    assert 'data_summary' in content
                    assert content['data_summary']['total_anomalies'] == 5
                    assert content['data_summary']['critical_anomalies'] == 2
    
    @pytest.mark.asyncio
    async def test_generate_html_content(self, reporting_service):
        """Test HTML content generation"""
        content = {
            'metadata': {
                'generated_at': '2024-01-01T00:00:00',
                'report_type': 'performance_summary',
                'devices_analyzed': 3
            },
            'summary': 'Test summary',
            'sections': [
                {
                    'title': 'Test Section',
                    'type': 'table',
                    'data': {'test': 'data'}
                }
            ],
            'insights': [
                {
                    'title': 'Test Insight',
                    'description': 'Test description',
                    'impact_level': 'medium'
                }
            ],
            'recommendations': [
                {
                    'title': 'Test Recommendation',
                    'description': 'Test description',
                    'priority': 'high'
                }
            ]
        }
        
        html = reporting_service._generate_html_content(content)
        
        assert '<!DOCTYPE html>' in html
        assert 'CHM Analytics Report' in html
        assert 'Test summary' in html
        assert 'Test Section' in html
        assert 'Test Insight' in html
        assert 'Test Recommendation' in html
    
    @pytest.mark.asyncio
    async def test_flatten_content_for_csv(self, reporting_service):
        """Test CSV content flattening"""
        content = {
            'sections': [
                {
                    'title': 'Test Section',
                    'type': 'table',
                    'data': {'test': 'data'}
                }
            ],
            'insights': [
                {
                    'title': 'Test Insight',
                    'type': 'performance',
                    'description': 'Test description'
                }
            ],
            'recommendations': [
                {
                    'title': 'Test Recommendation',
                    'type': 'optimization',
                    'description': 'Test description'
                }
            ]
        }
        
        csv_data = reporting_service._flatten_content_for_csv(content)
        
        assert len(csv_data) > 1  # Headers + data
        assert csv_data[0] == ['Section', 'Type', 'Title', 'Data']  # Headers
        assert any('Test Section' in row for row in csv_data)
        assert any('Test Insight' in row for row in csv_data)
        assert any('Test Recommendation' in row for row in csv_data)


class TestDataAggregationService:
    """Test Data Aggregation Service"""
    
    @pytest.fixture
    def aggregation_service(self, db_session):
        return DataAggregationService(db_session)
    
    @pytest.fixture
    def sample_metrics_for_aggregation(self):
        """Create sample metrics for aggregation testing"""
        base_time = datetime.now()
        metrics = []
        
        # Create metrics across multiple devices and categories
        for device_id in [1, 2]:
            for metric_name in ['cpu_utilization', 'memory_utilization', 'network_throughput']:
                for i in range(12):  # 12 data points per metric
                    timestamp = base_time + timedelta(hours=i)
                    value = 50 + (i * 2) + (device_id * 10) + (hash(metric_name) % 20)
                    metrics.append(Metric(
                        id=len(metrics) + 1,
                        device_id=device_id,
                        metric_name=metric_name,
                        value=value,
                        timestamp=timestamp,
                        category=MetricCategory.PERFORMANCE,
                        quality_score=0.8 + (i % 3) * 0.1
                    ))
        
        return metrics
    
    @pytest.mark.asyncio
    async def test_aggregate_metrics(self, aggregation_service, sample_metrics_for_aggregation):
        """Test metrics aggregation"""
        with patch.object(aggregation_service.metrics_query, 'get_metrics') as mock_get_metrics:
            mock_get_metrics.return_value = CollectionResult(
                success=True,
                metrics=sample_metrics_for_aggregation,
                total_count=len(sample_metrics_for_aggregation)
            )
            
            result = await aggregation_service.aggregate_metrics(
                device_ids=[1, 2],
                metric_names=['cpu_utilization', 'memory_utilization'],
                time_range=(datetime.now() - timedelta(hours=24), datetime.now())
            )
            
            assert result.success is True
            assert 'aggregated_data' in result.__dict__
            assert 'by_device' in result.aggregated_data
            assert 'by_metric' in result.aggregated_data
            assert 'by_time' in result.aggregated_data
            assert 'by_category' in result.aggregated_data
            assert 'cross_analysis' in result.aggregated_data
            assert 'statistical_summary' in result.aggregated_data
            assert result.quality_score > 0
            assert len(result.insights) >= 0
    
    @pytest.mark.asyncio
    async def test_perform_multi_dimensional_aggregation(self, aggregation_service, sample_metrics_for_aggregation):
        """Test multi-dimensional aggregation"""
        config = AggregationConfig()
        
        aggregated_data = await aggregation_service._perform_multi_dimensional_aggregation(
            sample_metrics_for_aggregation, config
        )
        
        assert 'by_device' in aggregated_data
        assert 'by_metric' in aggregated_data
        assert 'by_time' in aggregated_data
        assert 'by_category' in aggregated_data
        assert 'cross_analysis' in aggregated_data
        assert 'statistical_summary' in aggregated_data
        
        # Check device aggregation
        assert 1 in aggregated_data['by_device']
        assert 2 in aggregated_data['by_device']
        
        # Check metric aggregation
        assert 'cpu_utilization' in aggregated_data['by_metric']
        assert 'memory_utilization' in aggregated_data['by_metric']
        assert 'network_throughput' in aggregated_data['by_metric']
    
    @pytest.mark.asyncio
    async def test_aggregate_device_metrics(self, aggregation_service, sample_metrics_for_aggregation):
        """Test device metrics aggregation"""
        config = AggregationConfig()
        device_1_metrics = [m for m in sample_metrics_for_aggregation if m.device_id == 1]
        
        device_aggregation = await aggregation_service._aggregate_device_metrics(
            device_1_metrics, config
        )
        
        assert 'cpu_utilization' in device_aggregation
        assert 'memory_utilization' in device_aggregation
        assert 'network_throughput' in device_aggregation
        assert 'overall' in device_aggregation
        
        # Check aggregation functions
        cpu_agg = device_aggregation['cpu_utilization']
        assert 'mean' in cpu_agg
        assert 'min' in cpu_agg
        assert 'max' in cpu_agg
        assert 'count' in cpu_agg
        assert 'std' in cpu_agg
    
    @pytest.mark.asyncio
    async def test_aggregate_metric_data(self, aggregation_service, sample_metrics_for_aggregation):
        """Test metric data aggregation"""
        config = AggregationConfig()
        cpu_metrics = [m for m in sample_metrics_for_aggregation if m.metric_name == 'cpu_utilization']
        
        metric_aggregation = await aggregation_service._aggregate_metric_data(
            cpu_metrics, config
        )
        
        assert 'device_1' in metric_aggregation
        assert 'device_2' in metric_aggregation
        assert 'overall' in metric_aggregation
        assert 'trend' in metric_aggregation
        
        # Check overall statistics
        overall = metric_aggregation['overall']
        assert overall['total_measurements'] == 24  # 12 per device * 2 devices
        assert overall['device_count'] == 2
    
    @pytest.mark.asyncio
    async def test_calculate_aggregation_functions(self, aggregation_service):
        """Test aggregation function calculations"""
        metrics = [
            Metric(id=1, device_id=1, metric_name='test', value=10, timestamp=datetime.now()),
            Metric(id=2, device_id=1, metric_name='test', value=20, timestamp=datetime.now()),
            Metric(id=3, device_id=1, metric_name='test', value=30, timestamp=datetime.now()),
            Metric(id=4, device_id=1, metric_name='test', value=40, timestamp=datetime.now()),
            Metric(id=5, device_id=1, metric_name='test', value=50, timestamp=datetime.now())
        ]
        
        functions = ['mean', 'min', 'max', 'count', 'std', 'median', 'p95', 'p99']
        
        results = await aggregation_service._calculate_aggregation_functions(metrics, functions)
        
        assert results['mean'] == 30.0
        assert results['min'] == 10.0
        assert results['max'] == 50.0
        assert results['count'] == 5
        assert results['median'] == 30.0
        assert results['p95'] == 48.0  # 95th percentile
        assert results['p99'] == 49.6  # 99th percentile
    
    @pytest.mark.asyncio
    async def test_group_by_time_window(self, aggregation_service, sample_metrics_for_aggregation):
        """Test time window grouping"""
        # Test hourly grouping
        hourly_groups = await aggregation_service._group_by_time_window(
            sample_metrics_for_aggregation, "1h"
        )
        
        assert len(hourly_groups) > 0
        assert all(len(metrics) > 0 for metrics in hourly_groups.values())
        
        # Test daily grouping
        daily_groups = await aggregation_service._group_by_time_window(
            sample_metrics_for_aggregation, "1d"
        )
        
        assert len(daily_groups) > 0
        assert len(daily_groups) <= len(hourly_groups)  # Fewer daily groups than hourly
    
    @pytest.mark.asyncio
    async def test_analyze_metric_trend(self, aggregation_service):
        """Test metric trend analysis"""
        # Create metrics with increasing trend
        metrics = []
        base_time = datetime.now()
        for i in range(10):
            timestamp = base_time + timedelta(hours=i)
            value = 50 + (i * 5)  # Linear increase
            metrics.append(Metric(
                id=i+1,
                device_id=1,
                metric_name='test',
                value=value,
                timestamp=timestamp
            ))
        
        trend = await aggregation_service._analyze_metric_trend(metrics)
        
        assert trend['trend'] == 'increasing'
        assert trend['slope'] > 0
        assert trend['change_percentage'] > 0
        assert trend['data_points'] == 10
    
    @pytest.mark.asyncio
    async def test_analyze_metric_correlations(self, aggregation_service, sample_metrics_for_aggregation):
        """Test metric correlation analysis"""
        config = AggregationConfig()
        config.enable_correlation_analysis = True
        
        cross_analysis = await aggregation_service._perform_cross_analysis(
            sample_metrics_for_aggregation, config
        )
        
        assert 'correlations' in cross_analysis
        correlations = cross_analysis['correlations']
        
        # Should have correlations for each device
        assert len(correlations) > 0
    
    @pytest.mark.asyncio
    async def test_detect_cross_metric_outliers(self, aggregation_service, sample_metrics_for_aggregation):
        """Test cross-metric outlier detection"""
        config = AggregationConfig()
        config.enable_outlier_detection = True
        
        # Add some outliers
        outlier_metrics = sample_metrics_for_aggregation.copy()
        outlier_metrics.append(Metric(
            id=1000,
            device_id=1,
            metric_name='cpu_utilization',
            value=500,  # Extreme outlier
            timestamp=datetime.now()
        ))
        
        cross_analysis = await aggregation_service._perform_cross_analysis(
            outlier_metrics, config
        )
        
        assert 'outliers' in cross_analysis
        outliers = cross_analysis['outliers']
        
        # Should detect the outlier we added
        assert len(outliers) > 0
    
    @pytest.mark.asyncio
    async def test_calculate_overall_statistics(self, aggregation_service, sample_metrics_for_aggregation):
        """Test overall statistics calculation"""
        config = AggregationConfig()
        
        stats = await aggregation_service._calculate_overall_statistics(
            sample_metrics_for_aggregation, config
        )
        
        assert stats['total_measurements'] == 72  # 2 devices * 3 metrics * 12 data points
        assert stats['unique_devices'] == 2
        assert stats['unique_metrics'] == 3
        assert 'value_statistics' in stats
        assert 'quality_statistics' in stats
        
        value_stats = stats['value_statistics']
        assert 'mean' in value_stats
        assert 'median' in value_stats
        assert 'min' in value_stats
        assert 'max' in value_stats
        assert 'std' in value_stats
    
    @pytest.mark.asyncio
    async def test_calculate_aggregation_quality(self, aggregation_service, sample_metrics_for_aggregation):
        """Test aggregation quality calculation"""
        aggregated_data = {
            'by_device': {1: {}, 2: {}},
            'by_metric': {'cpu': {}, 'memory': {}},
            'by_time': {'2024-01-01': {}, '2024-01-02': {}}
        }
        
        quality_score = await aggregation_service._calculate_aggregation_quality(
            sample_metrics_for_aggregation, aggregated_data
        )
        
        assert 0.0 <= quality_score <= 1.0
        assert quality_score > 0.5  # Should be reasonably high with good data
    
    @pytest.mark.asyncio
    async def test_generate_aggregation_insights(self, aggregation_service):
        """Test aggregation insight generation"""
        aggregated_data = {
            'by_device': {i: {} for i in range(15)},  # 15 devices
            'by_metric': {f'metric_{i}': {} for i in range(60)},  # 60 metrics
            'by_time': {f'time_{i}': {} for i in range(150)}  # 150 time windows
        }
        
        quality_score = 0.3  # Low quality
        
        insights = await aggregation_service._generate_aggregation_insights(
            aggregated_data, quality_score
        )
        
        assert len(insights) > 0
        
        # Should have quality insight
        quality_insights = [i for i in insights if i['type'] == 'data_quality']
        assert len(quality_insights) > 0
        
        # Should have performance insights
        performance_insights = [i for i in insights if i['type'] == 'performance']
        assert len(performance_insights) > 0
        
        # Should have monitoring insights
        monitoring_insights = [i for i in insights if i['type'] == 'monitoring']
        assert len(monitoring_insights) > 0


class TestAnalyticsModels:
    """Test Analytics Models"""
    
    def test_performance_analysis_model(self):
        """Test PerformanceAnalysis model"""
        analysis = PerformanceAnalysis(
            device_id=1,
            metric_name="cpu_utilization",
            analysis_type=AnalysisType.TREND_ANALYSIS,
            time_range_start=datetime.now() - timedelta(hours=24),
            time_range_end=datetime.now(),
            analysis_window_hours=24,
            baseline_value=50.0,
            current_value=60.0,
            change_percentage=20.0,
            trend_direction="increasing",
            trend_strength=0.8,
            confidence_score=0.9
        )
        
        assert analysis.device_id == 1
        assert analysis.metric_name == "cpu_utilization"
        assert analysis.analysis_type == AnalysisType.TREND_ANALYSIS
        assert analysis.trend_direction == "increasing"
        assert analysis.trend_strength == 0.8
        assert analysis.confidence_score == 0.9
    
    def test_anomaly_detection_model(self):
        """Test AnomalyDetection model"""
        detection = AnomalyDetection(
            device_id=1,
            metric_name="cpu_utilization",
            anomaly_type="spike",
            severity=AnomalySeverity.HIGH,
            confidence_score=0.85,
            detection_method="statistical",
            baseline_value=50.0,
            anomalous_value=90.0,
            deviation_percentage=80.0,
            deviation_std_devs=3.5,
            detected_at=datetime.now()
        )
        
        assert detection.device_id == 1
        assert detection.metric_name == "cpu_utilization"
        assert detection.anomaly_type == "spike"
        assert detection.severity == AnomalySeverity.HIGH
        assert detection.confidence_score == 0.85
        assert detection.deviation_percentage == 80.0
    
    def test_capacity_planning_model(self):
        """Test CapacityPlanning model"""
        capacity = CapacityPlanning(
            device_id=1,
            resource_type="cpu",
            current_utilization=75.0,
            avg_utilization_24h=70.0,
            avg_utilization_7d=65.0,
            peak_utilization=90.0,
            forecast_30d=80.0,
            upgrade_recommended=True,
            upgrade_urgency="medium"
        )
        
        assert capacity.device_id == 1
        assert capacity.resource_type == "cpu"
        assert capacity.current_utilization == 75.0
        assert capacity.avg_utilization_24h == 70.0
        assert capacity.upgrade_recommended is True
        assert capacity.upgrade_urgency == "medium"
    
    def test_trend_forecast_model(self):
        """Test TrendForecast model"""
        forecast = TrendForecast(
            device_id=1,
            metric_name="cpu_utilization",
            forecast_type="linear",
            forecast_horizon_days=30,
            confidence_interval=0.95,
            historical_start_date=datetime.now() - timedelta(days=30),
            historical_end_date=datetime.now(),
            forecast_values=[{"timestamp": "2024-02-01", "value": 75.0}],
            model_accuracy=0.85,
            trend_direction="increasing",
            trend_strength=0.7
        )
        
        assert forecast.device_id == 1
        assert forecast.metric_name == "cpu_utilization"
        assert forecast.forecast_type == "linear"
        assert forecast.forecast_horizon_days == 30
        assert forecast.confidence_interval == 0.95
        assert forecast.model_accuracy == 0.85
        assert forecast.trend_direction == "increasing"
    
    def test_analytics_report_model(self):
        """Test AnalyticsReport model"""
        report = AnalyticsReport(
            name="Performance Summary Report",
            description="Monthly performance summary",
            report_type=ReportType.PERFORMANCE_SUMMARY,
            report_config={"time_range": "last_month"},
            generated_by=1,
            generated_at=datetime.now(),
            available_formats=[ReportFormat.HTML, ReportFormat.PDF],
            tags=["monthly", "performance"]
        )
        
        assert report.name == "Performance Summary Report"
        assert report.report_type == ReportType.PERFORMANCE_SUMMARY
        assert report.generated_by == 1
        assert ReportFormat.HTML in report.available_formats
        assert ReportFormat.PDF in report.available_formats
        assert "monthly" in report.tags
    
    def test_analytics_insight_model(self):
        """Test AnalyticsInsight model"""
        insight = AnalyticsInsight(
            insight_type="performance",
            insight_category="optimization",
            title="High CPU Utilization Detected",
            description="Device shows consistently high CPU usage",
            impact_level="high",
            priority_score=0.8,
            actionable=True,
            estimated_effort="medium",
            estimated_benefit="high"
        )
        
        assert insight.insight_type == "performance"
        assert insight.insight_category == "optimization"
        assert insight.title == "High CPU Utilization Detected"
        assert insight.impact_level == "high"
        assert insight.priority_score == 0.8
        assert insight.actionable is True


@pytest.mark.asyncio
async def test_integration_workflow(db_session):
    """Test integration workflow between analytics services"""
    # Initialize services
    analytics_service = PerformanceAnalyticsService(db_session)
    reporting_service = AdvancedReportingService(db_session)
    aggregation_service = DataAggregationService(db_session)
    
    # Test that services can be initialized and share the database session
    assert analytics_service.db_session == db_session
    assert reporting_service.db_session == db_session
    assert aggregation_service.db_session == db_session
    
    # Test that services can access their dependencies
    assert hasattr(analytics_service, 'metrics_query')
    assert hasattr(reporting_service, 'metrics_query')
    assert hasattr(aggregation_service, 'metrics_query')
    
    # Test that services can access their configurations
    assert hasattr(analytics_service, 'trend_config')
    assert hasattr(analytics_service, 'anomaly_config')
    assert hasattr(analytics_service, 'capacity_config')
    
    assert hasattr(reporting_service, 'report_templates')
    assert hasattr(aggregation_service, 'agg_config')
    assert hasattr(aggregation_service, 'insight_config')
