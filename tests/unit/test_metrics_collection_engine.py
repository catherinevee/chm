"""
CHM Metrics Collection Engine Tests
Comprehensive testing for all metrics collection services
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import List, Dict, Any

from sqlalchemy.ext.asyncio import AsyncSession

from chm.services.metrics_collection import (
    MetricsCollectionService, 
    CollectionConfig, 
    CollectionResult
)
from chm.services.metrics_storage import (
    MetricsStorageService, 
    StorageConfig, 
    StorageStats
)
from chm.services.metrics_processing import (
    MetricsProcessingService, 
    ProcessingConfig, 
    ValidationResult,
    AggregationResult,
    QualityAssessment
)
from chm.services.metrics_query import (
    MetricsQueryService, 
    QueryConfig, 
    QueryFilter,
    QueryResult
)
from chm.models import (
    Metric, Device, DeviceCredentials, 
    CollectionMethod, MetricQuality, MetricType, MetricCategory
)
from chm.models.result_objects import MetricsCollectionResult, StorageResult

@pytest.fixture
def mock_db_session():
    """Mock database session"""
    session = Mock(spec=AsyncSession)
    session.execute = AsyncMock()
    session.add_all = Mock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    return session

@pytest.fixture
def mock_device():
    """Mock device for testing"""
    device = Mock(spec=Device)
    device.id = 1
    device.ip_address = "192.168.1.1"
    device.protocol = "snmp"
    device.port = 161
    return device

@pytest.fixture
def mock_credentials():
    """Mock device credentials for testing"""
    credentials = Mock(spec=DeviceCredentials)
    credentials.id = 1
    credentials.device_id = 1
    credentials.credential_type = "snmp"
    credentials.status = "active"
    credentials.is_deleted = False
    return credentials

@pytest.fixture
def mock_metric():
    """Mock metric for testing"""
    metric = Mock(spec=Metric)
    metric.id = 1
    metric.device_id = 1
    metric.name = "cpu_usage"
    metric.value = 75.5
    metric.unit = "percent"
    metric.timestamp = datetime.now()
    metric.category = MetricCategory.SYSTEM
    metric.metric_type = MetricType.GAUGE
    metric.is_valid = True
    metric.quality_score = 0.9
    metric.storage_tier = "hot"
    metric.tags = []
    return metric

class TestMetricsCollectionService:
    """Test Metrics Collection Service"""
    
    @pytest.mark.asyncio
    async def test_init(self, mock_db_session):
        """Test service initialization"""
        service = MetricsCollectionService(mock_db_session)
        assert service.db_session == mock_db_session
        assert service.config is not None
        assert service.snmp_oids is not None
        assert service.ssh_commands is not None
    
    @pytest.mark.asyncio
    async def test_collect_device_metrics_success(self, mock_db_session, mock_device, mock_credentials):
        """Test successful metric collection"""
        # Mock device and credentials retrieval
        service = MetricsCollectionService(mock_db_session)
        service._get_device = AsyncMock(return_value=mock_device)
        service._get_device_credentials = AsyncMock(return_value=mock_credentials)
        service._collect_snmp_metrics = AsyncMock(return_value=[Mock(spec=Metric)])
        service._store_metrics = AsyncMock(return_value=1)
        
        result = await service.collect_device_metrics(1)
        
        assert result.status == "success"
        assert result.metrics_count == 1
        assert result.device_id == 1
    
    @pytest.mark.asyncio
    async def test_collect_device_metrics_device_not_found(self, mock_db_session):
        """Test metric collection when device not found"""
        service = MetricsCollectionService(mock_db_session)
        service._get_device = AsyncMock(return_value=None)
        
        result = await service.collect_device_metrics(999)
        
        assert result.status == "failed"
        assert "Device not found" in result.error
    
    @pytest.mark_asyncio
    async def test_collect_device_metrics_no_credentials(self, mock_db_session, mock_device):
        """Test metric collection when no credentials found"""
        service = MetricsCollectionService(mock_db_session)
        service._get_device = AsyncMock(return_value=mock_device)
        service._get_device_credentials = AsyncMock(return_value=None)
        
        result = await service.collect_device_metrics(1)
        
        assert result.status == "failed"
        assert "No credentials found" in result.error
    
    @pytest.mark.asyncio
    async def test_collect_device_metrics_unsupported_protocol(self, mock_db_session, mock_device, mock_credentials):
        """Test metric collection with unsupported protocol"""
        mock_device.protocol = "unsupported"
        
        service = MetricsCollectionService(mock_db_session)
        service._get_device = AsyncMock(return_value=mock_device)
        service._get_device_credentials = AsyncMock(return_value=mock_credentials)
        
        result = await service.collect_device_metrics(1)
        
        assert result.status == "failed"
        assert "Unsupported protocol" in result.error
    
    @pytest.mark.asyncio
    async def test_collect_batch_metrics(self, mock_db_session):
        """Test batch metric collection"""
        service = MetricsCollectionService(mock_db_session)
        service.collect_device_metrics = AsyncMock(return_value=Mock(spec=MetricsCollectionResult))
        
        results = await service.collect_batch_metrics([1, 2, 3])
        
        assert len(results) == 3
        assert service.collect_device_metrics.call_count == 3
    
    @pytest.mark.asyncio
    async def test_collect_batch_metrics_with_exceptions(self, mock_db_session):
        """Test batch metric collection with exceptions"""
        service = MetricsCollectionService(mock_db_session)
        service.collect_device_metrics = AsyncMock(side_effect=[Exception("Error"), Mock(spec=MetricsCollectionResult), Exception("Error")])
        
        results = await service.collect_batch_metrics([1, 2, 3])
        
        assert len(results) == 3
        assert results[0].status == "failed"
        assert results[1].status == "success"
        assert results[2].status == "failed"
    
    @pytest.mark.asyncio
    async def test_get_collection_stats(self, mock_db_session):
        """Test collection statistics retrieval"""
        service = MetricsCollectionService(mock_db_session)
        
        # Mock metrics data
        mock_metrics = [
            Mock(is_valid=True, quality_score=0.9, collection_method=CollectionMethod.SNMP),
            Mock(is_valid=True, quality_score=0.8, collection_method=CollectionMethod.SSH),
            Mock(is_valid=False, quality_score=0.3, collection_method=CollectionMethod.SNMP)
        ]
        
        service._get_metrics_in_range = AsyncMock(return_value=mock_metrics)
        
        stats = await service.get_collection_stats(1, 24)
        
        assert stats["total_metrics"] == 3
        assert stats["success_rate"] == 66.67
        assert stats["average_quality"] == 0.67
        assert "snmp" in stats["collection_methods"]
        assert "ssh" in stats["collection_methods"]

class TestMetricsStorageService:
    """Test Metrics Storage Service"""
    
    @pytest.mark.asyncio
    async def test_init(self, mock_db_session):
        """Test service initialization"""
        service = MetricsStorageService(mock_db_session)
        assert service.db_session == mock_db_session
        assert service.config is not None
    
    @pytest.mark.asyncio
    async def test_store_metrics_success(self, mock_db_session, mock_metric):
        """Test successful metrics storage"""
        service = MetricsStorageService(mock_db_session)
        service._preprocess_metrics = AsyncMock(return_value=[mock_metric])
        service._post_storage_optimization = AsyncMock()
        
        result = await service.store_metrics([mock_metric])
        
        assert result.status == "success"
        assert result.stored_count == 1
        mock_db_session.add_all.assert_called_once()
        mock_db_session.commit.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_store_metrics_empty_list(self, mock_db_session):
        """Test storage with empty metrics list"""
        service = MetricsStorageService(mock_db_session)
        
        result = await service.store_metrics([])
        
        assert result.status == "success"
        assert result.stored_count == 0
    
    @pytest.mark.asyncio
    async def test_store_metrics_failure(self, mock_db_session, mock_metric):
        """Test metrics storage failure"""
        service = MetricsStorageService(mock_db_session)
        service._preprocess_metrics = AsyncMock(return_value=[mock_metric])
        mock_db_session.commit.side_effect = Exception("Database error")
        
        result = await service.store_metrics([mock_metric])
        
        assert result.status == "failed"
        assert "Database error" in result.error
        mock_db_session.rollback.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_preprocess_metrics(self, mock_db_session, mock_metric):
        """Test metrics preprocessing"""
        service = MetricsStorageService(mock_db_session)
        
        processed_metrics = await service._preprocess_metrics([mock_metric])
        
        assert len(processed_metrics) == 1
        assert processed_metrics[0].processed_at is not None
        assert processed_metrics[0].storage_tier is not None
        assert processed_metrics[0].retention_days is not None
        assert processed_metrics[0].expires_at is not None
    
    @pytest.mark.asyncio
    async def test_determine_storage_tier(self, mock_db_session):
        """Test storage tier determination"""
        service = MetricsStorageService(mock_db_session)
        
        # Test hot storage
        recent_time = datetime.now() - timedelta(hours=12)
        tier = service._determine_storage_tier(recent_time)
        assert tier == "hot"
        
        # Test warm storage
        old_time = datetime.now() - timedelta(days=15)
        tier = service._determine_storage_tier(old_time)
        assert tier == "warm"
        
        # Test cold storage
        very_old_time = datetime.now() - timedelta(days=200)
        tier = service._determine_storage_tier(very_old_time)
        assert tier == "cold"
    
    @pytest.mark.asyncio
    async def test_calculate_retention_days(self, mock_db_session, mock_metric):
        """Test retention period calculation"""
        service = MetricsStorageService(mock_db_session)
        
        # Test system metrics
        mock_metric.category = MetricCategory.SYSTEM
        retention = service._calculate_retention_days(mock_metric)
        assert retention == 90
        
        # Test security metrics
        mock_metric.category = MetricCategory.SECURITY
        retention = service._calculate_retention_days(mock_metric)
        assert retention == 730
    
    @pytest.mark.asyncio
    async def test_get_storage_stats(self, mock_db_session):
        """Test storage statistics retrieval"""
        service = MetricsStorageService(mock_db_session)
        
        # Mock database results
        mock_db_session.execute.return_value.scalar.side_effect = [
            100,  # total_metrics
            50,   # hot_metrics
            30,   # warm_metrics
            20,   # cold_metrics
            25,   # compressed_metrics
            datetime.now() - timedelta(days=30),  # oldest_metric
            datetime.now(),  # newest_metric
            0.75  # compression_ratio
        ]
        
        stats = await service.get_storage_stats()
        
        assert stats.total_metrics == 100
        assert stats.hot_metrics == 50
        assert stats.warm_metrics == 30
        assert stats.cold_metrics == 20
        assert stats.compressed_metrics == 25
        assert stats.compression_ratio == 0.75

class TestMetricsProcessingService:
    """Test Metrics Processing Service"""
    
    @pytest.mark.asyncio
    async def test_init(self, mock_db_session):
        """Test service initialization"""
        service = MetricsProcessingService(mock_db_session)
        assert service.db_session == mock_db_session
        assert service.config is not None
        assert service.config.validation_rules is not None
        assert service.config.aggregation_windows is not None
    
    @pytest.mark.asyncio
    async def test_process_metrics_success(self, mock_db_session, mock_metric):
        """Test successful metrics processing"""
        service = MetricsProcessingService(mock_db_session)
        service._validate_metric = AsyncMock(return_value=Mock(spec=ValidationResult, is_valid=True, confidence_score=0.9))
        service._transform_metric = AsyncMock()
        service._assess_metric_quality = AsyncMock(return_value=Mock(spec=QualityAssessment, overall_score=0.85))
        
        processed_metrics = await service.process_metrics([mock_metric])
        
        assert len(processed_metrics) == 1
        assert processed_metrics[0].is_valid is True
        assert processed_metrics[0].confidence == 0.9
        assert processed_metrics[0].quality_score == 0.85
    
    @pytest.mark.asyncio
    async def test_process_metrics_validation_failure(self, mock_db_session, mock_metric):
        """Test metrics processing with validation failure"""
        service = MetricsProcessingService(mock_db_session)
        service._validate_metric = AsyncMock(return_value=Mock(spec=ValidationResult, is_valid=False, confidence_score=0.5, errors=["Invalid value"]))
        service._transform_metric = AsyncMock()
        service._assess_metric_quality = AsyncMock(return_value=Mock(spec=QualityAssessment, overall_score=0.3))
        
        processed_metrics = await service.process_metrics([mock_metric])
        
        assert len(processed_metrics) == 1
        assert processed_metrics[0].is_valid is False
        assert processed_metrics[0].confidence == 0.5
        assert processed_metrics[0].validation_errors == ["Invalid value"]
    
    @pytest.mark.asyncio
    async def test_validate_metric_success(self, mock_db_session, mock_metric):
        """Test successful metric validation"""
        service = MetricsProcessingService(mock_db_session)
        
        result = await service._validate_metric(mock_metric)
        
        assert result.is_valid is True
        assert len(result.errors) == 0
        assert result.confidence_score > 0.8
    
    @pytest.mark.asyncio
    async def test_validate_metric_range_violation(self, mock_db_session, mock_metric):
        """Test metric validation with range violation"""
        service = MetricsProcessingService(mock_db_session)
        mock_metric.name = "cpu_usage"
        mock_metric.value = 150.0  # Above 100% max
        
        result = await service._validate_metric(mock_metric)
        
        assert result.is_valid is False
        assert len(result.errors) > 0
        assert "above maximum" in result.errors[0]
        assert result.confidence_score < 0.6
    
    @pytest.mark.asyncio
    async def test_validate_metric_future_timestamp(self, mock_db_session, mock_metric):
        """Test metric validation with future timestamp"""
        service = MetricsProcessingService(mock_db_session)
        mock_metric.timestamp = datetime.now() + timedelta(hours=1)
        
        result = await service._validate_metric(mock_metric)
        
        assert result.is_valid is False
        assert "future" in result.errors[0]
        assert result.confidence_score < 0.4
    
    @pytest.mark.asyncio
    async def test_transform_metric_unit_conversion(self, mock_db_session, mock_metric):
        """Test metric transformation with unit conversion"""
        service = MetricsProcessingService(mock_db_session)
        mock_metric.unit = "bytes"
        mock_metric.value = 2048  # 2KB
        
        await service._transform_metric(mock_metric)
        
        assert mock_metric.value == 2.0
        assert mock_metric.unit == "KB"
    
    @pytest.mark.asyncio
    async def test_transform_metric_percentage_normalization(self, mock_db_session, mock_metric):
        """Test metric transformation with percentage normalization"""
        service = MetricsProcessingService(mock_db_session)
        mock_metric.unit = "percent"
        mock_metric.value = 85.0  # Already normalized
        
        await service._transform_metric(mock_metric)
        
        assert mock_metric.value == 85.0  # Should remain unchanged
        assert mock_metric.unit == "percent"
    
    @pytest.mark.asyncio
    async def test_assess_metric_quality(self, mock_db_session, mock_metric):
        """Test metric quality assessment"""
        service = MetricsProcessingService(mock_db_session)
        mock_metric.is_valid = True
        mock_metric.confidence = 0.9
        mock_metric.collection_duration_ms = 500
        
        assessment = await service._assess_metric_quality(mock_metric)
        
        assert assessment.overall_score > 0.8
        assert assessment.data_quality > 0.8
        assert assessment.collection_quality > 0.8
        assert len(assessment.recommendations) >= 0
    
    @pytest.mark.asyncio
    async def test_aggregate_metrics(self, mock_db_session):
        """Test metrics aggregation"""
        service = MetricsProcessingService(mock_db_session)
        
        # Create mock metrics for aggregation
        base_time = datetime.now()
        mock_metrics = []
        for i in range(10):
            metric = Mock(spec=Metric)
            metric.device_id = 1
            metric.name = "cpu_usage"
            metric.value = 50.0 + i
            metric.timestamp = base_time + timedelta(minutes=i*5)
            metric.unit = "percent"
            metric.category = MetricCategory.SYSTEM
            metric.metric_type = MetricType.GAUGE
            mock_metrics.append(metric)
        
        service._get_metrics_in_range = AsyncMock(return_value=mock_metrics)
        
        result = await service.aggregate_metrics(
            device_id=1,
            metric_name="cpu_usage",
            window_seconds=900,  # 15 minutes
            start_time=base_time,
            end_time=base_time + timedelta(minutes=45)
        )
        
        assert result.original_count == 10
        assert result.aggregated_count > 0
        assert result.aggregation_window == 900
        assert "mean" in result.statistics
        assert "min" in result.statistics
        assert "max" in result.statistics

class TestMetricsQueryService:
    """Test Metrics Query Service"""
    
    @pytest.mark.asyncio
    async def test_init(self, mock_db_session):
        """Test service initialization"""
        service = MetricsQueryService(mock_db_session)
        assert service.db_session == mock_db_session
        assert service.config is not None
        assert service._query_cache == {}
    
    @pytest.mark.asyncio
    async def test_query_metrics_success(self, mock_db_session):
        """Test successful metrics query"""
        service = MetricsQueryService(mock_db_session)
        
        # Mock database results
        mock_metrics = [Mock(spec=Metric) for _ in range(5)]
        mock_db_session.execute.return_value.scalar.side_effect = [5]  # total_count
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        filters = QueryFilter(device_ids=[1], metric_names=["cpu_usage"])
        
        result = await service.query_metrics(filters, page=1, limit=10)
        
        assert result.metrics == mock_metrics
        assert result.total_count == 5
        assert result.page == 1
        assert result.page_size == 10
        assert result.total_pages == 1
        assert result.query_time_ms > 0
    
    @pytest.mark.asyncio
    async def test_query_metrics_with_filters(self, mock_db_session):
        """Test metrics query with various filters"""
        service = MetricsQueryService(mock_db_session)
        
        # Mock database results
        mock_metrics = [Mock(spec=Metric) for _ in range(3)]
        mock_db_session.execute.return_value.scalar.side_effect = [3]  # total_count
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        filters = QueryFilter(
            device_ids=[1, 2],
            categories=["system", "network"],
            start_time=datetime.now() - timedelta(hours=24),
            end_time=datetime.now(),
            min_value=0.0,
            max_value=100.0
        )
        
        result = await service.query_metrics(filters)
        
        assert result.metrics == mock_metrics
        assert result.total_count == 3
    
    @pytest.mark.asyncio
    async def test_get_metrics_by_device(self, mock_db_session):
        """Test getting metrics by device"""
        service = MetricsQueryService(mock_db_session)
        
        mock_metrics = [Mock(spec=Metric) for _ in range(5)]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        metrics = await service.get_metrics_by_device(1, hours=24, metric_names=["cpu_usage"])
        
        assert len(metrics) == 5
        assert metrics == mock_metrics
    
    @pytest.mark.asyncio
    async def test_get_metrics_by_name(self, mock_db_session):
        """Test getting metrics by name"""
        service = MetricsQueryService(mock_db_session)
        
        mock_metrics = [Mock(spec=Metric) for _ in range(3)]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        metrics = await service.get_metrics_by_name("cpu_usage", device_ids=[1, 2], hours=24)
        
        assert len(metrics) == 3
        assert metrics == mock_metrics
    
    @pytest.mark.asyncio
    async def test_get_latest_metrics(self, mock_db_session):
        """Test getting latest metrics"""
        service = MetricsQueryService(mock_db_session)
        
        mock_metrics = [Mock(spec=Metric) for _ in range(10)]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        metrics = await service.get_latest_metrics(1, metric_names=["cpu_usage"], limit=10)
        
        assert len(metrics) == 10
        assert metrics == mock_metrics
    
    @pytest.mark.asyncio
    async def test_get_metrics_summary(self, mock_db_session):
        """Test getting metrics summary"""
        service = MetricsQueryService(mock_db_session)
        
        # Mock database results for summary
        mock_db_session.execute.return_value.scalar.side_effect = [
            100,  # total_metrics
            0.85  # avg_quality
        ]
        mock_db_session.execute.return_value.all.return_value = [
            (MetricCategory.SYSTEM, 60),
            (MetricCategory.NETWORK, 40)
        ]
        mock_db_session.execute.return_value.first.return_value = (
            datetime.now() - timedelta(hours=24),
            datetime.now()
        )
        
        summary = await service.get_metrics_summary(1, hours=24)
        
        assert summary["device_id"] == 1
        assert summary["total_metrics"] == 100
        assert summary["average_quality"] == 0.85
        assert "SYSTEM" in summary["category_breakdown"]
        assert "NETWORK" in summary["category_breakdown"]
    
    @pytest.mark.asyncio
    async def test_search_metrics(self, mock_db_session):
        """Test metrics search"""
        service = MetricsQueryService(mock_db_session)
        
        mock_metrics = [Mock(spec=Metric) for _ in range(5)]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        results = await service.search_metrics("cpu", device_ids=[1], limit=10)
        
        assert len(results) == 5
        assert results == mock_metrics
    
    @pytest.mark.asyncio
    async def test_get_metrics_trends(self, mock_db_session):
        """Test getting metrics trends"""
        service = MetricsQueryService(mock_db_session)
        
        # Mock metrics for trend calculation
        base_time = datetime.now() - timedelta(hours=24)
        mock_metrics = []
        for i in range(10):
            metric = Mock(spec=Metric)
            metric.value = 50.0 + i
            metric.timestamp = base_time + timedelta(hours=i)
            mock_metrics.append(metric)
        
        service.get_metrics_by_device = AsyncMock(return_value=mock_metrics)
        
        trends = await service.get_metrics_trends(1, "cpu_usage", hours=24, interval_minutes=60)
        
        assert trends["device_id"] == 1
        assert trends["metric_name"] == "cpu_usage"
        assert len(trends["trends"]) > 0
        assert "statistics" in trends
    
    @pytest.mark.asyncio
    async def test_get_metrics_by_quality(self, mock_db_session):
        """Test getting metrics by quality level"""
        service = MetricsQueryService(mock_db_session)
        
        mock_metrics = [Mock(spec=Metric) for _ in range(5)]
        mock_db_session.execute.return_value.scalars.return_value.all.return_value = mock_metrics
        
        metrics = await service.get_metrics_by_quality("excellent", device_ids=[1], hours=24)
        
        assert len(metrics) == 5
        assert metrics == mock_metrics
    
    @pytest.mark.asyncio
    async def test_clear_cache(self, mock_db_session):
        """Test cache clearing"""
        service = MetricsQueryService(mock_db_session)
        service._query_cache = {"test": "data"}
        service._cache_timestamps = {"test": datetime.now()}
        
        await service.clear_cache()
        
        assert service._query_cache == {}
        assert service._cache_timestamps == {}
    
    @pytest.mark.asyncio
    async def test_get_query_stats(self, mock_db_session):
        """Test query statistics retrieval"""
        service = MetricsQueryService(mock_db_session)
        
        # Mock database results
        mock_db_session.execute.return_value.scalar.side_effect = [
            1000,  # total_metrics
            {"hot": 500, "warm": 300, "cold": 200}  # storage_tier_breakdown
        ]
        
        stats = await service.get_query_stats()
        
        assert stats["total_metrics"] == 1000
        assert "hot" in stats["storage_tier_breakdown"]
        assert "warm" in stats["storage_tier_breakdown"]
        assert "cold" in stats["storage_tier_breakdown"]
        assert "config" in stats

@pytest.mark.asyncio
async def test_integration_metrics_pipeline(mock_db_session, mock_device, mock_credentials, mock_metric):
    """Integration test for the complete metrics pipeline"""
    
    # Initialize all services
    collection_service = MetricsCollectionService(mock_db_session)
    storage_service = MetricsStorageService(mock_db_session)
    processing_service = MetricsProcessingService(mock_db_session)
    query_service = MetricsQueryService(mock_db_session)
    
    # Mock collection service methods
    collection_service._get_device = AsyncMock(return_value=mock_device)
    collection_service._get_device_credentials = AsyncMock(return_value=mock_credentials)
    collection_service._collect_snmp_metrics = AsyncMock(return_value=[mock_metric])
    collection_service._store_metrics = AsyncMock(return_value=1)
    
    # Mock processing service methods
    processing_service._validate_metric = AsyncMock(return_value=Mock(spec=ValidationResult, is_valid=True, confidence_score=0.9))
    processing_service._transform_metric = AsyncMock()
    processing_service._assess_metric_quality = AsyncMock(return_value=Mock(spec=QualityAssessment, overall_score=0.85))
    
    # Mock storage service methods
    storage_service._preprocess_metrics = AsyncMock(return_value=[mock_metric])
    storage_service._post_storage_optimization = AsyncMock()
    
    # Mock query service methods
    mock_db_session.execute.return_value.scalar.side_effect = [1]  # total_count
    mock_db_session.execute.return_value.scalars.return_value.all.return_value = [mock_metric]
    
    # Test complete pipeline
    # 1. Collect metrics
    collection_result = await collection_service.collect_device_metrics(1)
    assert collection_result.status == "success"
    
    # 2. Process metrics
    processed_metrics = await processing_service.process_metrics([mock_metric])
    assert len(processed_metrics) == 1
    assert processed_metrics[0].is_valid is True
    
    # 3. Store metrics
    storage_result = await storage_service.store_metrics(processed_metrics)
    assert storage_result.status == "success"
    
    # 4. Query metrics
    filters = QueryFilter(device_ids=[1])
    query_result = await query_service.query_metrics(filters)
    assert len(query_result.metrics) == 1
    assert query_result.total_count == 1
    
    # Verify the complete flow works
    assert collection_result.metrics_count == 1
    assert storage_result.stored_count == 1
    assert query_result.metrics[0].id == mock_metric.id
