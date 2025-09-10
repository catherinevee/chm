"""
Comprehensive tests for CHM Result Objects
Tests all result object classes and their methods
"""

import pytest
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

def test_operation_status_enum():
    """Test OperationStatus enum values"""
    from models.result_objects import OperationStatus
    
    # Test all enum values
    assert OperationStatus.SUCCESS == "success"
    assert OperationStatus.PARTIAL_SUCCESS == "partial_success"
    assert OperationStatus.FAILED == "failed"
    assert OperationStatus.TIMEOUT == "timeout"
    assert OperationStatus.UNAUTHORIZED == "unauthorized"
    assert OperationStatus.NOT_FOUND == "not_found"
    
    print("PASS: OperationStatus enum works correctly")

def test_device_status_enum():
    """Test DeviceStatus enum values"""
    from models.result_objects import DeviceStatus
    
    # Test all enum values
    assert DeviceStatus.ONLINE == "online"
    assert DeviceStatus.OFFLINE == "offline"
    assert DeviceStatus.DEGRADED == "degraded"
    assert DeviceStatus.MAINTENANCE == "maintenance"
    assert DeviceStatus.UNKNOWN == "unknown"
    assert DeviceStatus.ERROR == "error"
    
    print("PASS: DeviceStatus enum works correctly")

def test_base_result():
    """Test BaseResult dataclass"""
    from models.result_objects import BaseResult, OperationStatus
    
    # Test with timestamp
    timestamp = datetime.now()
    result = BaseResult(
        status=OperationStatus.SUCCESS,
        timestamp=timestamp,
        operation="test_operation",
        message="Test message"
    )
    
    assert result.status == OperationStatus.SUCCESS
    assert result.timestamp == timestamp
    assert result.operation == "test_operation"
    assert result.message == "Test message"
    
    # Test without timestamp (should auto-set)
    result2 = BaseResult(
        status=OperationStatus.FAILED,
        timestamp=None,
        operation="test_operation2",
        message="Test message2"
    )
    
    assert result2.status == OperationStatus.FAILED
    assert result2.timestamp is not None
    assert isinstance(result2.timestamp, datetime)
    
    print("PASS: BaseResult works correctly")

def test_device_status_result_success():
    """Test DeviceStatusResult success creation"""
    from models.result_objects import DeviceStatusResult, DeviceStatus, OperationStatus
    
    # Test success creation
    result = DeviceStatusResult.success(
        device_id=1,
        status=DeviceStatus.ONLINE,
        response_time=150.5
    )
    
    assert result.status == OperationStatus.SUCCESS
    assert result.device_id == 1
    assert result.device_status == DeviceStatus.ONLINE
    assert result.response_time_ms == 150.5
    assert result.operation == "device_status_check"
    assert "successfully" in result.message
    assert result.timestamp is not None
    assert result.error is None
    assert result.fallback_data is None
    
    print("PASS: DeviceStatusResult success works correctly")

def test_device_status_result_failure():
    """Test DeviceStatusResult failure creation"""
    from models.result_objects import DeviceStatusResult, DeviceStatus, OperationStatus
    
    # Test failure creation
    fallback_data = {"status": "cached", "last_check": "2023-01-01"}
    result = DeviceStatusResult.failure(
        device_id=2,
        error="Connection timeout",
        fallback_data=fallback_data
    )
    
    assert result.status == OperationStatus.FAILED
    assert result.device_id == 2
    assert result.device_status == DeviceStatus.UNKNOWN
    assert result.error == "Connection timeout"
    assert result.fallback_data == fallback_data
    assert result.operation == "device_status_check"
    assert "failed" in result.message
    assert result.timestamp is not None
    
    # Test failure without fallback data
    result2 = DeviceStatusResult.failure(device_id=3, error="Network error")
    assert result2.fallback_data is not None
    assert "status" in result2.fallback_data
    assert "last_check" in result2.fallback_data
    
    print("PASS: DeviceStatusResult failure works correctly")

def test_metrics_collection_result():
    """Test MetricsCollectionResult creation"""
    from models.result_objects import MetricsCollectionResult, OperationStatus
    
    # Test success
    result = MetricsCollectionResult.success(device_id=1, metrics_count=25)
    assert result.status == OperationStatus.SUCCESS
    assert result.device_id == 1
    assert result.metrics_count == 25
    assert result.operation == "metrics_collection"
    assert result.collection_time is not None
    assert result.error is None
    
    # Test failure
    fallback_data = {"last_collection": "2023-01-01"}
    result2 = MetricsCollectionResult.failure(
        device_id=2,
        error="Collection failed",
        fallback_data=fallback_data
    )
    assert result2.status == OperationStatus.FAILED
    assert result2.device_id == 2
    assert result2.metrics_count == 0
    assert result2.error == "Collection failed"
    assert result2.fallback_data == fallback_data
    
    print("PASS: MetricsCollectionResult works correctly")

def test_storage_result():
    """Test StorageResult creation"""
    from models.result_objects import StorageResult, OperationStatus
    
    # Test success
    result = StorageResult.success(stored_count=100, storage_size_bytes=1024)
    assert result.status == OperationStatus.SUCCESS
    assert result.stored_count == 100
    assert result.storage_size_bytes == 1024
    assert result.operation == "data_storage"
    assert result.error is None
    
    # Test failure
    fallback_data = {"storage_available": False}
    result2 = StorageResult.failure("Storage full", fallback_data)
    assert result2.status == OperationStatus.FAILED
    assert result2.stored_count == 0
    assert result2.error == "Storage full"
    assert result2.fallback_data == fallback_data
    
    print("PASS: StorageResult works correctly")

def test_alert_generation_result():
    """Test AlertGenerationResult creation"""
    from models.result_objects import AlertGenerationResult, OperationStatus
    
    # Test success
    result = AlertGenerationResult.success(alert_id=123, action="email_sent")
    assert result.status == OperationStatus.SUCCESS
    assert result.alert_id == 123
    assert result.action == "email_sent"
    assert result.operation == "alert_generation"
    assert result.error is None
    
    # Test failure
    result2 = AlertGenerationResult.failure("Email service down", "log_error")
    assert result2.status == OperationStatus.FAILED
    assert result2.alert_id is None
    assert result2.action == "log_error"
    assert result2.error == "Email service down"
    assert result2.fallback_data == {"action": "log_error"}
    
    print("PASS: AlertGenerationResult works correctly")

def test_discovery_result():
    """Test DiscoveryResult creation"""
    from models.result_objects import DiscoveryResult, OperationStatus
    
    # Test success
    devices = [{"id": 1, "ip": "192.168.1.1"}, {"id": 2, "ip": "192.168.1.2"}]
    result = DiscoveryResult.success(discovered_count=2, devices=devices)
    assert result.status == OperationStatus.SUCCESS
    assert result.discovered_count == 2
    assert result.devices == devices
    assert result.operation == "network_discovery"
    assert "Discovered 2 devices" in result.message
    assert result.error is None
    
    # Test failure
    fallback_data = {"last_discovery": "2023-01-01"}
    result2 = DiscoveryResult.failure("Network unreachable", fallback_data)
    assert result2.status == OperationStatus.FAILED
    assert result2.discovered_count == 0
    assert result2.devices == []
    assert result2.error == "Network unreachable"
    assert result2.fallback_data == fallback_data
    
    print("PASS: DiscoveryResult works correctly")

def test_correlation_result():
    """Test CorrelationResult creation"""
    from models.result_objects import CorrelationResult, OperationStatus
    
    # Test success
    result = CorrelationResult.success(group_id=456, correlated_count=3)
    assert result.status == OperationStatus.SUCCESS
    assert result.group_id == 456
    assert result.correlated_count == 3
    assert result.operation == "alert_correlation"
    assert "Correlated 3 alerts" in result.message
    assert result.error is None
    
    # Test failure
    fallback_data = {"correlation_available": False}
    result2 = CorrelationResult.failure("Correlation engine down", fallback_data)
    assert result2.status == OperationStatus.FAILED
    assert result2.group_id is None
    assert result2.correlated_count == 1
    assert result2.error == "Correlation engine down"
    assert result2.fallback_data == fallback_data
    
    print("PASS: CorrelationResult works correctly")

def test_access_result():
    """Test AccessResult creation"""
    from models.result_objects import AccessResult, OperationStatus
    
    # Test success
    result = AccessResult.success("User has admin privileges")
    assert result.status == OperationStatus.SUCCESS
    assert result.granted == True
    assert result.reason == "User has admin privileges"
    assert result.operation == "access_control"
    assert result.error is None
    
    # Test denied
    fallback_data = {"access_level": "read_only"}
    result2 = AccessResult.denied("Insufficient permissions", fallback_data)
    assert result2.status == OperationStatus.UNAUTHORIZED
    assert result2.granted == False
    assert result2.reason == "Insufficient permissions"
    assert result2.error is None
    assert result2.fallback_data == fallback_data
    
    print("PASS: AccessResult works correctly")

def test_collection_result():
    """Test CollectionResult creation"""
    from models.result_objects import CollectionResult, OperationStatus
    
    # Test success (all successful)
    failed_devices = []
    result = CollectionResult.success(successful_count=10, failed_count=0, failed_devices=failed_devices)
    assert result.status == OperationStatus.SUCCESS
    assert result.successful_count == 10
    assert result.failed_count == 0
    assert result.failed_devices == []
    assert result.operation == "batch_collection"
    assert "10 success, 0 failed" in result.message
    
    # Test partial success
    failed_devices = [(1, "timeout"), (2, "connection_error")]
    result2 = CollectionResult.success(successful_count=8, failed_count=2, failed_devices=failed_devices)
    assert result2.status == OperationStatus.PARTIAL_SUCCESS
    assert result2.successful_count == 8
    assert result2.failed_count == 2
    assert result2.failed_devices == failed_devices
    
    # Test failure
    partial_results = [{"device": 1, "status": "partial"}]
    result3 = CollectionResult.failure("Complete failure", partial_results)
    assert result3.status == OperationStatus.FAILED
    assert result3.successful_count == 0
    assert result3.failed_count == 0
    assert result3.failed_devices == []
    assert result3.partial_results == partial_results
    assert result3.error == "Complete failure"
    
    print("PASS: CollectionResult works correctly")

def test_optimization_result():
    """Test OptimizationResult creation"""
    from models.result_objects import OptimizationResult, OperationStatus
    
    # Test success
    result = OptimizationResult.success(
        partitions_created=5,
        data_compressed=1000,
        storage_saved=500
    )
    assert result.status == OperationStatus.SUCCESS
    assert result.partitions_created == 5
    assert result.data_compressed == 1000
    assert result.storage_saved == 500
    assert result.operation == "storage_optimization"
    assert "5 partitions" in result.message
    assert "1000 compressed" in result.message
    assert "500 saved" in result.message
    assert result.error is None
    
    # Test failure
    result2 = OptimizationResult.failure("Disk space insufficient")
    assert result2.status == OperationStatus.FAILED
    assert result2.partitions_created == 0
    assert result2.data_compressed == 0
    assert result2.storage_saved == 0
    assert result2.error == "Disk space insufficient"
    assert result2.fallback_data == {"optimization_available": False}
    
    print("PASS: OptimizationResult works correctly")

def test_result_objects_edge_cases():
    """Test edge cases and error handling"""
    from models.result_objects import (
        BaseResult, DeviceStatusResult, MetricsCollectionResult,
        StorageResult, AlertGenerationResult, DiscoveryResult,
        CorrelationResult, AccessResult, CollectionResult, OptimizationResult,
        OperationStatus, DeviceStatus
    )
    
    # Test BaseResult with None timestamp
    result = BaseResult(
        status=OperationStatus.SUCCESS,
        timestamp=None,
        operation="test",
        message="test"
    )
    assert result.timestamp is not None
    assert isinstance(result.timestamp, datetime)
    
    # Test DeviceStatusResult with None response time
    result2 = DeviceStatusResult.success(device_id=1, status=DeviceStatus.ONLINE)
    assert result2.response_time_ms is None
    
    # Test StorageResult with None storage size
    result3 = StorageResult.success(stored_count=50)
    assert result3.storage_size_bytes is None
    
    # Test AlertGenerationResult with None alert_id
    result4 = AlertGenerationResult.success(alert_id=None, action="none")
    assert result4.alert_id is None
    
    # Test DiscoveryResult with empty devices list
    result5 = DiscoveryResult.success(discovered_count=0, devices=[])
    assert result5.discovered_count == 0
    assert result5.devices == []
    
    # Test CorrelationResult with None group_id
    result6 = CorrelationResult.success(group_id=None, correlated_count=1)
    assert result6.group_id is None
    
    # Test CollectionResult with None partial_results
    result7 = CollectionResult.failure("test error")
    assert result7.partial_results == []
    
    print("PASS: Result objects edge cases work correctly")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
