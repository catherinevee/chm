"""
CHM Result Objects
Structured return values for all operations with fallback mechanisms
"""

from typing import Any, Dict, List, Optional, Union
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

class OperationStatus(str, Enum):
    """Operation result status"""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAUTHORIZED = "unauthorized"
    NOT_FOUND = "not_found"

class DeviceStatus(str, Enum):
    """Device operational status"""
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"
    ERROR = "error"

@dataclass
class BaseResult:
    """Base result object with common fields"""
    status: OperationStatus
    timestamp: datetime
    operation: str
    message: str
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.utcnow()

@dataclass
class DeviceStatusResult(BaseResult):
    """Result of device status check operation"""
    device_id: int
    device_status: DeviceStatus
    response_time_ms: Optional[float] = None
    last_seen: Optional[datetime] = None
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, device_id: int, status: DeviceStatus, response_time: Optional[float] = None) -> "DeviceStatusResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="device_status_check",
            message="Device status retrieved successfully",
            device_id=device_id,
            device_status=status,
            response_time_ms=response_time,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, device_id: int, error: str, fallback_data: Optional[Dict[str, Any]] = None) -> "DeviceStatusResult":
        """Create failure result with fallback data"""
        return cls(
            status=OperationStatus.FAILED,
            operation="device_status_check",
            message=f"Device status check failed: {error}",
            device_id=device_id,
            device_status=DeviceStatus.UNKNOWN,
            error=error,
            fallback_data=fallback_data or {"status": "unknown", "last_check": datetime.utcnow().isoformat()},
            timestamp=datetime.utcnow()
        )

@dataclass
class MetricsCollectionResult(BaseResult):
    """Result of metrics collection operation"""
    device_id: int
    metrics_count: int
    collection_time: datetime
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, device_id: int, metrics_count: int) -> "MetricsCollectionResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="metrics_collection",
            message="Metrics collected successfully",
            device_id=device_id,
            metrics_count=metrics_count,
            collection_time=datetime.utcnow(),
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, device_id: int, error: str, fallback_data: Optional[Dict[str, Any]] = None) -> "MetricsCollectionResult":
        """Create failure result with fallback data"""
        return cls(
            status=OperationStatus.FAILED,
            operation="metrics_collection",
            message=f"Metrics collection failed: {error}",
            device_id=device_id,
            metrics_count=0,
            collection_time=datetime.utcnow(),
            error=error,
            fallback_data=fallback_data or {"last_collection": datetime.utcnow().isoformat()},
            timestamp=datetime.utcnow()
        )

@dataclass
class StorageResult(BaseResult):
    """Result of data storage operation"""
    stored_count: int
    storage_size_bytes: Optional[int] = None
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, stored_count: int, storage_size_bytes: Optional[int] = None) -> "StorageResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="data_storage",
            message="Data stored successfully",
            stored_count=stored_count,
            storage_size_bytes=storage_size_bytes,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, error: str, fallback_data: Optional[Dict[str, Any]] = None) -> "StorageResult":
        """Create failure result with fallback data"""
        return cls(
            status=OperationStatus.FAILED,
            operation="data_storage",
            message=f"Data storage failed: {error}",
            stored_count=0,
            error=error,
            fallback_data=fallback_data or {"storage_available": False},
            timestamp=datetime.utcnow()
        )

@dataclass
class AlertGenerationResult(BaseResult):
    """Result of alert generation operation"""
    alert_id: Optional[int] = None
    action: str = "none"
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, alert_id: int, action: str) -> "AlertGenerationResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="alert_generation",
            message="Alert generated successfully",
            alert_id=alert_id,
            action=action,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, error: str, fallback_action: str = "log_error") -> "AlertGenerationResult":
        """Create failure result with fallback action"""
        return cls(
            status=OperationStatus.FAILED,
            operation="alert_generation",
            message=f"Alert generation failed: {error}",
            action=fallback_action,
            error=error,
            fallback_data={"action": fallback_action},
            timestamp=datetime.utcnow()
        )

@dataclass
class DiscoveryResult(BaseResult):
    """Result of network discovery operation"""
    discovered_count: int
    devices: List[Dict[str, Any]]
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, discovered_count: int, devices: List[Dict[str, Any]]) -> "DiscoveryResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="network_discovery",
            message=f"Discovered {discovered_count} devices",
            discovered_count=discovered_count,
            devices=devices,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, error: str, fallback_data: Optional[Dict[str, Any]] = None) -> "DiscoveryResult":
        """Create failure result with fallback data"""
        return cls(
            status=OperationStatus.FAILED,
            operation="network_discovery",
            message=f"Network discovery failed: {error}",
            discovered_count=0,
            devices=[],
            error=error,
            fallback_data=fallback_data or {"last_discovery": datetime.utcnow().isoformat()},
            timestamp=datetime.utcnow()
        )

@dataclass
class CorrelationResult(BaseResult):
    """Result of alert correlation operation"""
    group_id: Optional[int] = None
    correlated_count: int = 1
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, group_id: Optional[int], correlated_count: int) -> "CorrelationResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="alert_correlation",
            message=f"Correlated {correlated_count} alerts",
            group_id=group_id,
            correlated_count=correlated_count,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, error: str, fallback_data: Optional[Dict[str, Any]] = None) -> "CorrelationResult":
        """Create failure result with fallback data"""
        return cls(
            status=OperationStatus.FAILED,
            operation="alert_correlation",
            message=f"Alert correlation failed: {error}",
            correlated_count=1,
            error=error,
            fallback_data=fallback_data or {"correlation_available": False},
            timestamp=datetime.utcnow()
        )

@dataclass
class AccessResult(BaseResult):
    """Result of access control check"""
    granted: bool
    reason: str
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, reason: str = "Access granted") -> "AccessResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="access_control",
            message=reason,
            granted=True,
            reason=reason,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def denied(cls, reason: str, fallback_data: Optional[Dict[str, Any]] = None) -> "AccessResult":
        """Create access denied result"""
        return cls(
            status=OperationStatus.UNAUTHORIZED,
            operation="access_control",
            message=f"Access denied: {reason}",
            granted=False,
            reason=reason,
            fallback_data=fallback_data or {"access_level": "none"},
            timestamp=datetime.utcnow()
        )

@dataclass
class CollectionResult(BaseResult):
    """Result of batch collection operation"""
    successful_count: int
    failed_count: int
    failed_devices: List[tuple]
    partial_results: Optional[List[Any]] = None
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, successful_count: int, failed_count: int, failed_devices: List[tuple]) -> "CollectionResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS if failed_count == 0 else OperationStatus.PARTIAL_SUCCESS,
            operation="batch_collection",
            message=f"Collection completed: {successful_count} success, {failed_count} failed",
            successful_count=successful_count,
            failed_count=failed_count,
            failed_devices=failed_devices,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, error: str, partial_results: Optional[List[Any]] = None) -> "CollectionResult":
        """Create failure result with partial results"""
        return cls(
            status=OperationStatus.FAILED,
            operation="batch_collection",
            message=f"Collection failed: {error}",
            successful_count=0,
            failed_count=0,
            failed_devices=[],
            partial_results=partial_results or [],
            error=error,
            fallback_data={"partial_results": partial_results or []},
            timestamp=datetime.utcnow()
        )

@dataclass
class OptimizationResult(BaseResult):
    """Result of storage optimization operation"""
    partitions_created: int = 0
    data_compressed: int = 0
    storage_saved: int = 0
    fallback_data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    @classmethod
    def success(cls, partitions_created: int, data_compressed: int, storage_saved: int) -> "OptimizationResult":
        """Create successful result"""
        return cls(
            status=OperationStatus.SUCCESS,
            operation="storage_optimization",
            message=f"Storage optimized: {partitions_created} partitions, {data_compressed} compressed, {storage_saved} saved",
            partitions_created=partitions_created,
            data_compressed=data_compressed,
            storage_saved=storage_saved,
            timestamp=datetime.utcnow()
        )
    
    @classmethod
    def failure(cls, error: str) -> "OptimizationResult":
        """Create failure result"""
        return cls(
            status=OperationStatus.FAILED,
            operation="storage_optimization",
            message=f"Storage optimization failed: {error}",
            error=error,
            fallback_data={"optimization_available": False},
            timestamp=datetime.utcnow()
        )
