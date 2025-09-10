"""
Result objects for CHM application to replace None returns with meaningful data
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class ResultStatus(Enum):
    """Status enumeration for operation results"""
    SUCCESS = "success"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class HealthLevel(Enum):
    """Health level enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    UNKNOWN = "unknown"
    MAINTENANCE = "maintenance"


@dataclass
class FallbackData:
    """Fallback data when primary operations fail"""
    
    data: Any = None
    source: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    validity_period: timedelta = field(default_factory=lambda: timedelta(hours=1))
    confidence: float = 0.0
    is_stale: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if fallback data is still valid"""
        return datetime.utcnow() - self.timestamp < self.validity_period
    
    def mark_stale(self):
        """Mark data as stale"""
        self.is_stale = True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'data': self.data,
            'source': self.source,
            'timestamp': self.timestamp.isoformat(),
            'validity_period_seconds': self.validity_period.total_seconds(),
            'confidence': self.confidence,
            'is_stale': self.is_stale,
            'metadata': self.metadata
        }


@dataclass
class HealthStatus:
    """Health status information for services and operations"""
    
    status: HealthLevel = HealthLevel.UNKNOWN
    details: Dict[str, Any] = field(default_factory=dict)
    last_check: datetime = field(default_factory=datetime.utcnow)
    degradation_reason: Optional[str] = None
    capabilities: List[str] = field(default_factory=list)
    fallback_available: bool = False
    recovery_attempts: int = 0
    next_check: Optional[datetime] = None
    health_score: float = 0.0
    
    def update_status(self, new_status: HealthLevel, reason: str = None):
        """Update health status"""
        self.status = new_status
        self.degradation_reason = reason
        self.last_check = datetime.utcnow()
        
        if new_status == HealthLevel.HEALTHY:
            self.health_score = 1.0
            self.recovery_attempts = 0
        elif new_status == HealthLevel.DEGRADED:
            self.health_score = 0.5
        elif new_status == HealthLevel.DOWN:
            self.health_score = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'status': self.status.value,
            'details': self.details,
            'last_check': self.last_check.isoformat(),
            'degradation_reason': self.degradation_reason,
            'capabilities': self.capabilities,
            'fallback_available': self.fallback_available,
            'recovery_attempts': self.recovery_attempts,
            'next_check': self.next_check.isoformat() if self.next_check else None,
            'health_score': self.health_score
        }


@dataclass
class DiscoveryResult:
    """Structured result object for discovery operations"""
    
    success: bool = False
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    fallback_data: Optional[FallbackData] = None
    health_status: Optional[HealthStatus] = None
    suggestions: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    attempts: int = 0
    recovery_attempts: int = 0
    discovery_methods: List[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'error_code': self.error_code,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'health_status': self.health_status.to_dict() if self.health_status else None,
            'suggestions': self.suggestions,
            'timestamp': self.timestamp.isoformat(),
            'attempts': self.attempts,
            'recovery_attempts': self.recovery_attempts,
            'discovery_methods': self.discovery_methods,
            'confidence': self.confidence,
            'metadata': self.metadata
        }


@dataclass
class DeviceInfo:
    """Enhanced device information with fallback capabilities"""
    
    ip_address: str
    hostname: Optional[str] = None
    device_type: str = "unknown"
    vendor: str = "unknown"
    model: str = "unknown"
    capabilities: List[str] = field(default_factory=list)
    discovery_methods: List[str] = field(default_factory=list)
    fallback_data: Dict[str, Any] = field(default_factory=dict)
    health_indicators: Dict[str, Any] = field(default_factory=dict)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    discovery_confidence: float = 0.0
    status: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Post-initialization setup"""
        if not self.hostname:
            self.hostname = f"unknown-{self.ip_address.replace('.', '-')}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'device_type': self.device_type,
            'vendor': self.vendor,
            'model': self.model,
            'capabilities': self.capabilities,
            'discovery_methods': self.discovery_methods,
            'fallback_data': self.fallback_data,
            'health_indicators': self.health_indicators,
            'last_seen': self.last_seen.isoformat(),
            'discovery_confidence': self.discovery_confidence,
            'status': self.status,
            'metadata': self.metadata
        }


@dataclass
class ProtocolResult:
    """Result from protocol operations (SSH, SNMP, REST, etc.)"""
    
    protocol: str
    success: bool = False
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    response_time: Optional[float] = None
    retry_count: int = 0
    fallback_used: bool = False
    fallback_data: Optional[FallbackData] = None
    health_status: Optional[HealthStatus] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'protocol': self.protocol,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'error_code': self.error_code,
            'response_time': self.response_time,
            'retry_count': self.retry_count,
            'fallback_used': self.fallback_used,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'health_status': self.health_status.to_dict() if self.health_status else None,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class MonitoringResult:
    """Result from monitoring operations"""
    
    device_id: str
    metric_type: str
    success: bool = False
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    collection_time: Optional[datetime] = None
    fallback_data: Optional[FallbackData] = None
    health_status: Optional[HealthStatus] = None
    thresholds: Dict[str, Any] = field(default_factory=dict)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'device_id': self.device_id,
            'metric_type': self.metric_type,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'error_code': self.error_code,
            'collection_time': self.collection_time.isoformat() if self.collection_time else None,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'health_status': self.health_status.to_dict() if self.health_status else None,
            'thresholds': self.thresholds,
            'alerts': self.alerts,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class AuthenticationResult:
    """Result from authentication operations"""
    
    success: bool = False
    authenticated: bool = False
    user_id: Optional[str] = None
    username: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    error: Optional[str] = None
    error_code: Optional[str] = None
    auth_method: Optional[str] = None
    fallback_method_used: bool = False
    session_info: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'success': self.success,
            'authenticated': self.authenticated,
            'user_id': self.user_id,
            'username': self.username,
            'permissions': self.permissions,
            'roles': self.roles,
            'error': self.error,
            'error_code': self.error_code,
            'auth_method': self.auth_method,
            'fallback_method_used': self.fallback_method_used,
            'session_info': self.session_info,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class DatabaseResult:
    """Result from database operations"""
    
    operation: str
    success: bool = False
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    affected_rows: int = 0
    execution_time: Optional[float] = None
    connection_info: Dict[str, Any] = field(default_factory=dict)
    fallback_used: bool = False
    fallback_data: Optional[FallbackData] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'success': self.success,
            'operation': self.operation,
            'data': self.data,
            'error': self.error,
            'error_code': self.error_code,
            'affected_rows': self.affected_rows,
            'execution_time': self.execution_time,
            'connection_info': self.connection_info,
            'fallback_used': self.fallback_used,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ConfigurationResult:
    """Result from configuration operations"""
    
    operation: str
    success: bool = False
    config_key: Optional[str] = None
    config_value: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    validation_errors: List[str] = field(default_factory=list)
    fallback_value_used: bool = False
    fallback_data: Optional[FallbackData] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'success': self.success,
            'operation': self.operation,
            'config_key': self.config_key,
            'config_value': self.config_value,
            'error': self.error,
            'error_code': self.error_code,
            'validation_errors': self.validation_errors,
            'fallback_value_used': self.fallback_value_used,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


@dataclass
class ServiceResult:
    """Result from service operations"""
    
    service_name: str
    success: bool = False
    data: Any = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    service_status: str = "unknown"
    health_status: Optional[HealthStatus] = None
    fallback_service_used: bool = False
    fallback_data: Optional[FallbackData] = None
    response_time: Optional[float] = None
    retry_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation"""
        return {
            'service_name': self.service_name,
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'error_code': self.error_code,
            'service_status': self.service_status,
            'health_status': self.health_status.to_dict() if self.health_status else None,
            'fallback_service_used': self.fallback_service_used,
            'fallback_data': self.fallback_data.to_dict() if self.fallback_data else None,
            'response_time': self.response_time,
            'retry_count': self.retry_count,
            'metadata': self.metadata,
            'timestamp': self.timestamp.isoformat()
        }


def create_success_result(data: Any = None, **kwargs) -> DiscoveryResult:
    """Create a successful result object"""
    return DiscoveryResult(
        success=True,
        data=data,
        health_status=HealthStatus(status=HealthLevel.HEALTHY),
        **kwargs
    )


def create_failure_result(error: str, error_code: str = None, suggestions: List[str] = None, 
                         fallback_data: FallbackData = None, **kwargs) -> DiscoveryResult:
    """Create a failure result object with fallback data"""
    return DiscoveryResult(
        success=False,
        error=error,
        error_code=error_code,
        suggestions=suggestions or [],
        fallback_data=fallback_data,
        health_status=HealthStatus(status=HealthLevel.DOWN),
        **kwargs
    )


def create_partial_success_result(data: Any, fallback_data: FallbackData = None, 
                                health_status: HealthStatus = None, **kwargs) -> DiscoveryResult:
    """Create a partial success result object"""
    if health_status is None:
        health_status = HealthStatus(status=HealthLevel.DEGRADED)
    
    return DiscoveryResult(
        success=True,
        data=data,
        fallback_data=fallback_data,
        health_status=health_status,
        **kwargs
    )
