"""
CHM Metric Model
Time-series performance metrics storage model
"""

from sqlalchemy import Column, Integer, String, Boolean, DateTime, Float, JSON, Text, Enum, Index, BigInteger
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
import enum

from ..core.database import Base

class MetricType(str, enum.Enum):
    """Metric type enumeration"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    RATE = "rate"
    DELTA = "delta"

class MetricCategory(str, enum.Enum):
    """Metric category enumeration"""
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"
    CUSTOM = "custom"
    PERFORMANCE = "performance"
    SECURITY = "security"
    AVAILABILITY = "availability"

class CollectionMethod(str, enum.Enum):
    """How the metric was collected"""
    SNMP = "snmp"
    SSH = "ssh"
    HTTP = "http"
    AGENT = "agent"
    PUSH = "push"
    PULL = "pull"
    SCRIPT = "script"

class MetricQuality(str, enum.Enum):
    """Quality level of the collected metric"""
    EXCELLENT = "excellent"      # 0.9-1.0
    GOOD = "good"                # 0.7-0.89
    FAIR = "fair"                # 0.5-0.69
    POOR = "poor"                # 0.3-0.49
    UNRELIABLE = "unreliable"    # 0.0-0.29

class Metric(Base):
    """Enhanced metric model for storing time-series performance data"""
    
    __tablename__ = "metrics"
    
    # Primary key
    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(UUID(as_uuid=True), unique=True, index=True, default=uuid.uuid4)
    
    # Metric identification
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    metric_type = Column(Enum(MetricType), nullable=False)
    category = Column(Enum(MetricCategory), nullable=False, default=MetricCategory.SYSTEM)
    
    # Device relationship
    device_id = Column(Integer, nullable=False, index=True)
    device = relationship("Device", back_populates="metrics")
    
    # Metric value and metadata
    value = Column(Float, nullable=False)
    unit = Column(String(20), nullable=True)  # e.g., "bytes", "percent", "seconds"
    labels = Column(JSON, nullable=True)  # Key-value pairs for filtering
    
    # Enhanced collection metadata
    collection_method = Column(Enum(CollectionMethod), nullable=True, index=True)
    collection_source = Column(String(100), nullable=True)  # e.g., "snmp_oid", "ssh_command", "script_path"
    collection_duration_ms = Column(Float, nullable=True)  # How long collection took
    collection_retries = Column(Integer, default=0, nullable=False)
    
    # Quality and validation
    quality_score = Column(Float, nullable=True)  # 0.0 to 1.0
    quality_level = Column(Enum(MetricQuality), nullable=True, index=True)
    is_valid = Column(Boolean, default=True, nullable=False)
    confidence = Column(Float, nullable=True)  # 0.0 to 1.0
    error_margin = Column(Float, nullable=True)
    validation_errors = Column(ARRAY(String), nullable=True)
    
    # Aggregation and trending
    previous_value = Column(Float, nullable=True)
    change_rate = Column(Float, nullable=True)  # Rate of change per second
    trend_direction = Column(String(20), nullable=True)  # "increasing", "decreasing", "stable"
    aggregation_window = Column(Integer, nullable=True)  # Seconds for aggregation
    
    # Performance optimization
    compression_ratio = Column(Float, nullable=True)
    storage_tier = Column(String(20), default="hot", nullable=False)  # hot, warm, cold
    retention_days = Column(Integer, nullable=True)
    
    # Timestamps
    timestamp = Column(DateTime, nullable=False, index=True)
    collected_at = Column(DateTime, default=func.now(), nullable=False)
    processed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    
    # Raw data and metadata
    raw_value = Column(Text, nullable=True)  # Original value before conversion
    metadata = Column(JSON, nullable=True)  # Additional collection metadata
    tags = Column(ARRAY(String), nullable=True, index=True)  # Searchable tags
    
    # Audit fields
    created_at = Column(DateTime, default=func.now(), nullable=False)
    created_by = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Soft delete
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime, nullable=True)
    deleted_by = Column(Integer, nullable=True)
    
    # Enhanced composite indexes for efficient querying
    __table_args__ = (
        Index('idx_metrics_device_timestamp', 'device_id', 'timestamp'),
        Index('idx_metrics_name_timestamp', 'name', 'timestamp'),
        Index('idx_metrics_category_timestamp', 'category', 'timestamp'),
        Index('idx_metrics_quality_timestamp', 'quality_level', 'timestamp'),
        Index('idx_metrics_method_timestamp', 'collection_method', 'timestamp'),
        Index('idx_metrics_storage_tier', 'storage_tier', 'timestamp'),
        Index('idx_metrics_expires_at', 'expires_at', 'timestamp'),
    )
    
    def __repr__(self):
        return f"<Metric(id={self.id}, name='{self.name}', value={self.value}, timestamp='{self.timestamp}')>"
    
    @property
    def age_seconds(self) -> float:
        """Get age of metric in seconds"""
        return (datetime.now() - self.timestamp).total_seconds()
    
    @property
    def age_minutes(self) -> float:
        """Get age of metric in minutes"""
        return self.age_seconds / 60.0
    
    @property
    def age_hours(self) -> float:
        """Get age of metric in hours"""
        return self.age_seconds / 3600.0
    
    @property
    def formatted_value(self) -> str:
        """Get formatted value with unit"""
        if self.unit:
            return f"{self.value} {self.unit}"
        return str(self.value)
    
    @property
    def is_recent(self) -> bool:
        """Check if metric is recent (less than 1 hour old)"""
        return self.age_hours < 1.0
    
    @property
    def is_stale(self) -> bool:
        """Check if metric is stale (more than 24 hours old)"""
        return self.age_hours > 24.0
    
    @property
    def is_expired(self) -> bool:
        """Check if metric has expired"""
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at
    
    @property
    def needs_compression(self) -> bool:
        """Check if metric should be compressed (older than 1 day)"""
        return self.age_hours > 24.0
    
    @property
    def should_archive(self) -> bool:
        """Check if metric should be archived (older than 30 days)"""
        return self.age_hours > 720.0  # 30 days
    
    @property
    def quality_description(self) -> str:
        """Get human-readable quality description"""
        if self.quality_score is None:
            return "unknown"
        
        if self.quality_score >= 0.9:
            return "excellent"
        elif self.quality_score >= 0.7:
            return "good"
        elif self.quality_score >= 0.5:
            return "fair"
        elif self.quality_score >= 0.3:
            return "poor"
        else:
            return "unreliable"
    
    def calculate_change_rate(self, previous_metric: Optional['Metric'] = None) -> Optional[float]:
        """Calculate rate of change if previous value is available"""
        if previous_metric and previous_metric.timestamp < self.timestamp:
            time_diff = (self.timestamp - previous_metric.timestamp).total_seconds()
            if time_diff > 0:
                value_diff = self.value - previous_metric.value
                return value_diff / time_diff
        return None
    
    def update_quality_score(self, score: float):
        """Update quality score and level"""
        self.quality_score = max(0.0, min(1.0, score))
        
        if self.quality_score >= 0.9:
            self.quality_level = MetricQuality.EXCELLENT
        elif self.quality_score >= 0.7:
            self.quality_level = MetricQuality.GOOD
        elif self.quality_score >= 0.5:
            self.quality_level = MetricQuality.FAIR
        elif self.quality_score >= 0.3:
            self.quality_level = MetricQuality.POOR
        else:
            self.quality_level = MetricQuality.UNRELIABLE
    
    def add_tag(self, tag: str):
        """Add a tag to the metric"""
        if not self.tags:
            self.tags = []
        if tag not in self.tags:
            self.tags.append(tag)
    
    def remove_tag(self, tag: str):
        """Remove a tag from the metric"""
        if self.tags and tag in self.tags:
            self.tags.remove(tag)
    
    def to_dict(self) -> dict:
        """Convert metric to dictionary"""
        return {
            "id": self.id,
            "uuid": str(self.uuid),
            "name": self.name,
            "description": self.description,
            "metric_type": self.metric_type.value,
            "category": self.category.value,
            "device_id": self.device_id,
            "value": self.value,
            "unit": self.unit,
            "labels": self.labels,
            "collection_method": self.collection_method.value if self.collection_method else None,
            "collection_source": self.collection_source,
            "collection_duration_ms": self.collection_duration_ms,
            "quality_score": self.quality_score,
            "quality_level": self.quality_level.value if self.quality_level else None,
            "is_valid": self.is_valid,
            "confidence": self.confidence,
            "error_margin": self.error_margin,
            "change_rate": self.change_rate,
            "trend_direction": self.trend_direction,
            "storage_tier": self.storage_tier,
            "timestamp": self.timestamp.isoformat(),
            "collected_at": self.collected_at.isoformat(),
            "processed_at": self.processed_at.isoformat() if self.processed_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "raw_value": self.raw_value,
            "metadata": self.metadata,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
            "age_seconds": self.age_seconds,
            "age_minutes": self.age_minutes,
            "age_hours": self.age_hours,
            "formatted_value": self.formatted_value,
            "is_recent": self.is_recent,
            "is_stale": self.is_stale,
            "is_expired": self.is_expired,
            "quality_description": self.quality_description
        }
    
    @classmethod
    def create_system_metric(
        cls,
        device_id: int,
        name: str,
        value: float,
        unit: Optional[str] = None,
        labels: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        collection_method: Optional[CollectionMethod] = None,
        collection_source: Optional[str] = None
    ) -> 'Metric':
        """Create a system metric"""
        return cls(
            device_id=device_id,
            name=name,
            value=value,
            unit=unit,
            labels=labels,
            timestamp=timestamp or datetime.now(),
            metric_type=MetricType.GAUGE,
            category=MetricCategory.SYSTEM,
            collection_method=collection_method,
            collection_source=collection_source
        )
    
    @classmethod
    def create_network_metric(
        cls,
        device_id: int,
        name: str,
        value: float,
        unit: Optional[str] = None,
        labels: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        collection_method: Optional[CollectionMethod] = None,
        collection_source: Optional[str] = None
    ) -> 'Metric':
        """Create a network metric"""
        return cls(
            device_id=device_id,
            name=name,
            value=value,
            unit=unit,
            labels=labels,
            timestamp=timestamp or datetime.now(),
            metric_type=MetricType.GAUGE,
            category=MetricCategory.NETWORK,
            collection_method=collection_method,
            collection_source=collection_source
        )
    
    @classmethod
    def create_counter_metric(
        cls,
        device_id: int,
        name: str,
        value: float,
        unit: Optional[str] = None,
        labels: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        collection_method: Optional[CollectionMethod] = None,
        collection_source: Optional[str] = None
    ) -> 'Metric':
        """Create a counter metric"""
        return cls(
            device_id=device_id,
            name=name,
            value=value,
            unit=unit,
            labels=labels,
            timestamp=timestamp or datetime.now(),
            metric_type=MetricType.COUNTER,
            category=MetricCategory.SYSTEM,
            collection_method=collection_method,
            collection_source=collection_source
        )
    
    @classmethod
    def create_performance_metric(
        cls,
        device_id: int,
        name: str,
        value: float,
        unit: Optional[str] = None,
        labels: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None,
        collection_method: Optional[CollectionMethod] = None,
        collection_source: Optional[str] = None
    ) -> 'Metric':
        """Create a performance metric"""
        return cls(
            device_id=device_id,
            name=name,
            value=value,
            unit=unit,
            labels=labels,
            timestamp=timestamp or datetime.now(),
            metric_type=MetricType.GAUGE,
            category=MetricCategory.PERFORMANCE,
            collection_method=collection_method,
            collection_source=collection_source
        )
