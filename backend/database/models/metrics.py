"""
Metrics model for CHM
"""
from sqlalchemy import Column, String, Float, DateTime, Integer, JSON, Enum, ForeignKey, Index, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
import enum

from database.base import Base


class MetricType(enum.Enum):
    """Metric type enumeration"""
    # System metrics
    CPU_USAGE = "cpu_usage"
    MEMORY_USAGE = "memory_usage"
    DISK_USAGE = "disk_usage"
    TEMPERATURE = "temperature"
    POWER = "power"
    FAN_SPEED = "fan_speed"
    
    # Network metrics
    BANDWIDTH_IN = "bandwidth_in"
    BANDWIDTH_OUT = "bandwidth_out"
    PACKET_RATE_IN = "packet_rate_in"
    PACKET_RATE_OUT = "packet_rate_out"
    ERROR_RATE = "error_rate"
    DISCARD_RATE = "discard_rate"
    LATENCY = "latency"
    JITTER = "jitter"
    PACKET_LOSS = "packet_loss"
    
    # Interface metrics
    INTERFACE_UTILIZATION = "interface_utilization"
    INTERFACE_ERRORS = "interface_errors"
    INTERFACE_DISCARDS = "interface_discards"
    
    # Application metrics
    RESPONSE_TIME = "response_time"
    TRANSACTION_RATE = "transaction_rate"
    CONNECTION_COUNT = "connection_count"
    THROUGHPUT = "throughput"
    
    # Custom metrics
    CUSTOM = "custom"


class DeviceMetric(Base):
    """Time-series metrics data model"""
    __tablename__ = "device_metrics"
    __table_args__ = (
        Index("idx_metrics_device_time", "device_id", "timestamp"),
        Index("idx_metrics_type_time", "metric_type", "timestamp"),
        Index("idx_metrics_device_type_time", "device_id", "metric_type", "timestamp"),
        {"timescaledb_hypertable": {"time_column_name": "timestamp"}}  # For TimescaleDB
    )
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    
    # Metric identification
    metric_type = Column(Enum(MetricType), nullable=False)
    metric_name = Column(String(255), nullable=False)
    metric_path = Column(String(500))  # Full metric path/OID
    
    # Metric value
    value = Column(Float, nullable=False)
    unit = Column(String(50))  # percent, bytes, packets, celsius, etc.
    
    # Context
    interface_id = Column(UUID(as_uuid=True), ForeignKey("interfaces.id"))
    component = Column(String(100))  # CPU1, Disk1, etc.
    instance = Column(String(100))  # Instance identifier for multi-instance metrics
    
    # Metadata
    metadata = Column(JSON)  # Additional context data
    tags = Column(JSON)  # Tags for filtering and grouping
    
    # Quality indicators
    quality = Column(String(20))  # good, degraded, bad
    confidence = Column(Float)  # 0-100 confidence score
    
    # Timestamps
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    device = relationship("Device", back_populates="metrics")
    interface = relationship("Interface")


class MetricAggregate(Base):
    """Aggregated metrics for performance optimization"""
    __tablename__ = "metric_aggregates"
    __table_args__ = (
        Index("idx_aggregate_device_period", "device_id", "period", "timestamp"),
        Index("idx_aggregate_type_period", "metric_type", "period", "timestamp"),
    )
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    
    # Aggregation parameters
    metric_type = Column(Enum(MetricType), nullable=False)
    metric_name = Column(String(255), nullable=False)
    period = Column(String(20), nullable=False)  # 5min, 1hour, 1day, 1week, 1month
    
    # Aggregated values
    min_value = Column(Float)
    max_value = Column(Float)
    avg_value = Column(Float)
    sum_value = Column(Float)
    count = Column(Integer)
    percentile_50 = Column(Float)
    percentile_95 = Column(Float)
    percentile_99 = Column(Float)
    stddev = Column(Float)
    
    # Time window
    timestamp = Column(DateTime(timezone=True), nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    
    # Metadata
    metadata = Column(JSON)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class PerformanceBaseline(Base):
    """Performance baseline for anomaly detection"""
    __tablename__ = "performance_baselines"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    
    # Baseline identification
    metric_type = Column(Enum(MetricType), nullable=False)
    metric_name = Column(String(255), nullable=False)
    baseline_type = Column(String(50))  # daily, weekly, monthly
    
    # Time context
    hour_of_day = Column(Integer)  # 0-23 for hourly patterns
    day_of_week = Column(Integer)  # 0-6 for weekly patterns
    day_of_month = Column(Integer)  # 1-31 for monthly patterns
    
    # Statistical values
    mean = Column(Float, nullable=False)
    median = Column(Float)
    mode = Column(Float)
    stddev = Column(Float)
    variance = Column(Float)
    min_value = Column(Float)
    max_value = Column(Float)
    percentile_5 = Column(Float)
    percentile_25 = Column(Float)
    percentile_75 = Column(Float)
    percentile_95 = Column(Float)
    
    # Thresholds
    lower_bound = Column(Float)  # Lower threshold for normal range
    upper_bound = Column(Float)  # Upper threshold for normal range
    critical_lower = Column(Float)  # Critical lower threshold
    critical_upper = Column(Float)  # Critical upper threshold
    
    # Metadata
    sample_count = Column(Integer)
    confidence_score = Column(Float)
    last_updated = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_baseline_device_metric", "device_id", "metric_type", "metric_name"),
        Index("idx_baseline_active", "is_active", "device_id"),
    )


class MetricThreshold(Base):
    """Dynamic metric thresholds for alerting"""
    __tablename__ = "metric_thresholds"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"))
    
    # Threshold scope
    scope = Column(String(20))  # global, device_type, device, interface
    device_type = Column(String(50))  # If scope is device_type
    interface_id = Column(UUID(as_uuid=True), ForeignKey("interfaces.id"))
    
    # Metric identification
    metric_type = Column(Enum(MetricType), nullable=False)
    metric_name = Column(String(255), nullable=False)
    
    # Threshold values
    warning_threshold = Column(Float)
    critical_threshold = Column(Float)
    operator = Column(String(10))  # >, <, >=, <=, ==, !=
    
    # Hysteresis
    hysteresis = Column(Float, default=0)  # Prevent flapping
    
    # Time-based conditions
    duration_seconds = Column(Integer)  # How long condition must persist
    occurrences = Column(Integer)  # Number of occurrences in time window
    time_window_seconds = Column(Integer)  # Time window for occurrences
    
    # Schedule
    schedule = Column(JSON)  # Time-based activation schedule
    
    # Status
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=5)  # 1-10, higher is more important
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_threshold_active", "is_active", "scope"),
        Index("idx_threshold_device_metric", "device_id", "metric_type"),
    )


class CapacityForecast(Base):
    """Capacity planning and forecasting"""
    __tablename__ = "capacity_forecasts"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    device_id = Column(UUID(as_uuid=True), ForeignKey("devices.id"), nullable=False)
    
    # Forecast identification
    metric_type = Column(Enum(MetricType), nullable=False)
    metric_name = Column(String(255), nullable=False)
    resource_type = Column(String(50))  # cpu, memory, disk, bandwidth
    
    # Current state
    current_value = Column(Float)
    current_utilization_percent = Column(Float)
    capacity_limit = Column(Float)
    
    # Trend analysis
    trend_direction = Column(String(20))  # increasing, decreasing, stable
    trend_rate = Column(Float)  # Rate of change per day
    trend_confidence = Column(Float)  # Confidence score 0-100
    
    # Forecasts
    forecast_7_days = Column(Float)
    forecast_30_days = Column(Float)
    forecast_90_days = Column(Float)
    forecast_180_days = Column(Float)
    forecast_365_days = Column(Float)
    
    # Capacity exhaustion
    days_to_warning = Column(Integer)  # Days until warning threshold
    days_to_critical = Column(Integer)  # Days until critical threshold
    days_to_exhaustion = Column(Integer)  # Days until capacity exhausted
    exhaustion_date = Column(DateTime(timezone=True))
    
    # Model metadata
    model_type = Column(String(50))  # linear, exponential, arima, etc.
    model_accuracy = Column(Float)  # Model accuracy score
    model_parameters = Column(JSON)  # Model-specific parameters
    
    # Recommendations
    recommendations = Column(JSON)  # List of recommendations
    
    # Timestamps
    calculated_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_forecast_device", "device_id", "resource_type"),
        Index("idx_forecast_exhaustion", "days_to_exhaustion", "device_id"),
    )