"""
Analytics Models for CHM Advanced Analytics & Reporting System

This module defines the data models for performance analytics, anomaly detection,
capacity planning, and advanced reporting capabilities.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Union
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY as PG_ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from ..core.database import Base


class AnalysisType(str, Enum):
    """Types of performance analysis"""
    TREND_ANALYSIS = "trend_analysis"
    ANOMALY_DETECTION = "anomaly_detection"
    CAPACITY_PLANNING = "capacity_planning"
    PERFORMANCE_OPTIMIZATION = "performance_optimization"
    FORECASTING = "forecasting"
    COMPARATIVE_ANALYSIS = "comparative_analysis"


class AnomalySeverity(str, Enum):
    """Severity levels for detected anomalies"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReportType(str, Enum):
    """Types of generated reports"""
    PERFORMANCE_SUMMARY = "performance_summary"
    ANOMALY_REPORT = "anomaly_report"
    CAPACITY_ANALYSIS = "capacity_analysis"
    TREND_FORECAST = "trend_forecast"
    COMPARATIVE_ANALYSIS = "comparative_analysis"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    """Available report output formats"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"


class PerformanceAnalysis(Base):
    """Performance analysis results for devices and metrics"""
    __tablename__ = "performance_analyses"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    analysis_type = Column(String(50), nullable=False, index=True)
    
    # Analysis parameters
    time_range_start = Column(DateTime, nullable=False, index=True)
    time_range_end = Column(DateTime, nullable=False, index=True)
    analysis_window_hours = Column(Integer, nullable=False)
    
    # Results
    baseline_value = Column(Float, nullable=True)
    baseline_std_dev = Column(Float, nullable=True)
    current_value = Column(Float, nullable=True)
    change_percentage = Column(Float, nullable=True)
    trend_direction = Column(String(20), nullable=True)  # increasing, decreasing, stable
    trend_strength = Column(Float, nullable=True)  # 0.0 to 1.0
    
    # Statistical data
    min_value = Column(Float, nullable=True)
    max_value = Column(Float, nullable=True)
    mean_value = Column(Float, nullable=True)
    median_value = Column(Float, nullable=True)
    percentile_95 = Column(Float, nullable=True)
    percentile_99 = Column(Float, nullable=True)
    
    # Analysis metadata
    confidence_score = Column(Float, nullable=True)  # 0.0 to 1.0
    data_points_analyzed = Column(Integer, nullable=True)
    analysis_duration_ms = Column(Integer, nullable=True)
    
    # Insights and recommendations
    insights = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    risk_assessment = Column(String(50), nullable=True)  # low, medium, high, critical
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    device = relationship("Device", back_populates="performance_analyses")
    
    # Indexes
    __table_args__ = (
        Index('idx_perf_analysis_device_metric_time', 'device_id', 'metric_name', 'time_range_start'),
        Index('idx_perf_analysis_type_time', 'analysis_type', 'time_range_start'),
        Index('idx_perf_analysis_confidence', 'confidence_score'),
    )


class AnomalyDetection(Base):
    """Detected anomalies in metrics and performance"""
    __tablename__ = "anomaly_detections"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    
    # Anomaly details
    anomaly_type = Column(String(50), nullable=False, index=True)  # spike, drop, trend_change, outlier
    severity = Column(String(20), nullable=False, index=True)
    confidence_score = Column(Float, nullable=False, index=True)  # 0.0 to 1.0
    
    # Detection parameters
    detection_method = Column(String(50), nullable=False)  # statistical, ml, rule_based
    detection_algorithm = Column(String(100), nullable=True)
    detection_threshold = Column(Float, nullable=True)
    
    # Anomaly characteristics
    baseline_value = Column(Float, nullable=True)
    anomalous_value = Column(Float, nullable=True)
    deviation_percentage = Column(Float, nullable=True)
    deviation_std_devs = Column(Float, nullable=True)
    
    # Time information
    detected_at = Column(DateTime, nullable=False, index=True)
    anomaly_start_time = Column(DateTime, nullable=True)
    anomaly_end_time = Column(DateTime, nullable=True)
    duration_minutes = Column(Integer, nullable=True)
    
    # Context and correlation
    related_anomalies = Column(PG_ARRAY(Integer), nullable=True)  # IDs of related anomalies
    contributing_factors = Column(JSON, nullable=True)
    business_impact = Column(String(50), nullable=True)  # low, medium, high, critical
    
    # Status and handling
    status = Column(String(20), default="active", nullable=False, index=True)  # active, investigated, resolved, false_positive
    investigation_notes = Column(Text, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    resolved_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    device = relationship("Device", back_populates="anomaly_detections")
    resolved_by_user = relationship("User", foreign_keys=[resolved_by])
    
    # Indexes
    __table_args__ = (
        Index('idx_anomaly_device_metric_time', 'device_id', 'metric_name', 'detected_at'),
        Index('idx_anomaly_severity_status', 'severity', 'status'),
        Index('idx_anomaly_confidence_time', 'confidence_score', 'detected_at'),
    )


class CapacityPlanning(Base):
    """Capacity planning analysis and forecasts"""
    __tablename__ = "capacity_planning"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    resource_type = Column(String(50), nullable=False, index=True)  # cpu, memory, disk, network, bandwidth
    
    # Current capacity
    current_utilization = Column(Float, nullable=False)  # percentage
    current_capacity = Column(Float, nullable=True)  # absolute value
    current_unit = Column(String(20), nullable=True)  # %, MB, GB, Mbps, etc.
    
    # Historical trends
    avg_utilization_1h = Column(Float, nullable=True)
    avg_utilization_24h = Column(Float, nullable=True)
    avg_utilization_7d = Column(Float, nullable=True)
    avg_utilization_30d = Column(Float, nullable=True)
    
    # Peak analysis
    peak_utilization = Column(Float, nullable=True)
    peak_timestamp = Column(DateTime, nullable=True)
    peak_duration_minutes = Column(Integer, nullable=True)
    
    # Forecasting
    forecast_30d = Column(Float, nullable=True)
    forecast_90d = Column(Float, nullable=True)
    forecast_180d = Column(Float, nullable=True)
    forecast_365d = Column(Float, nullable=True)
    
    # Thresholds and alerts
    warning_threshold = Column(Float, nullable=True)
    critical_threshold = Column(Float, nullable=True)
    recommended_threshold = Column(Float, nullable=True)
    
    # Recommendations
    upgrade_recommended = Column(Boolean, default=False, nullable=False)
    upgrade_urgency = Column(String(20), nullable=True)  # low, medium, high, critical
    upgrade_timeline_months = Column(Integer, nullable=True)
    upgrade_cost_estimate = Column(Float, nullable=True)
    upgrade_benefits = Column(JSON, nullable=True)
    
    # Analysis metadata
    analysis_date = Column(DateTime, nullable=False, index=True)
    data_points_analyzed = Column(Integer, nullable=True)
    confidence_score = Column(Float, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    device = relationship("Device", back_populates="capacity_planning")
    
    # Indexes
    __table_args__ = (
        Index('idx_capacity_device_resource_time', 'device_id', 'resource_type', 'analysis_date'),
        Index('idx_capacity_utilization', 'current_utilization'),
        Index('idx_capacity_upgrade_urgency', 'upgrade_urgency'),
    )


class TrendForecast(Base):
    """Trend analysis and forecasting results"""
    __tablename__ = "trend_forecasts"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    
    # Forecast parameters
    forecast_type = Column(String(50), nullable=False)  # linear, exponential, seasonal, arima
    forecast_horizon_days = Column(Integer, nullable=False)
    confidence_interval = Column(Float, nullable=False)  # 0.0 to 1.0
    
    # Historical data
    historical_start_date = Column(DateTime, nullable=False)
    historical_end_date = Column(DateTime, nullable=False)
    historical_data_points = Column(Integer, nullable=True)
    
    # Forecast results
    forecast_values = Column(JSON, nullable=False)  # Array of predicted values with timestamps
    forecast_confidence_lower = Column(JSON, nullable=True)  # Lower confidence bounds
    forecast_confidence_upper = Column(JSON, nullable=True)  # Upper confidence bounds
    
    # Model performance
    model_accuracy = Column(Float, nullable=True)  # R-squared or similar metric
    mean_absolute_error = Column(Float, nullable=True)
    root_mean_square_error = Column(Float, nullable=True)
    
    # Seasonal patterns
    has_seasonality = Column(Boolean, default=False, nullable=False)
    seasonal_period = Column(Integer, nullable=True)  # in hours
    seasonal_strength = Column(Float, nullable=True)  # 0.0 to 1.0
    
    # Trend characteristics
    trend_direction = Column(String(20), nullable=True)  # increasing, decreasing, stable
    trend_strength = Column(Float, nullable=True)  # 0.0 to 1.0
    trend_breakpoints = Column(JSON, nullable=True)  # Points where trend changes
    
    # Analysis metadata
    analysis_date = Column(DateTime, nullable=False, index=True)
    model_version = Column(String(50), nullable=True)
    parameters = Column(JSON, nullable=True)  # Model parameters
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    device = relationship("Device", back_populates="trend_forecasts")
    
    # Indexes
    __table_args__ = (
        Index('idx_forecast_device_metric_time', 'device_id', 'metric_name', 'analysis_date'),
        Index('idx_forecast_type_horizon', 'forecast_type', 'forecast_horizon_days'),
        Index('idx_forecast_accuracy', 'model_accuracy'),
    )


class AnalyticsReport(Base):
    """Generated analytics reports"""
    __tablename__ = "analytics_reports"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    report_type = Column(String(50), nullable=False, index=True)
    
    # Report configuration
    report_config = Column(JSON, nullable=False)  # Report parameters and filters
    target_audience = Column(String(100), nullable=True)  # engineers, managers, executives
    report_frequency = Column(String(50), nullable=True)  # daily, weekly, monthly, on-demand
    
    # Generation details
    generated_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    generated_at = Column(DateTime, nullable=False, index=True)
    generation_duration_ms = Column(Integer, nullable=True)
    
    # Content and format
    report_content = Column(JSON, nullable=True)  # Structured report data
    report_summary = Column(Text, nullable=True)
    key_insights = Column(JSON, nullable=True)
    recommendations = Column(JSON, nullable=True)
    
    # Output formats
    available_formats = Column(PG_ARRAY(String), nullable=True)
    generated_files = Column(JSON, nullable=True)  # Paths to generated files
    
    # Distribution
    recipients = Column(PG_ARRAY(String), nullable=True)  # Email addresses or user IDs
    distribution_status = Column(String(20), default="pending", nullable=False)  # pending, sent, failed
    sent_at = Column(DateTime, nullable=True)
    
    # Metadata
    tags = Column(PG_ARRAY(String), nullable=True)
    is_template = Column(Boolean, default=False, nullable=False)
    template_id = Column(Integer, ForeignKey("analytics_reports.id"), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    generated_by_user = relationship("User", foreign_keys=[generated_by])
    template = relationship("AnalyticsReport", foreign_keys=[template_id], remote_side=[id])
    
    # Indexes
    __table_args__ = (
        Index('idx_report_type_time', 'report_type', 'generated_at'),
        Index('idx_report_generated_by', 'generated_by'),
        Index('idx_report_template', 'is_template'),
    )


class AnalyticsInsight(Base):
    """Generated insights from analytics analysis"""
    __tablename__ = "analytics_insights"
    
    id = Column(Integer, primary_key=True, index=True)
    insight_type = Column(String(50), nullable=False, index=True)  # performance, anomaly, capacity, trend
    insight_category = Column(String(50), nullable=False, index=True)  # optimization, alert, recommendation
    
    # Insight details
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    summary = Column(Text, nullable=True)
    
    # Context and data
    related_devices = Column(PG_ARRAY(Integer), nullable=True)  # Device IDs
    related_metrics = Column(PG_ARRAY(String), nullable=True)  # Metric names
    related_anomalies = Column(PG_ARRAY(Integer), nullable=True)  # Anomaly IDs
    context_data = Column(JSON, nullable=True)
    
    # Impact and priority
    impact_level = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    business_value = Column(String(50), nullable=True)  # cost_savings, performance, reliability
    priority_score = Column(Float, nullable=True)  # 0.0 to 1.0
    
    # Actionability
    actionable = Column(Boolean, default=True, nullable=False)
    recommended_actions = Column(JSON, nullable=True)
    estimated_effort = Column(String(20), nullable=True)  # low, medium, high
    estimated_benefit = Column(String(20), nullable=True)  # low, medium, high
    
    # Status and tracking
    status = Column(String(20), default="new", nullable=False, index=True)  # new, reviewed, implemented, dismissed
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    implementation_notes = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    reviewed_by_user = relationship("User", foreign_keys=[reviewed_by])
    
    # Indexes
    __table_args__ = (
        Index('idx_insight_type_category', 'insight_type', 'insight_category'),
        Index('idx_insight_impact_priority', 'impact_level', 'priority_score'),
        Index('idx_insight_status_time', 'status', 'created_at'),
    )
