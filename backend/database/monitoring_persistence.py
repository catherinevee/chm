"""
Database persistence layer for monitoring metrics and health check history.
Provides long-term storage and querying capabilities for monitoring data.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from decimal import Decimal
import zlib
import base64

from sqlalchemy import (
    Column, String, Float, Integer, DateTime, Boolean, Text, JSON,
    Index, UniqueConstraint, ForeignKey, BigInteger, LargeBinary,
    select, and_, or_, func, desc, asc
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import relationship, selectinload
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.sql import text

from backend.database.base import Base
from backend.database.session import get_async_session
from backend.monitoring.health_monitor import HealthStatus, SystemMetrics
from backend.monitoring.performance_tracker import PerformanceMetric, PerformanceStats

logger = logging.getLogger(__name__)


class MetricAggregationType(str, Enum):
    """Types of metric aggregations"""
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


class MetricRecord(Base):
    """Database model for metric records"""
    __tablename__ = "metric_records"
    
    id = Column(BigInteger, primary_key=True, index=True)
    metric_name = Column(String(255), nullable=False, index=True)
    metric_type = Column(String(50), nullable=False)
    value = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    labels = Column(JSONB if 'postgresql' in str(Base.metadata.bind) else JSON, nullable=True)
    metadata = Column(JSONB if 'postgresql' in str(Base.metadata.bind) else JSON, nullable=True)
    duration_ms = Column(Float, nullable=True)
    
    # Optimization: partition key for time-series data
    partition_date = Column(DateTime, nullable=False, index=True)
    
    # Compression for large metadata
    compressed_metadata = Column(LargeBinary, nullable=True)
    
    __table_args__ = (
        Index('idx_metric_name_timestamp', 'metric_name', 'timestamp'),
        Index('idx_partition_date', 'partition_date'),
        Index('idx_labels', 'labels', postgresql_using='gin'),
    )
    
    def set_metadata(self, metadata: Dict[str, Any]):
        """Set metadata with compression for large payloads"""
        if metadata:
            json_str = json.dumps(metadata)
            if len(json_str) > 1000:  # Compress if larger than 1KB
                compressed = zlib.compress(json_str.encode('utf-8'))
                self.compressed_metadata = compressed
                self.metadata = {"_compressed": True, "size": len(json_str)}
            else:
                self.metadata = metadata
                self.compressed_metadata = None
    
    def get_metadata(self) -> Optional[Dict[str, Any]]:
        """Get metadata, decompressing if necessary"""
        if self.compressed_metadata:
            decompressed = zlib.decompress(self.compressed_metadata)
            return json.loads(decompressed.decode('utf-8'))
        return self.metadata


class MetricAggregation(Base):
    """Pre-aggregated metrics for faster queries"""
    __tablename__ = "metric_aggregations"
    
    id = Column(BigInteger, primary_key=True, index=True)
    metric_name = Column(String(255), nullable=False, index=True)
    aggregation_type = Column(String(20), nullable=False)
    period_start = Column(DateTime, nullable=False, index=True)
    period_end = Column(DateTime, nullable=False)
    
    # Aggregated values
    count = Column(Integer, nullable=False)
    sum_value = Column(Float, nullable=False)
    min_value = Column(Float, nullable=False)
    max_value = Column(Float, nullable=False)
    avg_value = Column(Float, nullable=False)
    
    # Percentiles stored as JSON
    percentiles = Column(JSONB if 'postgresql' in str(Base.metadata.bind) else JSON, nullable=True)
    
    # Labels for grouped aggregations
    labels = Column(JSONB if 'postgresql' in str(Base.metadata.bind) else JSON, nullable=True)
    
    __table_args__ = (
        UniqueConstraint('metric_name', 'aggregation_type', 'period_start', 'labels'),
        Index('idx_metric_agg_lookup', 'metric_name', 'aggregation_type', 'period_start'),
    )


class HealthCheckHistory(Base):
    """Database model for health check history"""
    __tablename__ = "health_check_history"
    
    id = Column(BigInteger, primary_key=True, index=True)
    check_name = Column(String(255), nullable=False, index=True)
    status = Column(String(20), nullable=False)
    message = Column(Text, nullable=True)
    duration_ms = Column(Float, nullable=False)
    timestamp = Column(DateTime, nullable=False, index=True)
    metadata = Column(JSONB if 'postgresql' in str(Base.metadata.bind) else JSON, nullable=True)
    consecutive_failures = Column(Integer, default=0)
    critical = Column(Boolean, default=False)
    
    __table_args__ = (
        Index('idx_health_check_lookup', 'check_name', 'timestamp'),
        Index('idx_health_status', 'status', 'timestamp'),
    )


class SystemMetricsHistory(Base):
    """Database model for system metrics history"""
    __tablename__ = "system_metrics_history"
    
    id = Column(BigInteger, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True, unique=True)
    cpu_percent = Column(Float, nullable=False)
    memory_percent = Column(Float, nullable=False)
    memory_used_mb = Column(Float, nullable=False)
    memory_available_mb = Column(Float, nullable=False)
    disk_usage_percent = Column(Float, nullable=False)
    disk_used_gb = Column(Float, nullable=False)
    disk_free_gb = Column(Float, nullable=False)
    network_bytes_sent = Column(BigInteger, nullable=False)
    network_bytes_recv = Column(BigInteger, nullable=False)
    load_average_1min = Column(Float, nullable=True)
    load_average_5min = Column(Float, nullable=True)
    load_average_15min = Column(Float, nullable=True)
    open_files = Column(Integer, nullable=False)
    active_connections = Column(Integer, nullable=False)
    
    # Additional system info
    hostname = Column(String(255), nullable=True)
    kernel_version = Column(String(255), nullable=True)
    
    __table_args__ = (
        Index('idx_system_metrics_time', 'timestamp'),
    )


class MonitoringPersistenceService:
    """Service for persisting monitoring data to database"""
    
    def __init__(self, batch_size: int = 1000, flush_interval: float = 60.0):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        
        # Batching for efficient writes
        self._metric_buffer: List[MetricRecord] = []
        self._health_buffer: List[HealthCheckHistory] = []
        self._system_buffer: List[SystemMetricsHistory] = []
        
        self._buffer_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Statistics
        self._metrics_persisted = 0
        self._health_checks_persisted = 0
        self._flush_errors = 0
    
    async def start(self):
        """Start the persistence service"""
        if self._running:
            return
        
        self._running = True
        self._flush_task = asyncio.create_task(self._flush_loop())
        logger.info("Monitoring persistence service started")
    
    async def stop(self):
        """Stop the persistence service"""
        if not self._running:
            return
        
        self._running = False
        
        # Final flush
        await self._flush_all()
        
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        logger.info(f"Monitoring persistence service stopped. "
                   f"Metrics persisted: {self._metrics_persisted}, "
                   f"Health checks persisted: {self._health_checks_persisted}")
    
    async def record_metric(self, metric: PerformanceMetric):
        """Record a performance metric for persistence"""
        record = MetricRecord(
            metric_name=metric.name,
            metric_type="performance",
            value=metric.value,
            timestamp=metric.timestamp,
            labels=metric.labels,
            duration_ms=metric.duration_ms,
            partition_date=metric.timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
        )
        record.set_metadata(metric.metadata)
        
        async with self._buffer_lock:
            self._metric_buffer.append(record)
            
            # Flush if buffer is full
            if len(self._metric_buffer) >= self.batch_size:
                asyncio.create_task(self._flush_metrics())
    
    async def record_health_check(self, 
                                 check_name: str,
                                 status: HealthStatus,
                                 message: str,
                                 duration_ms: float,
                                 metadata: Optional[Dict[str, Any]] = None,
                                 consecutive_failures: int = 0,
                                 critical: bool = False):
        """Record a health check result"""
        record = HealthCheckHistory(
            check_name=check_name,
            status=status.value,
            message=message,
            duration_ms=duration_ms,
            timestamp=datetime.now(),
            metadata=metadata,
            consecutive_failures=consecutive_failures,
            critical=critical
        )
        
        async with self._buffer_lock:
            self._health_buffer.append(record)
            
            if len(self._health_buffer) >= self.batch_size:
                asyncio.create_task(self._flush_health_checks())
    
    async def record_system_metrics(self, metrics: SystemMetrics, hostname: Optional[str] = None):
        """Record system metrics"""
        import platform
        
        record = SystemMetricsHistory(
            timestamp=metrics.timestamp,
            cpu_percent=metrics.cpu_percent,
            memory_percent=metrics.memory_percent,
            memory_used_mb=metrics.memory_used_mb,
            memory_available_mb=metrics.memory_available_mb,
            disk_usage_percent=metrics.disk_usage_percent,
            disk_used_gb=metrics.disk_used_gb,
            disk_free_gb=metrics.disk_free_gb,
            network_bytes_sent=metrics.network_bytes_sent,
            network_bytes_recv=metrics.network_bytes_recv,
            load_average_1min=metrics.load_average[0] if metrics.load_average else None,
            load_average_5min=metrics.load_average[1] if metrics.load_average else None,
            load_average_15min=metrics.load_average[2] if metrics.load_average else None,
            open_files=metrics.open_files,
            active_connections=metrics.active_connections,
            hostname=hostname or platform.node(),
            kernel_version=platform.release()
        )
        
        async with self._buffer_lock:
            self._system_buffer.append(record)
            
            if len(self._system_buffer) >= self.batch_size:
                asyncio.create_task(self._flush_system_metrics())
    
    async def _flush_loop(self):
        """Background task to periodically flush buffers"""
        try:
            while self._running:
                await asyncio.sleep(self.flush_interval)
                await self._flush_all()
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in flush loop: {e}")
            self._flush_errors += 1
    
    async def _flush_all(self):
        """Flush all buffers to database"""
        tasks = []
        
        if self._metric_buffer:
            tasks.append(self._flush_metrics())
        if self._health_buffer:
            tasks.append(self._flush_health_checks())
        if self._system_buffer:
            tasks.append(self._flush_system_metrics())
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _flush_metrics(self):
        """Flush metric buffer to database"""
        async with self._buffer_lock:
            if not self._metric_buffer:
                return
            
            buffer = self._metric_buffer[:]
            self._metric_buffer.clear()
        
        try:
            async with get_async_session() as session:
                session.add_all(buffer)
                await session.commit()
                self._metrics_persisted += len(buffer)
                logger.debug(f"Flushed {len(buffer)} metrics to database")
        except Exception as e:
            logger.error(f"Failed to flush metrics: {e}")
            self._flush_errors += 1
            # Re-add to buffer for retry
            async with self._buffer_lock:
                self._metric_buffer.extend(buffer)
    
    async def _flush_health_checks(self):
        """Flush health check buffer to database"""
        async with self._buffer_lock:
            if not self._health_buffer:
                return
            
            buffer = self._health_buffer[:]
            self._health_buffer.clear()
        
        try:
            async with get_async_session() as session:
                session.add_all(buffer)
                await session.commit()
                self._health_checks_persisted += len(buffer)
                logger.debug(f"Flushed {len(buffer)} health checks to database")
        except Exception as e:
            logger.error(f"Failed to flush health checks: {e}")
            self._flush_errors += 1
            async with self._buffer_lock:
                self._health_buffer.extend(buffer)
    
    async def _flush_system_metrics(self):
        """Flush system metrics buffer to database"""
        async with self._buffer_lock:
            if not self._system_buffer:
                return
            
            buffer = self._system_buffer[:]
            self._system_buffer.clear()
        
        try:
            async with get_async_session() as session:
                # Use upsert to handle duplicate timestamps
                for record in buffer:
                    existing = await session.execute(
                        select(SystemMetricsHistory).where(
                            SystemMetricsHistory.timestamp == record.timestamp
                        )
                    )
                    if not existing.scalar():
                        session.add(record)
                
                await session.commit()
                logger.debug(f"Flushed {len(buffer)} system metrics to database")
        except Exception as e:
            logger.error(f"Failed to flush system metrics: {e}")
            self._flush_errors += 1
            async with self._buffer_lock:
                self._system_buffer.extend(buffer)
    
    async def query_metrics(self,
                          metric_name: str,
                          start_time: datetime,
                          end_time: datetime,
                          labels: Optional[Dict[str, str]] = None,
                          limit: int = 10000) -> List[MetricRecord]:
        """Query metrics from database"""
        try:
            async with get_async_session() as session:
                query = select(MetricRecord).where(
                    and_(
                        MetricRecord.metric_name == metric_name,
                        MetricRecord.timestamp >= start_time,
                        MetricRecord.timestamp <= end_time
                    )
                )
                
                if labels:
                    # Filter by labels (JSON containment)
                    for key, value in labels.items():
                        query = query.where(
                            MetricRecord.labels[key].astext == value
                        )
                
                query = query.order_by(desc(MetricRecord.timestamp)).limit(limit)
                
                result = await session.execute(query)
                return result.scalars().all()
        except Exception as e:
            logger.error(f"Failed to query metrics: {e}")
            return []
    
    async def query_health_history(self,
                                  check_name: Optional[str] = None,
                                  status: Optional[HealthStatus] = None,
                                  start_time: Optional[datetime] = None,
                                  end_time: Optional[datetime] = None,
                                  limit: int = 1000) -> List[HealthCheckHistory]:
        """Query health check history from database"""
        try:
            async with get_async_session() as session:
                query = select(HealthCheckHistory)
                
                conditions = []
                if check_name:
                    conditions.append(HealthCheckHistory.check_name == check_name)
                if status:
                    conditions.append(HealthCheckHistory.status == status.value)
                if start_time:
                    conditions.append(HealthCheckHistory.timestamp >= start_time)
                if end_time:
                    conditions.append(HealthCheckHistory.timestamp <= end_time)
                
                if conditions:
                    query = query.where(and_(*conditions))
                
                query = query.order_by(desc(HealthCheckHistory.timestamp)).limit(limit)
                
                result = await session.execute(query)
                return result.scalars().all()
        except Exception as e:
            logger.error(f"Failed to query health history: {e}")
            return []
    
    async def get_metric_aggregations(self,
                                     metric_name: str,
                                     aggregation_type: MetricAggregationType,
                                     start_time: datetime,
                                     end_time: datetime) -> List[MetricAggregation]:
        """Get pre-aggregated metrics"""
        try:
            async with get_async_session() as session:
                query = select(MetricAggregation).where(
                    and_(
                        MetricAggregation.metric_name == metric_name,
                        MetricAggregation.aggregation_type == aggregation_type.value,
                        MetricAggregation.period_start >= start_time,
                        MetricAggregation.period_end <= end_time
                    )
                ).order_by(MetricAggregation.period_start)
                
                result = await session.execute(query)
                return result.scalars().all()
        except Exception as e:
            logger.error(f"Failed to get metric aggregations: {e}")
            return []
    
    async def create_aggregations(self, metric_name: str, period: datetime):
        """Create metric aggregations for a specific period"""
        try:
            async with get_async_session() as session:
                # Calculate different aggregation periods
                minute_start = period.replace(second=0, microsecond=0)
                hour_start = period.replace(minute=0, second=0, microsecond=0)
                day_start = period.replace(hour=0, minute=0, second=0, microsecond=0)
                
                # Aggregate by minute
                await self._create_aggregation(
                    session, metric_name, MetricAggregationType.MINUTE,
                    minute_start, minute_start + timedelta(minutes=1)
                )
                
                # Aggregate by hour (every 10 minutes)
                if period.minute % 10 == 0:
                    await self._create_aggregation(
                        session, metric_name, MetricAggregationType.HOUR,
                        hour_start, hour_start + timedelta(hours=1)
                    )
                
                # Aggregate by day (every hour)
                if period.minute == 0:
                    await self._create_aggregation(
                        session, metric_name, MetricAggregationType.DAY,
                        day_start, day_start + timedelta(days=1)
                    )
                
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to create aggregations: {e}")
    
    async def _create_aggregation(self,
                                 session: AsyncSession,
                                 metric_name: str,
                                 aggregation_type: MetricAggregationType,
                                 period_start: datetime,
                                 period_end: datetime):
        """Create a single aggregation record"""
        # Query raw metrics for the period
        result = await session.execute(
            select(
                func.count(MetricRecord.id).label('count'),
                func.sum(MetricRecord.value).label('sum'),
                func.min(MetricRecord.value).label('min'),
                func.max(MetricRecord.value).label('max'),
                func.avg(MetricRecord.value).label('avg')
            ).where(
                and_(
                    MetricRecord.metric_name == metric_name,
                    MetricRecord.timestamp >= period_start,
                    MetricRecord.timestamp < period_end
                )
            )
        )
        
        stats = result.first()
        if stats and stats.count > 0:
            # Calculate percentiles (simplified - would use proper percentile function in production)
            values_result = await session.execute(
                select(MetricRecord.value).where(
                    and_(
                        MetricRecord.metric_name == metric_name,
                        MetricRecord.timestamp >= period_start,
                        MetricRecord.timestamp < period_end
                    )
                ).order_by(MetricRecord.value)
            )
            values = [row[0] for row in values_result]
            
            if values:
                percentiles = {
                    'p50': values[int(len(values) * 0.50)],
                    'p75': values[int(len(values) * 0.75)],
                    'p90': values[int(len(values) * 0.90)],
                    'p95': values[int(len(values) * 0.95)],
                    'p99': values[int(len(values) * 0.99)] if len(values) > 100 else values[-1]
                }
                
                # Check if aggregation already exists
                existing = await session.execute(
                    select(MetricAggregation).where(
                        and_(
                            MetricAggregation.metric_name == metric_name,
                            MetricAggregation.aggregation_type == aggregation_type.value,
                            MetricAggregation.period_start == period_start
                        )
                    )
                )
                
                if not existing.scalar():
                    aggregation = MetricAggregation(
                        metric_name=metric_name,
                        aggregation_type=aggregation_type.value,
                        period_start=period_start,
                        period_end=period_end,
                        count=stats.count,
                        sum_value=float(stats.sum),
                        min_value=float(stats.min),
                        max_value=float(stats.max),
                        avg_value=float(stats.avg),
                        percentiles=percentiles
                    )
                    session.add(aggregation)
    
    async def cleanup_old_data(self, retention_days: int = 30):
        """Clean up old monitoring data"""
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        try:
            async with get_async_session() as session:
                # Delete old metric records
                await session.execute(
                    text("DELETE FROM metric_records WHERE timestamp < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                
                # Delete old health check history
                await session.execute(
                    text("DELETE FROM health_check_history WHERE timestamp < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                
                # Delete old system metrics (keep longer)
                system_cutoff = datetime.now() - timedelta(days=retention_days * 3)
                await session.execute(
                    text("DELETE FROM system_metrics_history WHERE timestamp < :cutoff"),
                    {"cutoff": system_cutoff}
                )
                
                # Delete old aggregations
                await session.execute(
                    text("DELETE FROM metric_aggregations WHERE period_end < :cutoff"),
                    {"cutoff": cutoff_date}
                )
                
                await session.commit()
                logger.info(f"Cleaned up monitoring data older than {retention_days} days")
        except Exception as e:
            logger.error(f"Failed to cleanup old monitoring data: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get persistence service statistics"""
        return {
            "metrics_persisted": self._metrics_persisted,
            "health_checks_persisted": self._health_checks_persisted,
            "flush_errors": self._flush_errors,
            "metric_buffer_size": len(self._metric_buffer),
            "health_buffer_size": len(self._health_buffer),
            "system_buffer_size": len(self._system_buffer)
        }