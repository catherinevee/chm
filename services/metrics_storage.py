"""
CHM Metrics Storage Service
Optimized storage with time-series capabilities, compression, and retention policies
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import json
import gzip
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, text
from sqlalchemy.orm import selectinload

from ..models import Metric, Device
from ..models.result_objects import StorageResult, OperationStatus
from ..core.database import Base

logger = logging.getLogger(__name__)

@dataclass
class StorageConfig:
    """Configuration for metrics storage"""
    hot_data_days: int = 7          # Keep in hot storage for 7 days
    warm_data_days: int = 30        # Keep in warm storage for 30 days
    cold_data_days: int = 365       # Keep in cold storage for 1 year
    compression_threshold_hours: int = 24  # Compress data older than 24 hours
    batch_size: int = 1000          # Batch size for bulk operations
    enable_compression: bool = True
    enable_partitioning: bool = True
    retention_enabled: bool = True

@dataclass
class StorageStats:
    """Storage statistics"""
    total_metrics: int
    hot_metrics: int
    warm_metrics: int
    cold_metrics: int
    compressed_metrics: int
    total_size_bytes: int
    compression_ratio: float
    oldest_metric: Optional[datetime]
    newest_metric: Optional[datetime]

class MetricsStorageService:
    """Service for optimized metrics storage with time-series capabilities"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.config = StorageConfig()
        
    async def store_metrics(self, metrics: List[Metric]) -> StorageResult:
        """Store metrics with optimization"""
        if not metrics:
            return StorageResult.success(stored_count=0)
        
        start_time = datetime.now()
        
        try:
            # Pre-process metrics for storage optimization
            processed_metrics = await self._preprocess_metrics(metrics)
            
            # Store metrics in batches
            stored_count = 0
            for i in range(0, len(processed_metrics), self.config.batch_size):
                batch = processed_metrics[i:i + self.config.batch_size]
                self.db_session.add_all(batch)
                stored_count += len(batch)
            
            await self.db_session.commit()
            
            # Post-storage optimization
            await self._post_storage_optimization()
            
            storage_duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Stored {stored_count} metrics in {storage_duration:.2f}s")
            
            return StorageResult.success(stored_count=stored_count)
            
        except Exception as e:
            logger.error(f"Failed to store metrics: {str(e)}")
            await self.db_session.rollback()
            return StorageResult.failure(error=str(e))
    
    async def _preprocess_metrics(self, metrics: List[Metric]) -> List[Metric]:
        """Pre-process metrics for storage optimization"""
        processed_metrics = []
        
        for metric in metrics:
            # Set storage tier based on age
            metric.storage_tier = self._determine_storage_tier(metric.timestamp)
            
            # Set retention period
            metric.retention_days = self._calculate_retention_days(metric)
            
            # Set expiration date
            metric.expires_at = metric.timestamp + timedelta(days=metric.retention_days)
            
            # Add processing timestamp
            metric.processed_at = datetime.now()
            
            # Add tags for better searchability
            if not metric.tags:
                metric.tags = []
            metric.tags.extend([
                f"tier:{metric.storage_tier}",
                f"category:{metric.category.value}",
                f"method:{metric.collection_method.value}" if metric.collection_method else "unknown"
            ])
            
            processed_metrics.append(metric)
        
        return processed_metrics
    
    def _determine_storage_tier(self, timestamp: datetime) -> str:
        """Determine storage tier based on metric age"""
        age_hours = (datetime.now() - timestamp).total_seconds() / 3600
        
        if age_hours <= self.config.hot_data_days * 24:
            return "hot"
        elif age_hours <= self.config.warm_data_days * 24:
            return "warm"
        else:
            return "cold"
    
    def _calculate_retention_days(self, metric: Metric) -> int:
        """Calculate retention period for a metric"""
        # Base retention on category and type
        base_retention = {
            "system": 90,      # System metrics: 90 days
            "network": 180,    # Network metrics: 180 days
            "performance": 365, # Performance metrics: 1 year
            "security": 730,   # Security metrics: 2 years
            "availability": 365, # Availability metrics: 1 year
            "application": 180, # Application metrics: 180 days
            "custom": 90       # Custom metrics: 90 days
        }
        
        return base_retention.get(metric.category.value, 90)
    
    async def _post_storage_optimization(self):
        """Perform post-storage optimization tasks"""
        try:
            # Compress old metrics
            if self.config.enable_compression:
                await self._compress_old_metrics()
            
            # Clean up expired metrics
            if self.config.retention_enabled:
                await self._cleanup_expired_metrics()
            
            # Update storage statistics
            await self._update_storage_stats()
            
        except Exception as e:
            logger.warning(f"Post-storage optimization failed: {str(e)}")
    
    async def _compress_old_metrics(self):
        """Compress metrics older than threshold"""
        threshold = datetime.now() - timedelta(hours=self.config.compression_threshold_hours)
        
        # Find uncompressed metrics older than threshold
        result = await self.db_session.execute(
            select(Metric).where(
                and_(
                    Metric.timestamp < threshold,
                    Metric.compression_ratio.is_(None),
                    Metric.is_deleted == False
                )
            )
        )
        
        old_metrics = result.scalars().all()
        
        for metric in old_metrics:
            try:
                # Compress metadata and raw_value
                if metric.metadata:
                    compressed_metadata = gzip.compress(json.dumps(metric.metadata).encode())
                    metric.metadata = {"compressed": True, "size": len(compressed_metadata)}
                
                if metric.raw_value:
                    compressed_raw = gzip.compress(metric.raw_value.encode())
                    metric.raw_value = compressed_raw.decode('latin1')  # Store as string
                    metric.compression_ratio = len(compressed_raw) / len(metric.raw_value.encode())
                
                metric.storage_tier = "warm"  # Move to warm storage
                
            except Exception as e:
                logger.warning(f"Failed to compress metric {metric.id}: {str(e)}")
                continue
        
        if old_metrics:
            await self.db_session.commit()
            logger.info(f"Compressed {len(old_metrics)} old metrics")
    
    async def _cleanup_expired_metrics(self):
        """Clean up expired metrics"""
        now = datetime.now()
        
        # Find expired metrics
        result = await self.db_session.execute(
            select(Metric).where(
                and_(
                    Metric.expires_at < now,
                    Metric.is_deleted == False
                )
            )
        )
        
        expired_metrics = result.scalars().all()
        
        if expired_metrics:
            # Soft delete expired metrics
            for metric in expired_metrics:
                metric.is_deleted = True
                metric.deleted_at = now
            
            await self.db_session.commit()
            logger.info(f"Cleaned up {len(expired_metrics)} expired metrics")
    
    async def _update_storage_stats(self):
        """Update storage statistics"""
        # This would typically update a separate stats table
        # For now, we'll just log the current stats
        stats = await self.get_storage_stats()
        logger.debug(f"Storage stats updated: {stats}")
    
    async def get_storage_stats(self) -> StorageStats:
        """Get comprehensive storage statistics"""
        try:
            # Get total metrics count
            total_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(Metric.is_deleted == False)
            )
            total_metrics = total_result.scalar() or 0
            
            # Get metrics by storage tier
            hot_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(
                    and_(
                        Metric.storage_tier == "hot",
                        Metric.is_deleted == False
                    )
                )
            )
            hot_metrics = hot_result.scalar() or 0
            
            warm_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(
                    and_(
                        Metric.storage_tier == "warm",
                        Metric.is_deleted == False
                    )
                )
            )
            warm_metrics = warm_result.scalar() or 0
            
            cold_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(
                    and_(
                        Metric.storage_tier == "cold",
                        Metric.is_deleted == False
                    )
                )
            )
            cold_metrics = cold_result.scalar() or 0
            
            # Get compressed metrics count
            compressed_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(
                    and_(
                        Metric.compression_ratio.is_not(None),
                        Metric.is_deleted == False
                    )
                )
            )
            compressed_metrics = compressed_result.scalar() or 0
            
            # Get oldest and newest metrics
            oldest_result = await self.db_session.execute(
                select(Metric.timestamp).where(Metric.is_deleted == False).order_by(Metric.timestamp.asc()).limit(1)
            )
            oldest_metric = oldest_result.scalar()
            
            newest_result = await self.db_session.execute(
                select(Metric.timestamp).where(Metric.is_deleted == False).order_by(Metric.timestamp.desc()).limit(1)
            )
            newest_metric = newest_result.scalar()
            
            # Calculate compression ratio
            compression_ratio = 0.0
            if compressed_metrics > 0:
                avg_compression_result = await self.db_session.execute(
                    select(func.avg(Metric.compression_ratio)).where(
                        and_(
                            Metric.compression_ratio.is_not(None),
                            Metric.is_deleted == False
                        )
                    )
                )
                compression_ratio = avg_compression_result.scalar() or 0.0
            
            # Estimate total size (rough calculation)
            total_size_bytes = total_metrics * 1024  # Rough estimate: 1KB per metric
            
            return StorageStats(
                total_metrics=total_metrics,
                hot_metrics=hot_metrics,
                warm_metrics=warm_metrics,
                cold_metrics=cold_metrics,
                compressed_metrics=compressed_metrics,
                total_size_bytes=total_size_bytes,
                compression_ratio=compression_ratio,
                oldest_metric=oldest_metric,
                newest_metric=newest_metric
            )
            
        except Exception as e:
            logger.error(f"Failed to get storage stats: {str(e)}")
            return StorageStats(
                total_metrics=0,
                hot_metrics=0,
                warm_metrics=0,
                cold_metrics=0,
                compressed_metrics=0,
                total_size_bytes=0,
                compression_ratio=0.0,
                oldest_metric=None,
                newest_metric=None
            )
    
    async def optimize_storage(self) -> StorageResult:
        """Perform storage optimization tasks"""
        try:
            start_time = datetime.now()
            
            # Compress old metrics
            if self.config.enable_compression:
                await self._compress_old_metrics()
            
            # Move metrics between tiers
            await self._move_metrics_between_tiers()
            
            # Clean up expired metrics
            if self.config.retention_enabled:
                await self._cleanup_expired_metrics()
            
            # Update statistics
            await self._update_storage_stats()
            
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Storage optimization completed in {duration:.2f}s")
            
            return StorageResult.success(stored_count=0)
            
        except Exception as e:
            logger.error(f"Storage optimization failed: {str(e)}")
            return StorageResult.failure(error=str(e))
    
    async def _move_metrics_between_tiers(self):
        """Move metrics between storage tiers based on age"""
        now = datetime.now()
        
        # Move hot metrics to warm if they're old enough
        hot_to_warm_threshold = now - timedelta(days=self.config.hot_data_days)
        hot_to_warm_result = await self.db_session.execute(
            select(Metric).where(
                and_(
                    Metric.storage_tier == "hot",
                    Metric.timestamp < hot_to_warm_threshold,
                    Metric.is_deleted == False
                )
            )
        )
        
        hot_to_warm_metrics = hot_to_warm_result.scalars().all()
        for metric in hot_to_warm_metrics:
            metric.storage_tier = "warm"
        
        # Move warm metrics to cold if they're old enough
        warm_to_cold_threshold = now - timedelta(days=self.config.warm_data_days)
        warm_to_cold_result = await self.db_session.execute(
            select(Metric).where(
                and_(
                    Metric.storage_tier == "warm",
                    Metric.timestamp < warm_to_cold_threshold,
                    Metric.is_deleted == False
                )
            )
        )
        
        warm_to_cold_metrics = warm_to_cold_result.scalars().all()
        for metric in warm_to_cold_metrics:
            metric.storage_tier = "cold"
        
        # Commit changes
        if hot_to_warm_metrics or warm_to_cold_metrics:
            await self.db_session.commit()
            logger.info(f"Moved {len(hot_to_warm_metrics)} metrics from hot to warm, {len(warm_to_cold_metrics)} from warm to cold")
    
    async def get_metrics_by_tier(self, tier: str, limit: int = 1000) -> List[Metric]:
        """Get metrics by storage tier"""
        try:
            result = await self.db_session.execute(
                select(Metric).where(
                    and_(
                        Metric.storage_tier == tier,
                        Metric.is_deleted == False
                    )
                ).order_by(Metric.timestamp.desc()).limit(limit)
            )
            
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get metrics by tier {tier}: {str(e)}")
            return []
    
    def update_config(self, config: StorageConfig):
        """Update storage configuration"""
        self.config = config
        logger.info(f"Updated metrics storage config: {config}")
    
    async def get_retention_policy_summary(self) -> Dict[str, Any]:
        """Get summary of retention policies"""
        return {
            "hot_data_days": self.config.hot_data_days,
            "warm_data_days": self.config.warm_data_days,
            "cold_data_days": self.config.cold_data_days,
            "compression_threshold_hours": self.config.compression_threshold_hours,
            "retention_enabled": self.config.retention_enabled,
            "compression_enabled": self.config.enable_compression,
            "partitioning_enabled": self.config.enable_partitioning
        }
