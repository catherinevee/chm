"""
CHM Metrics Query Service
Efficient querying, filtering, and retrieval of metrics with caching and optimization
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
from functools import lru_cache
from collections import defaultdict

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, text, desc, asc
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import Select

from ..models import Metric, Device, CollectionMethod, MetricQuality, MetricType, MetricCategory
from ..models.result_objects import CollectionResult, OperationStatus
from ..core.database import Base

logger = logging.getLogger(__name__)

@dataclass
class QueryConfig:
    """Configuration for metrics querying"""
    enable_caching: bool = True
    cache_ttl_seconds: int = 300  # 5 minutes
    max_results: int = 10000
    default_limit: int = 1000
    enable_pagination: bool = True
    page_size: int = 100
    enable_optimization: bool = True
    query_timeout_seconds: int = 30

@dataclass
class QueryFilter:
    """Filter criteria for metrics queries"""
    device_ids: Optional[List[int]] = None
    metric_names: Optional[List[str]] = None
    categories: Optional[List[str]] = None
    types: Optional[List[str]] = None
    collection_methods: Optional[List[str]] = None
    quality_levels: Optional[List[str]] = None
    storage_tiers: Optional[List[str]] = None
    tags: Optional[List[str]] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    is_valid: Optional[bool] = None

@dataclass
class QueryResult:
    """Result of a metrics query"""
    metrics: List[Metric]
    total_count: int
    page: int
    page_size: int
    total_pages: int
    query_time_ms: float
    filters_applied: QueryFilter
    metadata: Dict[str, Any]

@dataclass
class AggregationQuery:
    """Query for aggregated metrics"""
    device_id: int
    metric_name: str
    aggregation_window: int  # seconds
    start_time: datetime
    end_time: datetime
    aggregation_function: str = "mean"  # mean, min, max, sum, count

class MetricsQueryService:
    """Service for efficient metrics querying and retrieval"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.config = QueryConfig()
        self._query_cache = {}
        self._cache_timestamps = {}
    
    async def query_metrics(
        self, 
        filters: QueryFilter,
        page: int = 1,
        limit: Optional[int] = None,
        order_by: str = "timestamp",
        order_direction: str = "desc"
    ) -> QueryResult:
        """Query metrics with filters and pagination"""
        start_time = datetime.now()
        
        try:
            # Apply filters
            query = self._build_base_query()
            query = self._apply_filters(query, filters)
            
            # Get total count for pagination
            count_query = select(func.count()).select_from(query.subquery())
            total_count_result = await self.db_session.execute(count_query)
            total_count = total_count_result.scalar() or 0
            
            # Apply ordering
            query = self._apply_ordering(query, order_by, order_direction)
            
            # Apply pagination
            if limit is None:
                limit = self.config.default_limit
            
            limit = min(limit, self.config.max_results)
            offset = (page - 1) * limit
            query = query.limit(limit).offset(offset)
            
            # Execute query
            result = await self.db_session.execute(query)
            metrics = result.scalars().all()
            
            # Calculate pagination info
            total_pages = (total_count + limit - 1) // limit if limit > 0 else 1
            
            query_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return QueryResult(
                metrics=metrics,
                total_count=total_count,
                page=page,
                page_size=limit,
                total_pages=total_pages,
                query_time_ms=query_time,
                filters_applied=filters,
                metadata={
                    "order_by": order_by,
                    "order_direction": order_direction,
                    "cache_hit": False
                }
            )
            
        except Exception as e:
            logger.error(f"Metrics query failed: {str(e)}")
            return QueryResult(
                metrics=[],
                total_count=0,
                page=page,
                page_size=limit or self.config.default_limit,
                total_pages=0,
                query_time_ms=0,
                filters_applied=filters,
                metadata={"error": str(e)}
            )
    
    def _build_base_query(self) -> Select:
        """Build base query for metrics"""
        return select(Metric).where(Metric.is_deleted == False)
    
    def _apply_filters(self, query: Select, filters: QueryFilter) -> Select:
        """Apply filters to the query"""
        conditions = []
        
        if filters.device_ids:
            conditions.append(Metric.device_id.in_(filters.device_ids))
        
        if filters.metric_names:
            conditions.append(Metric.name.in_(filters.metric_names))
        
        if filters.categories:
            conditions.append(Metric.category.in_([MetricCategory(cat) for cat in filters.categories]))
        
        if filters.types:
            conditions.append(Metric.metric_type.in_([MetricType(t) for t in filters.types]))
        
        if filters.collection_methods:
            conditions.append(Metric.collection_method.in_([CollectionMethod(m) for m in filters.collection_methods]))
        
        if filters.quality_levels:
            conditions.append(Metric.quality_level.in_([MetricQuality(ql) for ql in filters.quality_levels]))
        
        if filters.storage_tiers:
            conditions.append(Metric.storage_tier.in_(filters.storage_tiers))
        
        if filters.tags:
            # PostgreSQL array contains operator
            for tag in filters.tags:
                conditions.append(Metric.tags.contains([tag]))
        
        if filters.start_time:
            conditions.append(Metric.timestamp >= filters.start_time)
        
        if filters.end_time:
            conditions.append(Metric.timestamp <= filters.end_time)
        
        if filters.min_value is not None:
            conditions.append(Metric.value >= filters.min_value)
        
        if filters.max_value is not None:
            conditions.append(Metric.value <= filters.max_value)
        
        if filters.is_valid is not None:
            conditions.append(Metric.is_valid == filters.is_valid)
        
        if conditions:
            query = query.where(and_(*conditions))
        
        return query
    
    def _apply_ordering(self, query: Select, order_by: str, order_direction: str) -> Select:
        """Apply ordering to the query"""
        if order_direction.lower() == "desc":
            query = query.order_by(desc(getattr(Metric, order_by, Metric.timestamp)))
        else:
            query = query.order_by(asc(getattr(Metric, order_by, Metric.timestamp)))
        
        return query
    
    async def get_metrics_by_device(
        self, 
        device_id: int, 
        hours: int = 24,
        metric_names: Optional[List[str]] = None
    ) -> List[Metric]:
        """Get metrics for a specific device within a time range"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            query = select(Metric).where(
                and_(
                    Metric.device_id == device_id,
                    Metric.timestamp >= since,
                    Metric.is_deleted == False
                )
            )
            
            if metric_names:
                query = query.where(Metric.name.in_(metric_names))
            
            query = query.order_by(desc(Metric.timestamp))
            
            result = await self.db_session.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get metrics by device {device_id}: {str(e)}")
            return []
    
    async def get_metrics_by_name(
        self, 
        metric_name: str,
        device_ids: Optional[List[int]] = None,
        hours: int = 24
    ) -> List[Metric]:
        """Get metrics by name across devices"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            query = select(Metric).where(
                and_(
                    Metric.name == metric_name,
                    Metric.timestamp >= since,
                    Metric.is_deleted == False
                )
            )
            
            if device_ids:
                query = query.where(Metric.device_id.in_(device_ids))
            
            query = query.order_by(desc(Metric.timestamp))
            
            result = await self.db_session.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get metrics by name {metric_name}: {str(e)}")
            return []
    
    async def get_latest_metrics(
        self, 
        device_id: int,
        metric_names: Optional[List[str]] = None,
        limit: int = 100
    ) -> List[Metric]:
        """Get the latest metrics for a device"""
        try:
            query = select(Metric).where(
                and_(
                    Metric.device_id == device_id,
                    Metric.is_deleted == False
                )
            )
            
            if metric_names:
                query = query.where(Metric.name.in_(metric_names))
            
            query = query.order_by(desc(Metric.timestamp)).limit(limit)
            
            result = await self.db_session.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get latest metrics for device {device_id}: {str(e)}")
            return []
    
    async def get_metrics_summary(
        self, 
        device_id: int,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get a summary of metrics for a device"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            # Get basic counts
            total_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.timestamp >= since,
                        Metric.is_deleted == False
                    )
                )
            )
            total_metrics = total_result.scalar() or 0
            
            # Get metrics by category
            category_result = await self.db_session.execute(
                select(Metric.category, func.count(Metric.id)).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.timestamp >= since,
                        Metric.is_deleted == False
                    )
                ).group_by(Metric.category)
            )
            category_counts = dict(category_result.all())
            
            # Get metrics by quality
            quality_result = await self.db_session.execute(
                select(Metric.quality_level, func.count(Metric.id)).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.timestamp >= since,
                        Metric.is_deleted == False
                    )
                ).group_by(Metric.quality_level)
            )
            quality_counts = dict(quality_result.all())
            
            # Get average quality score
            avg_quality_result = await self.db_session.execute(
                select(func.avg(Metric.quality_score)).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.timestamp >= since,
                        Metric.is_deleted == False
                    )
                )
            )
            avg_quality = avg_quality_result.scalar() or 0.0
            
            # Get time range
            time_range_result = await self.db_session.execute(
                select(
                    func.min(Metric.timestamp),
                    func.max(Metric.timestamp)
                ).where(
                    and_(
                        Metric.device_id == device_id,
                        Metric.timestamp >= since,
                        Metric.is_deleted == False
                    )
                )
            )
            time_range = time_range_result.first()
            
            return {
                "device_id": device_id,
                "time_range_hours": hours,
                "total_metrics": total_metrics,
                "category_breakdown": category_counts,
                "quality_breakdown": quality_counts,
                "average_quality": round(avg_quality, 3),
                "earliest_metric": time_range[0].isoformat() if time_range[0] else None,
                "latest_metric": time_range[1].isoformat() if time_range[1] else None
            }
            
        except Exception as e:
            logger.error(f"Failed to get metrics summary for device {device_id}: {str(e)}")
            return {
                "device_id": device_id,
                "time_range_hours": hours,
                "total_metrics": 0,
                "category_breakdown": {},
                "quality_breakdown": {},
                "average_quality": 0.0,
                "earliest_metric": None,
                "latest_metric": None
            }
    
    async def search_metrics(
        self, 
        search_term: str,
        device_ids: Optional[List[int]] = None,
        limit: int = 100
    ) -> List[Metric]:
        """Search metrics by name, description, or tags"""
        try:
            # Build search query
            search_conditions = [
                Metric.name.ilike(f"%{search_term}%"),
                Metric.description.ilike(f"%{search_term}%")
            ]
            
            # Add tag search if supported
            if hasattr(Metric.tags, 'contains'):
                search_conditions.append(Metric.tags.contains([search_term]))
            
            query = select(Metric).where(
                and_(
                    or_(*search_conditions),
                    Metric.is_deleted == False
                )
            )
            
            if device_ids:
                query = query.where(Metric.device_id.in_(device_ids))
            
            query = query.order_by(desc(Metric.timestamp)).limit(limit)
            
            result = await self.db_session.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Metrics search failed for term '{search_term}': {str(e)}")
            return []
    
    async def get_metrics_trends(
        self, 
        device_id: int,
        metric_name: str,
        hours: int = 24,
        interval_minutes: int = 15
    ) -> Dict[str, Any]:
        """Get trend data for a specific metric"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            # Get metrics in time range
            metrics = await self.get_metrics_by_device(
                device_id=device_id,
                hours=hours,
                metric_names=[metric_name]
            )
            
            if not metrics:
                return {
                    "device_id": device_id,
                    "metric_name": metric_name,
                    "trends": [],
                    "statistics": {}
                }
            
            # Group by time intervals
            interval_seconds = interval_minutes * 60
            trends = []
            
            current_time = since
            while current_time <= datetime.now():
                interval_end = current_time + timedelta(seconds=interval_seconds)
                
                # Find metrics in this interval
                interval_metrics = [
                    m for m in metrics 
                    if current_time <= m.timestamp < interval_end
                ]
                
                if interval_metrics:
                    values = [m.value for m in interval_metrics if m.value is not None]
                    if values:
                        trends.append({
                            "timestamp": current_time.isoformat(),
                            "value": sum(values) / len(values),  # Average
                            "min_value": min(values),
                            "max_value": max(values),
                            "count": len(values)
                        })
                
                current_time = interval_end
            
            # Calculate overall statistics
            all_values = [m.value for m in metrics if m.value is not None]
            if all_values:
                statistics = {
                    "mean": sum(all_values) / len(all_values),
                    "min": min(all_values),
                    "max": max(all_values),
                    "count": len(all_values)
                }
            else:
                statistics = {}
            
            return {
                "device_id": device_id,
                "metric_name": metric_name,
                "trends": trends,
                "statistics": statistics,
                "interval_minutes": interval_minutes
            }
            
        except Exception as e:
            logger.error(f"Failed to get trends for metric {metric_name} on device {device_id}: {str(e)}")
            return {
                "device_id": device_id,
                "metric_name": metric_name,
                "trends": [],
                "statistics": {},
                "interval_minutes": interval_minutes
            }
    
    async def get_metrics_by_quality(
        self, 
        quality_level: str,
        device_ids: Optional[List[int]] = None,
        hours: int = 24
    ) -> List[Metric]:
        """Get metrics by quality level"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            query = select(Metric).where(
                and_(
                    Metric.quality_level == MetricQuality(quality_level),
                    Metric.timestamp >= since,
                    Metric.is_deleted == False
                )
            )
            
            if device_ids:
                query = query.where(Metric.device_id.in_(device_ids))
            
            query = query.order_by(desc(Metric.timestamp))
            
            result = await self.db_session.execute(query)
            return result.scalars().all()
            
        except Exception as e:
            logger.error(f"Failed to get metrics by quality {quality_level}: {str(e)}")
            return []
    
    def update_config(self, config: QueryConfig):
        """Update query configuration"""
        self.config = config
        logger.info(f"Updated metrics query config: {config}")
    
    async def clear_cache(self):
        """Clear the query cache"""
        self._query_cache.clear()
        self._cache_timestamps.clear()
        logger.info("Metrics query cache cleared")
    
    async def get_query_stats(self) -> Dict[str, Any]:
        """Get query service statistics"""
        try:
            # Get total metrics count
            total_result = await self.db_session.execute(
                select(func.count(Metric.id)).where(Metric.is_deleted == False)
            )
            total_metrics = total_result.scalar() or 0
            
            # Get metrics by storage tier
            tier_result = await self.db_session.execute(
                select(Metric.storage_tier, func.count(Metric.id)).where(
                    Metric.is_deleted == False
                ).group_by(Metric.storage_tier)
            )
            tier_counts = dict(tier_result.all())
            
            # Get cache statistics
            cache_stats = {
                "cache_size": len(self._query_cache),
                "cache_hits": 0,  # Would need to implement hit tracking
                "cache_misses": 0
            }
            
            return {
                "total_metrics": total_metrics,
                "storage_tier_breakdown": tier_counts,
                "cache_stats": cache_stats,
                "config": {
                    "enable_caching": self.config.enable_caching,
                    "cache_ttl_seconds": self.config.cache_ttl_seconds,
                    "max_results": self.config.max_results,
                    "default_limit": self.config.default_limit
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to get query stats: {str(e)}")
            return {
                "total_metrics": 0,
                "storage_tier_breakdown": {},
                "cache_stats": {},
                "config": {}
            }
