"""
Graceful degradation patterns for maintaining service availability
when components fail or become unavailable.
"""

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Callable, Union
from functools import wraps

try:
    import redis.asyncio as redis
    from redis.asyncio import Redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False


logger = logging.getLogger(__name__)

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


class ServiceStatus(Enum):
    """Service health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class DegradationMode(Enum):
    """Types of degradation modes."""
    NONE = "none"
    CACHING = "caching"
    SIMPLIFIED = "simplified"
    READ_ONLY = "read_only"
    FALLBACK = "fallback"
    DISABLED = "disabled"


@dataclass
class ServiceHealth:
    """Health status of a service component."""
    service_name: str
    status: ServiceStatus
    last_check: datetime
    error_count: int = 0
    success_count: int = 0
    response_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        total = self.success_count + self.error_count
        if total == 0:
            return 1.0
        return self.success_count / total
    
    @property
    def availability_score(self) -> float:
        """Calculate availability score (0.0 to 1.0)."""
        if self.status == ServiceStatus.HEALTHY:
            return 1.0
        elif self.status == ServiceStatus.DEGRADED:
            return 0.7
        elif self.status == ServiceStatus.UNHEALTHY:
            return 0.3
        elif self.status == ServiceStatus.CRITICAL:
            return 0.1
        else:  # UNKNOWN
            return 0.5


@dataclass
class DegradationRule:
    """Rule for triggering degradation."""
    service_name: str
    condition: Callable[[ServiceHealth], bool]
    degradation_mode: DegradationMode
    fallback_handler: Optional[Callable] = None
    cache_ttl_seconds: int = 300
    description: str = ""
    priority: int = 0  # Higher priority rules are checked first


class HealthMonitor:
    """Monitors service health for degradation decisions."""
    
    def __init__(self, check_interval: float = 30.0):
        self.check_interval = check_interval
        self._services: Dict[str, ServiceHealth] = {}
        self._health_checks: Dict[str, Callable] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._shutdown = False
        self._callbacks: List[Callable[[str, ServiceHealth], None]] = []
    
    def register_service(
        self,
        service_name: str,
        health_check: Callable[[], bool]
    ):
        """Register a service for health monitoring."""
        self._health_checks[service_name] = health_check
        self._services[service_name] = ServiceHealth(
            service_name=service_name,
            status=ServiceStatus.UNKNOWN,
            last_check=datetime.now(timezone.utc)
        )
        logger.info(f"Registered service for health monitoring: {service_name}")
    
    def add_health_change_callback(
        self,
        callback: Callable[[str, ServiceHealth], None]
    ):
        """Add callback for health status changes."""
        self._callbacks.append(callback)
    
    async def start(self):
        """Start health monitoring."""
        if self._monitor_task:
            return
        
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Started health monitoring")
    
    async def stop(self):
        """Stop health monitoring."""
        self._shutdown = True
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped health monitoring")
    
    async def _monitor_loop(self):
        """Main monitoring loop."""
        while not self._shutdown:
            try:
                await self._check_all_services()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Error in health monitoring loop: {e}")
                await asyncio.sleep(5)
    
    async def _check_all_services(self):
        """Check health of all registered services."""
        for service_name in self._services:
            try:
                await self._check_service_health(service_name)
            except Exception as e:
                logger.error(f"Error checking health of {service_name}: {e}")
    
    async def _check_service_health(self, service_name: str):
        """Check health of a specific service."""
        health_check = self._health_checks.get(service_name)
        if not health_check:
            return
        
        service = self._services[service_name]
        start_time = time.time()
        
        try:
            # Run health check with timeout
            is_healthy = await asyncio.wait_for(
                self._run_health_check(health_check),
                timeout=10.0
            )
            
            response_time = (time.time() - start_time) * 1000
            
            # Update health status
            old_status = service.status
            
            if is_healthy:
                service.success_count += 1
                service.status = self._determine_status_from_metrics(service)
            else:
                service.error_count += 1
                service.status = ServiceStatus.UNHEALTHY
            
            service.response_time_ms = response_time
            service.last_check = datetime.now(timezone.utc)
            
            # Notify callbacks if status changed
            if old_status != service.status:
                for callback in self._callbacks:
                    try:
                        callback(service_name, service)
                    except Exception as e:
                        logger.error(f"Error in health change callback: {e}")
        
        except asyncio.TimeoutError:
            service.error_count += 1
            service.status = ServiceStatus.CRITICAL
            service.response_time_ms = 10000  # Timeout
            service.last_check = datetime.now(timezone.utc)
            logger.warning(f"Health check timeout for {service_name}")
    
    async def _run_health_check(self, health_check: Callable) -> bool:
        """Run a health check function."""
        if asyncio.iscoroutinefunction(health_check):
            return await health_check()
        else:
            # Run sync function in executor
            return await asyncio.get_event_loop().run_in_executor(
                None, health_check
            )
    
    def _determine_status_from_metrics(self, service: ServiceHealth) -> ServiceStatus:
        """Determine service status based on metrics."""
        success_rate = service.success_rate
        response_time = service.response_time_ms
        
        if success_rate >= 0.95 and response_time < 1000:
            return ServiceStatus.HEALTHY
        elif success_rate >= 0.80 and response_time < 3000:
            return ServiceStatus.DEGRADED
        elif success_rate >= 0.50:
            return ServiceStatus.UNHEALTHY
        else:
            return ServiceStatus.CRITICAL
    
    def get_service_health(self, service_name: str) -> Optional[ServiceHealth]:
        """Get health status of a service."""
        return self._services.get(service_name)
    
    def get_all_health_statuses(self) -> Dict[str, ServiceHealth]:
        """Get health status of all services."""
        return self._services.copy()


class DegradationManager:
    """Manages graceful degradation based on service health."""
    
    def __init__(
        self,
        health_monitor: HealthMonitor,
        cache_backend: Optional[Any] = None
    ):
        self.health_monitor = health_monitor
        self.cache_backend = cache_backend
        self._rules: List[DegradationRule] = []
        self._current_modes: Dict[str, DegradationMode] = {}
        self._fallback_cache: Dict[str, Tuple[Any, datetime]] = {}
        
        # Register for health change notifications
        health_monitor.add_health_change_callback(self._on_health_changed)
    
    def add_rule(self, rule: DegradationRule):
        """Add a degradation rule."""
        self._rules.append(rule)
        # Sort by priority (higher first)
        self._rules.sort(key=lambda r: r.priority, reverse=True)
        logger.info(f"Added degradation rule for {rule.service_name}: {rule.description}")
    
    def _on_health_changed(self, service_name: str, health: ServiceHealth):
        """Handle health status changes."""
        # Check all rules for this service
        for rule in self._rules:
            if rule.service_name == service_name:
                if rule.condition(health):
                    self._activate_degradation(rule, health)
                else:
                    self._deactivate_degradation(rule.service_name)
    
    def _activate_degradation(self, rule: DegradationRule, health: ServiceHealth):
        """Activate degradation mode for a service."""
        old_mode = self._current_modes.get(rule.service_name, DegradationMode.NONE)
        
        if old_mode != rule.degradation_mode:
            self._current_modes[rule.service_name] = rule.degradation_mode
            logger.warning(
                f"Activating degradation for {rule.service_name}: "
                f"{old_mode.value} -> {rule.degradation_mode.value} "
                f"(health: {health.status.value})"
            )
    
    def _deactivate_degradation(self, service_name: str):
        """Deactivate degradation mode for a service."""
        if service_name in self._current_modes:
            old_mode = self._current_modes[service_name]
            self._current_modes[service_name] = DegradationMode.NONE
            logger.info(f"Deactivating degradation for {service_name}: {old_mode.value} -> none")
    
    def get_current_mode(self, service_name: str) -> DegradationMode:
        """Get current degradation mode for a service."""
        return self._current_modes.get(service_name, DegradationMode.NONE)
    
    def is_service_degraded(self, service_name: str) -> bool:
        """Check if a service is currently degraded."""
        return self.get_current_mode(service_name) != DegradationMode.NONE
    
    async def execute_with_degradation(
        self,
        service_name: str,
        primary_handler: Callable,
        cache_key: Optional[str] = None,
        fallback_handler: Optional[Callable] = None,
        **kwargs
    ) -> Any:
        """Execute function with degradation handling."""
        mode = self.get_current_mode(service_name)
        
        if mode == DegradationMode.NONE:
            # Normal operation
            return await self._execute_handler(primary_handler, **kwargs)
        
        elif mode == DegradationMode.CACHING:
            # Try cache first, then primary, then fallback
            if cache_key:
                cached = await self._get_cached_result(cache_key)
                if cached is not None:
                    return cached
            
            try:
                result = await self._execute_handler(primary_handler, **kwargs)
                if cache_key:
                    await self._cache_result(cache_key, result, 300)  # 5 min TTL
                return result
            except Exception:
                if fallback_handler:
                    return await self._execute_handler(fallback_handler, **kwargs)
                raise
        
        elif mode == DegradationMode.FALLBACK:
            # Use fallback handler
            if fallback_handler:
                return await self._execute_handler(fallback_handler, **kwargs)
            else:
                raise RuntimeError(f"Service {service_name} is degraded but no fallback available")
        
        elif mode == DegradationMode.READ_ONLY:
            # Only allow read operations
            operation_type = kwargs.get('operation_type', 'read')
            if operation_type in ['create', 'update', 'delete']:
                raise RuntimeError(f"Service {service_name} is in read-only mode")
            return await self._execute_handler(primary_handler, **kwargs)
        
        elif mode == DegradationMode.DISABLED:
            # Service is completely disabled
            raise RuntimeError(f"Service {service_name} is currently disabled")
        
        else:
            # Simplified mode - use fallback or cached data
            if cache_key:
                cached = await self._get_cached_result(cache_key)
                if cached is not None:
                    return cached
            
            if fallback_handler:
                return await self._execute_handler(fallback_handler, **kwargs)
            
            raise RuntimeError(f"Service {service_name} is degraded and no fallback available")
    
    async def _execute_handler(self, handler: Callable, **kwargs) -> Any:
        """Execute a handler function."""
        if asyncio.iscoroutinefunction(handler):
            return await handler(**kwargs)
        else:
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: handler(**kwargs)
            )
    
    async def _get_cached_result(self, cache_key: str) -> Optional[Any]:
        """Get cached result."""
        if self.cache_backend and REDIS_AVAILABLE:
            try:
                data = await self.cache_backend.get(cache_key)
                if data:
                    import json
                    return json.loads(data.decode() if isinstance(data, bytes) else data)
            except Exception as e:
                logger.warning(f"Cache retrieval error: {e}")
        
        # Fallback to local cache
        if cache_key in self._fallback_cache:
            result, timestamp = self._fallback_cache[cache_key]
            # Check if still valid (5 minute TTL)
            if datetime.now(timezone.utc) - timestamp < timedelta(minutes=5):
                return result
            else:
                del self._fallback_cache[cache_key]
        
        return create_partial_success_result(
            data=None,
            error_code="FALLBACK_CACHE_EXPIRED",
            message="Fallback cache entry has expired",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="Cache expired",
                    details="Fallback cache entry exceeded 5-minute TTL"
                )
            ),
            suggestions=["Refresh cache data", "Check service health", "Review cache TTL settings"]
        )
    
    async def _cache_result(self, cache_key: str, result: Any, ttl: int):
        """Cache a result."""
        if self.cache_backend and REDIS_AVAILABLE:
            try:
                import json
                data = json.dumps(result, default=str)
                await self.cache_backend.setex(cache_key, ttl, data)
            except Exception as e:
                logger.warning(f"Cache storage error: {e}")
        
        # Always store in local fallback cache
        self._fallback_cache[cache_key] = (result, datetime.now(timezone.utc))
        
        # Limit local cache size
        if len(self._fallback_cache) > 1000:
            # Remove oldest 100 entries
            sorted_keys = sorted(
                self._fallback_cache.keys(),
                key=lambda k: self._fallback_cache[k][1]
            )
            for key in sorted_keys[:100]:
                del self._fallback_cache[key]


def with_degradation(
    service_name: str,
    degradation_manager: DegradationManager,
    cache_key: Optional[str] = None,
    fallback_handler: Optional[Callable] = None
):
    """Decorator for adding degradation handling to functions."""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await degradation_manager.execute_with_degradation(
                service_name=service_name,
                primary_handler=lambda **kw: func(*args, **kw),
                cache_key=cache_key,
                fallback_handler=fallback_handler,
                **kwargs
            )
        return wrapper
    return decorator


class DefaultDegradationRules:
    """Common degradation rules for typical services."""
    
    @staticmethod
    def database_degradation() -> DegradationRule:
        """Rule for database degradation."""
        def condition(health: ServiceHealth) -> bool:
            return (health.status in [ServiceStatus.UNHEALTHY, ServiceStatus.CRITICAL] or
                   health.response_time_ms > 5000)
        
        return DegradationRule(
            service_name="database",
            condition=condition,
            degradation_mode=DegradationMode.CACHING,
            cache_ttl_seconds=600,
            description="Cache database queries when DB is slow/unhealthy",
            priority=100
        )
    
    @staticmethod
    def api_degradation() -> DegradationRule:
        """Rule for external API degradation."""
        def condition(health: ServiceHealth) -> bool:
            return health.success_rate < 0.8
        
        return DegradationRule(
            service_name="external_api",
            condition=condition,
            degradation_mode=DegradationMode.FALLBACK,
            description="Use fallback when external API is unreliable",
            priority=90
        )
    
    @staticmethod
    def critical_service_degradation() -> DegradationRule:
        """Rule for critical service that should stay available."""
        def condition(health: ServiceHealth) -> bool:
            return health.status == ServiceStatus.CRITICAL
        
        return DegradationRule(
            service_name="critical_service",
            condition=condition,
            degradation_mode=DegradationMode.READ_ONLY,
            description="Switch to read-only when critical service fails",
            priority=200
        )
    
    @staticmethod
    def cache_degradation() -> DegradationRule:
        """Rule for cache service degradation."""
        def condition(health: ServiceHealth) -> bool:
            return health.status in [ServiceStatus.UNHEALTHY, ServiceStatus.CRITICAL]
        
        return DegradationRule(
            service_name="cache",
            condition=condition,
            degradation_mode=DegradationMode.SIMPLIFIED,
            description="Skip caching when cache service is down",
            priority=50
        )


class ServiceCircuitBreaker:
    """Circuit breaker for service calls."""
    
    def __init__(
        self,
        failure_threshold: int = 5,
        success_threshold: int = 3,
        timeout: float = 60.0
    ):
        self.failure_threshold = failure_threshold
        self.success_threshold = success_threshold
        self.timeout = timeout
        
        self._failure_count = 0
        self._success_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._state = "closed"  # closed, open, half_open
    
    async def call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function through circuit breaker."""
        if self._state == "open":
            if self._should_attempt_reset():
                self._state = "half_open"
            else:
                raise RuntimeError("Circuit breaker is open")
        
        try:
            result = await self._execute_function(func, *args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise e
    
    def _should_attempt_reset(self) -> bool:
        """Check if we should attempt to reset the circuit breaker."""
        if self._last_failure_time is None:
            return False
        
        time_since_failure = datetime.now(timezone.utc) - self._last_failure_time
        return time_since_failure.total_seconds() >= self.timeout
    
    def _on_success(self):
        """Handle successful call."""
        if self._state == "half_open":
            self._success_count += 1
            if self._success_count >= self.success_threshold:
                self._state = "closed"
                self._failure_count = 0
                self._success_count = 0
        else:
            self._failure_count = max(0, self._failure_count - 1)
    
    def _on_failure(self):
        """Handle failed call."""
        self._failure_count += 1
        self._last_failure_time = datetime.now(timezone.utc)
        
        if self._failure_count >= self.failure_threshold:
            self._state = "open"
            self._success_count = 0
    
    async def _execute_function(self, func: Callable, *args, **kwargs) -> Any:
        """Execute a function."""
        if asyncio.iscoroutinefunction(func):
            return await func(*args, **kwargs)
        else:
            return await asyncio.get_event_loop().run_in_executor(
                None, lambda: func(*args, **kwargs)
            )
    
    @property
    def state(self) -> str:
        """Get current circuit breaker state."""
        return self._state
    
    @property
    def failure_count(self) -> int:
        """Get current failure count."""
        return self._failure_count