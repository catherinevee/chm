"""
Production-grade circuit breaker implementation.
Provides fault tolerance and prevents cascading failures in distributed systems.
"""

import asyncio
import time
import functools
import random
from typing import Dict, List, Optional, Any, Callable, Union, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
from collections import deque
import threading
import weakref
import inspect

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)

T = TypeVar('T')


class CircuitState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"       # Normal operation
    OPEN = "open"           # Failing, reject requests
    HALF_OPEN = "half_open" # Testing if service recovered


class FailureType(Enum):
    """Types of failures to track"""
    TIMEOUT = "timeout"
    ERROR = "error"
    EXCEPTION = "exception"
    STATUS_CODE = "status_code"
    CUSTOM = "custom"


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration"""
    # Failure thresholds
    failure_threshold: int = 5          # Failures to open circuit
    success_threshold: int = 3          # Successes to close from half-open
    timeout: float = 10.0               # Request timeout in seconds
    
    # Time windows
    window_size: int = 60               # Rolling window in seconds
    half_open_timeout: int = 30         # Time before trying half-open
    
    # Failure criteria
    error_threshold_percentage: float = 50.0  # Error percentage to open
    slow_call_duration: float = 5.0           # Slow call threshold
    slow_call_rate_threshold: float = 50.0    # Slow call percentage to open
    
    # Advanced settings
    permitted_calls_in_half_open: int = 3     # Calls allowed in half-open
    sliding_window_type: str = "count"        # "count" or "time"
    minimum_number_of_calls: int = 10         # Min calls before evaluation
    
    # Recovery
    exponential_backoff: bool = True          # Exponential backoff for retry
    max_backoff: int = 300                    # Max backoff in seconds
    jitter: bool = True                       # Add jitter to prevent thundering herd
    
    # Exceptions to track
    tracked_exceptions: List[type] = field(default_factory=lambda: [Exception])
    ignored_exceptions: List[type] = field(default_factory=list)
    
    # Fallback
    fallback_function: Optional[Callable] = None
    
    # Distributed state
    use_redis: bool = True
    redis_key_prefix: str = "circuit"
    sync_interval: float = 5.0  # Sync with Redis every N seconds


@dataclass
class CircuitMetrics:
    """Circuit breaker metrics"""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    slow_calls: int = 0
    calls_not_permitted: int = 0
    
    state_transitions: List[Tuple[CircuitState, datetime]] = field(default_factory=list)
    response_times: deque = field(default_factory=lambda: deque(maxlen=1000))
    
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    
    # Sliding window metrics
    window_calls: deque = field(default_factory=lambda: deque(maxlen=100))
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate"""
        if self.total_calls == 0:
            return 0.0
        return (self.failed_calls / self.total_calls) * 100
    
    @property
    def slow_call_rate(self) -> float:
        """Calculate slow call rate"""
        if self.total_calls == 0:
            return 0.0
        return (self.slow_calls / self.total_calls) * 100
    
    @property
    def average_response_time(self) -> float:
        """Calculate average response time"""
        if not self.response_times:
            return 0.0
        return sum(self.response_times) / len(self.response_times)
    
    def get_recent_failure_rate(self, window_seconds: int = 60) -> float:
        """Get failure rate for recent window"""
        cutoff = time.time() - window_seconds
        recent_calls = [call for call in self.window_calls if call['timestamp'] > cutoff]
        
        if not recent_calls:
            return 0.0
        
        failures = sum(1 for call in recent_calls if not call['success'])
        return (failures / len(recent_calls)) * 100


class CircuitBreaker(Generic[T]):
    """Generic circuit breaker implementation"""
    
    def __init__(self, 
                 name: str,
                 config: Optional[CircuitBreakerConfig] = None,
                 redis_client: Optional[redis.Redis] = None):
        self.name = name
        self.config = config or CircuitBreakerConfig()
        self.redis_client = redis_client if self.config.use_redis else None
        
        # State
        self._state = CircuitState.CLOSED
        self._state_lock = threading.RLock()
        
        # Metrics
        self.metrics = CircuitMetrics()
        
        # Timers
        self._last_state_change = time.time()
        self._next_attempt_time = 0
        self._half_open_calls = 0
        
        # Consecutive successes/failures
        self._consecutive_successes = 0
        self._consecutive_failures = 0
        
        # Backoff
        self._failure_count = 0
        self._backoff_time = self.config.half_open_timeout
        
        # Distributed sync
        self._last_sync = 0
        self._sync_lock = threading.Lock()
    
    @property
    def state(self) -> CircuitState:
        """Get current state with automatic transitions"""
        with self._state_lock:
            # Check if should transition from OPEN to HALF_OPEN
            if self._state == CircuitState.OPEN:
                if time.time() >= self._next_attempt_time:
                    self._transition_to_half_open()
            
            return self._state
    
    @state.setter
    def state(self, value: CircuitState):
        """Set state and record transition"""
        with self._state_lock:
            if self._state != value:
                self._state = value
                self._last_state_change = time.time()
                self.metrics.state_transitions.append((value, datetime.now()))
                
                # Reset counters on state change
                if value == CircuitState.HALF_OPEN:
                    self._half_open_calls = 0
                
                logger.info(f"Circuit breaker '{self.name}' transitioned to {value.value}")
    
    def _transition_to_half_open(self):
        """Transition from OPEN to HALF_OPEN"""
        self.state = CircuitState.HALF_OPEN
        self._consecutive_successes = 0
        self._consecutive_failures = 0
    
    def _transition_to_open(self):
        """Transition to OPEN state"""
        self.state = CircuitState.OPEN
        
        # Calculate next attempt time with backoff
        if self.config.exponential_backoff:
            self._backoff_time = min(
                self._backoff_time * 2,
                self.config.max_backoff
            )
        else:
            self._backoff_time = self.config.half_open_timeout
        
        # Add jitter if configured
        if self.config.jitter:
            jitter = random.uniform(0, self._backoff_time * 0.1)
            self._next_attempt_time = time.time() + self._backoff_time + jitter
        else:
            self._next_attempt_time = time.time() + self._backoff_time
        
        self._failure_count += 1
    
    def _transition_to_closed(self):
        """Transition to CLOSED state"""
        self.state = CircuitState.CLOSED
        self._failure_count = 0
        self._backoff_time = self.config.half_open_timeout
        self._consecutive_failures = 0
        self._consecutive_successes = 0
    
    async def call(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Execute function through circuit breaker"""
        # Sync with distributed state if needed
        await self._sync_distributed_state()
        
        # Check if call is permitted
        if not self._is_call_permitted():
            self.metrics.calls_not_permitted += 1
            
            # Use fallback if available
            if self.config.fallback_function:
                return await self._execute_fallback(func, *args, **kwargs)
            
            raise CircuitBreakerError(f"Circuit breaker '{self.name}' is OPEN")
        
        # Record call start
        start_time = time.time()
        self.metrics.total_calls += 1
        
        try:
            # Execute with timeout
            if asyncio.iscoroutinefunction(func):
                result = await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=self.config.timeout
                )
            else:
                result = await asyncio.wait_for(
                    asyncio.to_thread(func, *args, **kwargs),
                    timeout=self.config.timeout
                )
            
            # Record success
            duration = time.time() - start_time
            await self._on_success(duration)
            
            return result
            
        except asyncio.TimeoutError as e:
            # Record timeout
            duration = time.time() - start_time
            await self._on_failure(FailureType.TIMEOUT, e, duration)
            raise
            
        except Exception as e:
            # Check if should track this exception
            if self._should_track_exception(e):
                duration = time.time() - start_time
                await self._on_failure(FailureType.EXCEPTION, e, duration)
            raise
    
    def _is_call_permitted(self) -> bool:
        """Check if call is permitted based on state"""
        current_state = self.state  # This triggers automatic transitions
        
        if current_state == CircuitState.CLOSED:
            return True
        
        elif current_state == CircuitState.OPEN:
            return False
        
        elif current_state == CircuitState.HALF_OPEN:
            with self._state_lock:
                if self._half_open_calls < self.config.permitted_calls_in_half_open:
                    self._half_open_calls += 1
                    return True
                return False
        
        return False
    
    def _should_track_exception(self, exception: Exception) -> bool:
        """Check if exception should be tracked"""
        # Check ignored exceptions
        for ignored_type in self.config.ignored_exceptions:
            if isinstance(exception, ignored_type):
                return False
        
        # Check tracked exceptions
        for tracked_type in self.config.tracked_exceptions:
            if isinstance(exception, tracked_type):
                return True
        
        return False
    
    async def _on_success(self, duration: float):
        """Handle successful call"""
        self.metrics.successful_calls += 1
        self.metrics.last_success_time = datetime.now()
        self.metrics.response_times.append(duration)
        
        # Check for slow call
        if duration > self.config.slow_call_duration:
            self.metrics.slow_calls += 1
        
        # Record in window
        self.metrics.window_calls.append({
            'timestamp': time.time(),
            'success': True,
            'duration': duration
        })
        
        with self._state_lock:
            self._consecutive_successes += 1
            self._consecutive_failures = 0
            
            # State transitions based on success
            if self._state == CircuitState.HALF_OPEN:
                if self._consecutive_successes >= self.config.success_threshold:
                    self._transition_to_closed()
            
            elif self._state == CircuitState.CLOSED:
                # Reset failure tracking on success
                pass
        
        # Update distributed state
        await self._update_distributed_state()
    
    async def _on_failure(self, failure_type: FailureType, exception: Exception, duration: float):
        """Handle failed call"""
        self.metrics.failed_calls += 1
        self.metrics.last_failure_time = datetime.now()
        self.metrics.response_times.append(duration)
        
        # Record in window
        self.metrics.window_calls.append({
            'timestamp': time.time(),
            'success': False,
            'duration': duration,
            'failure_type': failure_type.value
        })
        
        with self._state_lock:
            self._consecutive_failures += 1
            self._consecutive_successes = 0
            
            # State transitions based on failure
            if self._state == CircuitState.HALF_OPEN:
                # Single failure in half-open goes back to open
                self._transition_to_open()
            
            elif self._state == CircuitState.CLOSED:
                # Check if should open circuit
                if self._should_open_circuit():
                    self._transition_to_open()
        
        # Update distributed state
        await self._update_distributed_state()
    
    def _should_open_circuit(self) -> bool:
        """Determine if circuit should open"""
        # Check minimum calls
        if self.metrics.total_calls < self.config.minimum_number_of_calls:
            return False
        
        # Check consecutive failures
        if self._consecutive_failures >= self.config.failure_threshold:
            return True
        
        # Check failure rate
        recent_failure_rate = self.metrics.get_recent_failure_rate(self.config.window_size)
        if recent_failure_rate > self.config.error_threshold_percentage:
            return True
        
        # Check slow call rate
        if self.metrics.slow_call_rate > self.config.slow_call_rate_threshold:
            return True
        
        return False
    
    async def _execute_fallback(self, original_func: Callable, *args, **kwargs) -> T:
        """Execute fallback function"""
        if not self.config.fallback_function:
            raise CircuitBreakerError(f"No fallback configured for '{self.name}'")
        
        try:
            if asyncio.iscoroutinefunction(self.config.fallback_function):
                return await self.config.fallback_function(original_func, *args, **kwargs)
            else:
                return self.config.fallback_function(original_func, *args, **kwargs)
        except Exception as e:
            logger.error(f"Fallback failed for circuit '{self.name}': {e}")
            raise
    
    async def _sync_distributed_state(self):
        """Sync state with Redis if configured"""
        if not self.redis_client or not self.config.use_redis:
            return
        
        # Rate limit syncing
        if time.time() - self._last_sync < self.config.sync_interval:
            return
        
        with self._sync_lock:
            try:
                key = f"{self.config.redis_key_prefix}:{self.name}:state"
                
                # Get distributed state
                state_data = await self.redis_client.get(key)
                
                if state_data:
                    distributed_state = json.loads(state_data)
                    
                    # Sync if distributed state is more restrictive
                    if distributed_state['state'] == CircuitState.OPEN.value:
                        if self._state != CircuitState.OPEN:
                            self.state = CircuitState.OPEN
                            self._next_attempt_time = distributed_state.get('next_attempt', time.time())
                
                self._last_sync = time.time()
                
            except Exception as e:
                logger.warning(f"Failed to sync distributed state for '{self.name}': {e}")
    
    async def _update_distributed_state(self):
        """Update distributed state in Redis"""
        if not self.redis_client or not self.config.use_redis:
            return
        
        try:
            key = f"{self.config.redis_key_prefix}:{self.name}:state"
            
            state_data = {
                'state': self._state.value,
                'next_attempt': self._next_attempt_time,
                'failure_count': self._failure_count,
                'metrics': {
                    'total_calls': self.metrics.total_calls,
                    'failed_calls': self.metrics.failed_calls,
                    'failure_rate': self.metrics.failure_rate
                },
                'updated_at': time.time()
            }
            
            await self.redis_client.setex(
                key,
                self.config.window_size,
                json.dumps(state_data)
            )
            
        except Exception as e:
            logger.warning(f"Failed to update distributed state for '{self.name}': {e}")
    
    def reset(self):
        """Manually reset circuit breaker"""
        with self._state_lock:
            self._transition_to_closed()
            self.metrics = CircuitMetrics()
            logger.info(f"Circuit breaker '{self.name}' manually reset")
    
    def get_status(self) -> Dict[str, Any]:
        """Get circuit breaker status"""
        return {
            'name': self.name,
            'state': self.state.value,
            'metrics': {
                'total_calls': self.metrics.total_calls,
                'successful_calls': self.metrics.successful_calls,
                'failed_calls': self.metrics.failed_calls,
                'slow_calls': self.metrics.slow_calls,
                'calls_not_permitted': self.metrics.calls_not_permitted,
                'failure_rate': self.metrics.failure_rate,
                'slow_call_rate': self.metrics.slow_call_rate,
                'average_response_time': self.metrics.average_response_time
            },
            'consecutive_failures': self._consecutive_failures,
            'consecutive_successes': self._consecutive_successes,
            'next_attempt_time': self._next_attempt_time if self.state == CircuitState.OPEN else None
        }


class CircuitBreakerError(Exception):
    """Circuit breaker exception"""
    pass


class CircuitBreakerRegistry:
    """Registry for managing multiple circuit breakers"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self._breakers: Dict[str, CircuitBreaker] = {}
        self._lock = threading.Lock()
        
        # Weak references for garbage collection
        self._weak_refs: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
    
    def get_or_create(self, 
                      name: str,
                      config: Optional[CircuitBreakerConfig] = None) -> CircuitBreaker:
        """Get existing or create new circuit breaker"""
        with self._lock:
            if name not in self._breakers:
                breaker = CircuitBreaker(name, config, self.redis_client)
                self._breakers[name] = breaker
                self._weak_refs[name] = breaker
            
            return self._breakers[name]
    
    def get(self, name: str) -> Optional[CircuitBreaker]:
        """Get circuit breaker by name"""
        return self._breakers.get(name)
    
    def remove(self, name: str) -> bool:
        """Remove circuit breaker"""
        with self._lock:
            if name in self._breakers:
                del self._breakers[name]
                return True
            return False
    
    def get_all_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all circuit breakers"""
        return {
            name: breaker.get_status()
            for name, breaker in self._breakers.items()
        }
    
    def reset_all(self):
        """Reset all circuit breakers"""
        for breaker in self._breakers.values():
            breaker.reset()


# Global registry
_global_registry = CircuitBreakerRegistry()


def circuit_breaker(name: Optional[str] = None,
                   config: Optional[CircuitBreakerConfig] = None):
    """Decorator for applying circuit breaker to functions"""
    def decorator(func):
        # Use function name if no name provided
        breaker_name = name or f"{func.__module__}.{func.__name__}"
        
        # Get or create circuit breaker
        breaker = _global_registry.get_or_create(breaker_name, config)
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await breaker.call(func, *args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            # Run async circuit breaker in sync context
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(breaker.call(func, *args, **kwargs))
            finally:
                loop.close()
        
        # Return appropriate wrapper
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator