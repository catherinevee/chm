"""
Common utility functions and decorators
"""

import asyncio
import functools
import logging
from typing import Any, Callable, Optional, Type, Union, Tuple, Dict
from datetime import datetime, timedelta
import random
import hashlib
import uuid

logger = logging.getLogger(__name__)

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    jitter: bool = True,
    max_delay: float = 300.0,
    exceptions: Tuple[Type[Exception], ...] = (Exception,),
    on_retry: Optional[Callable] = None
):
    """
    Retry decorator with exponential backoff and jitter
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier
        jitter: Whether to add jitter to prevent thundering herd
        max_delay: Maximum delay between retries
        exceptions: Tuple of exceptions to catch
        on_retry: Optional callback function called on each retry
    """
    def decorator(func):
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    if asyncio.iscoroutinefunction(func):
                        return await func(*args, **kwargs)
                    else:
                        # Handle sync function in async context
                        loop = asyncio.get_event_loop()
                        return await loop.run_in_executor(None, lambda: func(*args, **kwargs))
                        
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.error(f"Max retries ({max_attempts}) exceeded for {func.__name__}: {e}")
                        raise
                    
                    logger.warning(f"Attempt {attempt}/{max_attempts} failed for {func.__name__}: {e}")
                    
                    if on_retry:
                        try:
                            if asyncio.iscoroutinefunction(on_retry):
                                await on_retry(attempt, e)
                            else:
                                on_retry(attempt, e)
                        except Exception as callback_error:
                            logger.error(f"Error in retry callback: {callback_error}")
                    
                    # Calculate delay with exponential backoff
                    retry_delay = min(delay * (backoff ** (attempt - 1)), max_delay)
                    
                    # Add jitter to prevent thundering herd
                    if jitter:
                        jitter_amount = random.uniform(-retry_delay * 0.1, retry_delay * 0.1)
                        retry_delay = max(0.1, retry_delay + jitter_amount)
                    
                    logger.debug(f"Retrying {func.__name__} in {retry_delay:.2f} seconds")
                    await asyncio.sleep(retry_delay)
            
            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError(f"Retry decorator failed for unknown reason")
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            import time
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                    
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.error(f"Max retries ({max_attempts}) exceeded for {func.__name__}: {e}")
                        raise
                    
                    logger.warning(f"Attempt {attempt}/{max_attempts} failed for {func.__name__}: {e}")
                    
                    if on_retry:
                        try:
                            on_retry(attempt, e)
                        except Exception as callback_error:
                            logger.error(f"Error in retry callback: {callback_error}")
                    
                    # Calculate delay with exponential backoff
                    retry_delay = min(delay * (backoff ** (attempt - 1)), max_delay)
                    
                    # Add jitter to prevent thundering herd
                    if jitter:
                        jitter_amount = random.uniform(-retry_delay * 0.1, retry_delay * 0.1)
                        retry_delay = max(0.1, retry_delay + jitter_amount)
                    
                    logger.debug(f"Retrying {func.__name__} in {retry_delay:.2f} seconds")
                    time.sleep(retry_delay)
            
            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
            else:
                raise RuntimeError(f"Retry decorator failed for unknown reason")
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def rate_limit(
    max_calls: int,
    period: timedelta = timedelta(seconds=60)
):
    """
    Rate limiting decorator
    
    Args:
        max_calls: Maximum number of calls allowed
        period: Time period for rate limiting
    """
    def decorator(func):
        calls = []
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            nonlocal calls
            now = datetime.utcnow()
            
            # Remove old calls outside the period
            calls = [call_time for call_time in calls 
                    if now - call_time < period]
            
            if len(calls) >= max_calls:
                wait_time = (calls[0] + period - now).total_seconds()
                raise Exception(f"Rate limit exceeded. Try again in {wait_time:.1f} seconds")
            
            calls.append(now)
            return await func(*args, **kwargs)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            nonlocal calls
            now = datetime.utcnow()
            
            # Remove old calls outside the period
            calls = [call_time for call_time in calls 
                    if now - call_time < period]
            
            if len(calls) >= max_calls:
                wait_time = (calls[0] + period - now).total_seconds()
                raise Exception(f"Rate limit exceeded. Try again in {wait_time:.1f} seconds")
            
            calls.append(now)
            return func(*args, **kwargs)
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def timeout(seconds: int):
    """
    Timeout decorator for async functions
    
    Args:
        seconds: Timeout in seconds
    """
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(
                    func(*args, **kwargs),
                    timeout=seconds
                )
            except asyncio.TimeoutError:
                logger.error(f"Function {func.__name__} timed out after {seconds} seconds")
                raise
        
        return wrapper
    return decorator


# Import database service for circuit breaker state
try:
    from backend.database.circuit_breaker_service import circuit_breaker_db_service
    _use_db_persistence = True
except ImportError:
    logger.warning("Circuit breaker database service not available, using memory-only fallback")
    _use_db_persistence = False
    
    # Fallback in-memory state manager
    class MemoryCircuitBreakerState:
        def __init__(self):
            self._state_cache = {}
        
        async def get_circuit_breaker_state(self, identifier: str, **kwargs) -> Dict[str, Any]:
            if identifier not in self._state_cache:
                self._state_cache[identifier] = {
                    'state': 'closed',
                    'failure_count': 0,
                    'success_count': 0,
                    'last_failure_time': None,
                    'last_success_time': None,
                    'opened_at': None,
                    'next_attempt_time': None,
                    'failure_threshold': kwargs.get('failure_threshold', 5),
                    'recovery_timeout': kwargs.get('recovery_timeout', 60),
                    'success_threshold': kwargs.get('success_threshold', 3),
                    'total_calls': 0,
                    'total_failures': 0,
                    'error_details': {},
                    'metadata': {},
                    'updated_at': datetime.now()
                }
            return self._state_cache[identifier]
        
        async def update_circuit_breaker_state(self, identifier: str, updates: Dict[str, Any]) -> bool:
            if identifier in self._state_cache:
                self._state_cache[identifier].update(updates)
                self._state_cache[identifier]['updated_at'] = datetime.now()
            return True
        
        async def record_circuit_breaker_call(self, identifier: str, success: bool, error_details=None):
            state = await self.get_circuit_breaker_state(identifier)
            state['total_calls'] += 1
            if success:
                state['success_count'] += 1
                state['last_success_time'] = datetime.now()
            else:
                state['failure_count'] += 1
                state['total_failures'] += 1
                state['last_failure_time'] = datetime.now()
                if error_details:
                    state['error_details']['last_error'] = error_details
        
        async def check_circuit_breaker_recovery(self, identifier: str) -> bool:
            state = await self.get_circuit_breaker_state(identifier)
            if (state['state'] == 'open' and 
                state['next_attempt_time'] and
                datetime.now() >= state['next_attempt_time']):
                await self.update_circuit_breaker_state(identifier, {
                    'state': 'half_open',
                    'success_count': 0
                })
                return True
            return False
    
    circuit_breaker_db_service = MemoryCircuitBreakerState()


def circuit_breaker(
    failure_threshold: int = 5,
    recovery_timeout: int = 60,
    expected_exception: Type[Exception] = Exception,
    success_threshold: int = 3
):
    """
    Production-ready circuit breaker with persistent database state
    
    Args:
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before attempting recovery
        expected_exception: Exception type to count as failure
        success_threshold: Number of successes required to close from half-open
    """
    def decorator(func):
        circuit_id = f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Check for recovery from open state
            await circuit_breaker_db_service.check_circuit_breaker_recovery(circuit_id)
            
            # Get current state
            state = await circuit_breaker_db_service.get_circuit_breaker_state(
                circuit_id,
                failure_threshold=failure_threshold,
                recovery_timeout=recovery_timeout,
                success_threshold=success_threshold
            )
            
            current_time = datetime.now()
            
            # Check if circuit is open
            if state['state'] == 'open':
                next_attempt = state.get('next_attempt_time')
                if next_attempt and current_time < next_attempt:
                    wait_seconds = (next_attempt - current_time).total_seconds()
                    raise Exception(
                        f"Circuit breaker is open for {func.__name__}. "
                        f"Next attempt in {wait_seconds:.1f} seconds"
                    )
            
            # Check if we're in half-open state with too many ongoing calls
            if state['state'] == 'half_open':
                if state['success_count'] >= success_threshold:
                    # Should have been closed already, but handle edge case
                    await circuit_breaker_db_service.update_circuit_breaker_state(
                        circuit_id, {'state': 'closed', 'failure_count': 0}
                    )
            
            # Execute the function
            error_details = None
            success = False
            
            try:
                result = await func(*args, **kwargs)
                success = True
                return result
                
            except expected_exception as e:
                error_details = {
                    'exception_type': type(e).__name__,
                    'message': str(e),
                    'timestamp': current_time.isoformat()
                }
                raise
            
            except Exception as e:
                # Unexpected exceptions should also be tracked
                error_details = {
                    'exception_type': type(e).__name__,
                    'message': str(e),
                    'timestamp': current_time.isoformat(),
                    'unexpected': True
                }
                raise
            
            finally:
                # Record the call result
                try:
                    await circuit_breaker_db_service.record_circuit_breaker_call(
                        circuit_id, success, error_details
                    )
                except Exception as db_error:
                    logger.error(f"Failed to record circuit breaker call: {db_error}")
                    # Don't fail the original operation due to logging issues
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            """
            Synchronous wrapper with simplified state management
            Note: Sync functions use function-local state for performance
            """
            if not hasattr(func, '_cb_state'):
                func._cb_state = {
                    'state': 'closed',
                    'failure_count': 0,
                    'last_failure_time': None,
                    'last_success_time': None
                }
            
            state = func._cb_state
            current_time = datetime.now()
            
            # Check if circuit should recover
            if (state['state'] == 'open' and 
                state['last_failure_time'] and
                (current_time - state['last_failure_time']).total_seconds() > recovery_timeout):
                state['state'] = 'half_open'
                logger.info(f"Circuit breaker for {func.__name__} entering half-open state")
            
            # Block if circuit is open
            if state['state'] == 'open':
                time_until_retry = recovery_timeout
                if state['last_failure_time']:
                    elapsed = (current_time - state['last_failure_time']).total_seconds()
                    time_until_retry = max(0, recovery_timeout - elapsed)
                
                raise Exception(
                    f"Circuit breaker is open for {func.__name__}. "
                    f"Retry in {time_until_retry:.1f} seconds"
                )
            
            try:
                result = func(*args, **kwargs)
                
                # Success - reset or close circuit
                if state['state'] == 'half_open':
                    state['state'] = 'closed'
                    state['failure_count'] = 0
                    logger.info(f"Circuit breaker for {func.__name__} closed after successful recovery")
                
                state['last_success_time'] = current_time
                return result
                
            except expected_exception as e:
                state['failure_count'] += 1
                state['last_failure_time'] = current_time
                
                if state['failure_count'] >= failure_threshold or state['state'] == 'half_open':
                    state['state'] = 'open'
                    logger.error(f"Circuit breaker for {func.__name__} opened after {state['failure_count']} failures")
                
                raise
        
        # Return appropriate wrapper based on function type
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


async def get_circuit_breaker_stats() -> Dict[str, Any]:
    """Get circuit breaker statistics across the application"""
    try:
        return await circuit_breaker_db_service.get_circuit_breaker_stats()
    except Exception as e:
        logger.error(f"Failed to get circuit breaker stats: {e}")
        return {'error': str(e)}


async def reset_circuit_breaker(identifier: str) -> bool:
    """Reset a circuit breaker to closed state"""
    try:
        return await circuit_breaker_db_service.update_circuit_breaker_state(
            identifier,
            {
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'opened_at': None,
                'next_attempt_time': None
            }
        )
    except Exception as e:
        logger.error(f"Failed to reset circuit breaker {identifier}: {e}")
        return False


def generate_unique_id(prefix: str = "") -> str:
    """Generate a unique identifier"""
    unique_id = str(uuid.uuid4())
    if prefix:
        return f"{prefix}_{unique_id}"
    return unique_id


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password with salt
    
    Returns:
        Tuple of (hashed_password, salt)
    """
    if not salt:
        salt = hashlib.sha256(str(random.random()).encode()).hexdigest()
    
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        100000  # iterations
    )
    
    return hashed.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify a password against hash"""
    new_hash, _ = hash_password(password, salt)
    return new_hash == hashed


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename for safe storage"""
    import re
    # Remove any path components
    filename = filename.split('/')[-1].split('\\')[-1]
    # Remove dangerous characters
    filename = re.sub(r'[^\w\s.-]', '', filename)
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
        filename = name[:250] + '.' + ext if ext else name[:255]
    return filename


def format_bytes(bytes_value: int) -> str:
    """Format bytes to human readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_value < 1024.0:
            return f"{bytes_value:.2f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.2f} PB"


def parse_duration(duration_str: str) -> timedelta:
    """
    Parse duration string to timedelta
    Examples: "1h", "30m", "1d", "1h30m"
    """
    import re
    
    pattern = re.compile(r'((?P<days>\d+)d)?((?P<hours>\d+)h)?((?P<minutes>\d+)m)?((?P<seconds>\d+)s)?')
    match = pattern.match(duration_str)
    
    if not match:
        raise ValueError(f"Invalid duration format: {duration_str}")
    
    parts = match.groupdict()
    time_params = {}
    
    for name, param in parts.items():
        if param:
            time_params[name] = int(param)
    
    return timedelta(**time_params)


def chunks(lst: list, n: int):
    """Yield successive n-sized chunks from list"""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def flatten(nested_list: list) -> list:
    """Flatten a nested list"""
    result = []
    for item in nested_list:
        if isinstance(item, list):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result


def get_client_ip(request) -> str:
    """Get client IP from request, considering proxies"""
    # Check for X-Forwarded-For header
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fall back to remote address
    return request.client.host if hasattr(request, 'client') else '0.0.0.0'


class AsyncContextManager:
    """Base class for async context managers"""
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MeasureTime(AsyncContextManager):
    """Context manager to measure execution time"""
    
    def __init__(self, name: str = "Operation"):
        self.name = name
        self.start_time = None
        self.end_time = None
    
    async def __aenter__(self):
        self.start_time = datetime.utcnow()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.end_time = datetime.utcnow()
        duration = (self.end_time - self.start_time).total_seconds()
        logger.info(f"{self.name} took {duration:.3f} seconds")
    
    @property
    def elapsed(self) -> float:
        """Get elapsed time in seconds"""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        elif self.start_time:
            return (datetime.utcnow() - self.start_time).total_seconds()
        return 0.0