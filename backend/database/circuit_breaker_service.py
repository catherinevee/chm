"""
Database service for managing circuit breaker state persistence
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from contextlib import asynccontextmanager

from sqlalchemy import select, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError

from backend.database.models import CircuitBreakerState, SystemHealthMetric
from backend.database.session import get_async_session
from backend.common.exceptions import CHMException

# Import Redis service for distributed state
try:
    from backend.database.redis_service import redis_service, redis_circuit_breaker
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis_service = None
    redis_circuit_breaker = None

logger = logging.getLogger(__name__)


class CircuitBreakerDatabaseService:
    """Service for managing circuit breaker state with database persistence and Redis distribution"""
    
    def __init__(self):
        self._cache = {}  # In-memory cache for performance
        self._cache_ttl = 30  # seconds
        self._last_cache_update = {}
        self._use_redis = REDIS_AVAILABLE and redis_service
        self._use_distributed_locks = True
        
    @asynccontextmanager
    async def _get_session(self):
        """Get async database session with proper cleanup"""
        async with get_async_session() as session:
            try:
                yield session
            except Exception as e:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    async def get_circuit_breaker_state(
        self,
        identifier: str,
        failure_threshold: int = 5,
        recovery_timeout: int = 60,
        success_threshold: int = 3
    ) -> Dict[str, Any]:
        """Get circuit breaker state with Redis distribution and database persistence"""
        
        # Check Redis first if available
        if self._use_redis:
            try:
                redis_state = await redis_circuit_breaker.get_state(identifier)
                if redis_state and redis_state.get('state'):
                    logger.debug(f"Retrieved circuit breaker state for {identifier} from Redis")
                    return redis_state
            except Exception as e:
                logger.warning(f"Failed to get circuit breaker state from Redis: {e}")
        
        # Check local cache
        cache_key = f"cb_state_{identifier}"
        if cache_key in self._cache:
            last_update = self._last_cache_update.get(cache_key, datetime.min)
            if datetime.now() - last_update < timedelta(seconds=self._cache_ttl):
                return self._cache[cache_key].copy()
        
        try:
            async with self._get_session() as session:
                # Query existing state from database
                stmt = select(CircuitBreakerState).where(
                    CircuitBreakerState.identifier == identifier
                )
                result = await session.execute(stmt)
                state_record = result.scalar_one_or_none()
                
                if state_record:
                    state_dict = {
                        'state': state_record.state,
                        'failure_count': state_record.failure_count,
                        'success_count': state_record.success_count,
                        'last_failure_time': state_record.last_failure_time,
                        'last_success_time': state_record.last_success_time,
                        'opened_at': state_record.opened_at,
                        'next_attempt_time': state_record.next_attempt_time,
                        'failure_threshold': state_record.failure_threshold,
                        'recovery_timeout': state_record.recovery_timeout,
                        'success_threshold': state_record.success_threshold,
                        'total_calls': state_record.total_calls,
                        'total_failures': state_record.total_failures,
                        'error_details': state_record.error_details or {},
                        'metadata': state_record.metadata or {},
                        'updated_at': state_record.updated_at
                    }
                else:
                    # Create default state
                    state_dict = {
                        'state': 'closed',
                        'failure_count': 0,
                        'success_count': 0,
                        'last_failure_time': None,
                        'last_success_time': None,
                        'opened_at': None,
                        'next_attempt_time': None,
                        'failure_threshold': failure_threshold,
                        'recovery_timeout': recovery_timeout,
                        'success_threshold': success_threshold,
                        'total_calls': 0,
                        'total_failures': 0,
                        'error_details': {},
                        'metadata': {},
                        'updated_at': None
                    }
                    
                    # Create initial record
                    await self._upsert_circuit_breaker_state(
                        session, identifier, state_dict
                    )
                
                # Update local cache
                self._cache[cache_key] = state_dict.copy()
                self._last_cache_update[cache_key] = datetime.now()
                
                # Update Redis cache if available
                if self._use_redis:
                    try:
                        await redis_circuit_breaker.update_state(identifier, state_dict)
                        logger.debug(f"Cached circuit breaker state for {identifier} in Redis")
                    except Exception as e:
                        logger.warning(f"Failed to cache circuit breaker state in Redis: {e}")
                
                return state_dict
                
        except SQLAlchemyError as e:
            logger.error(f"Database error getting circuit breaker state for {identifier}: {e}")
            # Return default state if database fails
            return {
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'last_failure_time': None,
                'last_success_time': None,
                'opened_at': None,
                'next_attempt_time': None,
                'failure_threshold': failure_threshold,
                'recovery_timeout': recovery_timeout,
                'success_threshold': success_threshold,
                'total_calls': 0,
                'total_failures': 0,
                'error_details': {},
                'metadata': {},
                'updated_at': None
            }
    
    async def update_circuit_breaker_state(
        self,
        identifier: str,
        state_updates: Dict[str, Any]
    ) -> bool:
        """Update circuit breaker state with distributed coordination"""
        
        # Use distributed locking for atomic updates if Redis is available
        lock_name = f"cb_update_{identifier}"
        lock = None
        
        try:
            if self._use_redis and self._use_distributed_locks:
                lock = await redis_service.acquire_lock(lock_name, timeout=5, blocking_timeout=2)
                if not lock:
                    logger.warning(f"Failed to acquire lock for circuit breaker {identifier}")
                    # Continue without lock as fallback
            
            async with self._get_session() as session:
                current_time = datetime.now()
                state_updates['updated_at'] = current_time
                
                # Get current state
                current_state = await self.get_circuit_breaker_state(identifier)
                
                # Merge updates
                merged_state = {**current_state, **state_updates}
                
                # Calculate next attempt time if state is opening
                if merged_state['state'] == 'open' and not merged_state.get('next_attempt_time'):
                    merged_state['next_attempt_time'] = current_time + timedelta(
                        seconds=merged_state['recovery_timeout']
                    )
                
                # Clear next attempt time if state is not open
                if merged_state['state'] != 'open':
                    merged_state['next_attempt_time'] = None
                
                # Update database
                success = await self._upsert_circuit_breaker_state(
                    session, identifier, merged_state
                )
                
                if success:
                    # Update local cache
                    cache_key = f"cb_state_{identifier}"
                    self._cache[cache_key] = merged_state.copy()
                    self._last_cache_update[cache_key] = current_time
                    
                    # Update Redis cache
                    if self._use_redis:
                        try:
                            await redis_circuit_breaker.update_state(identifier, merged_state)
                        except Exception as e:
                            logger.warning(f"Failed to update Redis cache: {e}")
                    
                    # Log state transition
                    await self._log_health_metric(
                        session,
                        'circuit_breaker',
                        f'state_transition_{identifier}',
                        metric_text=merged_state['state'],
                        tags={
                            'identifier': identifier,
                            'failure_count': merged_state['failure_count'],
                            'success_count': merged_state['success_count'],
                            'distributed': self._use_redis
                        }
                    )
                
                return success
                
        finally:
            if lock:
                try:
                    await lock.release()
                except Exception as e:
                    logger.warning(f"Failed to release distributed lock: {e}")
                
        except SQLAlchemyError as e:
            logger.error(f"Database error updating circuit breaker state for {identifier}: {e}")
            return False
    
    async def _upsert_circuit_breaker_state(
        self,
        session: AsyncSession,
        identifier: str,
        state_dict: Dict[str, Any]
    ) -> bool:
        """Insert or update circuit breaker state"""
        try:
            # Use PostgreSQL UPSERT (ON CONFLICT) functionality
            stmt = insert(CircuitBreakerState).values(
                identifier=identifier,
                state=state_dict['state'],
                failure_count=state_dict['failure_count'],
                success_count=state_dict['success_count'],
                last_failure_time=state_dict['last_failure_time'],
                last_success_time=state_dict['last_success_time'],
                opened_at=state_dict['opened_at'],
                next_attempt_time=state_dict['next_attempt_time'],
                failure_threshold=state_dict['failure_threshold'],
                recovery_timeout=state_dict['recovery_timeout'],
                success_threshold=state_dict['success_threshold'],
                total_calls=state_dict['total_calls'],
                total_failures=state_dict['total_failures'],
                error_details=state_dict['error_details'],
                metadata=state_dict['metadata']
            )
            
            # On conflict, update all fields except id and created_at
            stmt = stmt.on_conflict_do_update(
                index_elements=[CircuitBreakerState.identifier],
                set_={
                    'state': stmt.excluded.state,
                    'failure_count': stmt.excluded.failure_count,
                    'success_count': stmt.excluded.success_count,
                    'last_failure_time': stmt.excluded.last_failure_time,
                    'last_success_time': stmt.excluded.last_success_time,
                    'opened_at': stmt.excluded.opened_at,
                    'next_attempt_time': stmt.excluded.next_attempt_time,
                    'failure_threshold': stmt.excluded.failure_threshold,
                    'recovery_timeout': stmt.excluded.recovery_timeout,
                    'success_threshold': stmt.excluded.success_threshold,
                    'total_calls': stmt.excluded.total_calls,
                    'total_failures': stmt.excluded.total_failures,
                    'error_details': stmt.excluded.error_details,
                    'metadata': stmt.excluded.metadata,
                    'updated_at': datetime.now()
                }
            )
            
            await session.execute(stmt)
            await session.commit()
            return True
            
        except SQLAlchemyError as e:
            logger.error(f"Error upserting circuit breaker state for {identifier}: {e}")
            await session.rollback()
            return False
    
    async def record_circuit_breaker_call(
        self,
        identifier: str,
        success: bool,
        error_details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Record a circuit breaker call result with distributed counting"""
        
        # Use Redis atomic counters for distributed environments
        if self._use_redis:
            try:
                # Atomic increment of counters
                await redis_circuit_breaker.increment_counter(identifier, 'total_calls')
                if success:
                    await redis_circuit_breaker.increment_counter(identifier, 'success_count')
                else:
                    await redis_circuit_breaker.increment_counter(identifier, 'failure_count')
                    await redis_circuit_breaker.increment_counter(identifier, 'total_failures')
            except Exception as e:
                logger.warning(f"Failed to update Redis counters: {e}")
        
        current_state = await self.get_circuit_breaker_state(identifier)
        
        updates = {
            'total_calls': current_state['total_calls'] + 1
        }
        
        if success:
            updates.update({
                'last_success_time': datetime.now(),
                'success_count': current_state['success_count'] + 1
            })
            
            # Reset failure count on success in half-open state
            if current_state['state'] == 'half_open':
                if current_state['success_count'] + 1 >= current_state['success_threshold']:
                    # Circuit should close
                    updates.update({
                        'state': 'closed',
                        'failure_count': 0,
                        'opened_at': None
                    })
        else:
            updates.update({
                'last_failure_time': datetime.now(),
                'failure_count': current_state['failure_count'] + 1,
                'total_failures': current_state['total_failures'] + 1
            })
            
            if error_details:
                # Keep only recent errors (last 10)
                recent_errors = current_state.get('error_details', {}).get('recent_errors', [])
                recent_errors.append({
                    'timestamp': datetime.now().isoformat(),
                    'details': error_details
                })
                recent_errors = recent_errors[-10:]  # Keep last 10 errors
                
                updates['error_details'] = {
                    'recent_errors': recent_errors,
                    'last_error': error_details
                }
            
            # Check if circuit should open
            if (current_state['state'] == 'closed' and 
                current_state['failure_count'] + 1 >= current_state['failure_threshold']):
                updates.update({
                    'state': 'open',
                    'opened_at': datetime.now(),
                    'success_count': 0  # Reset success count when opening
                })
            elif current_state['state'] == 'half_open':
                # Any failure in half-open state reopens circuit
                updates.update({
                    'state': 'open',
                    'opened_at': datetime.now(),
                    'success_count': 0
                })
        
        await self.update_circuit_breaker_state(identifier, updates)
    
    async def check_circuit_breaker_recovery(self, identifier: str) -> bool:
        """Check if circuit breaker should transition to half-open state"""
        current_state = await self.get_circuit_breaker_state(identifier)
        
        if (current_state['state'] == 'open' and 
            current_state['next_attempt_time'] and
            datetime.now() >= current_state['next_attempt_time']):
            
            # Transition to half-open
            await self.update_circuit_breaker_state(identifier, {
                'state': 'half_open',
                'success_count': 0,
                'next_attempt_time': None
            })
            return True
        
        return False
    
    async def get_circuit_breaker_stats(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get comprehensive circuit breaker statistics from all sources"""
        try:
            stats = {
                'total_circuit_breakers': 0,
                'states': {
                    'closed': 0,
                    'open': 0,
                    'half_open': 0
                },
                'total_calls': 0,
                'total_failures': 0,
                'failure_rate': 0.0,
                'circuit_breakers': [],
                'data_sources': []
            }
            
            # Get stats from Redis if available
            redis_states = {}
            if self._use_redis:
                try:
                    redis_states = await redis_circuit_breaker.get_all_states()
                    stats['data_sources'].append('redis')
                    logger.debug(f"Retrieved {len(redis_states)} states from Redis")
                except Exception as e:
                    logger.warning(f"Failed to get Redis circuit breaker states: {e}")
            
            # Get stats from database
            db_states = {}
            async with self._get_session() as session:
                stmt = select(CircuitBreakerState)
                result = await session.execute(stmt)
                db_records = result.scalars().all()
                stats['data_sources'].append('database')
                
                for record in db_records:
                    db_states[record.identifier] = {
                        'state': record.state,
                        'failure_count': record.failure_count,
                        'success_count': record.success_count,
                        'total_calls': record.total_calls,
                        'total_failures': record.total_failures,
                        'last_updated': record.updated_at
                    }
            
            # Merge states (Redis takes precedence for active systems)
            all_states = {**db_states, **redis_states}
            stats['total_circuit_breakers'] = len(all_states)
                
                stats = {
                    'total_circuit_breakers': len(states),
                    'states': {
                        'closed': 0,
                        'open': 0,
                        'half_open': 0
                    },
                    'total_calls': 0,
                    'total_failures': 0,
                    'failure_rate': 0.0,
                    'circuit_breakers': []
                }
                
            for identifier, state_data in all_states.items():
                state = state_data['state']
                stats['states'][state] += 1
                stats['total_calls'] += state_data.get('total_calls', 0)
                stats['total_failures'] += state_data.get('total_failures', 0)
                
                total_calls = state_data.get('total_calls', 0)
                total_failures = state_data.get('total_failures', 0)
                failure_rate = (total_failures / max(total_calls, 1)) * 100 if total_calls > 0 else 0
                
                stats['circuit_breakers'].append({
                    'identifier': identifier,
                    'state': state,
                    'failure_count': state_data.get('failure_count', 0),
                    'success_count': state_data.get('success_count', 0),
                    'total_calls': total_calls,
                    'total_failures': total_failures,
                    'failure_rate': failure_rate,
                    'last_updated': state_data.get('last_updated'),
                    'source': 'redis' if identifier in redis_states else 'database'
                })
                
            if stats['total_calls'] > 0:
                stats['failure_rate'] = (stats['total_failures'] / stats['total_calls']) * 100
            
            stats['redis_available'] = self._use_redis
            stats['distributed_locks'] = self._use_distributed_locks
            
            return stats
                
        except SQLAlchemyError as e:
            logger.error(f"Database error getting circuit breaker stats: {e}")
            return {
                'error': str(e),
                'total_circuit_breakers': 0,
                'states': {'closed': 0, 'open': 0, 'half_open': 0}
            }
    
    async def cleanup_old_states(self, days_old: int = 30) -> int:
        """Clean up old circuit breaker states that haven't been updated"""
        try:
            async with self._get_session() as session:
                cutoff_time = datetime.now() - timedelta(days=days_old)
                
                stmt = delete(CircuitBreakerState).where(
                    CircuitBreakerState.updated_at < cutoff_time
                )
                
                result = await session.execute(stmt)
                deleted_count = result.rowcount
                await session.commit()
                
                logger.info(f"Cleaned up {deleted_count} old circuit breaker states")
                
                # Clear cache entries for deleted states
                to_remove = []
                for cache_key in self._cache:
                    if cache_key.startswith('cb_state_'):
                        identifier = cache_key[9:]  # Remove 'cb_state_' prefix
                        state = await self.get_circuit_breaker_state(identifier)
                        if not state.get('updated_at'):
                            to_remove.append(cache_key)
                
                for key in to_remove:
                    del self._cache[key]
                    if key in self._last_cache_update:
                        del self._last_cache_update[key]
                
                return deleted_count
                
        except SQLAlchemyError as e:
            logger.error(f"Error cleaning up old circuit breaker states: {e}")
            return 0
    
    async def _log_health_metric(
        self,
        session: AsyncSession,
        category: str,
        name: str,
        value: Optional[float] = None,
        metric_text: Optional[str] = None,
        service_name: str = 'circuit_breaker',
        tags: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log system health metric"""
        try:
            metric = SystemHealthMetric(
                metric_category=category,
                metric_name=name,
                metric_value=value,
                metric_text=metric_text,
                service_name=service_name,
                tags=tags or {},
                timestamp=datetime.now()
            )
            
            session.add(metric)
            await session.commit()
            
        except SQLAlchemyError as e:
            logger.warning(f"Failed to log health metric: {e}")
            # Don't fail the main operation for logging issues
            await session.rollback()


# Global instance
circuit_breaker_db_service = CircuitBreakerDatabaseService()