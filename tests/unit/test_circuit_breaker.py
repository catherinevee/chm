"""
Comprehensive unit tests for circuit breaker functionality
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

from backend.database.circuit_breaker_service import CircuitBreakerDatabaseService
from backend.common.utils import circuit_breaker, get_circuit_breaker_stats
from backend.common.exceptions import CHMException


class TestCircuitBreakerDatabaseService:
    """Test circuit breaker database service"""
    
    @pytest.mark.asyncio
    async def test_get_circuit_breaker_state_new(self, circuit_breaker_service):
        """Test getting state for new circuit breaker"""
        identifier = "test.function"
        
        # Mock database session to return no existing state
        with patch.object(circuit_breaker_service, '_get_session') as mock_session:
            mock_db = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db
            mock_db.execute.return_value.scalar_one_or_none.return_value = None
            
            state = await circuit_breaker_service.get_circuit_breaker_state(identifier)
            
            assert state['state'] == 'closed'
            assert state['failure_count'] == 0
            assert state['success_count'] == 0
            assert state['failure_threshold'] == 5
            assert state['recovery_timeout'] == 60
            assert state['success_threshold'] == 3
    
    @pytest.mark.asyncio
    async def test_get_circuit_breaker_state_existing(self, circuit_breaker_service):
        """Test getting state for existing circuit breaker"""
        identifier = "test.function"
        
        # Mock existing state record
        mock_state = Mock()
        mock_state.state = 'open'
        mock_state.failure_count = 7
        mock_state.success_count = 0
        mock_state.last_failure_time = datetime.now()
        mock_state.opened_at = datetime.now()
        mock_state.next_attempt_time = datetime.now() + timedelta(seconds=60)
        mock_state.failure_threshold = 5
        mock_state.recovery_timeout = 60
        mock_state.success_threshold = 3
        mock_state.total_calls = 10
        mock_state.total_failures = 7
        mock_state.error_details = {'last_error': 'Connection failed'}
        mock_state.metadata = {}
        mock_state.updated_at = datetime.now()
        
        with patch.object(circuit_breaker_service, '_get_session') as mock_session:
            mock_db = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db
            mock_db.execute.return_value.scalar_one_or_none.return_value = mock_state
            
            state = await circuit_breaker_service.get_circuit_breaker_state(identifier)
            
            assert state['state'] == 'open'
            assert state['failure_count'] == 7
            assert state['success_count'] == 0
            assert state['total_calls'] == 10
            assert state['total_failures'] == 7
    
    @pytest.mark.asyncio
    async def test_update_circuit_breaker_state(self, circuit_breaker_service):
        """Test updating circuit breaker state"""
        identifier = "test.function"
        updates = {
            'state': 'open',
            'failure_count': 6,
            'last_failure_time': datetime.now()
        }
        
        # Mock current state
        with patch.object(circuit_breaker_service, 'get_circuit_breaker_state') as mock_get:
            mock_get.return_value = {
                'state': 'closed',
                'failure_count': 5,
                'success_count': 2,
                'failure_threshold': 5,
                'recovery_timeout': 60,
                'total_calls': 7,
                'total_failures': 5
            }
            
            with patch.object(circuit_breaker_service, '_upsert_circuit_breaker_state') as mock_upsert:
                mock_upsert.return_value = True
                
                with patch.object(circuit_breaker_service, '_get_session') as mock_session:
                    mock_db = AsyncMock()
                    mock_session.return_value.__aenter__.return_value = mock_db
                    
                    result = await circuit_breaker_service.update_circuit_breaker_state(identifier, updates)
                    
                    assert result is True
                    mock_upsert.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_record_circuit_breaker_call_success(self, circuit_breaker_service):
        """Test recording successful circuit breaker call"""
        identifier = "test.function"
        
        # Mock current state in half-open with enough successes to close
        with patch.object(circuit_breaker_service, 'get_circuit_breaker_state') as mock_get:
            mock_get.return_value = {
                'state': 'half_open',
                'failure_count': 0,
                'success_count': 2,
                'failure_threshold': 5,
                'recovery_timeout': 60,
                'success_threshold': 3,
                'total_calls': 8,
                'total_failures': 5,
                'opened_at': datetime.now() - timedelta(seconds=120)
            }
            
            with patch.object(circuit_breaker_service, 'update_circuit_breaker_state') as mock_update:
                mock_update.return_value = True
                
                await circuit_breaker_service.record_circuit_breaker_call(identifier, True)
                
                # Should be called to update success count and potentially close circuit
                mock_update.assert_called_once()
                call_args = mock_update.call_args[0][1]  # Get the updates dict
                
                assert 'last_success_time' in call_args
                assert call_args['success_count'] == 3
                assert call_args['total_calls'] == 9
    
    @pytest.mark.asyncio
    async def test_record_circuit_breaker_call_failure_opens_circuit(self, circuit_breaker_service):
        """Test recording failure that opens circuit"""
        identifier = "test.function"
        error_details = {'exception_type': 'ConnectionError', 'message': 'Connection failed'}
        
        # Mock current state at threshold
        with patch.object(circuit_breaker_service, 'get_circuit_breaker_state') as mock_get:
            mock_get.return_value = {
                'state': 'closed',
                'failure_count': 4,  # One less than threshold
                'success_count': 5,
                'failure_threshold': 5,
                'recovery_timeout': 60,
                'success_threshold': 3,
                'total_calls': 9,
                'total_failures': 4,
                'error_details': {}
            }
            
            with patch.object(circuit_breaker_service, 'update_circuit_breaker_state') as mock_update:
                mock_update.return_value = True
                
                await circuit_breaker_service.record_circuit_breaker_call(identifier, False, error_details)
                
                mock_update.assert_called_once()
                call_args = mock_update.call_args[0][1]
                
                assert call_args['failure_count'] == 5
                assert call_args['state'] == 'open'
                assert 'opened_at' in call_args
                assert 'last_error' in call_args['error_details']
    
    @pytest.mark.asyncio
    async def test_check_circuit_breaker_recovery(self, circuit_breaker_service):
        """Test checking circuit breaker recovery"""
        identifier = "test.function"
        
        # Mock state that should transition to half-open
        past_time = datetime.now() - timedelta(seconds=120)  # 2 minutes ago
        with patch.object(circuit_breaker_service, 'get_circuit_breaker_state') as mock_get:
            mock_get.return_value = {
                'state': 'open',
                'failure_count': 5,
                'success_count': 0,
                'next_attempt_time': past_time,  # In the past
                'recovery_timeout': 60,
                'total_calls': 10,
                'total_failures': 5
            }
            
            with patch.object(circuit_breaker_service, 'update_circuit_breaker_state') as mock_update:
                mock_update.return_value = True
                
                result = await circuit_breaker_service.check_circuit_breaker_recovery(identifier)
                
                assert result is True
                mock_update.assert_called_once()
                call_args = mock_update.call_args[0][1]
                assert call_args['state'] == 'half_open'
                assert call_args['success_count'] == 0
    
    @pytest.mark.asyncio
    async def test_get_circuit_breaker_stats(self, circuit_breaker_service):
        """Test getting circuit breaker statistics"""
        # Mock multiple circuit breaker states
        mock_states = [
            Mock(
                identifier='service.a',
                state='closed',
                failure_count=1,
                success_count=10,
                total_calls=11,
                total_failures=1,
                updated_at=datetime.now()
            ),
            Mock(
                identifier='service.b', 
                state='open',
                failure_count=5,
                success_count=5,
                total_calls=10,
                total_failures=5,
                updated_at=datetime.now()
            ),
            Mock(
                identifier='service.c',
                state='half_open',
                failure_count=3,
                success_count=1,
                total_calls=8,
                total_failures=4,
                updated_at=datetime.now()
            )
        ]
        
        with patch.object(circuit_breaker_service, '_get_session') as mock_session:
            mock_db = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db
            mock_db.execute.return_value.scalars.return_value.all.return_value = mock_states
            
            stats = await circuit_breaker_service.get_circuit_breaker_stats()
            
            assert stats['total_circuit_breakers'] == 3
            assert stats['states']['closed'] == 1
            assert stats['states']['open'] == 1
            assert stats['states']['half_open'] == 1
            assert stats['total_calls'] == 29
            assert stats['total_failures'] == 10
            assert abs(stats['failure_rate'] - (10/29 * 100)) < 0.01
    
    @pytest.mark.asyncio
    async def test_cleanup_old_states(self, circuit_breaker_service):
        """Test cleanup of old circuit breaker states"""
        with patch.object(circuit_breaker_service, '_get_session') as mock_session:
            mock_db = AsyncMock()
            mock_session.return_value.__aenter__.return_value = mock_db
            mock_db.execute.return_value.rowcount = 3
            
            result = await circuit_breaker_service.cleanup_old_states(days_old=30)
            
            assert result == 3
            mock_db.execute.assert_called_once()
            mock_db.commit.assert_called_once()


class TestCircuitBreakerDecorator:
    """Test circuit breaker decorator functionality"""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_allows_success(self):
        """Test circuit breaker allows successful operations"""
        call_count = 0
        
        @circuit_breaker(failure_threshold=3, recovery_timeout=60)
        async def test_function():
            nonlocal call_count
            call_count += 1
            return "success"
        
        # Mock the database service
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'closed',
                'failure_count': 0,
                'success_count': 5,
                'failure_threshold': 3,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            result = await test_function()
            
            assert result == "success"
            assert call_count == 1
            mock_service.record_circuit_breaker_call.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_blocks_when_open(self):
        """Test circuit breaker blocks calls when open"""
        @circuit_breaker(failure_threshold=3, recovery_timeout=60)
        async def test_function():
            return "success"
        
        # Mock open circuit state
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'open',
                'failure_count': 5,
                'success_count': 0,
                'next_attempt_time': datetime.now() + timedelta(seconds=30),
                'failure_threshold': 3,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            
            with pytest.raises(Exception) as exc_info:
                await test_function()
            
            assert "Circuit breaker is open" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_records_failures(self):
        """Test circuit breaker records failures properly"""
        @circuit_breaker(failure_threshold=3, recovery_timeout=60)
        async def failing_function():
            raise ConnectionError("Connection failed")
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'closed',
                'failure_count': 2,
                'success_count': 1,
                'failure_threshold': 3,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            with pytest.raises(ConnectionError):
                await failing_function()
            
            # Verify failure was recorded
            mock_service.record_circuit_breaker_call.assert_called_once()
            call_args = mock_service.record_circuit_breaker_call.call_args
            assert call_args[0][1] is False  # success=False
            assert call_args[0][2] is not None  # error_details provided
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker recovery from half-open state"""
        success_count = 0
        
        @circuit_breaker(failure_threshold=3, recovery_timeout=60, success_threshold=2)
        async def test_function():
            nonlocal success_count
            success_count += 1
            return f"success_{success_count}"
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'half_open',
                'failure_count': 0,
                'success_count': 1,  # One success already
                'failure_threshold': 3,
                'recovery_timeout': 60,
                'success_threshold': 2
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            result = await test_function()
            
            assert result == "success_1"
            assert success_count == 1
            mock_service.record_circuit_breaker_call.assert_called_once_with(
                'tests.unit.test_circuit_breaker.TestCircuitBreakerDecorator.test_circuit_breaker_half_open_recovery.<locals>.test_function',
                True,
                None
            )
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_custom_exception_type(self):
        """Test circuit breaker with custom exception type"""
        @circuit_breaker(failure_threshold=2, expected_exception=ValueError)
        async def test_function(should_fail: bool = False, error_type: str = "value"):
            if should_fail:
                if error_type == "value":
                    raise ValueError("Value error")
                else:
                    raise TypeError("Type error")
            return "success"
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'failure_threshold': 2,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            # ValueError should be caught and recorded
            with pytest.raises(ValueError):
                await test_function(should_fail=True, error_type="value")
            
            mock_service.record_circuit_breaker_call.assert_called_once()
            assert mock_service.record_circuit_breaker_call.call_args[0][1] is False
            
            # Reset mock
            mock_service.record_circuit_breaker_call.reset_mock()
            
            # TypeError should not be caught by circuit breaker but still recorded
            with pytest.raises(TypeError):
                await test_function(should_fail=True, error_type="type")
            
            # Should still record the call as failure
            mock_service.record_circuit_breaker_call.assert_called_once()
            assert mock_service.record_circuit_breaker_call.call_args[0][1] is False
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_sync_function_fallback(self):
        """Test circuit breaker with synchronous function fallback"""
        call_count = 0
        
        @circuit_breaker(failure_threshold=3, recovery_timeout=60)
        def sync_test_function():
            nonlocal call_count
            call_count += 1
            return "sync_success"
        
        result = sync_test_function()
        
        assert result == "sync_success"
        assert call_count == 1
    
    @pytest.mark.asyncio
    async def test_get_circuit_breaker_stats_integration(self):
        """Test getting circuit breaker statistics"""
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_stats = {
                'total_circuit_breakers': 5,
                'states': {'closed': 3, 'open': 1, 'half_open': 1},
                'total_calls': 150,
                'total_failures': 25,
                'failure_rate': 16.67,
                'circuit_breakers': [
                    {
                        'identifier': 'service.a',
                        'state': 'closed',
                        'failure_count': 2,
                        'total_calls': 50
                    }
                ]
            }
            mock_service.get_circuit_breaker_stats = AsyncMock(return_value=mock_stats)
            
            stats = await get_circuit_breaker_stats()
            
            assert stats['total_circuit_breakers'] == 5
            assert stats['states']['closed'] == 3
            assert stats['failure_rate'] == 16.67
            assert len(stats['circuit_breakers']) == 1


class TestCircuitBreakerEdgeCases:
    """Test circuit breaker edge cases and error conditions"""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_database_failure(self):
        """Test circuit breaker behavior when database fails"""
        @circuit_breaker(failure_threshold=3, recovery_timeout=60)
        async def test_function():
            return "success"
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            # Simulate database failure
            mock_service.get_circuit_breaker_state = AsyncMock(side_effect=Exception("Database error"))
            mock_service.record_circuit_breaker_call = AsyncMock(side_effect=Exception("Database error"))
            
            # Function should still work despite database issues
            result = await test_function()
            assert result == "success"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_concurrent_access(self):
        """Test circuit breaker under concurrent access"""
        call_count = 0
        
        @circuit_breaker(failure_threshold=5, recovery_timeout=60)
        async def concurrent_function(delay: float = 0):
            nonlocal call_count
            call_count += 1
            if delay > 0:
                await asyncio.sleep(delay)
            return f"call_{call_count}"
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'failure_threshold': 5,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            # Run multiple concurrent calls
            tasks = [concurrent_function(0.01) for _ in range(10)]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # All should succeed
            assert len(results) == 10
            assert all('call_' in str(result) for result in results)
            
            # Should have recorded all calls
            assert mock_service.record_circuit_breaker_call.call_count == 10
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_state_transitions(self):
        """Test all circuit breaker state transitions"""
        failure_count = 0
        
        @circuit_breaker(failure_threshold=2, recovery_timeout=1, success_threshold=2)
        async def state_test_function(should_fail: bool = False):
            nonlocal failure_count
            if should_fail:
                failure_count += 1
                raise Exception(f"Failure {failure_count}")
            return "success"
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            # Start in closed state
            mock_state = {
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'failure_threshold': 2,
                'recovery_timeout': 1,
                'success_threshold': 2,
                'next_attempt_time': None
            }
            
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value=mock_state)
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            # First failure - should still be closed
            with pytest.raises(Exception):
                await state_test_function(should_fail=True)
            
            # Update state to show one failure
            mock_state['failure_count'] = 1
            mock_service.get_circuit_breaker_state.return_value = mock_state
            
            # Second failure - should open circuit
            with pytest.raises(Exception):
                await state_test_function(should_fail=True)
            
            # Now circuit should be open
            mock_state['state'] = 'open'
            mock_state['failure_count'] = 2
            mock_state['next_attempt_time'] = datetime.now() + timedelta(seconds=30)
            
            # Should block calls
            with pytest.raises(Exception) as exc_info:
                await state_test_function(should_fail=False)
            
            assert "Circuit breaker is open" in str(exc_info.value)
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_error_details_recording(self):
        """Test proper error details recording"""
        @circuit_breaker(failure_threshold=3, recovery_timeout=60)
        async def detailed_error_function():
            raise CHMException(
                message="Custom error message",
                error_code="TEST_ERROR",
                details={"key": "value"}
            )
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'failure_threshold': 3,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            with pytest.raises(CHMException):
                await detailed_error_function()
            
            # Verify error details were properly captured
            mock_service.record_circuit_breaker_call.assert_called_once()
            call_args = mock_service.record_circuit_breaker_call.call_args
            
            assert call_args[0][1] is False  # success=False
            error_details = call_args[0][2]
            assert error_details is not None
            assert 'exception_type' in error_details
            assert error_details['exception_type'] == 'CHMException'
            assert 'message' in error_details
            assert 'timestamp' in error_details


@pytest.mark.integration
class TestCircuitBreakerIntegration:
    """Integration tests for circuit breaker with real components"""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_with_mock_database(self, mock_database):
        """Test circuit breaker with mocked database operations"""
        service = CircuitBreakerDatabaseService()
        
        # Test the full flow with mocked database
        identifier = "integration.test"
        
        # Mock database responses for state operations
        mock_database.execute.return_value.scalar_one_or_none.return_value = None
        
        # Get initial state
        state = await service.get_circuit_breaker_state(identifier)
        assert state['state'] == 'closed'
        
        # Record a failure
        await service.record_circuit_breaker_call(identifier, False, {"error": "test"})
        
        # Check recovery (should not trigger yet)
        recovery_result = await service.check_circuit_breaker_recovery(identifier)
        assert recovery_result is False
    
    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_circuit_breaker_performance(self):
        """Test circuit breaker performance under load"""
        call_count = 0
        
        @circuit_breaker(failure_threshold=100, recovery_timeout=60)
        async def performance_test_function():
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.001)  # Small delay to simulate work
            return call_count
        
        with patch('backend.common.utils.circuit_breaker_db_service') as mock_service:
            mock_service.check_circuit_breaker_recovery = AsyncMock(return_value=False)
            mock_service.get_circuit_breaker_state = AsyncMock(return_value={
                'state': 'closed',
                'failure_count': 0,
                'success_count': 0,
                'failure_threshold': 100,
                'recovery_timeout': 60,
                'success_threshold': 3
            })
            mock_service.record_circuit_breaker_call = AsyncMock()
            
            # Run many concurrent operations
            start_time = datetime.now()
            tasks = [performance_test_function() for _ in range(100)]
            results = await asyncio.gather(*tasks)
            end_time = datetime.now()
            
            duration = (end_time - start_time).total_seconds()
            
            assert len(results) == 100
            assert call_count == 100
            assert duration < 5.0  # Should complete within 5 seconds
            
            # All calls should have been recorded
            assert mock_service.record_circuit_breaker_call.call_count == 100