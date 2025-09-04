"""
Comprehensive unit tests for error classification system
"""

import pytest
import socket
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime, timedelta
from typing import Dict, Any

from backend.common.error_classification import (
    ErrorClassifier, ErrorHandler, ClassifiedError, ErrorPattern,
    ErrorCategory, ErrorSeverity, RecoveryAction,
    global_error_classifier, global_error_handler,
    error_handler, classify_and_handle_error
)
from backend.common.exceptions import CHMException


class TestErrorClassifier:
    """Test error classifier functionality"""
    
    def test_classifier_initialization(self):
        """Test error classifier initialization with default patterns"""
        classifier = ErrorClassifier()
        
        assert len(classifier.patterns) > 0
        assert len(classifier.error_history) == 0
        assert len(classifier.pattern_stats) == 0
        
        # Check some expected patterns exist
        pattern_names = [p.name for p in classifier.patterns]
        assert "connection_timeout" in pattern_names
        assert "connection_refused" in pattern_names
        assert "authentication_failed" in pattern_names
        assert "out_of_memory" in pattern_names
    
    def test_classify_connection_timeout(self):
        """Test classification of connection timeout errors"""
        classifier = ErrorClassifier()
        
        timeout_error = socket.timeout("Connection timed out")
        classified = classifier.classify_error(timeout_error)
        
        assert classified.category == ErrorCategory.NETWORK
        assert classified.severity == ErrorSeverity.HIGH
        assert classified.recovery_action == RecoveryAction.RETRY
        assert classified.matched_pattern == "connection_timeout"
        assert classified.auto_recoverable is True
    
    def test_classify_connection_refused(self):
        """Test classification of connection refused errors"""
        classifier = ErrorClassifier()
        
        refused_error = ConnectionRefusedError("Connection refused")
        classified = classifier.classify_error(refused_error)
        
        assert classified.category == ErrorCategory.NETWORK
        assert classified.severity == ErrorSeverity.HIGH
        assert classified.recovery_action == RecoveryAction.CHECK_NETWORK
        assert classified.matched_pattern == "connection_refused"
        assert classified.auto_recoverable is False
    
    def test_classify_dns_error(self):
        """Test classification of DNS resolution errors"""
        classifier = ErrorClassifier()
        
        dns_error = socket.gaierror("Name resolution failed")
        classified = classifier.classify_error(dns_error)
        
        assert classified.category == ErrorCategory.NETWORK
        assert classified.severity == ErrorSeverity.MEDIUM
        assert classified.recovery_action == RecoveryAction.CHECK_NETWORK
        assert classified.matched_pattern == "dns_resolution"
        assert "dns" in classified.suggested_fixes[0].lower()
    
    def test_classify_permission_error(self):
        """Test classification of permission errors"""
        classifier = ErrorClassifier()
        
        perm_error = PermissionError("Permission denied")
        classified = classifier.classify_error(perm_error)
        
        assert classified.category == ErrorCategory.AUTHENTICATION
        assert classified.severity == ErrorSeverity.MEDIUM
        assert classified.recovery_action == RecoveryAction.CHECK_CREDENTIALS
        assert "permission" in classified.matched_pattern
    
    def test_classify_memory_error(self):
        """Test classification of memory errors"""
        classifier = ErrorClassifier()
        
        mem_error = MemoryError("Out of memory")
        classified = classifier.classify_error(mem_error)
        
        assert classified.category == ErrorCategory.RESOURCE
        assert classified.severity == ErrorSeverity.CRITICAL
        assert classified.recovery_action == RecoveryAction.SCALE_RESOURCES
        assert classified.matched_pattern == "out_of_memory"
    
    def test_classify_unknown_error(self):
        """Test classification of unknown error types"""
        classifier = ErrorClassifier()
        
        unknown_error = RuntimeError("Some unknown error")
        classified = classifier.classify_error(unknown_error)
        
        assert classified.category == ErrorCategory.UNKNOWN
        assert classified.severity == ErrorSeverity.MEDIUM
        assert classified.recovery_action == RecoveryAction.MANUAL_INTERVENTION
        assert classified.matched_pattern is None
        assert classified.auto_recoverable is False
    
    def test_classify_with_context(self):
        """Test error classification with context information"""
        classifier = ErrorClassifier()
        
        context = {
            'hostname': 'test.example.com',
            'function': 'connect_to_device',
            'retry_count': 2
        }
        
        error = ConnectionError("Failed to connect")
        classified = classifier.classify_error(error, context)
        
        assert classified.context == context
        assert classified.context['hostname'] == 'test.example.com'
    
    def test_add_custom_pattern(self):
        """Test adding custom error patterns"""
        classifier = ErrorClassifier()
        initial_count = len(classifier.patterns)
        
        custom_pattern = ErrorPattern(
            name="custom_test_error",
            category=ErrorCategory.APPLICATION,
            severity=ErrorSeverity.LOW,
            recovery_action=RecoveryAction.IGNORE,
            patterns=[r"custom.*test.*error"],
            keywords=["custom", "test"],
            description="Custom test error pattern"
        )
        
        classifier.add_custom_pattern(custom_pattern)
        
        assert len(classifier.patterns) == initial_count + 1
        
        # Test the custom pattern works
        test_error = ValueError("Custom test error occurred")
        classified = classifier.classify_error(test_error)
        
        assert classified.matched_pattern == "custom_test_error"
        assert classified.category == ErrorCategory.APPLICATION
        assert classified.severity == ErrorSeverity.LOW
    
    def test_error_history_tracking(self):
        """Test error history tracking"""
        classifier = ErrorClassifier()
        
        errors = [
            socket.timeout("Timeout 1"),
            ConnectionError("Connection 1"),
            socket.timeout("Timeout 2")
        ]
        
        for error in errors:
            classifier.classify_error(error)
        
        assert len(classifier.error_history) == 3
        
        # Check history ordering (most recent first)
        history_list = list(classifier.error_history)
        assert "Timeout 2" in str(history_list[-1].original_exception)
    
    def test_get_error_statistics(self):
        """Test error statistics generation"""
        classifier = ErrorClassifier()
        
        # Generate some test errors
        errors = [
            socket.timeout("Timeout"),
            ConnectionRefusedError("Refused"),
            socket.timeout("Another timeout"),
            MemoryError("Out of memory")
        ]
        
        for error in errors:
            classifier.classify_error(error)
        
        stats = classifier.get_error_statistics(hours=24)
        
        assert stats['total_errors'] == 4
        assert stats['by_category'][ErrorCategory.NETWORK.value] == 3
        assert stats['by_category'][ErrorCategory.RESOURCE.value] == 1
        assert stats['by_severity'][ErrorSeverity.HIGH.value] == 2
        assert stats['by_severity'][ErrorSeverity.CRITICAL.value] == 1
    
    def test_get_similar_errors(self):
        """Test finding similar errors"""
        classifier = ErrorClassifier()
        
        # Create some historical errors
        historical_errors = [
            socket.timeout("Connection timeout to server A"),
            ConnectionError("Failed to connect to server B"),
            socket.timeout("Timeout connecting to server C")
        ]
        
        for error in historical_errors:
            classifier.classify_error(error)
        
        # Test with a new similar error
        new_error = socket.timeout("Connection timeout to server D")
        new_classified = classifier.classify_error(new_error)
        
        similar = classifier.get_similar_errors(new_classified, limit=3)
        
        # Should find the other timeout errors
        assert len(similar) >= 2
        timeout_matches = [s for s in similar if "timeout" in str(s.original_exception).lower()]
        assert len(timeout_matches) >= 2


class TestErrorHandler:
    """Test error handler functionality"""
    
    @pytest.mark.asyncio
    async def test_error_handler_initialization(self):
        """Test error handler initialization"""
        classifier = ErrorClassifier()
        handler = ErrorHandler(classifier)
        
        assert handler.classifier is classifier
        assert len(handler.error_callbacks) == 0
        assert len(handler.severity_callbacks) == 0
    
    @pytest.mark.asyncio
    async def test_handle_error_basic(self):
        """Test basic error handling"""
        classifier = ErrorClassifier()
        handler = ErrorHandler(classifier)
        
        error = ConnectionError("Test connection error")
        context = {'test': 'context'}
        
        with patch('backend.common.error_classification.logger') as mock_logger:
            classified = await handler.handle_error(error, context, notify=False)
            
            assert isinstance(classified, ClassifiedError)
            assert classified.original_exception is error
            assert classified.context == context
            mock_logger.log.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_error_handler_callbacks(self):
        """Test error handler callback system"""
        classifier = ErrorClassifier()
        handler = ErrorHandler(classifier)
        
        category_callback_called = False
        severity_callback_called = False
        
        async def category_callback(classified_error):
            nonlocal category_callback_called
            category_callback_called = True
            assert classified_error.category == ErrorCategory.NETWORK
        
        def severity_callback(classified_error):
            nonlocal severity_callback_called
            severity_callback_called = True
            assert classified_error.severity == ErrorSeverity.HIGH
        
        handler.register_category_callback(ErrorCategory.NETWORK, category_callback)
        handler.register_severity_callback(ErrorSeverity.HIGH, severity_callback)
        
        error = socket.timeout("Network timeout")
        await handler.handle_error(error, notify=True)
        
        assert category_callback_called
        assert severity_callback_called
    
    @pytest.mark.asyncio
    async def test_error_handler_callback_exception(self):
        """Test error handler with callback that raises exception"""
        classifier = ErrorClassifier()
        handler = ErrorHandler(classifier)
        
        async def failing_callback(classified_error):
            raise Exception("Callback failed")
        
        handler.register_category_callback(ErrorCategory.NETWORK, failing_callback)
        
        with patch('backend.common.error_classification.logger') as mock_logger:
            error = socket.timeout("Test timeout")
            classified = await handler.handle_error(error, notify=True)
            
            # Should still classify the error despite callback failure
            assert isinstance(classified, ClassifiedError)
            # Should log the callback error
            assert mock_logger.error.called
    
    @pytest.mark.asyncio
    async def test_log_level_mapping(self):
        """Test correct log level mapping for different severities"""
        classifier = ErrorClassifier()
        handler = ErrorHandler(classifier)
        
        test_cases = [
            (ErrorSeverity.CRITICAL, 'CRITICAL'),
            (ErrorSeverity.HIGH, 'ERROR'),
            (ErrorSeverity.MEDIUM, 'WARNING'),
            (ErrorSeverity.LOW, 'INFO'),
            (ErrorSeverity.INFO, 'DEBUG')
        ]
        
        with patch('backend.common.error_classification.logger') as mock_logger:
            for severity, expected_level in test_cases:
                # Create a mock pattern that returns the desired severity
                with patch.object(classifier, 'classify_error') as mock_classify:
                    mock_classified = ClassifiedError(
                        original_exception=Exception("Test"),
                        error_type="Exception",
                        category=ErrorCategory.UNKNOWN,
                        severity=severity,
                        recovery_action=RecoveryAction.IGNORE,
                        message="Test error"
                    )
                    mock_classify.return_value = mock_classified
                    
                    await handler.handle_error(Exception("Test"), notify=False)
                    
                    # Check that the correct log level was used
                    call_args = mock_logger.log.call_args
                    actual_level = call_args[0][0]
                    
                    import logging
                    expected_level_int = getattr(logging, expected_level)
                    assert actual_level == expected_level_int


class TestErrorDecorator:
    """Test error handler decorator functionality"""
    
    @pytest.mark.asyncio
    async def test_error_decorator_async_success(self):
        """Test error decorator with successful async function"""
        @error_handler()
        async def successful_function():
            return "success"
        
        result = await successful_function()
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_error_decorator_async_failure(self):
        """Test error decorator with failing async function"""
        with patch('backend.common.error_classification.global_error_handler') as mock_handler:
            mock_handler.handle_error = AsyncMock()
            
            @error_handler()
            async def failing_function():
                raise ValueError("Test error")
            
            with pytest.raises(ValueError):
                await failing_function()
            
            mock_handler.handle_error.assert_called_once()
            call_args = mock_handler.handle_error.call_args[0]
            assert isinstance(call_args[0], ValueError)
            assert isinstance(call_args[1], dict)  # context
    
    def test_error_decorator_sync_function(self):
        """Test error decorator with synchronous function"""
        @error_handler()
        def sync_failing_function():
            raise ConnectionError("Sync connection error")
        
        with patch('backend.common.error_classification.global_error_classifier') as mock_classifier:
            mock_classified = ClassifiedError(
                original_exception=ConnectionError("test"),
                error_type="ConnectionError",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.HIGH,
                recovery_action=RecoveryAction.RETRY,
                message="Sync connection error"
            )
            mock_classifier.classify_error.return_value = mock_classified
            
            with patch('backend.common.error_classification.logger') as mock_logger:
                with pytest.raises(ConnectionError):
                    sync_failing_function()
                
                mock_classifier.classify_error.assert_called_once()
                mock_logger.log.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_error_decorator_with_hints(self):
        """Test error decorator with category and severity hints"""
        from backend.common.error_classification import ErrorCategory, ErrorSeverity
        
        with patch('backend.common.error_classification.global_error_handler') as mock_handler:
            mock_handler.handle_error = AsyncMock()
            
            @error_handler(
                category_hint=ErrorCategory.DATABASE,
                severity_hint=ErrorSeverity.CRITICAL
            )
            async def database_function():
                raise Exception("Database error")
            
            with pytest.raises(Exception):
                await database_function()
            
            # Check that hints were added to context
            call_args = mock_handler.handle_error.call_args[0]
            context = call_args[1]
            assert context['category_hint'] == ErrorCategory.DATABASE.value
            assert context['severity_hint'] == ErrorSeverity.CRITICAL.value
    
    @pytest.mark.asyncio
    async def test_error_decorator_with_context_provider(self):
        """Test error decorator with context provider function"""
        def context_provider(*args, **kwargs):
            return {
                'args_provided': len(args),
                'kwargs_provided': len(kwargs),
                'custom_data': 'test_value'
            }
        
        with patch('backend.common.error_classification.global_error_handler') as mock_handler:
            mock_handler.handle_error = AsyncMock()
            
            @error_handler(context_provider=context_provider)
            async def function_with_context(arg1, arg2, kwarg1=None):
                raise ValueError("Test with context")
            
            with pytest.raises(ValueError):
                await function_with_context("a", "b", kwarg1="c")
            
            # Check context was augmented
            call_args = mock_handler.handle_error.call_args[0]
            context = call_args[1]
            assert context['args_provided'] == 2
            assert context['kwargs_provided'] == 1
            assert context['custom_data'] == 'test_value'


class TestGlobalErrorHandling:
    """Test global error handling functions"""
    
    @pytest.mark.asyncio
    async def test_classify_and_handle_error_function(self):
        """Test global classify_and_handle_error function"""
        error = socket.timeout("Global test timeout")
        context = {'global': 'test'}
        
        with patch('backend.common.error_classification.global_error_handler') as mock_handler:
            mock_classified = ClassifiedError(
                original_exception=error,
                error_type="timeout", 
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.HIGH,
                recovery_action=RecoveryAction.RETRY,
                message="Global test timeout"
            )
            mock_handler.handle_error = AsyncMock(return_value=mock_classified)
            
            result = await classify_and_handle_error(error, context)
            
            assert result is mock_classified
            mock_handler.handle_error.assert_called_once_with(error, context)
    
    def test_global_error_classifier_instance(self):
        """Test global error classifier instance"""
        assert global_error_classifier is not None
        assert isinstance(global_error_classifier, ErrorClassifier)
        assert len(global_error_classifier.patterns) > 0
    
    def test_global_error_handler_instance(self):
        """Test global error handler instance"""
        assert global_error_handler is not None
        assert isinstance(global_error_handler, ErrorHandler)
        assert global_error_handler.classifier is global_error_classifier


class TestErrorPatternMatching:
    """Test error pattern matching edge cases"""
    
    def test_regex_pattern_matching(self):
        """Test regex pattern matching"""
        classifier = ErrorClassifier()
        
        # Test various timeout message formats
        timeout_messages = [
            "Connection timed out after 30 seconds",
            "Socket timeout occurred",
            "Read timeout on network operation", 
            "Operation timeout: 60000ms exceeded"
        ]
        
        for message in timeout_messages:
            error = Exception(message)
            classified = classifier.classify_error(error)
            
            # Should match timeout pattern
            assert classified.matched_pattern == "connection_timeout"
            assert classified.category == ErrorCategory.NETWORK
    
    def test_keyword_matching(self):
        """Test keyword-based matching"""
        classifier = ErrorClassifier()
        
        # Test DNS-related keywords
        dns_messages = [
            "DNS resolution failed for host",
            "Could not resolve hostname via DNS",
            "Name resolution error occurred"
        ]
        
        for message in dns_messages:
            error = socket.gaierror(message) 
            classified = classifier.classify_error(error)
            
            assert classified.category == ErrorCategory.NETWORK
            assert "dns" in [keyword.lower() for keyword in classified.suggested_fixes[0].split()]
    
    def test_exception_type_priority(self):
        """Test that exception type matching has priority over message patterns"""
        classifier = ErrorClassifier()
        
        # MemoryError should be classified as resource error even with generic message
        memory_error = MemoryError("Something went wrong")
        classified = classifier.classify_error(memory_error)
        
        assert classified.category == ErrorCategory.RESOURCE
        assert classified.severity == ErrorSeverity.CRITICAL
        assert classified.matched_pattern == "out_of_memory"
    
    def test_pattern_scoring(self):
        """Test pattern scoring and best match selection"""
        classifier = ErrorClassifier()
        
        # Create an error that could match multiple patterns
        error = ConnectionRefusedError("Connection refused: timeout occurred")
        classified = classifier.classify_error(error)
        
        # Should prefer the more specific exception type match over keyword match
        assert classified.matched_pattern == "connection_refused"
        assert classified.recovery_action == RecoveryAction.CHECK_NETWORK


class TestErrorRecoveryStrategies:
    """Test error recovery strategy suggestions"""
    
    def test_suggest_recovery_strategy_network_error(self):
        """Test recovery strategy for network errors"""
        classifier = ErrorClassifier()
        
        timeout_error = socket.timeout("Connection timeout")
        classified = classifier.classify_error(timeout_error)
        
        strategy = classifier.suggest_recovery_strategy(classified)
        
        assert strategy['immediate_action'] == RecoveryAction.RETRY.value
        assert strategy['auto_retry'] is True
        assert 'retry_strategy' in strategy
        assert strategy['retry_strategy']['max_retries'] == 3
        assert 'Monitor network connectivity' in strategy['monitoring_recommendations']
    
    def test_suggest_recovery_strategy_resource_error(self):
        """Test recovery strategy for resource errors"""
        classifier = ErrorClassifier()
        
        memory_error = MemoryError("Out of memory") 
        classified = classifier.classify_error(memory_error)
        
        strategy = classifier.suggest_recovery_strategy(classified)
        
        assert strategy['immediate_action'] == RecoveryAction.SCALE_RESOURCES.value
        assert strategy['escalation_required'] is True
        assert strategy['auto_retry'] is False
        assert 'Monitor system resources' in strategy['monitoring_recommendations']
    
    def test_recovery_strategy_escalation_logic(self):
        """Test escalation logic in recovery strategies"""
        classifier = ErrorClassifier()
        
        # Critical error should require escalation
        critical_error = MemoryError("Critical memory error")
        critical_classified = classifier.classify_error(critical_error)
        critical_strategy = classifier.suggest_recovery_strategy(critical_classified)
        assert critical_strategy['escalation_required'] is True
        
        # Low severity error should not require escalation
        low_error = ValueError("Minor validation error")
        with patch.object(classifier, 'classify_error') as mock_classify:
            low_classified = ClassifiedError(
                original_exception=low_error,
                error_type="ValueError",
                category=ErrorCategory.VALIDATION,
                severity=ErrorSeverity.LOW,
                recovery_action=RecoveryAction.IGNORE,
                message="Minor validation error"
            )
            mock_classify.return_value = low_classified
            
            low_strategy = classifier.suggest_recovery_strategy(low_classified)
            assert low_strategy['escalation_required'] is False