"""
Comprehensive error classification and handling system for network monitoring
"""

import logging
import traceback
import re
import inspect
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Type, Union, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import asyncio
import socket
import ssl

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from sqlalchemy.exc import SQLAlchemyError
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False
    SQLAlchemyError = Exception

try:
    import redis
    from redis.exceptions import RedisError
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    RedisError = Exception

try:
    from paramiko.ssh_exception import SSHException, NoValidConnectionsError, AuthenticationException
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False
    SSHException = Exception
    NoValidConnectionsError = Exception
    AuthenticationException = Exception

from backend.common.exceptions import CHMException

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels"""
    CRITICAL = "critical"     # System failure, immediate attention required
    HIGH = "high"            # Major functionality impacted
    MEDIUM = "medium"        # Some functionality impacted
    LOW = "low"              # Minor issues, cosmetic problems
    INFO = "info"            # Informational, not actually errors


class ErrorCategory(Enum):
    """Error categories for classification"""
    NETWORK = "network"              # Network connectivity, timeouts, DNS
    AUTHENTICATION = "authentication" # Login, credentials, permissions
    DATABASE = "database"            # Database connections, queries, transactions
    RESOURCE = "resource"            # Memory, CPU, disk, file handles
    CONFIGURATION = "configuration"  # Config files, settings, environment
    EXTERNAL_SERVICE = "external"    # Third-party services, APIs
    VALIDATION = "validation"        # Data validation, format errors
    PROTOCOL = "protocol"           # SNMP, SSH, HTTP protocol errors
    SECURITY = "security"           # Security violations, unauthorized access
    SYSTEM = "system"               # OS errors, system calls
    APPLICATION = "application"     # Application logic errors
    UNKNOWN = "unknown"             # Uncategorized errors


class RecoveryAction(Enum):
    """Recommended recovery actions"""
    RETRY = "retry"                 # Retry the operation
    RESTART_SERVICE = "restart"     # Restart the service/component
    CHECK_CONFIG = "check_config"   # Verify configuration
    CHECK_NETWORK = "check_network" # Check network connectivity
    CHECK_CREDENTIALS = "check_creds" # Verify credentials
    SCALE_RESOURCES = "scale_resources" # Increase resources
    MANUAL_INTERVENTION = "manual"  # Requires manual intervention
    IGNORE = "ignore"               # Safe to ignore
    ESCALATE = "escalate"          # Escalate to administrator


@dataclass
class ErrorPattern:
    """Pattern for error classification"""
    name: str
    category: ErrorCategory
    severity: ErrorSeverity
    recovery_action: RecoveryAction
    patterns: List[str] = field(default_factory=list)  # Regex patterns to match
    exception_types: List[Type[Exception]] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    description: str = ""
    documentation_link: str = ""
    auto_recoverable: bool = False


@dataclass
class ClassifiedError:
    """Classified error information"""
    original_exception: Exception
    error_type: str
    category: ErrorCategory
    severity: ErrorSeverity
    recovery_action: RecoveryAction
    message: str
    context: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    stack_trace: str = ""
    matched_pattern: Optional[str] = None
    suggested_fixes: List[str] = field(default_factory=list)
    retry_count: int = 0
    auto_recoverable: bool = False


class ErrorClassifier:
    """Comprehensive error classification system"""
    
    def __init__(self):
        self.patterns: List[ErrorPattern] = []
        self.error_history: deque = deque(maxlen=1000)
        self.pattern_stats: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._initialize_default_patterns()
    
    def _initialize_default_patterns(self):
        """Initialize default error patterns"""
        
        # Network errors
        self.patterns.extend([
            ErrorPattern(
                name="connection_timeout",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.HIGH,
                recovery_action=RecoveryAction.RETRY,
                patterns=[
                    r"connection.*timeout", r"timed out", r"timeout.*connect",
                    r"socket.*timeout", r"read.*timeout"
                ],
                exception_types=[socket.timeout, asyncio.TimeoutError, TimeoutError],
                keywords=["timeout", "connection", "unreachable"],
                description="Network connection timeout",
                auto_recoverable=True
            ),
            ErrorPattern(
                name="connection_refused",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.HIGH,
                recovery_action=RecoveryAction.CHECK_NETWORK,
                patterns=[
                    r"connection refused", r"could not connect", r"no route to host"
                ],
                exception_types=[ConnectionRefusedError, socket.error],
                keywords=["refused", "connect", "unreachable"],
                description="Network connection refused",
                auto_recoverable=False
            ),
            ErrorPattern(
                name="dns_resolution",
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.MEDIUM,
                recovery_action=RecoveryAction.CHECK_NETWORK,
                patterns=[
                    r"name resolution failed", r"getaddrinfo failed", 
                    r"nodename nor servname provided", r"dns.*error"
                ],
                exception_types=[socket.gaierror],
                keywords=["dns", "resolution", "hostname", "getaddrinfo"],
                description="DNS resolution failure",
                auto_recoverable=True
            )
        ])
        
        # Authentication errors
        self.patterns.extend([
            ErrorPattern(
                name="authentication_failed",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.HIGH,
                recovery_action=RecoveryAction.CHECK_CREDENTIALS,
                patterns=[
                    r"authentication failed", r"invalid.*credentials", 
                    r"login.*failed", r"access denied", r"unauthorized"
                ],
                exception_types=[AuthenticationException] if PARAMIKO_AVAILABLE else [],
                keywords=["authentication", "credentials", "login", "password"],
                description="Authentication failure",
                auto_recoverable=False
            ),
            ErrorPattern(
                name="permission_denied",
                category=ErrorCategory.AUTHENTICATION,
                severity=ErrorSeverity.MEDIUM,
                recovery_action=RecoveryAction.CHECK_CREDENTIALS,
                patterns=[
                    r"permission denied", r"access.*denied", r"forbidden",
                    r"not authorized", r"insufficient.*privileges"
                ],
                exception_types=[PermissionError],
                keywords=["permission", "access", "denied", "forbidden"],
                description="Permission denied",
                auto_recoverable=False
            )
        ])
        
        # Database errors\n        if SQLALCHEMY_AVAILABLE:\n            self.patterns.extend([\n                ErrorPattern(\n                    name=\"database_connection\",\n                    category=ErrorCategory.DATABASE,\n                    severity=ErrorSeverity.CRITICAL,\n                    recovery_action=RecoveryAction.RESTART_SERVICE,\n                    patterns=[\n                        r\"could not connect.*database\", r\"database.*unavailable\",\n                        r\"connection.*database.*failed\", r\"database.*timeout\"\n                    ],\n                    exception_types=[SQLAlchemyError],\n                    keywords=[\"database\", \"connection\", \"postgres\", \"mysql\"],\n                    description=\"Database connection failure\",\n                    auto_recoverable=True\n                ),\n                ErrorPattern(\n                    name=\"database_query_error\",\n                    category=ErrorCategory.DATABASE,\n                    severity=ErrorSeverity.MEDIUM,\n                    recovery_action=RecoveryAction.RETRY,\n                    patterns=[\n                        r\"syntax error.*query\", r\"column.*does not exist\",\n                        r\"table.*does not exist\", r\"constraint.*violation\"\n                    ],\n                    exception_types=[SQLAlchemyError],\n                    keywords=[\"query\", \"syntax\", \"column\", \"table\"],\n                    description=\"Database query error\",\n                    auto_recoverable=False\n                )\n            ])\n        \n        # Resource errors\n        self.patterns.extend([\n            ErrorPattern(\n                name=\"out_of_memory\",\n                category=ErrorCategory.RESOURCE,\n                severity=ErrorSeverity.CRITICAL,\n                recovery_action=RecoveryAction.SCALE_RESOURCES,\n                patterns=[\n                    r\"out of memory\", r\"memory.*exhausted\", r\"cannot allocate\",\n                    r\"memory.*error\", r\"oom.*killer\"\n                ],\n                exception_types=[MemoryError],\n                keywords=[\"memory\", \"malloc\", \"allocation\", \"oom\"],\n                description=\"Out of memory error\",\n                auto_recoverable=False\n            ),\n            ErrorPattern(\n                name=\"disk_space\",\n                category=ErrorCategory.RESOURCE,\n                severity=ErrorSeverity.HIGH,\n                recovery_action=RecoveryAction.SCALE_RESOURCES,\n                patterns=[\n                    r\"no space left\", r\"disk.*full\", r\"insufficient.*space\",\n                    r\"quota.*exceeded\"\n                ],\n                exception_types=[OSError],\n                keywords=[\"disk\", \"space\", \"full\", \"quota\"],\n                description=\"Disk space exhausted\",\n                auto_recoverable=False\n            ),\n            ErrorPattern(\n                name=\"too_many_files\",\n                category=ErrorCategory.RESOURCE,\n                severity=ErrorSeverity.HIGH,\n                recovery_action=RecoveryAction.RESTART_SERVICE,\n                patterns=[\n                    r\"too many.*files\", r\"file.*limit.*exceeded\",\n                    r\"cannot.*open.*file\", r\"resource.*temporarily.*unavailable\"\n                ],\n                exception_types=[OSError],\n                keywords=[\"files\", \"limit\", \"descriptor\", \"resource\"],\n                description=\"File descriptor limit exceeded\",\n                auto_recoverable=True\n            )\n        ])\n        \n        # Protocol errors\n        self.patterns.extend([\n            ErrorPattern(\n                name=\"snmp_timeout\",\n                category=ErrorCategory.PROTOCOL,\n                severity=ErrorSeverity.MEDIUM,\n                recovery_action=RecoveryAction.RETRY,\n                patterns=[\n                    r\"snmp.*timeout\", r\"snmp.*no.*response\", r\"snmp.*error\"\n                ],\n                keywords=[\"snmp\", \"timeout\", \"response\", \"community\"],\n                description=\"SNMP operation timeout\",\n                auto_recoverable=True\n            ),\n            ErrorPattern(\n                name=\"ssh_connection\",\n                category=ErrorCategory.PROTOCOL,\n                severity=ErrorSeverity.HIGH,\n                recovery_action=RecoveryAction.CHECK_CREDENTIALS,\n                patterns=[\n                    r\"ssh.*connection.*failed\", r\"ssh.*timeout\", r\"ssh.*refused\"\n                ],\n                exception_types=[SSHException] if PARAMIKO_AVAILABLE else [],\n                keywords=[\"ssh\", \"connection\", \"failed\", \"refused\"],\n                description=\"SSH connection failure\",\n                auto_recoverable=True\n            )\n        ])\n        \n        # Redis errors\n        if REDIS_AVAILABLE:\n            self.patterns.extend([\n                ErrorPattern(\n                    name=\"redis_connection\",\n                    category=ErrorCategory.EXTERNAL_SERVICE,\n                    severity=ErrorSeverity.MEDIUM,\n                    recovery_action=RecoveryAction.RETRY,\n                    patterns=[\n                        r\"redis.*connection.*failed\", r\"redis.*timeout\",\n                        r\"redis.*not.*available\"\n                    ],\n                    exception_types=[RedisError],\n                    keywords=[\"redis\", \"connection\", \"timeout\"],\n                    description=\"Redis connection error\",\n                    auto_recoverable=True\n                )\n            ])\n        \n        # SSL/TLS errors\n        self.patterns.extend([\n            ErrorPattern(\n                name=\"ssl_certificate\",\n                category=ErrorCategory.SECURITY,\n                severity=ErrorSeverity.HIGH,\n                recovery_action=RecoveryAction.CHECK_CONFIG,\n                patterns=[\n                    r\"certificate.*verify.*failed\", r\"ssl.*certificate.*error\",\n                    r\"certificate.*expired\", r\"certificate.*invalid\"\n                ],\n                exception_types=[ssl.SSLError],\n                keywords=[\"certificate\", \"ssl\", \"tls\", \"verify\"],\n                description=\"SSL certificate error\",\n                auto_recoverable=False\n            )\n        ])\n        \n        # Configuration errors\n        self.patterns.extend([\n            ErrorPattern(\n                name=\"config_missing\",\n                category=ErrorCategory.CONFIGURATION,\n                severity=ErrorSeverity.HIGH,\n                recovery_action=RecoveryAction.CHECK_CONFIG,\n                patterns=[\n                    r\"config.*not found\", r\"configuration.*missing\",\n                    r\"settings.*not.*defined\"\n                ],\n                exception_types=[FileNotFoundError, KeyError],\n                keywords=[\"config\", \"configuration\", \"settings\", \"missing\"],\n                description=\"Configuration missing or invalid\",\n                auto_recoverable=False\n            )\n        ])\n    \n    def classify_error(\n        self,\n        exception: Exception,\n        context: Optional[Dict[str, Any]] = None\n    ) -> ClassifiedError:\n        \"\"\"Classify an error based on patterns and context\"\"\"\n        \n        context = context or {}\n        error_message = str(exception).lower()\n        exception_type = type(exception)\n        stack_trace = traceback.format_exc()\n        \n        # Find matching patterns\n        matched_pattern = None\n        best_match = None\n        \n        for pattern in self.patterns:\n            score = 0\n            \n            # Check exception type match\n            if exception_type in pattern.exception_types:\n                score += 10\n            \n            # Check regex patterns\n            for regex_pattern in pattern.patterns:\n                if re.search(regex_pattern, error_message, re.IGNORECASE):\n                    score += 5\n                    break\n            \n            # Check keywords\n            for keyword in pattern.keywords:\n                if keyword.lower() in error_message:\n                    score += 2\n            \n            # Check stack trace for additional context\n            if pattern.keywords:\n                for keyword in pattern.keywords:\n                    if keyword.lower() in stack_trace.lower():\n                        score += 1\n            \n            if score > 0 and (best_match is None or score > best_match[1]):\n                best_match = (pattern, score)\n                matched_pattern = pattern.name\n        \n        # Create classified error\n        if best_match:\n            pattern = best_match[0]\n            classified = ClassifiedError(\n                original_exception=exception,\n                error_type=type(exception).__name__,\n                category=pattern.category,\n                severity=pattern.severity,\n                recovery_action=pattern.recovery_action,\n                message=str(exception),\n                context=context,\n                stack_trace=stack_trace,\n                matched_pattern=matched_pattern,\n                auto_recoverable=pattern.auto_recoverable\n            )\n            \n            # Add suggested fixes based on pattern\n            classified.suggested_fixes = self._get_suggested_fixes(pattern, context)\n            \n            # Update pattern statistics\n            self.pattern_stats[pattern.name]['matches'] += 1\n            self.pattern_stats[pattern.name]['last_seen'] = int(datetime.now().timestamp())\n            \n        else:\n            # Unclassified error\n            classified = ClassifiedError(\n                original_exception=exception,\n                error_type=type(exception).__name__,\n                category=ErrorCategory.UNKNOWN,\n                severity=ErrorSeverity.MEDIUM,\n                recovery_action=RecoveryAction.MANUAL_INTERVENTION,\n                message=str(exception),\n                context=context,\n                stack_trace=stack_trace,\n                matched_pattern=None,\n                auto_recoverable=False\n            )\n            \n            # Try to infer category from exception type\n            classified.category = self._infer_category_from_exception(exception)\n        \n        # Add to history\n        self.error_history.append(classified)\n        \n        return classified\n    \n    def _infer_category_from_exception(self, exception: Exception) -> ErrorCategory:\n        \"\"\"Infer error category from exception type\"\"\"\n        exception_type = type(exception)\n        \n        if issubclass(exception_type, (socket.error, ConnectionError, TimeoutError)):\n            return ErrorCategory.NETWORK\n        elif issubclass(exception_type, (PermissionError, OSError)):\n            return ErrorCategory.SYSTEM\n        elif issubclass(exception_type, (KeyError, ValueError, TypeError)):\n            return ErrorCategory.VALIDATION\n        elif issubclass(exception_type, MemoryError):\n            return ErrorCategory.RESOURCE\n        elif SQLALCHEMY_AVAILABLE and issubclass(exception_type, SQLAlchemyError):\n            return ErrorCategory.DATABASE\n        elif REDIS_AVAILABLE and issubclass(exception_type, RedisError):\n            return ErrorCategory.EXTERNAL_SERVICE\n        else:\n            return ErrorCategory.UNKNOWN\n    \n    def _get_suggested_fixes(self, pattern: ErrorPattern, context: Dict[str, Any]) -> List[str]:\n        \"\"\"Get suggested fixes for an error pattern\"\"\"\n        fixes = []\n        \n        if pattern.recovery_action == RecoveryAction.RETRY:\n            fixes.append(\"Try the operation again after a short delay\")\n        elif pattern.recovery_action == RecoveryAction.CHECK_NETWORK:\n            fixes.append(\"Check network connectivity to the target host\")\n            fixes.append(\"Verify firewall rules and routing\")\n            if 'hostname' in context:\n                fixes.append(f\"Test connectivity: ping {context['hostname']}\")\n        elif pattern.recovery_action == RecoveryAction.CHECK_CREDENTIALS:\n            fixes.append(\"Verify username and password are correct\")\n            fixes.append(\"Check if account is locked or expired\")\n            fixes.append(\"Ensure proper permissions are granted\")\n        elif pattern.recovery_action == RecoveryAction.CHECK_CONFIG:\n            fixes.append(\"Review configuration files for errors\")\n            fixes.append(\"Check environment variables\")\n            fixes.append(\"Verify service settings\")\n        elif pattern.recovery_action == RecoveryAction.SCALE_RESOURCES:\n            fixes.append(\"Monitor and increase available resources\")\n            fixes.append(\"Check memory and disk usage\")\n            fixes.append(\"Consider scaling up the system\")\n        elif pattern.recovery_action == RecoveryAction.RESTART_SERVICE:\n            fixes.append(\"Restart the affected service or component\")\n            fixes.append(\"Check service logs for additional errors\")\n        \n        # Add pattern-specific fixes\n        if pattern.name == \"connection_timeout\":\n            fixes.append(\"Increase connection timeout values\")\n            fixes.append(\"Check network latency\")\n        elif pattern.name == \"dns_resolution\":\n            fixes.append(\"Check DNS server configuration\")\n            fixes.append(\"Try using IP address instead of hostname\")\n        elif pattern.name == \"ssl_certificate\":\n            fixes.append(\"Update SSL certificates\")\n            fixes.append(\"Check certificate expiration dates\")\n            fixes.append(\"Verify certificate chain\")\n        \n        return fixes\n    \n    def get_error_statistics(self, hours: int = 24) -> Dict[str, Any]:\n        \"\"\"Get error statistics for the specified time period\"\"\"\n        cutoff_time = datetime.now() - timedelta(hours=hours)\n        \n        recent_errors = [e for e in self.error_history if e.timestamp > cutoff_time]\n        \n        stats = {\n            'total_errors': len(recent_errors),\n            'by_category': defaultdict(int),\n            'by_severity': defaultdict(int),\n            'by_pattern': defaultdict(int),\n            'top_errors': [],\n            'recovery_actions': defaultdict(int),\n            'auto_recoverable': 0\n        }\n        \n        for error in recent_errors:\n            stats['by_category'][error.category.value] += 1\n            stats['by_severity'][error.severity.value] += 1\n            stats['by_pattern'][error.matched_pattern or 'unclassified'] += 1\n            stats['recovery_actions'][error.recovery_action.value] += 1\n            \n            if error.auto_recoverable:\n                stats['auto_recoverable'] += 1\n        \n        # Get top error patterns\n        pattern_counts = dict(stats['by_pattern'])\n        stats['top_errors'] = sorted(\n            pattern_counts.items(),\n            key=lambda x: x[1],\n            reverse=True\n        )[:10]\n        \n        # Convert defaultdicts to regular dicts for JSON serialization\n        for key in ['by_category', 'by_severity', 'by_pattern', 'recovery_actions']:\n            stats[key] = dict(stats[key])\n        \n        return stats\n    \n    def add_custom_pattern(self, pattern: ErrorPattern):\n        \"\"\"Add a custom error pattern\"\"\"\n        self.patterns.append(pattern)\n        logger.info(f\"Added custom error pattern: {pattern.name}\")\n    \n    def get_similar_errors(\n        self,\n        classified_error: ClassifiedError,\n        limit: int = 5\n    ) -> List[ClassifiedError]:\n        \"\"\"Find similar errors in history\"\"\"\n        similar = []\n        \n        for historical_error in self.error_history:\n            if historical_error == classified_error:\n                continue\n            \n            similarity_score = 0\n            \n            # Same pattern match\n            if (classified_error.matched_pattern and \n                historical_error.matched_pattern == classified_error.matched_pattern):\n                similarity_score += 10\n            \n            # Same category and severity\n            if historical_error.category == classified_error.category:\n                similarity_score += 5\n            if historical_error.severity == classified_error.severity:\n                similarity_score += 3\n            \n            # Similar error message\n            if classified_error.message in historical_error.message or historical_error.message in classified_error.message:\n                similarity_score += 3\n            \n            if similarity_score > 0:\n                similar.append((historical_error, similarity_score))\n        \n        # Sort by similarity score and return top matches\n        similar.sort(key=lambda x: x[1], reverse=True)\n        return [error for error, _ in similar[:limit]]\n    \n    def suggest_recovery_strategy(\n        self,\n        classified_error: ClassifiedError\n    ) -> Dict[str, Any]:\n        \"\"\"Suggest a comprehensive recovery strategy\"\"\"\n        strategy = {\n            'immediate_action': classified_error.recovery_action.value,\n            'priority': classified_error.severity.value,\n            'auto_retry': classified_error.auto_recoverable,\n            'suggested_fixes': classified_error.suggested_fixes,\n            'escalation_required': classified_error.severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH],\n            'monitoring_recommendations': []\n        }\n        \n        # Add monitoring recommendations based on error type\n        if classified_error.category == ErrorCategory.NETWORK:\n            strategy['monitoring_recommendations'].extend([\n                'Monitor network connectivity',\n                'Set up latency monitoring',\n                'Track connection failure rates'\n            ])\n        elif classified_error.category == ErrorCategory.RESOURCE:\n            strategy['monitoring_recommendations'].extend([\n                'Monitor system resources (CPU, memory, disk)',\n                'Set up resource usage alerts',\n                'Track resource growth trends'\n            ])\n        elif classified_error.category == ErrorCategory.DATABASE:\n            strategy['monitoring_recommendations'].extend([\n                'Monitor database performance',\n                'Track connection pool usage',\n                'Set up query performance monitoring'\n            ])\n        \n        # Add retry strategy for recoverable errors\n        if classified_error.auto_recoverable:\n            strategy['retry_strategy'] = {\n                'max_retries': 3,\n                'initial_delay': 1.0,\n                'backoff_multiplier': 2.0,\n                'max_delay': 60.0\n            }\n        \n        return strategy\n    \n    def export_error_patterns(self) -> List[Dict[str, Any]]:\n        \"\"\"Export error patterns for analysis or configuration\"\"\"\n        return [\n            {\n                'name': pattern.name,\n                'category': pattern.category.value,\n                'severity': pattern.severity.value,\n                'recovery_action': pattern.recovery_action.value,\n                'patterns': pattern.patterns,\n                'keywords': pattern.keywords,\n                'description': pattern.description,\n                'auto_recoverable': pattern.auto_recoverable\n            }\n            for pattern in self.patterns\n        ]""\n\n\nclass ErrorHandler:\n    \"\"\"Centralized error handler with classification\"\"\"\n    \n    def __init__(self, classifier: Optional[ErrorClassifier] = None):\n        self.classifier = classifier or ErrorClassifier()\n        self.error_callbacks: Dict[ErrorCategory, List[Callable]] = defaultdict(list)\n        self.severity_callbacks: Dict[ErrorSeverity, List[Callable]] = defaultdict(list)\n    \n    async def handle_error(\n        self,\n        exception: Exception,\n        context: Optional[Dict[str, Any]] = None,\n        notify: bool = True\n    ) -> ClassifiedError:\n        \"\"\"Handle and classify an error\"\"\"\n        classified_error = self.classifier.classify_error(exception, context)\n        \n        # Log the error with appropriate level\n        log_level = self._get_log_level(classified_error.severity)\n        logger.log(\n            log_level,\n            f\"[{classified_error.category.value.upper()}] {classified_error.message}\",\n            extra={\n                'error_category': classified_error.category.value,\n                'error_severity': classified_error.severity.value,\n                'recovery_action': classified_error.recovery_action.value,\n                'matched_pattern': classified_error.matched_pattern,\n                'context': context or {}\n            }\n        )\n        \n        if notify:\n            # Call registered callbacks\n            await self._notify_callbacks(classified_error)\n        \n        return classified_error\n    \n    def _get_log_level(self, severity: ErrorSeverity) -> int:\n        \"\"\"Get logging level for error severity\"\"\"\n        level_map = {\n            ErrorSeverity.CRITICAL: logging.CRITICAL,\n            ErrorSeverity.HIGH: logging.ERROR,\n            ErrorSeverity.MEDIUM: logging.WARNING,\n            ErrorSeverity.LOW: logging.INFO,\n            ErrorSeverity.INFO: logging.DEBUG\n        }\n        return level_map.get(severity, logging.ERROR)\n    \n    async def _notify_callbacks(self, classified_error: ClassifiedError):\n        \"\"\"Notify registered callbacks\"\"\"\n        # Category-specific callbacks\n        for callback in self.error_callbacks[classified_error.category]:\n            try:\n                if asyncio.iscoroutinefunction(callback):\n                    await callback(classified_error)\n                else:\n                    callback(classified_error)\n            except Exception as e:\n                logger.error(f\"Error in error callback: {e}\")\n        \n        # Severity-specific callbacks\n        for callback in self.severity_callbacks[classified_error.severity]:\n            try:\n                if asyncio.iscoroutinefunction(callback):\n                    await callback(classified_error)\n                else:\n                    callback(classified_error)\n            except Exception as e:\n                logger.error(f\"Error in severity callback: {e}\")\n    \n    def register_category_callback(\n        self,\n        category: ErrorCategory,\n        callback: Callable[[ClassifiedError], None]\n    ):\n        \"\"\"Register a callback for specific error category\"\"\"\n        self.error_callbacks[category].append(callback)\n    \n    def register_severity_callback(\n        self,\n        severity: ErrorSeverity,\n        callback: Callable[[ClassifiedError], None]\n    ):\n        \"\"\"Register a callback for specific error severity\"\"\"\n        self.severity_callbacks[severity].append(callback)\n\n\ndef error_handler(\n    category_hint: Optional[ErrorCategory] = None,\n    severity_hint: Optional[ErrorSeverity] = None,\n    context_provider: Optional[Callable] = None\n):\n    \"\"\"Decorator for automatic error handling and classification\"\"\"\n    def decorator(func):\n        @functools.wraps(func)\n        async def async_wrapper(*args, **kwargs):\n            try:\n                return await func(*args, **kwargs)\n            except Exception as e:\n                # Build context\n                context = {\n                    'function': func.__name__,\n                    'module': func.__module__,\n                    'args_count': len(args),\n                    'kwargs_count': len(kwargs)\n                }\n                \n                if context_provider:\n                    try:\n                        additional_context = context_provider(*args, **kwargs)\n                        if isinstance(additional_context, dict):\n                            context.update(additional_context)\n                    except Exception:\n                        pass  # Don't fail on context collection\n                \n                # Add hints to context\n                if category_hint:\n                    context['category_hint'] = category_hint.value\n                if severity_hint:\n                    context['severity_hint'] = severity_hint.value\n                \n                # Handle the error\n                await global_error_handler.handle_error(e, context)\n                raise\n        \n        @functools.wraps(func)\n        def sync_wrapper(*args, **kwargs):\n            try:\n                return func(*args, **kwargs)\n            except Exception as e:\n                # Build context (synchronous version)\n                context = {\n                    'function': func.__name__,\n                    'module': func.__module__,\n                    'args_count': len(args),\n                    'kwargs_count': len(kwargs)\n                }\n                \n                # Synchronous error handling\n                classified = global_error_classifier.classify_error(e, context)\n                log_level = logging.ERROR if classified.severity in [ErrorSeverity.CRITICAL, ErrorSeverity.HIGH] else logging.WARNING\n                \n                logger.log(\n                    log_level,\n                    f\"[{classified.category.value.upper()}] {classified.message}\",\n                    extra={\n                        'error_category': classified.category.value,\n                        'error_severity': classified.severity.value,\n                        'context': context\n                    }\n                )\n                \n                raise\n        \n        if asyncio.iscoroutinefunction(func):\n            return async_wrapper\n        else:\n            return sync_wrapper\n    \n    return decorator\n\n\n# Global instances\nglobal_error_classifier = ErrorClassifier()\nglobal_error_handler = ErrorHandler(global_error_classifier)\n\n\ndef get_error_stats() -> Dict[str, Any]:\n    \"\"\"Get global error statistics\"\"\"\n    return global_error_classifier.get_error_statistics()\n\n\ndef add_error_pattern(pattern: ErrorPattern):\n    \"\"\"Add a custom error pattern globally\"\"\"\n    global_error_classifier.add_custom_pattern(pattern)\n\n\nasync def classify_and_handle_error(\n    exception: Exception,\n    context: Optional[Dict[str, Any]] = None\n) -> ClassifiedError:\n    \"\"\"Convenience function to classify and handle an error\"\"\"\n    return await global_error_handler.handle_error(exception, context)