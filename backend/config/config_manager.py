"""
Production-ready configuration management with validation, hot reloading, and environment support
"""

import os
import json
import yaml
import logging
import asyncio
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, Callable, Type
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta
import threading
from enum import Enum
import hashlib
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

try:
    from pydantic import BaseModel, ValidationError, validator, Field
    from pydantic.env_settings import BaseSettings
    PYDANTIC_AVAILABLE = True
except ImportError:
    PYDANTIC_AVAILABLE = False
    BaseModel = object
    BaseSettings = object
    ValidationError = Exception

logger = logging.getLogger(__name__)

# Import result objects
from backend.common.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


class ConfigurationError(Exception):
    """Configuration validation error"""
    pass


class EnvironmentValidationError(Exception):
    """Environment variable validation error"""
    pass


class Environment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging" 
    PRODUCTION = "production"


class ConfigSource(Enum):
    """Configuration source types"""
    FILE = "file"
    ENVIRONMENT = "environment"
    DATABASE = "database"
    VAULT = "vault"
    CONSUL = "consul"


@dataclass
class ConfigValidationError:
    """Configuration validation error"""
    field: str
    value: Any
    error: str
    severity: str = "error"  # error, warning, info


@dataclass
class ConfigChange:
    """Configuration change event"""
    field: str
    old_value: Any
    new_value: Any
    timestamp: datetime
    source: ConfigSource


class DatabaseConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Database configuration with validation"""
    host: str = Field(..., description="Database host")
    port: int = Field(5432, ge=1, le=65535, description="Database port")
    name: str = Field(..., min_length=1, description="Database name")
    user: str = Field(..., min_length=1, description="Database user")
    password: str = Field(..., min_length=1, description="Database password")
    pool_size: int = Field(20, ge=1, le=100, description="Connection pool size")
    max_overflow: int = Field(10, ge=0, le=50, description="Max pool overflow")
    pool_timeout: int = Field(30, ge=1, le=300, description="Pool timeout seconds")
    pool_recycle: int = Field(3600, ge=300, le=86400, description="Pool recycle seconds")
    echo_queries: bool = Field(False, description="Echo SQL queries")
    ssl_mode: str = Field("prefer", description="SSL mode")
    
    @validator('host')
    def validate_host(cls, v):
        if not v or v.isspace():
            raise ValueError("Database host cannot be empty")
        # Basic hostname/IP validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', v):
            raise ValueError("Invalid database host format")
        return v
    
    @validator('ssl_mode')
    def validate_ssl_mode(cls, v):
        valid_modes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']
        if v not in valid_modes:
            raise ValueError(f"SSL mode must be one of: {valid_modes}")
        return v


class RedisConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Redis configuration with validation"""
    url: str = Field("redis://localhost:6379/0", description="Redis connection URL")
    max_connections: int = Field(50, ge=1, le=500, description="Max connections")
    socket_timeout: int = Field(5, ge=1, le=60, description="Socket timeout")
    socket_connect_timeout: int = Field(5, ge=1, le=60, description="Connect timeout")
    retry_on_timeout: bool = Field(True, description="Retry on timeout")
    health_check_interval: int = Field(30, ge=10, le=300, description="Health check interval")
    cluster_enabled: bool = Field(False, description="Enable cluster mode")
    sentinel_enabled: bool = Field(False, description="Enable sentinel mode")
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('redis://', 'rediss://')):
            raise ValueError("Redis URL must start with redis:// or rediss://")
        return v


class SNMPConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """SNMP configuration with validation"""
    default_community: str = Field("public", description="Default SNMP community")
    timeout: int = Field(5, ge=1, le=60, description="SNMP timeout")
    retries: int = Field(3, ge=1, le=10, description="SNMP retries")
    max_bulk_size: int = Field(25, ge=1, le=100, description="Max bulk request size")
    max_repetitions: int = Field(25, ge=1, le=100, description="Max repetitions")
    port: int = Field(161, ge=1, le=65535, description="SNMP port")
    mib_path: str = Field("/usr/share/snmp/mibs", description="MIB file path")
    cache_ttl: int = Field(300, ge=60, le=3600, description="MIB cache TTL")
    
    @validator('default_community')
    def validate_community(cls, v):
        if len(v) < 1 or len(v) > 32:
            raise ValueError("SNMP community must be 1-32 characters")
        return v


class SSHConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """SSH configuration with validation"""
    timeout: int = Field(30, ge=5, le=300, description="SSH timeout")
    key_storage_path: str = Field("/etc/chm/ssh_keys", description="SSH key storage path")
    host_keys_path: str = Field("/etc/chm/host_keys", description="Host keys path")
    max_connections: int = Field(50, ge=1, le=200, description="Max SSH connections")
    key_rotation_days: int = Field(90, ge=7, le=365, description="Key rotation interval")
    strict_host_key_checking: bool = Field(True, description="Strict host key checking")
    compression: bool = Field(False, description="Enable SSH compression")
    
    @validator('key_storage_path', 'host_keys_path')
    def validate_paths(cls, v):
        path = Path(v)
        if not path.is_absolute():
            raise ValueError("SSH paths must be absolute")
        return str(path)


class MonitoringConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Comprehensive monitoring and metrics configuration"""
    metrics_enabled: bool = Field(True, description="Enable metrics collection")
    metrics_port: int = Field(9090, ge=1024, le=65535, description="Metrics server port")
    health_check_port: int = Field(8080, ge=1024, le=65535, description="Health check port")
    health_check_host: str = Field("0.0.0.0", description="Health check server host")
    health_check_interval: int = Field(30, ge=5, le=300, description="Health check interval seconds")
    log_level: str = Field("INFO", description="Logging level")
    log_file: Optional[str] = Field(None, description="Log file path")
    max_log_size_mb: int = Field(100, ge=1, le=1000, description="Max log file size MB")
    log_retention_days: int = Field(30, ge=1, le=365, description="Log retention days")
    tracing_enabled: bool = Field(False, description="Enable distributed tracing")
    jaeger_endpoint: Optional[str] = Field(None, description="Jaeger collector endpoint")
    
    # Authentication for monitoring endpoints
    auth_enabled: bool = Field(True, description="Enable authentication for monitoring endpoints")
    auth_token: Optional[str] = Field(None, description="Bearer token for monitoring endpoints")
    cors_origins: List[str] = Field(default_factory=lambda: ["*"], description="CORS allowed origins")
    
    # Performance tracking
    performance_tracking_enabled: bool = Field(True, description="Enable performance tracking")
    performance_max_history_minutes: int = Field(1440, ge=60, le=10080, description="Max history in minutes")
    performance_window_size_seconds: int = Field(60, ge=10, le=300, description="Performance window size")
    
    # Database persistence
    persistence_enabled: bool = Field(True, description="Enable database persistence")
    persistence_batch_size: int = Field(1000, ge=100, le=10000, description="Batch size for persistence")
    persistence_flush_interval: float = Field(60.0, ge=10.0, le=300.0, description="Flush interval in seconds")
    persistence_retention_days: int = Field(30, ge=7, le=365, description="Data retention in days")
    
    # System metrics collection
    system_metrics_enabled: bool = Field(True, description="Enable system metrics collection")
    system_metrics_interval: int = Field(60, ge=10, le=300, description="System metrics collection interval")
    
    # Alert webhook configuration
    alert_webhook: Optional[str] = Field(None, description="Webhook URL for alerts")
    alert_threshold_cpu: float = Field(90.0, ge=50.0, le=100.0, description="CPU alert threshold")
    alert_threshold_memory: float = Field(90.0, ge=50.0, le=100.0, description="Memory alert threshold")
    alert_threshold_disk: float = Field(90.0, ge=50.0, le=100.0, description="Disk alert threshold")
    
    # Prometheus integration
    prometheus_pushgateway: Optional[str] = Field(None, description="Prometheus pushgateway URL")
    prometheus_push_interval: int = Field(60, ge=10, le=300, description="Push interval seconds")
    
    # Custom health checks
    health_checks: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Custom health check configurations"
    )
    
    # Custom metric definitions
    custom_metrics: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Custom metric definitions"
    )
    
    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()


class SecurityConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Security configuration"""
    secret_key: str = Field(..., min_length=32, description="Application secret key")
    encryption_algorithm: str = Field("AES-256-CBC", description="Encryption algorithm")
    hash_algorithm: str = Field("SHA-256", description="Hash algorithm")
    token_expiry_hours: int = Field(24, ge=1, le=168, description="Token expiry hours")
    max_login_attempts: int = Field(5, ge=1, le=20, description="Max login attempts")
    lockout_duration_minutes: int = Field(30, ge=5, le=1440, description="Account lockout duration")
    password_min_length: int = Field(8, ge=6, le=128, description="Minimum password length")
    require_tls: bool = Field(True, description="Require TLS connections")
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters")
        return v


class ResourceConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Resource limits configuration"""
    max_memory_mb: int = Field(2048, ge=512, le=32768, description="Max memory usage MB")
    max_cpu_percent: float = Field(80.0, ge=10.0, le=95.0, description="Max CPU percent")
    max_open_files: int = Field(2048, ge=256, le=65536, description="Max open files")
    max_concurrent_operations: int = Field(200, ge=10, le=1000, description="Max concurrent ops")
    rate_limit_per_minute: int = Field(1000, ge=10, le=10000, description="Rate limit per minute")
    circuit_breaker_failure_threshold: int = Field(5, ge=2, le=50, description="Circuit breaker threshold")
    circuit_breaker_timeout: int = Field(60, ge=10, le=600, description="Circuit breaker timeout")


class NetworkConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Network discovery configuration"""
    discovery_threads: int = Field(50, ge=1, le=200, description="Discovery thread count")
    ping_timeout: int = Field(3, ge=1, le=30, description="Ping timeout seconds")
    ping_packet_size: int = Field(56, ge=32, le=1472, description="Ping packet size")
    max_discovery_hosts: int = Field(10000, ge=1, le=100000, description="Max hosts per discovery")
    discovery_interval_hours: int = Field(24, ge=1, le=168, description="Discovery interval")
    enable_ipv6: bool = Field(True, description="Enable IPv6 support")
    dns_timeout: int = Field(5, ge=1, le=30, description="DNS resolution timeout")


class CHMConfig(BaseModel if PYDANTIC_AVAILABLE else object):
    """Main CHM application configuration"""
    environment: Environment = Field(Environment.DEVELOPMENT, description="Deployment environment")
    debug: bool = Field(False, description="Debug mode")
    version: str = Field("1.0.0", description="Application version")
    
    # Component configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    snmp: SNMPConfig = Field(default_factory=SNMPConfig)
    ssh: SSHConfig = Field(default_factory=SSHConfig)
    monitoring: MonitoringConfig = Field(default_factory=MonitoringConfig)
    security: SecurityConfig = Field(default_factory=lambda: SecurityConfig(secret_key=os.urandom(32).hex()))
    resources: ResourceConfig = Field(default_factory=ResourceConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    
    class Config:
        env_prefix = "CHM_"
        case_sensitive = False
        validate_assignment = True


class ConfigFileHandler(FileSystemEventHandler):
    """File system event handler for config file changes"""
    
    def __init__(self, config_manager: 'ConfigManager'):
        self.config_manager = config_manager
        self._last_modified = {}
    
    def on_modified(self, event):
        if event.is_directory:
            return
        
        file_path = Path(event.src_path)
        if file_path.suffix in ['.yaml', '.yml', '.json']:
            # Debounce rapid file changes
            now = datetime.now()
            last_mod = self._last_modified.get(file_path, datetime.min)
            
            if now - last_mod > timedelta(seconds=1):
                self._last_modified[file_path] = now
                logger.info(f"Config file changed: {file_path}")
                asyncio.create_task(self.config_manager.reload_config())


class ConfigManager:
    """Production-ready configuration manager"""
    
    def __init__(
        self,
        config_file: Optional[str] = None,
        environment: Optional[Environment] = None,
        watch_files: bool = True
    ):
        self.config_file = Path(config_file) if config_file else None
        self.environment = environment or self._detect_environment()
        self.watch_files = watch_files
        
        self._config: Optional[CHMConfig] = None
        self._config_lock = threading.RLock()
        self._file_watcher: Optional[Observer] = None
        self._change_callbacks: List[Callable[[ConfigChange], None]] = []
        self._validation_errors: List[ConfigValidationError] = []
        self._config_hash: Optional[str] = None
        
        # Load initial configuration
        self.load_config()
        
        # Start file watching if enabled
        if self.watch_files and self.config_file:
            self._start_file_watcher()
    
    def _detect_environment(self) -> Environment:
        """Auto-detect deployment environment"""
        env_var = os.getenv('CHM_ENVIRONMENT', os.getenv('ENVIRONMENT', 'development'))
        try:
            return Environment(env_var.lower())
        except ValueError:
            logger.warning(f"Invalid environment '{env_var}', defaulting to development")
            return Environment.DEVELOPMENT
    
    def load_config(self) -> bool:
        """Load configuration from all sources"""
        try:
            with self._config_lock:
                # Start with defaults
                config_data = {}
                
                # Load from file if specified
                if self.config_file and self.config_file.exists():
                    config_data.update(self._load_from_file(self.config_file))
                
                # Load environment-specific overrides
                env_config_file = self._get_environment_config_file()
                if env_config_file and env_config_file.exists():
                    config_data.update(self._load_from_file(env_config_file))
                
                # Override with environment variables
                config_data.update(self._load_from_environment())
                
                # Validate and create config object
                if PYDANTIC_AVAILABLE:
                    self._config = CHMConfig(**config_data)
                else:
                    # Fallback for when Pydantic is not available
                    self._config = self._create_fallback_config(config_data)
                
                # Calculate config hash for change detection
                new_hash = self._calculate_config_hash()
                config_changed = new_hash != self._config_hash
                self._config_hash = new_hash
                
                # Set environment from config
                self.environment = self._config.environment
                
                logger.info(f"Configuration loaded successfully for environment: {self.environment.value}")
                
                if config_changed:
                    self._notify_config_change()
                
                return True
                
        except ValidationError as e:
            self._validation_errors = [
                ConfigValidationError(
                    field=error['loc'][-1] if error['loc'] else 'unknown',
                    value=error.get('input', 'unknown'),
                    error=error['msg']
                )
                for error in e.errors()
            ]
            logger.error(f"Configuration validation failed: {len(self._validation_errors)} errors")
            for error in self._validation_errors:
                logger.error(f"  {error.field}: {error.error}")
            return False
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            return False
    
    def _load_from_file(self, file_path: Path) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            with open(file_path, 'r') as f:
                if file_path.suffix in ['.yaml', '.yml']:
                    return yaml.safe_load(f) or {}
                elif file_path.suffix == '.json':
                    return json.load(f)
                else:
                    logger.warning(f"Unsupported config file format: {file_path.suffix}")
                    return {}
        except Exception as e:
            logger.error(f"Failed to load config file {file_path}: {e}")
            return {}
    
    def _get_environment_config_file(self):
        """Get environment-specific config file"""
        if not self.config_file:
            return create_partial_success_result(
                data=None,
                error_code="NO_CONFIG_FILE",
                message="No base config file specified",
                fallback_data=FallbackData(
                    data=None,
                    health_status=HealthStatus(
                        level=HealthLevel.WARNING,
                        message="No base configuration file",
                        details="Base config file path is not set"
                    )
                ),
                suggestions=["Set base config file path", "Initialize configuration", "Check config file settings"]
            )
        
        base_path = self.config_file.parent
        base_name = self.config_file.stem
        extension = self.config_file.suffix
        
        env_file = base_path / f"{base_name}.{self.environment.value}{extension}"
        return env_file if env_file.exists() else None
    
    def _load_from_environment(self) -> Dict[str, Any]:
        """Load configuration from environment variables"""
        config = {}
        
        # Database config
        if os.getenv('CHM_DATABASE_HOST'):
            config.setdefault('database', {})['host'] = os.getenv('CHM_DATABASE_HOST')
        if os.getenv('CHM_DATABASE_PORT'):
            config.setdefault('database', {})['port'] = int(os.getenv('CHM_DATABASE_PORT'))
        if os.getenv('CHM_DATABASE_NAME'):
            config.setdefault('database', {})['name'] = os.getenv('CHM_DATABASE_NAME')
        if os.getenv('CHM_DATABASE_USER'):
            config.setdefault('database', {})['user'] = os.getenv('CHM_DATABASE_USER')
        if os.getenv('CHM_DATABASE_PASSWORD'):
            config.setdefault('database', {})['password'] = os.getenv('CHM_DATABASE_PASSWORD')
        
        # Redis config
        if os.getenv('CHM_REDIS_URL'):
            config.setdefault('redis', {})['url'] = os.getenv('CHM_REDIS_URL')
        
        # Security config
        if os.getenv('CHM_SECRET_KEY'):
            config.setdefault('security', {})['secret_key'] = os.getenv('CHM_SECRET_KEY')
        
        # General config
        if os.getenv('CHM_DEBUG'):
            config['debug'] = os.getenv('CHM_DEBUG').lower() in ['true', '1', 'yes']
        
        return config
    
    def _create_fallback_config(self, config_data: Dict[str, Any]) -> CHMConfig:
        """Create fallback config when Pydantic is not available"""
        # This would be a simplified version without validation
        # For production, Pydantic should be available
        logger.warning("Creating fallback configuration without validation")
        
        # Create a simple namespace object
        class SimpleConfig:
            pass
    
    def validate_required_environment_variables(self) -> List[str]:
        """Validate that all required environment variables are set"""
        missing_vars = []
        
        # Critical database variables
        required_db_vars = [
            'DATABASE_URL',
            'INFLUXDB_TOKEN',
            'NEO4J_PASSWORD'
        ]
        
        for var in required_db_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        # Security variables
        required_security_vars = [
            'JWT_SECRET_KEY',
            'JWT_ALGORITHM'
        ]
        
        for var in required_security_vars:
            if not os.getenv(var):
                missing_vars.append(var)
        
        # Optional but recommended variables
        recommended_vars = [
            'CHM_ENVIRONMENT',
            'CHM_LOG_LEVEL',
            'CHM_DEBUG'
        ]
        
        missing_recommended = []
        for var in recommended_vars:
            if not os.getenv(var):
                missing_recommended.append(var)
        
        if missing_recommended:
            logger.warning(f"Recommended environment variables not set: {missing_recommended}")
        
        return missing_vars
    
    def validate_database_configuration(self) -> bool:
        """Validate database configuration and connectivity"""
        try:
            from ..database.connections import db_manager
            
            # Check if we can parse the database URLs
            db_url = os.getenv('DATABASE_URL')
            if db_url:
                from urllib.parse import urlparse
                parsed = urlparse(db_url)
                if not parsed.scheme or not parsed.hostname:
                    logger.error("Invalid DATABASE_URL format")
                    return False
            
            # Check InfluxDB configuration
            influx_url = os.getenv('INFLUXDB_URL')
            if influx_url:
                parsed = urlparse(influx_url)
                if not parsed.scheme or not parsed.hostname:
                    logger.error("Invalid INFLUXDB_URL format")
                    return False
            
            # Check Redis configuration
            redis_url = os.getenv('REDIS_URL')
            if redis_url:
                parsed = urlparse(redis_url)
                if not parsed.scheme or not parsed.hostname:
                    logger.error("Invalid REDIS_URL format")
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Database configuration validation failed: {e}")
            return False
        
        config = SimpleConfig()
        
        # Set basic attributes
        config.environment = self.environment
        config.debug = config_data.get('debug', False)
        config.version = config_data.get('version', '1.0.0')
        
        return config
    
    def _calculate_config_hash(self) -> str:
        """Calculate hash of current configuration"""
        if not self._config:
            return ""
        
        # Convert config to JSON for hashing
        if PYDANTIC_AVAILABLE and hasattr(self._config, 'dict'):
            config_str = json.dumps(self._config.dict(), sort_keys=True)
        else:
            config_str = str(vars(self._config))
        
        return hashlib.md5(config_str.encode()).hexdigest()
    
    def _start_file_watcher(self):
        """Start file system watcher for config changes"""
        try:
            self._file_watcher = Observer()
            handler = ConfigFileHandler(self)
            
            watch_path = self.config_file.parent
            self._file_watcher.schedule(handler, str(watch_path), recursive=False)
            self._file_watcher.start()
            
            logger.info(f"Started config file watcher: {watch_path}")
            
        except Exception as e:
            logger.error(f"Failed to start config file watcher: {e}")
    
    def _stop_file_watcher(self):
        """Stop file system watcher"""
        if self._file_watcher:
            self._file_watcher.stop()
            self._file_watcher.join()
            self._file_watcher = None
    
    async def reload_config(self) -> bool:
        """Reload configuration asynchronously"""
        logger.info("Reloading configuration...")
        
        old_config = self._config
        success = self.load_config()
        
        if success and old_config:
            # Detect changes and notify callbacks
            changes = self._detect_changes(old_config, self._config)
            for change in changes:
                logger.info(f"Config changed: {change.field} = {change.new_value}")
                await self._notify_change_callbacks(change)
        
        return success
    
    def _detect_changes(self, old_config: CHMConfig, new_config: CHMConfig) -> List[ConfigChange]:
        """Detect configuration changes between old and new config"""
        changes = []
        
        if not PYDANTIC_AVAILABLE:
            return changes
        
        try:
            old_dict = old_config.dict() if hasattr(old_config, 'dict') else {}
            new_dict = new_config.dict() if hasattr(new_config, 'dict') else {}
            
            def compare_dicts(old_d, new_d, prefix=""):
                for key, new_value in new_d.items():
                    field_name = f"{prefix}.{key}" if prefix else key
                    old_value = old_d.get(key)
                    
                    if isinstance(new_value, dict) and isinstance(old_value, dict):
                        changes.extend(compare_dicts(old_value, new_value, field_name))
                    elif old_value != new_value:
                        changes.append(ConfigChange(
                            field=field_name,
                            old_value=old_value,
                            new_value=new_value,
                            timestamp=datetime.now(),
                            source=ConfigSource.FILE
                        ))
            
            compare_dicts(old_dict, new_dict)
            
        except Exception as e:
            logger.error(f"Error detecting config changes: {e}")
        
        return changes
    
    def _notify_config_change(self):
        """Notify that configuration has changed"""
        logger.info("Configuration change detected")
    
    async def _notify_change_callbacks(self, change: ConfigChange):
        """Notify registered change callbacks"""
        for callback in self._change_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(change)
                else:
                    callback(change)
            except Exception as e:
                logger.error(f"Error in config change callback: {e}")
    
    def register_change_callback(self, callback: Callable[[ConfigChange], None]):
        """Register a callback for configuration changes"""
        self._change_callbacks.append(callback)
    
    def get_config(self) -> CHMConfig:
        """Get current configuration"""
        with self._config_lock:
            if not self._config:
                raise RuntimeError("Configuration not loaded")
            return self._config
    
    def get_validation_errors(self) -> List[ConfigValidationError]:
        """Get configuration validation errors"""
        return self._validation_errors.copy()
    
    def is_valid(self) -> bool:
        """Check if configuration is valid"""
        return len(self._validation_errors) == 0
    
    def export_config(self, format_type: str = "yaml") -> str:
        """Export current configuration"""
        if not self._config:
            return ""
        
        try:
            if PYDANTIC_AVAILABLE and hasattr(self._config, 'dict'):
                config_dict = self._config.dict()
            else:
                config_dict = vars(self._config)
            
            if format_type.lower() == "json":
                return json.dumps(config_dict, indent=2, default=str)
            elif format_type.lower() in ["yaml", "yml"]:
                return yaml.dump(config_dict, indent=2, default_flow_style=False)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
        except Exception as e:
            logger.error(f"Failed to export config: {e}")
            return ""
    
    def validate_config_changes(self, changes: Dict[str, Any]) -> List[ConfigValidationError]:
        """Validate proposed configuration changes"""
        if not PYDANTIC_AVAILABLE:
            return []
        
        errors = []
        
        try:
            # Create a copy of current config
            current_dict = self._config.dict() if self._config else {}
            
            # Apply changes
            test_config = current_dict.copy()
            test_config.update(changes)
            
            # Validate
            CHMConfig(**test_config)
            
        except ValidationError as e:
            errors = [
                ConfigValidationError(
                    field=error['loc'][-1] if error['loc'] else 'unknown',
                    value=error.get('input', 'unknown'),
                    error=error['msg']
                )
                for error in e.errors()
            ]
        except Exception as e:
            errors.append(ConfigValidationError(
                field='unknown',
                value='unknown', 
                error=str(e)
            ))
        
        return errors
    
    def shutdown(self):
        """Shutdown configuration manager"""
        self._stop_file_watcher()
        logger.info("Configuration manager shut down")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()


# Global configuration manager instance
_config_manager: Optional[ConfigManager] = None
_config_lock = threading.Lock()


def initialize_config(
    config_file: Optional[str] = None,
    environment: Optional[Environment] = None
) -> ConfigManager:
    """Initialize global configuration manager"""
    global _config_manager
    
    with _config_lock:
        if _config_manager is not None:
            logger.warning("Configuration manager already initialized")
            return _config_manager
        
        _config_manager = ConfigManager(
            config_file=config_file,
            environment=environment
        )
        
        logger.info("Global configuration manager initialized")
        return _config_manager


def get_config() -> CHMConfig:
    """Get current configuration"""
    if _config_manager is None:
        # Auto-initialize with defaults
        initialize_config()
    
    return _config_manager.get_config()


def reload_config() -> bool:
    """Reload global configuration"""
    if _config_manager is None:
        return False
    
    return _config_manager.load_config()


def shutdown_config():
    """Shutdown global configuration manager"""
    global _config_manager
    
    with _config_lock:
        if _config_manager is not None:
            _config_manager.shutdown()
            _config_manager = None