"""
Application configuration management
"""

import os
from typing import Optional, List
from pydantic_settings import BaseSettings
from pydantic import Field, validator
from functools import lru_cache

class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application settings
    app_name: str = Field(default="Catalyst Health Monitor", env="APP_NAME")
    app_version: str = Field(default="2.0.0", env="APP_VERSION")
    environment: str = Field(default="development", env="ENVIRONMENT")
    debug: bool = Field(default=False, env="DEBUG")
    
    # API settings
    api_host: str = Field(default="0.0.0.0", env="API_HOST")
    api_port: int = Field(default=8000, env="API_PORT")
    api_workers: int = Field(default=1, env="API_WORKERS")
    api_prefix: str = Field(default="/api/v1", env="API_PREFIX")
    
    # Database settings
    database_url: str = Field(default="postgresql+asyncpg://user:pass@localhost/chm", env="DATABASE_URL")
    database_pool_size: int = Field(default=20, env="DATABASE_POOL_SIZE")
    database_max_overflow: int = Field(default=30, env="DATABASE_MAX_OVERFLOW")
    database_pool_timeout: int = Field(default=30, env="DATABASE_POOL_TIMEOUT")
    database_echo: bool = Field(default=False, env="DATABASE_ECHO")
    
    # Security settings
    jwt_secret_key: str = Field(default=None, env="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=30, env="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, env="REFRESH_TOKEN_EXPIRE_DAYS")
    password_reset_expire_hours: int = Field(default=24, env="PASSWORD_RESET_EXPIRE_HOURS")
    max_login_attempts: int = Field(default=5, env="MAX_LOGIN_ATTEMPTS")
    lockout_duration_minutes: int = Field(default=30, env="LOCKOUT_DURATION_MINUTES")
    
    # Encryption settings
    encryption_key: Optional[str] = Field(default=None, env="ENCRYPTION_KEY")
    snmp_encryption_key: Optional[str] = Field(default=None, env="SNMP_ENCRYPTION_KEY")
    
    # CORS settings
    cors_origins: List[str] = Field(default=["*"], env="CORS_ORIGINS")
    cors_allow_credentials: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")
    cors_allow_methods: List[str] = Field(default=["*"], env="CORS_ALLOW_METHODS")
    cors_allow_headers: List[str] = Field(default=["*"], env="CORS_ALLOW_HEADERS")
    
    # Redis settings (for future caching)
    redis_url: Optional[str] = Field(default=None, env="REDIS_URL")
    redis_pool_size: int = Field(default=10, env="REDIS_POOL_SIZE")
    redis_ttl: int = Field(default=300, env="REDIS_TTL")
    
    # SNMP settings
    snmp_default_community: str = Field(default="public", env="SNMP_DEFAULT_COMMUNITY")
    snmp_default_version: str = Field(default="2c", env="SNMP_DEFAULT_VERSION")
    snmp_timeout: int = Field(default=5, env="SNMP_TIMEOUT")
    snmp_retries: int = Field(default=3, env="SNMP_RETRIES")
    
    # Discovery settings
    discovery_parallel_scans: int = Field(default=10, env="DISCOVERY_PARALLEL_SCANS")
    discovery_default_ports: List[int] = Field(default=[22, 23, 80, 443, 161], env="DISCOVERY_DEFAULT_PORTS")
    
    # Background tasks settings
    background_workers: int = Field(default=10, env="BACKGROUND_WORKERS")
    background_task_interval: int = Field(default=60, env="BACKGROUND_TASK_INTERVAL")
    metrics_collection_interval: int = Field(default=300, env="METRICS_COLLECTION_INTERVAL")
    
    # Rate limiting settings
    rate_limit_default: int = Field(default=100, env="RATE_LIMIT_DEFAULT")
    rate_limit_window: int = Field(default=60, env="RATE_LIMIT_WINDOW")
    
    # Logging settings
    log_level: str = Field(default="INFO", env="LOG_LEVEL")
    log_format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s", env="LOG_FORMAT")
    log_file: Optional[str] = Field(default=None, env="LOG_FILE")
    
    # Email settings (for notifications)
    smtp_host: Optional[str] = Field(default=None, env="SMTP_HOST")
    smtp_port: int = Field(default=587, env="SMTP_PORT")
    smtp_username: Optional[str] = Field(default=None, env="SMTP_USERNAME")
    smtp_password: Optional[str] = Field(default=None, env="SMTP_PASSWORD")
    smtp_from_email: Optional[str] = Field(default=None, env="SMTP_FROM_EMAIL")
    smtp_use_tls: bool = Field(default=True, env="SMTP_USE_TLS")
    
    # Slack settings (for notifications)
    slack_webhook_url: Optional[str] = Field(default=None, env="SLACK_WEBHOOK_URL")
    slack_channel: Optional[str] = Field(default=None, env="SLACK_CHANNEL")
    
    # Monitoring settings
    enable_metrics: bool = Field(default=True, env="ENABLE_METRICS")
    metrics_port: int = Field(default=9090, env="METRICS_PORT")
    
    @validator("jwt_secret_key", pre=True)
    def generate_jwt_secret(cls, v):
        """Generate JWT secret if not provided"""
        if not v:
            import secrets
            return secrets.token_urlsafe(32)
        return v
    
    @validator("encryption_key", pre=True)
    def generate_encryption_key(cls, v):
        """Generate encryption key if not provided"""
        if not v:
            from cryptography.fernet import Fernet
            return Fernet.generate_key().decode()
        return v
    
    @validator("cors_origins", pre=True)
    def parse_cors_origins(cls, v):
        """Parse CORS origins from comma-separated string"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @validator("discovery_default_ports", pre=True)
    def parse_discovery_ports(cls, v):
        """Parse discovery ports from comma-separated string"""
        if isinstance(v, str):
            return [int(port.strip()) for port in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False
        extra = "ignore"  # Ignore extra fields from .env
    
    def get_database_url(self) -> str:
        """Get database URL with proper driver"""
        if self.database_url.startswith("sqlite"):
            # SQLite doesn't need asyncpg
            return self.database_url
        elif "postgresql" in self.database_url and "+asyncpg" not in self.database_url:
            # Add asyncpg driver for PostgreSQL if not present
            return self.database_url.replace("postgresql://", "postgresql+asyncpg://")
        return self.database_url
    
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment.lower() == "production"
    
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.environment.lower() == "development"
    
    def get_logging_config(self) -> dict:
        """Get logging configuration"""
        config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "default": {
                    "format": self.log_format
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "default",
                    "level": self.log_level
                }
            },
            "root": {
                "level": self.log_level,
                "handlers": ["console"]
            }
        }
        
        # Add file handler if log file specified
        if self.log_file:
            config["handlers"]["file"] = {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "default",
                "filename": self.log_file,
                "maxBytes": 10485760,  # 10MB
                "backupCount": 5,
                "level": self.log_level
            }
            config["root"]["handlers"].append("file")
        
        return config

@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()

# Global settings instance
settings = get_settings()