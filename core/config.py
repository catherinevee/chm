"""
CHM Configuration
Environment-based configuration management
"""

import os
from typing import List, Optional
from pydantic import BaseSettings, validator

class Settings(BaseSettings):
    """Application settings"""
    
    # Application
    app_name: str = "CHM - Catalyst Health Monitor"
    version: str = "2.0.0"
    debug: bool = False
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Security
    secret_key: str = "your-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = False
    max_failed_login_attempts: int = 5
    account_lockout_duration_minutes: int = 30
    password_expiry_days: int = 90
    
    # Database
    database_url: str = "postgresql://user:password@localhost/chm"
    database_pool_size: int = 20
    database_max_overflow: int = 30
    
    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_pool_size: int = 10
    
    # CORS
    allowed_hosts: List[str] = ["*"]
    trusted_hosts: Optional[List[str]] = None
    
    # Monitoring
    monitoring_interval: int = 60  # seconds
    alert_threshold: float = 0.8
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # External Services
    snmp_timeout: int = 10
    ssh_timeout: int = 30
    http_timeout: int = 30
    
    @validator("allowed_hosts", pre=True)
    def parse_allowed_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    @validator("trusted_hosts", pre=True)
    def parse_trusted_hosts(cls, v):
        if isinstance(v, str):
            return [host.strip() for host in v.split(",")]
        return v
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

# Global settings instance
_settings: Optional[Settings] = None

def get_settings() -> Settings:
    """Get application settings"""
    global _settings
    
    if _settings is None:
        _settings = Settings()
    
    return _settings

# Export settings
__all__ = ["Settings", "get_settings"]
