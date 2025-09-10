"""
Comprehensive audit logging system with structured events, compliance support,
and secure storage with integrity verification.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

try:
    from sqlalchemy import (
        Column, String, Integer, Float, Boolean, Text, DateTime,
        ForeignKey, Index, UniqueConstraint, CheckConstraint,
        create_engine, select, and_, or_, func, text
    )
    from sqlalchemy.ext.asyncio import AsyncSession, AsyncEngine, create_async_engine
    from sqlalchemy.orm import declarative_base, relationship, sessionmaker
    from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    SQLALCHEMY_AVAILABLE = False

try:
    import redis.asyncio as redis
    from redis.asyncio import Redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    from elasticsearch import AsyncElasticsearch
    ELASTICSEARCH_AVAILABLE = True
except ImportError:
    ELASTICSEARCH_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """Types of audit events."""
    # Authentication events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGE = "auth.password.change"
    PASSWORD_RESET = "auth.password.reset"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    
    # Authorization events
    PERMISSION_GRANTED = "authz.permission.granted"
    PERMISSION_DENIED = "authz.permission.denied"
    ROLE_ASSIGNED = "authz.role.assigned"
    ROLE_REVOKED = "authz.role.revoked"
    POLICY_CREATED = "authz.policy.created"
    POLICY_UPDATED = "authz.policy.updated"
    POLICY_DELETED = "authz.policy.deleted"
    
    # Data access events
    DATA_READ = "data.read"
    DATA_CREATE = "data.create"
    DATA_UPDATE = "data.update"
    DATA_DELETE = "data.delete"
    DATA_EXPORT = "data.export"
    DATA_IMPORT = "data.import"
    QUERY_EXECUTED = "data.query.executed"
    
    # System events
    SYSTEM_START = "system.start"
    SYSTEM_STOP = "system.stop"
    CONFIG_CHANGE = "system.config.change"
    SERVICE_START = "system.service.start"
    SERVICE_STOP = "system.service.stop"
    ERROR_CRITICAL = "system.error.critical"
    ERROR_WARNING = "system.error.warning"
    
    # Security events
    SECURITY_ALERT = "security.alert"
    INTRUSION_DETECTED = "security.intrusion.detected"
    RATE_LIMIT_EXCEEDED = "security.rate_limit.exceeded"
    INVALID_TOKEN = "security.token.invalid"
    ENCRYPTION_KEY_ROTATED = "security.key.rotated"
    CERTIFICATE_EXPIRED = "security.cert.expired"
    
    # Compliance events
    GDPR_DATA_REQUEST = "compliance.gdpr.request"
    GDPR_DATA_DELETION = "compliance.gdpr.deletion"
    CONSENT_GRANTED = "compliance.consent.granted"
    CONSENT_REVOKED = "compliance.consent.revoked"
    AUDIT_LOG_ACCESSED = "compliance.audit.accessed"
    AUDIT_LOG_EXPORTED = "compliance.audit.exported"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class AuditContext:
    """Context information for audit events."""
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    geo_location: Optional[Dict[str, Any]] = None
    device_info: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            k: v for k, v in self.__dict__.items()
            if v is not None
        }


@dataclass
class AuditEvent:
    """Structured audit event."""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: AuditEventType = AuditEventType.SYSTEM_START
    severity: AuditSeverity = AuditSeverity.INFO
    
    # Actor information
    user_id: Optional[str] = None
    service_id: Optional[str] = None
    api_key_id: Optional[str] = None
    
    # Target information
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    
    # Event details
    action: Optional[str] = None
    result: Optional[str] = None
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    # Context
    context: Optional[AuditContext] = None
    
    # Compliance fields
    data_classification: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)
    retention_days: Optional[int] = None
    
    # Security fields
    risk_score: Optional[float] = None
    threat_indicators: List[str] = field(default_factory=list)
    
    # Integrity
    checksum: Optional[str] = None
    previous_event_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'severity': self.severity.value,
        }
        
        # Add optional fields
        for field_name in ['user_id', 'service_id', 'api_key_id',
                          'resource_type', 'resource_id', 'resource_name',
                          'action', 'result', 'reason', 'details',
                          'data_classification', 'risk_score']:
            value = getattr(self, field_name)
            if value is not None:
                data[field_name] = value
        
        if self.context:
            data['context'] = self.context.to_dict()
        
        if self.compliance_tags:
            data['compliance_tags'] = self.compliance_tags
        
        if self.threat_indicators:
            data['threat_indicators'] = self.threat_indicators
        
        if self.retention_days is not None:
            data['retention_days'] = self.retention_days
        
        return data
    
    def calculate_checksum(self, secret_key: bytes) -> str:
        """Calculate HMAC checksum for event integrity."""
        if not CRYPTO_AVAILABLE:
            # Fallback to basic hash
            event_str = json.dumps(self.to_dict(), sort_keys=True)
            return hashlib.sha256(event_str.encode()).hexdigest()
        
        # Use HMAC for integrity with secret
        event_str = json.dumps(self.to_dict(), sort_keys=True)
        h = crypto_hmac.HMAC(secret_key, hashes.SHA256())
        h.update(event_str.encode())
        return h.finalize().hex()


if SQLALCHEMY_AVAILABLE:
    Base = declarative_base()
    
    class AuditLogModel(Base):
        """Database model for audit logs."""
        __tablename__ = 'audit_logs'
        
        id = Column(Integer, primary_key=True)
        event_id = Column(UUID(as_uuid=True), unique=True, nullable=False)
        timestamp = Column(DateTime(timezone=True), nullable=False)
        event_type = Column(String(100), nullable=False)
        severity = Column(String(20), nullable=False)
        
        # Actor
        user_id = Column(String(255), index=True)
        service_id = Column(String(255), index=True)
        api_key_id = Column(String(255))
        
        # Target
        resource_type = Column(String(100), index=True)
        resource_id = Column(String(255), index=True)
        resource_name = Column(String(255))
        
        # Event
        action = Column(String(100))
        result = Column(String(50))
        reason = Column(Text)
        details = Column(JSONB)
        
        # Context
        request_id = Column(String(255), index=True)
        session_id = Column(String(255), index=True)
        correlation_id = Column(String(255), index=True)
        ip_address = Column(String(45))
        user_agent = Column(Text)
        geo_location = Column(JSONB)
        
        # Compliance
        data_classification = Column(String(50))
        compliance_tags = Column(ARRAY(String))
        retention_days = Column(Integer)
        retention_expires = Column(DateTime(timezone=True))
        
        # Security
        risk_score = Column(Float)
        threat_indicators = Column(ARRAY(String))
        checksum = Column(String(64))
        previous_event_id = Column(UUID(as_uuid=True))
        
        # Indexes for common queries
        __table_args__ = (
            Index('idx_audit_timestamp', 'timestamp'),
            Index('idx_audit_event_type', 'event_type'),
            Index('idx_audit_user_resource', 'user_id', 'resource_type', 'resource_id'),
            Index('idx_audit_retention', 'retention_expires'),
            Index('idx_audit_risk', 'risk_score'),
        )


class AuditStorage:
    """Storage backend for audit logs."""
    
    def __init__(
        self,
        database_url: Optional[str] = None,
        redis_client: Optional['Redis'] = None,
        elasticsearch_client: Optional['AsyncElasticsearch'] = None,
        file_path: Optional[Path] = None,
        buffer_size: int = 100,
        flush_interval: float = 5.0
    ):
        self.database_url = database_url
        self.redis_client = redis_client
        self.elasticsearch_client = elasticsearch_client
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.flush_interval = flush_interval
        
        self._buffer: List[AuditEvent] = []
        self._db_engine: Optional[AsyncEngine] = None
        self._db_session_maker = None
        self._flush_task: Optional[asyncio.Task] = None
        self._shutdown = False
        
    async def initialize(self):
        """Initialize storage backends."""
        if self.database_url and SQLALCHEMY_AVAILABLE:
            self._db_engine = create_async_engine(
                self.database_url,
                pool_size=10,
                max_overflow=20,
                pool_pre_ping=True,
                pool_recycle=3600
            )
            
            # Create tables
            async with self._db_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            self._db_session_maker = sessionmaker(
                self._db_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
        
        if self.file_path:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Start background flush task
        self._flush_task = asyncio.create_task(self._periodic_flush())
    
    async def _periodic_flush(self):
        """Periodically flush buffer to storage."""
        while not self._shutdown:
            try:
                await asyncio.sleep(self.flush_interval)
                if self._buffer:
                    await self.flush()
            except Exception as e:
                logger.error(f"Error in periodic flush: {e}")
    
    async def store(self, event: AuditEvent):
        """Store an audit event."""
        self._buffer.append(event)
        
        if len(self._buffer) >= self.buffer_size:
            await self.flush()
    
    async def flush(self):
        """Flush buffered events to storage."""
        if not self._buffer:
            return
        
        events = self._buffer.copy()
        self._buffer.clear()
        
        # Store to multiple backends in parallel
        tasks = []
        
        if self._db_session_maker:
            tasks.append(self._store_to_database(events))
        
        if self.redis_client and REDIS_AVAILABLE:
            tasks.append(self._store_to_redis(events))
        
        if self.elasticsearch_client and ELASTICSEARCH_AVAILABLE:
            tasks.append(self._store_to_elasticsearch(events))
        
        if self.file_path:
            tasks.append(self._store_to_file(events))
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Storage backend {i} failed: {result}")
    
    async def _store_to_database(self, events: List[AuditEvent]):
        """Store events to database."""
        async with self._db_session_maker() as session:
            for event in events:
                log = AuditLogModel(
                    event_id=uuid.UUID(event.event_id),
                    timestamp=event.timestamp,
                    event_type=event.event_type.value,
                    severity=event.severity.value,
                    user_id=event.user_id,
                    service_id=event.service_id,
                    api_key_id=event.api_key_id,
                    resource_type=event.resource_type,
                    resource_id=event.resource_id,
                    resource_name=event.resource_name,
                    action=event.action,
                    result=event.result,
                    reason=event.reason,
                    details=event.details,
                    data_classification=event.data_classification,
                    compliance_tags=event.compliance_tags,
                    retention_days=event.retention_days,
                    risk_score=event.risk_score,
                    threat_indicators=event.threat_indicators,
                    checksum=event.checksum,
                    previous_event_id=uuid.UUID(event.previous_event_id) if event.previous_event_id else None
                )
                
                if event.context:
                    log.request_id = event.context.request_id
                    log.session_id = event.context.session_id
                    log.correlation_id = event.context.correlation_id
                    log.ip_address = event.context.ip_address
                    log.user_agent = event.context.user_agent
                    log.geo_location = event.context.geo_location
                
                if event.retention_days:
                    log.retention_expires = event.timestamp + timedelta(days=event.retention_days)
                
                session.add(log)
            
            await session.commit()
    
    async def _store_to_redis(self, events: List[AuditEvent]):
        """Store events to Redis for real-time processing."""
        pipeline = self.redis_client.pipeline()
        
        for event in events:
            # Store in sorted set by timestamp
            key = f"audit:events:{event.timestamp.strftime('%Y%m%d')}"
            pipeline.zadd(
                key,
                {json.dumps(event.to_dict()): event.timestamp.timestamp()}
            )
            
            # Set expiration based on retention
            ttl = (event.retention_days or 90) * 86400
            pipeline.expire(key, ttl)
            
            # Store in stream for real-time consumption
            stream_key = f"audit:stream:{event.event_type.value}"
            pipeline.xadd(
                stream_key,
                event.to_dict(),
                maxlen=10000,
                approximate=True
            )
        
        await pipeline.execute()
    
    async def _store_to_elasticsearch(self, events: List[AuditEvent]):
        """Store events to Elasticsearch for searching."""
        actions = []
        
        for event in events:
            actions.append({
                "_index": f"audit-logs-{event.timestamp.strftime('%Y.%m')}",
                "_id": event.event_id,
                "_source": event.to_dict()
            })
        
        if actions:
            await self.elasticsearch_client.bulk(body=actions)
    
    async def _store_to_file(self, events: List[AuditEvent]):
        """Store events to file for backup."""
        # Rotate files daily
        today = datetime.now().strftime('%Y%m%d')
        file_path = self.file_path.parent / f"{self.file_path.stem}_{today}{self.file_path.suffix}"
        
        async with asyncio.Lock():
            with open(file_path, 'a') as f:
                for event in events:
                    f.write(json.dumps(event.to_dict()) + '\n')
    
    async def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[AuditEventType]] = None,
        user_ids: Optional[List[str]] = None,
        resource_types: Optional[List[str]] = None,
        resource_ids: Optional[List[str]] = None,
        severity_min: Optional[AuditSeverity] = None,
        risk_score_min: Optional[float] = None,
        compliance_tags: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Query audit logs with filters."""
        if not self._db_session_maker:
            return []
        
        async with self._db_session_maker() as session:
            query = select(AuditLogModel)
            
            # Apply filters
            conditions = []
            
            if start_time:
                conditions.append(AuditLogModel.timestamp >= start_time)
            
            if end_time:
                conditions.append(AuditLogModel.timestamp <= end_time)
            
            if event_types:
                conditions.append(
                    AuditLogModel.event_type.in_([e.value for e in event_types])
                )
            
            if user_ids:
                conditions.append(AuditLogModel.user_id.in_(user_ids))
            
            if resource_types:
                conditions.append(AuditLogModel.resource_type.in_(resource_types))
            
            if resource_ids:
                conditions.append(AuditLogModel.resource_id.in_(resource_ids))
            
            if severity_min:
                severity_order = {
                    AuditSeverity.DEBUG: 1,
                    AuditSeverity.INFO: 2,
                    AuditSeverity.WARNING: 3,
                    AuditSeverity.ERROR: 4,
                    AuditSeverity.CRITICAL: 5
                }
                min_level = severity_order[severity_min]
                valid_severities = [
                    s.value for s, level in severity_order.items()
                    if level >= min_level
                ]
                conditions.append(AuditLogModel.severity.in_(valid_severities))
            
            if risk_score_min is not None:
                conditions.append(AuditLogModel.risk_score >= risk_score_min)
            
            if compliance_tags:
                conditions.append(
                    AuditLogModel.compliance_tags.contains(compliance_tags)
                )
            
            if conditions:
                query = query.where(and_(*conditions))
            
            # Order and paginate
            query = query.order_by(AuditLogModel.timestamp.desc())
            query = query.limit(limit).offset(offset)
            
            result = await session.execute(query)
            logs = result.scalars().all()
            
            return [self._model_to_dict(log) for log in logs]
    
    def _model_to_dict(self, log: 'AuditLogModel') -> Dict[str, Any]:
        """Convert database model to dictionary."""
        return {
            'event_id': str(log.event_id),
            'timestamp': log.timestamp.isoformat(),
            'event_type': log.event_type,
            'severity': log.severity,
            'user_id': log.user_id,
            'service_id': log.service_id,
            'resource_type': log.resource_type,
            'resource_id': log.resource_id,
            'action': log.action,
            'result': log.result,
            'details': log.details,
            'risk_score': log.risk_score,
            'checksum': log.checksum
        }
    
    async def cleanup_expired(self):
        """Remove expired audit logs."""
        if not self._db_session_maker:
            return
        
        async with self._db_session_maker() as session:
            # Delete expired logs
            await session.execute(
                text("""
                    DELETE FROM audit_logs
                    WHERE retention_expires IS NOT NULL
                    AND retention_expires < :now
                """),
                {"now": datetime.now(timezone.utc)}
            )
            await session.commit()
    
    async def shutdown(self):
        """Shutdown storage backends."""
        self._shutdown = True
        
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        # Final flush
        await self.flush()
        
        if self._db_engine:
            await self._db_engine.dispose()


class AuditLogger:
    """Main audit logging interface."""
    
    def __init__(
        self,
        storage: AuditStorage,
        secret_key: Optional[bytes] = None,
        enable_integrity: bool = True,
        enable_correlation: bool = True,
        enable_risk_scoring: bool = True,
        high_risk_threshold: float = 0.7
    ):
        self.storage = storage
        self.secret_key = secret_key or self._generate_secret_key()
        self.enable_integrity = enable_integrity
        self.enable_correlation = enable_correlation
        self.enable_risk_scoring = enable_risk_scoring
        self.high_risk_threshold = high_risk_threshold
        
        self._previous_event_id: Optional[str] = None
        self._correlation_map: Dict[str, str] = {}
        self._risk_patterns: Dict[str, float] = self._initialize_risk_patterns()
    
    def _generate_secret_key(self) -> bytes:
        """Generate a secret key for integrity checking."""
        if CRYPTO_AVAILABLE:
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'audit_salt_v1',
                iterations=100000
            )
            return kdf.derive(uuid.uuid4().bytes)
        else:
            return hashlib.sha256(uuid.uuid4().bytes).digest()
    
    def _initialize_risk_patterns(self) -> Dict[str, float]:
        """Initialize risk scoring patterns."""
        return {
            # High risk events
            AuditEventType.LOGIN_FAILURE.value: 0.3,
            AuditEventType.PERMISSION_DENIED.value: 0.4,
            AuditEventType.SECURITY_ALERT.value: 0.8,
            AuditEventType.INTRUSION_DETECTED.value: 0.9,
            AuditEventType.DATA_DELETE.value: 0.5,
            AuditEventType.DATA_EXPORT.value: 0.4,
            AuditEventType.ERROR_CRITICAL.value: 0.7,
            
            # Medium risk events
            AuditEventType.PASSWORD_CHANGE.value: 0.3,
            AuditEventType.ROLE_ASSIGNED.value: 0.3,
            AuditEventType.CONFIG_CHANGE.value: 0.4,
            AuditEventType.DATA_UPDATE.value: 0.2,
            
            # Low risk events
            AuditEventType.LOGIN_SUCCESS.value: 0.1,
            AuditEventType.DATA_READ.value: 0.1,
            AuditEventType.SYSTEM_START.value: 0.1,
        }
    
    async def log(
        self,
        event_type: AuditEventType,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[AuditContext] = None,
        severity: Optional[AuditSeverity] = None,
        compliance_tags: Optional[List[str]] = None,
        retention_days: Optional[int] = None
    ) -> str:
        """Log an audit event."""
        # Create event
        event = AuditEvent(
            event_type=event_type,
            severity=severity or self._determine_severity(event_type),
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action,
            result=result,
            details=details,
            context=context,
            compliance_tags=compliance_tags or [],
            retention_days=retention_days
        )
        
        # Add correlation
        if self.enable_correlation and context:
            if context.correlation_id:
                event.previous_event_id = self._correlation_map.get(
                    context.correlation_id
                )
                self._correlation_map[context.correlation_id] = event.event_id
            else:
                event.previous_event_id = self._previous_event_id
                self._previous_event_id = event.event_id
        
        # Calculate risk score
        if self.enable_risk_scoring:
            event.risk_score = self._calculate_risk_score(event)
            
            # Add threat indicators for high risk
            if event.risk_score >= self.high_risk_threshold:
                event.threat_indicators = self._identify_threat_indicators(event)
        
        # Add integrity checksum
        if self.enable_integrity:
            event.checksum = event.calculate_checksum(self.secret_key)
        
        # Store event
        await self.storage.store(event)
        
        # Log high risk events
        if event.risk_score and event.risk_score >= self.high_risk_threshold:
            logger.warning(
                f"High risk audit event: {event.event_type.value} "
                f"(risk_score={event.risk_score:.2f}, user={user_id})"
            )
        
        return event.event_id
    
    def _determine_severity(self, event_type: AuditEventType) -> AuditSeverity:
        """Determine severity based on event type."""
        critical_events = {
            AuditEventType.INTRUSION_DETECTED,
            AuditEventType.ERROR_CRITICAL,
            AuditEventType.SECURITY_ALERT
        }
        
        error_events = {
            AuditEventType.LOGIN_FAILURE,
            AuditEventType.PERMISSION_DENIED,
            AuditEventType.INVALID_TOKEN,
            AuditEventType.CERTIFICATE_EXPIRED
        }
        
        warning_events = {
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditEventType.ERROR_WARNING,
            AuditEventType.DATA_DELETE
        }
        
        if event_type in critical_events:
            return AuditSeverity.CRITICAL
        elif event_type in error_events:
            return AuditSeverity.ERROR
        elif event_type in warning_events:
            return AuditSeverity.WARNING
        else:
            return AuditSeverity.INFO
    
    def _calculate_risk_score(self, event: AuditEvent) -> float:
        """Calculate risk score for an event."""
        base_score = self._risk_patterns.get(event.event_type.value, 0.2)
        
        # Adjust based on context
        if event.context:
            # Suspicious IP patterns
            if event.context.ip_address:
                if self._is_suspicious_ip(event.context.ip_address):
                    base_score += 0.2
            
            # Unusual time patterns
            hour = event.timestamp.hour
            if hour < 6 or hour > 22:  # Outside business hours
                base_score += 0.1
            
            # Unusual user agent
            if event.context.user_agent:
                if self._is_suspicious_user_agent(event.context.user_agent):
                    base_score += 0.15
        
        # Adjust based on result
        if event.result == "failure":
            base_score += 0.1
        
        # Cap at 1.0
        return min(base_score, 1.0)
    
    def _is_suspicious_ip(self, ip: str) -> bool:
        """Check if IP address is suspicious."""
        # Check for known suspicious patterns
        suspicious_patterns = [
            '0.0.0.0',
            '127.0.0.',  # Localhost shouldn't be in production logs
            '192.168.',  # Private IPs might be suspicious in some contexts
            '10.',       # Private IPs
        ]
        
        return any(ip.startswith(pattern) for pattern in suspicious_patterns)
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if user agent is suspicious."""
        suspicious_keywords = [
            'bot', 'crawler', 'spider', 'scraper',
            'curl', 'wget', 'python-requests',
            'scanner', 'nikto', 'sqlmap'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(keyword in user_agent_lower for keyword in suspicious_keywords)
    
    def _identify_threat_indicators(self, event: AuditEvent) -> List[str]:
        """Identify threat indicators for high-risk events."""
        indicators = []
        
        if event.event_type == AuditEventType.LOGIN_FAILURE:
            indicators.append("repeated_login_failure")
        
        if event.event_type == AuditEventType.PERMISSION_DENIED:
            indicators.append("privilege_escalation_attempt")
        
        if event.context and event.context.ip_address:
            if self._is_suspicious_ip(event.context.ip_address):
                indicators.append("suspicious_ip_address")
        
        if event.context and event.context.user_agent:
            if self._is_suspicious_user_agent(event.context.user_agent):
                indicators.append("suspicious_user_agent")
        
        if event.risk_score >= 0.9:
            indicators.append("critical_security_event")
        
        return indicators
    
    async def query_logs(self, **kwargs) -> List[Dict[str, Any]]:
        """Query audit logs."""
        return await self.storage.query(**kwargs)
    
    async def export_logs(
        self,
        format: str = "json",
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        output_file: Optional[Path] = None
    ) -> Union[str, bytes]:
        """Export audit logs in specified format."""
        # Log the export action itself
        await self.log(
            event_type=AuditEventType.AUDIT_LOG_EXPORTED,
            details={
                "format": format,
                "start_time": start_time.isoformat() if start_time else None,
                "end_time": end_time.isoformat() if end_time else None
            }
        )
        
        # Query logs
        logs = await self.query_logs(
            start_time=start_time,
            end_time=end_time,
            limit=10000  # Reasonable limit for export
        )
        
        if format == "json":
            content = json.dumps(logs, indent=2)
        elif format == "csv":
            import csv
            import io
            
            output = io.StringIO()
            if logs:
                writer = csv.DictWriter(output, fieldnames=logs[0].keys())
                writer.writeheader()
                writer.writerows(logs)
            content = output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")
        
        if output_file:
            output_file.write_text(content)
            return str(output_file)
        
        return content
    
    async def verify_integrity(
        self,
        event_id: str
    ) -> bool:
        """Verify integrity of an audit event."""
        logs = await self.storage.query(
            resource_ids=[event_id],
            limit=1
        )
        
        if not logs:
            return False
        
        log = logs[0]
        stored_checksum = log.get('checksum')
        
        if not stored_checksum:
            return False
        
        # Recalculate checksum
        event_data = log.copy()
        event_data.pop('checksum', None)
        event_str = json.dumps(event_data, sort_keys=True)
        
        if CRYPTO_AVAILABLE:
            h = crypto_hmac.HMAC(self.secret_key, hashes.SHA256())
            h.update(event_str.encode())
            calculated_checksum = h.finalize().hex()
        else:
            calculated_checksum = hmac.new(
                self.secret_key,
                event_str.encode(),
                hashlib.sha256
            ).hexdigest()
        
        return calculated_checksum == stored_checksum
    
    async def cleanup(self):
        """Cleanup expired logs and perform maintenance."""
        await self.storage.cleanup_expired()
    
    async def shutdown(self):
        """Shutdown the audit logger."""
        await self.storage.shutdown()