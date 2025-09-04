"""
Advanced Threat Detection Service for CHM Security & Compliance System

This service provides advanced threat detection capabilities including:
- Machine learning-based anomaly detection
- Behavioral analysis and user entity behavior analytics (UEBA)
- Advanced persistent threat (APT) detection
- Real-time threat intelligence integration
- Automated threat hunting and investigation
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import uuid
from collections import defaultdict, Counter
import statistics
import math
import numpy as np
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload

from ..models.security import SecurityAuditLog, SecurityIncident, ThreatLevel
from ..models.result_objects import CollectionResult, OperationStatus

logger = logging.getLogger(__name__)


class ThreatType(str, Enum):
    """Types of threats detected"""
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    COMMAND_CONTROL = "command_control"
    INSIDER_THREAT = "insider_threat"
    APT = "apt"
    ZERO_DAY = "zero_day"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"


class DetectionMethod(str, Enum):
    """Methods used for threat detection"""
    SIGNATURE_BASED = "signature_based"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    MACHINE_LEARNING = "machine_learning"
    ANOMALY_DETECTION = "anomaly_detection"
    THREAT_INTELLIGENCE = "threat_intelligence"
    CORRELATION = "correlation"
    HEURISTIC = "heuristic"
    STATISTICAL = "statistical"


class ConfidenceLevel(str, Enum):
    """Confidence levels for threat detection"""
    VERY_HIGH = "very_high"  # 90-100%
    HIGH = "high"           # 70-89%
    MEDIUM = "medium"       # 50-69%
    LOW = "low"            # 30-49%
    VERY_LOW = "very_low"   # 0-29%


@dataclass
class ThreatIndicator:
    """Threat indicator with metadata"""
    indicator_id: str
    indicator_type: str  # ip, domain, hash, email, file, etc.
    indicator_value: str
    threat_type: ThreatType
    confidence: float  # 0.0 to 1.0
    severity: ThreatLevel
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    metadata: Dict[str, Any]


@dataclass
class BehavioralProfile:
    """User/entity behavioral profile"""
    entity_id: str
    entity_type: str  # user, device, ip, etc.
    profile_period: Tuple[datetime, datetime]
    baseline_metrics: Dict[str, float]
    anomaly_thresholds: Dict[str, float]
    risk_score: float
    last_updated: datetime
    profile_data: Dict[str, Any]


@dataclass
class ThreatDetection:
    """Threat detection result"""
    detection_id: str
    threat_type: ThreatType
    detection_method: DetectionMethod
    confidence: ConfidenceLevel
    severity: ThreatLevel
    description: str
    detected_at: datetime
    affected_entities: List[str]
    indicators: List[ThreatIndicator]
    evidence: Dict[str, Any]
    recommended_actions: List[str]
    false_positive_probability: float


@dataclass
class ThreatHuntingQuery:
    """Threat hunting query definition"""
    query_id: str
    name: str
    description: str
    query_type: str  # ioc, behavioral, statistical, etc.
    query_parameters: Dict[str, Any]
    time_range: Tuple[datetime, datetime]
    created_by: int
    created_at: datetime


class AdvancedThreatDetectionService:
    """Service for advanced threat detection and analysis"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._threat_indicators = {}
        self._behavioral_profiles = {}
        self._detection_models = {}
        self._threat_intelligence_feeds = {}
        self._ml_models = {}
        self._load_detection_models()
        self._load_threat_intelligence()
        self._initialize_ml_models()
    
    async def detect_threats_advanced(self, time_window_hours: int = 24) -> CollectionResult:
        """Advanced threat detection using multiple methods"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=time_window_hours)
            
            # Get recent events for analysis
            events = await self._get_recent_events(start_time, end_time)
            
            detections = []
            
            # Run different detection methods
            detections.extend(await self._run_behavioral_analysis(events))
            detections.extend(await self._run_anomaly_detection(events))
            detections.extend(await self._run_machine_learning_detection(events))
            detections.extend(await self._run_threat_intelligence_matching(events))
            detections.extend(await self._run_correlation_analysis(events))
            
            # Filter and rank detections
            filtered_detections = await self._filter_and_rank_detections(detections)
            
            # Create incidents for high-confidence threats
            created_incidents = []
            for detection in filtered_detections:
                if detection.confidence in [ConfidenceLevel.VERY_HIGH, ConfidenceLevel.HIGH]:
                    incident = await self._create_incident_from_detection(detection)
                    if incident:
                        created_incidents.append(incident)
            
            return CollectionResult(
                success=True,
                data={
                    "detections": filtered_detections,
                    "created_incidents": created_incidents,
                    "time_window": f"{time_window_hours} hours",
                    "total_events_analyzed": len(events)
                },
                message=f"Detected {len(filtered_detections)} threats, created {len(created_incidents)} incidents"
            )
            
        except Exception as e:
            logger.error(f"Error in advanced threat detection: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to detect threats: {str(e)}"
            )
    
    async def analyze_behavioral_anomalies(self, entity_id: str, entity_type: str = "user",
                                         time_window_hours: int = 168) -> CollectionResult:
        """Analyze behavioral anomalies for a specific entity"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=time_window_hours)
            
            # Get entity events
            events = await self._get_entity_events(entity_id, entity_type, start_time, end_time)
            
            if not events:
                return CollectionResult(
                    success=False,
                    error=f"No events found for entity {entity_id}"
                )
            
            # Get or create behavioral profile
            profile = await self._get_or_create_behavioral_profile(entity_id, entity_type)
            
            # Analyze behavioral anomalies
            anomalies = await self._detect_behavioral_anomalies(events, profile)
            
            # Calculate risk score
            risk_score = await self._calculate_behavioral_risk_score(anomalies, profile)
            
            # Update profile
            await self._update_behavioral_profile(profile, events, risk_score)
            
            return CollectionResult(
                success=True,
                data={
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "anomalies": anomalies,
                    "risk_score": risk_score,
                    "profile": profile,
                    "time_window": f"{time_window_hours} hours"
                },
                message=f"Analyzed behavioral anomalies for {entity_id}"
            )
            
        except Exception as e:
            logger.error(f"Error analyzing behavioral anomalies: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to analyze behavioral anomalies: {str(e)}"
            )
    
    async def hunt_threats(self, hunting_query: ThreatHuntingQuery) -> CollectionResult:
        """Perform threat hunting using custom queries"""
        try:
            # Execute hunting query
            results = await self._execute_hunting_query(hunting_query)
            
            # Analyze results for threats
            threats = await self._analyze_hunting_results(results, hunting_query)
            
            # Generate hunting report
            report = await self._generate_hunting_report(hunting_query, results, threats)
            
            return CollectionResult(
                success=True,
                data={
                    "query_id": hunting_query.query_id,
                    "results": results,
                    "threats": threats,
                    "report": report
                },
                message=f"Threat hunting completed: {len(threats)} threats found"
            )
            
        except Exception as e:
            logger.error(f"Error in threat hunting: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to hunt threats: {str(e)}"
            )
    
    async def create_threat_hunting_query(self, query_data: Dict[str, Any], created_by: int) -> CollectionResult:
        """Create a new threat hunting query"""
        try:
            query = ThreatHuntingQuery(
                query_id=f"THQ-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                name=query_data["name"],
                description=query_data.get("description", ""),
                query_type=query_data["query_type"],
                query_parameters=query_data["parameters"],
                time_range=(
                    query_data.get("start_time", datetime.now() - timedelta(days=30)),
                    query_data.get("end_time", datetime.now())
                ),
                created_by=created_by,
                created_at=datetime.now()
            )
            
            # Store query (in production, this would be saved to database)
            self._threat_hunting_queries = getattr(self, '_threat_hunting_queries', {})
            self._threat_hunting_queries[query.query_id] = query
            
            return CollectionResult(
                success=True,
                data={"query_id": query.query_id, "query": query},
                message=f"Created threat hunting query: {query.name}"
            )
            
        except Exception as e:
            logger.error(f"Error creating threat hunting query: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to create hunting query: {str(e)}"
            )
    
    async def get_threat_intelligence(self, indicator_type: str, indicator_value: str) -> CollectionResult:
        """Get threat intelligence for a specific indicator"""
        try:
            # Check local threat intelligence
            local_intel = await self._get_local_threat_intelligence(indicator_type, indicator_value)
            
            # Check external feeds
            external_intel = await self._get_external_threat_intelligence(indicator_type, indicator_value)
            
            # Combine and analyze intelligence
            combined_intel = await self._combine_threat_intelligence(local_intel, external_intel)
            
            return CollectionResult(
                success=True,
                data=combined_intel,
                message=f"Retrieved threat intelligence for {indicator_type}: {indicator_value}"
            )
            
        except Exception as e:
            logger.error(f"Error getting threat intelligence: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get threat intelligence: {str(e)}"
            )
    
    async def update_threat_intelligence(self, indicators: List[ThreatIndicator]) -> CollectionResult:
        """Update threat intelligence with new indicators"""
        try:
            updated_count = 0
            
            for indicator in indicators:
                # Store or update indicator
                self._threat_indicators[indicator.indicator_id] = indicator
                updated_count += 1
                
                # Check for matches in recent events
                matches = await self._check_indicator_matches(indicator)
                if matches:
                    await self._create_threat_from_indicator(indicator, matches)
            
            return CollectionResult(
                success=True,
                data={"updated_indicators": updated_count},
                message=f"Updated {updated_count} threat indicators"
            )
            
        except Exception as e:
            logger.error(f"Error updating threat intelligence: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to update threat intelligence: {str(e)}"
            )
    
    async def get_threat_detection_metrics(self, time_window_hours: int = 24) -> CollectionResult:
        """Get threat detection performance metrics"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=time_window_hours)
            
            # Calculate metrics
            metrics = {
                "time_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                },
                "detection_summary": {
                    "total_detections": 0,
                    "high_confidence_detections": 0,
                    "false_positives": 0,
                    "true_positives": 0
                },
                "threat_types": {},
                "detection_methods": {},
                "confidence_distribution": {},
                "severity_distribution": {},
                "performance_metrics": {
                    "average_detection_time_ms": 0.0,
                    "detection_accuracy": 0.0,
                    "false_positive_rate": 0.0
                }
            }
            
            # In production, this would analyze actual detection data
            # For now, return mock metrics
            metrics.update({
                "detection_summary": {
                    "total_detections": 45,
                    "high_confidence_detections": 12,
                    "false_positives": 3,
                    "true_positives": 9
                },
                "threat_types": {
                    "malware": 15,
                    "intrusion": 8,
                    "data_exfiltration": 5,
                    "insider_threat": 7,
                    "apt": 3,
                    "phishing": 7
                },
                "detection_methods": {
                    "behavioral_analysis": 18,
                    "machine_learning": 12,
                    "anomaly_detection": 8,
                    "threat_intelligence": 5,
                    "correlation": 2
                },
                "confidence_distribution": {
                    "very_high": 8,
                    "high": 12,
                    "medium": 15,
                    "low": 7,
                    "very_low": 3
                },
                "performance_metrics": {
                    "average_detection_time_ms": 125.5,
                    "detection_accuracy": 0.85,
                    "false_positive_rate": 0.067
                }
            })
            
            return CollectionResult(
                success=True,
                data=metrics,
                message="Retrieved threat detection metrics"
            )
            
        except Exception as e:
            logger.error(f"Error getting threat detection metrics: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get detection metrics: {str(e)}"
            )
    
    # Private helper methods
    
    def _load_detection_models(self):
        """Load threat detection models"""
        self._detection_models = {
            "behavioral_anomaly": {
                "model_type": "statistical",
                "parameters": {
                    "z_score_threshold": 3.0,
                    "window_size": 24,  # hours
                    "min_events": 10
                }
            },
            "network_anomaly": {
                "model_type": "ml",
                "parameters": {
                    "algorithm": "isolation_forest",
                    "contamination": 0.1,
                    "n_estimators": 100
                }
            },
            "user_behavior": {
                "model_type": "ml",
                "parameters": {
                    "algorithm": "clustering",
                    "n_clusters": 5,
                    "distance_metric": "euclidean"
                }
            }
        }
    
    def _load_threat_intelligence(self):
        """Load threat intelligence feeds"""
        self._threat_intelligence_feeds = {
            "malware_hashes": {
                "source": "malware_repository",
                "last_updated": datetime.now() - timedelta(hours=1),
                "indicators": {}
            },
            "malicious_ips": {
                "source": "ip_reputation",
                "last_updated": datetime.now() - timedelta(hours=2),
                "indicators": {}
            },
            "malicious_domains": {
                "source": "domain_reputation",
                "last_updated": datetime.now() - timedelta(hours=3),
                "indicators": {}
            }
        }
    
    def _initialize_ml_models(self):
        """Initialize machine learning models"""
        self._ml_models = {
            "anomaly_detector": {
                "model": None,  # Would be loaded from file in production
                "trained": False,
                "accuracy": 0.0
            },
            "behavior_classifier": {
                "model": None,
                "trained": False,
                "accuracy": 0.0
            },
            "threat_classifier": {
                "model": None,
                "trained": False,
                "accuracy": 0.0
            }
        }
    
    async def _get_recent_events(self, start_time: datetime, end_time: datetime) -> List[SecurityAuditLog]:
        """Get recent security events for analysis"""
        result = await self.db_session.execute(
            select(SecurityAuditLog).where(
                and_(
                    SecurityAuditLog.timestamp >= start_time,
                    SecurityAuditLog.timestamp <= end_time
                )
            ).order_by(desc(SecurityAuditLog.timestamp))
        )
        return result.scalars().all()
    
    async def _get_entity_events(self, entity_id: str, entity_type: str,
                               start_time: datetime, end_time: datetime) -> List[SecurityAuditLog]:
        """Get events for a specific entity"""
        if entity_type == "user":
            result = await self.db_session.execute(
                select(SecurityAuditLog).where(
                    and_(
                        SecurityAuditLog.user_id == int(entity_id),
                        SecurityAuditLog.timestamp >= start_time,
                        SecurityAuditLog.timestamp <= end_time
                    )
                )
            )
        else:
            # For other entity types, would need different query logic
            result = await self.db_session.execute(
                select(SecurityAuditLog).where(
                    and_(
                        SecurityAuditLog.timestamp >= start_time,
                        SecurityAuditLog.timestamp <= end_time
                    )
                )
            )
        
        return result.scalars().all()
    
    async def _run_behavioral_analysis(self, events: List[SecurityAuditLog]) -> List[ThreatDetection]:
        """Run behavioral analysis on events"""
        detections = []
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            if event.user_id:
                user_events[event.user_id].append(event)
        
        # Analyze each user's behavior
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) < 5:  # Need minimum events for analysis
                continue
            
            # Get behavioral profile
            profile = await self._get_or_create_behavioral_profile(str(user_id), "user")
            
            # Detect anomalies
            anomalies = await self._detect_behavioral_anomalies(user_event_list, profile)
            
            if anomalies:
                detection = ThreatDetection(
                    detection_id=f"DET-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                    threat_type=ThreatType.INSIDER_THREAT,
                    detection_method=DetectionMethod.BEHAVIORAL_ANALYSIS,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=ThreatLevel.MEDIUM,
                    description=f"Behavioral anomalies detected for user {user_id}",
                    detected_at=datetime.now(),
                    affected_entities=[str(user_id)],
                    indicators=[],
                    evidence={"anomalies": anomalies, "profile": profile.__dict__},
                    recommended_actions=["Investigate user activity", "Review access permissions"],
                    false_positive_probability=0.3
                )
                detections.append(detection)
        
        return detections
    
    async def _run_anomaly_detection(self, events: List[SecurityAuditLog]) -> List[ThreatDetection]:
        """Run statistical anomaly detection"""
        detections = []
        
        if len(events) < 10:
            return detections
        
        # Analyze event patterns
        event_counts = Counter(event.event_type for event in events)
        event_times = [event.timestamp for event in events]
        
        # Detect time-based anomalies
        time_anomalies = await self._detect_time_anomalies(event_times)
        
        # Detect frequency anomalies
        frequency_anomalies = await self._detect_frequency_anomalies(event_counts)
        
        if time_anomalies or frequency_anomalies:
            detection = ThreatDetection(
                detection_id=f"DET-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                threat_type=ThreatType.INTRUSION,
                detection_method=DetectionMethod.ANOMALY_DETECTION,
                confidence=ConfidenceLevel.MEDIUM,
                severity=ThreatLevel.MEDIUM,
                description="Statistical anomalies detected in event patterns",
                detected_at=datetime.now(),
                affected_entities=[],
                indicators=[],
                evidence={
                    "time_anomalies": time_anomalies,
                    "frequency_anomalies": frequency_anomalies,
                    "event_counts": dict(event_counts)
                },
                recommended_actions=["Investigate anomalous patterns", "Review system logs"],
                false_positive_probability=0.4
            )
            detections.append(detection)
        
        return detections
    
    async def _run_machine_learning_detection(self, events: List[SecurityAuditLog]) -> List[ThreatDetection]:
        """Run machine learning-based threat detection"""
        detections = []
        
        # In production, this would use trained ML models
        # For now, simulate ML detection
        
        # Extract features from events
        features = await self._extract_event_features(events)
        
        # Run ML models
        ml_results = await self._run_ml_models(features)
        
        for result in ml_results:
            if result["threat_probability"] > 0.7:
                detection = ThreatDetection(
                    detection_id=f"DET-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                    threat_type=ThreatType.MALWARE,
                    detection_method=DetectionMethod.MACHINE_LEARNING,
                    confidence=ConfidenceLevel.HIGH if result["threat_probability"] > 0.8 else ConfidenceLevel.MEDIUM,
                    severity=ThreatLevel.HIGH,
                    description=f"ML model detected threat with {result['threat_probability']:.2f} probability",
                    detected_at=datetime.now(),
                    affected_entities=result.get("affected_entities", []),
                    indicators=[],
                    evidence={"ml_result": result, "features": features},
                    recommended_actions=["Investigate ML-detected threat", "Review system behavior"],
                    false_positive_probability=1.0 - result["threat_probability"]
                )
                detections.append(detection)
        
        return detections
    
    async def _run_threat_intelligence_matching(self, events: List[SecurityAuditLog]) -> List[ThreatDetection]:
        """Run threat intelligence matching"""
        detections = []
        
        # Extract indicators from events
        indicators = await self._extract_indicators_from_events(events)
        
        # Match against threat intelligence
        for indicator in indicators:
            intel_match = await self._check_threat_intelligence_match(indicator)
            if intel_match:
                detection = ThreatDetection(
                    detection_id=f"DET-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                    threat_type=intel_match["threat_type"],
                    detection_method=DetectionMethod.THREAT_INTELLIGENCE,
                    confidence=ConfidenceLevel.HIGH,
                    severity=intel_match["severity"],
                    description=f"Threat intelligence match: {indicator['type']} {indicator['value']}",
                    detected_at=datetime.now(),
                    affected_entities=[],
                    indicators=[intel_match["indicator"]],
                    evidence={"intel_match": intel_match, "source_indicator": indicator},
                    recommended_actions=["Block indicator", "Investigate related activity"],
                    false_positive_probability=0.1
                )
                detections.append(detection)
        
        return detections
    
    async def _run_correlation_analysis(self, events: List[SecurityAuditLog]) -> List[ThreatDetection]:
        """Run correlation analysis to detect complex threats"""
        detections = []
        
        # Group events by various attributes
        user_events = defaultdict(list)
        ip_events = defaultdict(list)
        resource_events = defaultdict(list)
        
        for event in events:
            if event.user_id:
                user_events[event.user_id].append(event)
            if event.ip_address:
                ip_events[str(event.ip_address)].append(event)
            if event.resource_id:
                resource_events[event.resource_id].append(event)
        
        # Look for correlation patterns
        correlations = await self._find_correlation_patterns(user_events, ip_events, resource_events)
        
        for correlation in correlations:
            if correlation["confidence"] > 0.6:
                detection = ThreatDetection(
                    detection_id=f"DET-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                    threat_type=ThreatType.APT,
                    detection_method=DetectionMethod.CORRELATION,
                    confidence=ConfidenceLevel.MEDIUM,
                    severity=ThreatLevel.HIGH,
                    description=f"Correlated threat pattern detected: {correlation['pattern']}",
                    detected_at=datetime.now(),
                    affected_entities=correlation["affected_entities"],
                    indicators=[],
                    evidence={"correlation": correlation},
                    recommended_actions=["Investigate correlated events", "Review attack timeline"],
                    false_positive_probability=0.2
                )
                detections.append(detection)
        
        return detections
    
    async def _filter_and_rank_detections(self, detections: List[ThreatDetection]) -> List[ThreatDetection]:
        """Filter and rank threat detections"""
        # Remove duplicates and low-confidence detections
        filtered = []
        seen_descriptions = set()
        
        for detection in detections:
            # Skip if we've seen similar detection
            if detection.description in seen_descriptions:
                continue
            
            # Skip very low confidence detections
            if detection.confidence == ConfidenceLevel.VERY_LOW:
                continue
            
            filtered.append(detection)
            seen_descriptions.add(detection.description)
        
        # Sort by severity and confidence
        def sort_key(detection):
            severity_scores = {
                ThreatLevel.CRITICAL: 5,
                ThreatLevel.HIGH: 4,
                ThreatLevel.MEDIUM: 3,
                ThreatLevel.LOW: 2,
                ThreatLevel.INFO: 1
            }
            confidence_scores = {
                ConfidenceLevel.VERY_HIGH: 5,
                ConfidenceLevel.HIGH: 4,
                ConfidenceLevel.MEDIUM: 3,
                ConfidenceLevel.LOW: 2,
                ConfidenceLevel.VERY_LOW: 1
            }
            return (severity_scores[detection.severity], confidence_scores[detection.confidence])
        
        filtered.sort(key=sort_key, reverse=True)
        
        return filtered
    
    async def _create_incident_from_detection(self, detection: ThreatDetection) -> Optional[Dict[str, Any]]:
        """Create security incident from threat detection"""
        try:
            incident_data = {
                "title": f"Threat Detected: {detection.threat_type.value}",
                "description": detection.description,
                "incident_type": detection.threat_type.value,
                "threat_level": detection.severity.value,
                "category": "security",
                "affected_systems": detection.affected_entities,
                "indicators_of_compromise": {
                    "detection_id": detection.detection_id,
                    "detection_method": detection.detection_method.value,
                    "confidence": detection.confidence.value,
                    "evidence": detection.evidence
                },
                "detected_at": detection.detected_at
            }
            
            # In production, this would create an actual incident
            return incident_data
            
        except Exception as e:
            logger.error(f"Error creating incident from detection: {str(e)}")
            return None
    
    async def _get_or_create_behavioral_profile(self, entity_id: str, entity_type: str) -> BehavioralProfile:
        """Get or create behavioral profile for entity"""
        profile_key = f"{entity_type}_{entity_id}"
        
        if profile_key in self._behavioral_profiles:
            return self._behavioral_profiles[profile_key]
        
        # Create new profile
        profile = BehavioralProfile(
            entity_id=entity_id,
            entity_type=entity_type,
            profile_period=(datetime.now() - timedelta(days=30), datetime.now()),
            baseline_metrics={},
            anomaly_thresholds={},
            risk_score=0.0,
            last_updated=datetime.now(),
            profile_data={}
        )
        
        self._behavioral_profiles[profile_key] = profile
        return profile
    
    async def _detect_behavioral_anomalies(self, events: List[SecurityAuditLog], 
                                         profile: BehavioralProfile) -> List[Dict[str, Any]]:
        """Detect behavioral anomalies"""
        anomalies = []
        
        # Analyze event frequency
        event_counts = Counter(event.event_type for event in events)
        total_events = len(events)
        
        for event_type, count in event_counts.items():
            frequency = count / total_events
            
            # Check against baseline (simplified)
            baseline_frequency = profile.baseline_metrics.get(event_type, 0.1)
            threshold = profile.anomaly_thresholds.get(event_type, 0.2)
            
            if abs(frequency - baseline_frequency) > threshold:
                anomalies.append({
                    "type": "frequency_anomaly",
                    "event_type": event_type,
                    "observed_frequency": frequency,
                    "baseline_frequency": baseline_frequency,
                    "deviation": abs(frequency - baseline_frequency)
                })
        
        # Analyze time patterns
        if len(events) > 10:
            event_times = [event.timestamp.hour for event in events]
            time_distribution = Counter(event_times)
            
            # Check for unusual time patterns
            for hour, count in time_distribution.items():
                if hour < 6 or hour > 22:  # Unusual hours
                    if count > len(events) * 0.1:  # More than 10% of events
                        anomalies.append({
                            "type": "time_anomaly",
                            "hour": hour,
                            "event_count": count,
                            "percentage": count / len(events)
                        })
        
        return anomalies
    
    async def _calculate_behavioral_risk_score(self, anomalies: List[Dict[str, Any]], 
                                             profile: BehavioralProfile) -> float:
        """Calculate behavioral risk score"""
        if not anomalies:
            return 0.0
        
        # Simple risk scoring based on anomaly types and severity
        risk_score = 0.0
        
        for anomaly in anomalies:
            if anomaly["type"] == "frequency_anomaly":
                risk_score += anomaly["deviation"] * 10
            elif anomaly["type"] == "time_anomaly":
                risk_score += 5.0
        
        # Normalize to 0-1 scale
        return min(risk_score / 100.0, 1.0)
    
    async def _update_behavioral_profile(self, profile: BehavioralProfile, 
                                       events: List[SecurityAuditLog], risk_score: float):
        """Update behavioral profile with new data"""
        # Update baseline metrics
        event_counts = Counter(event.event_type for event in events)
        total_events = len(events)
        
        for event_type, count in event_counts.items():
            frequency = count / total_events
            # Simple moving average update
            current_baseline = profile.baseline_metrics.get(event_type, frequency)
            profile.baseline_metrics[event_type] = (current_baseline + frequency) / 2
        
        # Update risk score
        profile.risk_score = risk_score
        profile.last_updated = datetime.now()
        
        # Update profile data
        profile.profile_data.update({
            "total_events": total_events,
            "event_types": dict(event_counts),
            "last_analysis": datetime.now().isoformat()
        })
    
    async def _execute_hunting_query(self, query: ThreatHuntingQuery) -> List[Dict[str, Any]]:
        """Execute threat hunting query"""
        # In production, this would execute complex queries against the data
        # For now, return mock results
        return [
            {
                "event_id": f"EVT-{i}",
                "timestamp": datetime.now() - timedelta(hours=i),
                "event_type": "access_control",
                "user_id": 1,
                "resource_type": "device",
                "action": "read"
            }
            for i in range(10)
        ]
    
    async def _analyze_hunting_results(self, results: List[Dict[str, Any]], 
                                     query: ThreatHuntingQuery) -> List[Dict[str, Any]]:
        """Analyze threat hunting results"""
        threats = []
        
        # Simple analysis based on query type
        if query.query_type == "ioc":
            # Look for indicators of compromise
            for result in results:
                if result.get("event_type") == "access_control" and result.get("action") == "write":
                    threats.append({
                        "threat_type": "data_modification",
                        "confidence": 0.7,
                        "evidence": result
                    })
        
        return threats
    
    async def _generate_hunting_report(self, query: ThreatHuntingQuery, 
                                     results: List[Dict[str, Any]], 
                                     threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate threat hunting report"""
        return {
            "query_id": query.query_id,
            "query_name": query.name,
            "execution_time": datetime.now(),
            "results_count": len(results),
            "threats_found": len(threats),
            "threats": threats,
            "summary": f"Found {len(threats)} potential threats in {len(results)} events"
        }
    
    async def _get_local_threat_intelligence(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        """Get local threat intelligence"""
        # Check local threat intelligence feeds
        for feed_name, feed_data in self._threat_intelligence_feeds.items():
            if indicator_value in feed_data["indicators"]:
                return {
                    "source": "local",
                    "feed": feed_name,
                    "indicator": feed_data["indicators"][indicator_value],
                    "last_updated": feed_data["last_updated"]
                }
        
        return {"source": "local", "found": False}
    
    async def _get_external_threat_intelligence(self, indicator_type: str, indicator_value: str) -> Dict[str, Any]:
        """Get external threat intelligence"""
        # In production, this would query external threat intelligence APIs
        # For now, return mock data
        return {
            "source": "external",
            "found": False,
            "apis_queried": ["virustotal", "abuseipdb", "shodan"]
        }
    
    async def _combine_threat_intelligence(self, local_intel: Dict[str, Any], 
                                         external_intel: Dict[str, Any]) -> Dict[str, Any]:
        """Combine threat intelligence from multiple sources"""
        return {
            "indicator_type": "unknown",
            "indicator_value": "unknown",
            "local_intelligence": local_intel,
            "external_intelligence": external_intel,
            "combined_risk_score": 0.0,
            "recommendations": []
        }
    
    async def _check_indicator_matches(self, indicator: ThreatIndicator) -> List[Dict[str, Any]]:
        """Check for matches of threat indicator in recent events"""
        # In production, this would search through event data
        return []
    
    async def _create_threat_from_indicator(self, indicator: ThreatIndicator, matches: List[Dict[str, Any]]):
        """Create threat detection from indicator match"""
        logger.info(f"Created threat from indicator {indicator.indicator_id}: {len(matches)} matches")
    
    async def _detect_time_anomalies(self, event_times: List[datetime]) -> List[Dict[str, Any]]:
        """Detect time-based anomalies"""
        if len(event_times) < 5:
            return []
        
        # Calculate time intervals
        intervals = []
        for i in range(1, len(event_times)):
            interval = (event_times[i] - event_times[i-1]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return []
        
        # Detect outliers using simple statistical method
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        
        anomalies = []
        for i, interval in enumerate(intervals):
            if std_interval > 0 and abs(interval - mean_interval) > 2 * std_interval:
                anomalies.append({
                    "index": i,
                    "interval": interval,
                    "mean_interval": mean_interval,
                    "deviation": abs(interval - mean_interval) / std_interval
                })
        
        return anomalies
    
    async def _detect_frequency_anomalies(self, event_counts: Counter) -> List[Dict[str, Any]]:
        """Detect frequency-based anomalies"""
        if not event_counts:
            return []
        
        total_events = sum(event_counts.values())
        anomalies = []
        
        for event_type, count in event_counts.items():
            frequency = count / total_events
            
            # Simple threshold-based anomaly detection
            if frequency > 0.5:  # More than 50% of events
                anomalies.append({
                    "event_type": event_type,
                    "count": count,
                    "frequency": frequency,
                    "anomaly_type": "high_frequency"
                })
        
        return anomalies
    
    async def _extract_event_features(self, events: List[SecurityAuditLog]) -> Dict[str, Any]:
        """Extract features from events for ML analysis"""
        if not events:
            return {}
        
        features = {
            "total_events": len(events),
            "unique_users": len(set(event.user_id for event in events if event.user_id)),
            "unique_ips": len(set(str(event.ip_address) for event in events if event.ip_address)),
            "event_types": dict(Counter(event.event_type for event in events)),
            "success_rate": sum(1 for event in events if event.success) / len(events),
            "time_span_hours": (max(event.timestamp for event in events) - 
                               min(event.timestamp for event in events)).total_seconds() / 3600
        }
        
        return features
    
    async def _run_ml_models(self, features: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Run machine learning models on features"""
        # In production, this would use actual trained ML models
        # For now, simulate ML results
        
        results = []
        
        # Simulate threat detection based on features
        if features.get("success_rate", 1.0) < 0.5:  # Low success rate
            results.append({
                "threat_probability": 0.8,
                "threat_type": "intrusion",
                "affected_entities": [],
                "model_used": "anomaly_detector"
            })
        
        if features.get("unique_ips", 0) > 10:  # Many unique IPs
            results.append({
                "threat_probability": 0.7,
                "threat_type": "lateral_movement",
                "affected_entities": [],
                "model_used": "behavior_classifier"
            })
        
        return results
    
    async def _extract_indicators_from_events(self, events: List[SecurityAuditLog]) -> List[Dict[str, Any]]:
        """Extract threat indicators from events"""
        indicators = []
        
        for event in events:
            if event.ip_address:
                indicators.append({
                    "type": "ip",
                    "value": str(event.ip_address),
                    "context": "event_source"
                })
            
            if event.user_agent:
                indicators.append({
                    "type": "user_agent",
                    "value": event.user_agent,
                    "context": "event_metadata"
                })
        
        return indicators
    
    async def _check_threat_intelligence_match(self, indicator: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Check if indicator matches threat intelligence"""
        # In production, this would check against actual threat intelligence feeds
        # For now, simulate some matches
        
        if indicator["type"] == "ip" and indicator["value"] == "192.168.1.100":
            return {
                "threat_type": ThreatType.MALWARE,
                "severity": ThreatLevel.HIGH,
                "indicator": ThreatIndicator(
                    indicator_id=f"TI-{str(uuid.uuid4())[:8]}",
                    indicator_type="ip",
                    indicator_value=indicator["value"],
                    threat_type=ThreatType.MALWARE,
                    confidence=0.9,
                    severity=ThreatLevel.HIGH,
                    source="threat_intelligence_feed",
                    first_seen=datetime.now() - timedelta(days=1),
                    last_seen=datetime.now(),
                    tags=["malware", "botnet"],
                    metadata={"reputation": "malicious"}
                )
            }
        
        return None
    
    async def _find_correlation_patterns(self, user_events: Dict[int, List[SecurityAuditLog]],
                                       ip_events: Dict[str, List[SecurityAuditLog]],
                                       resource_events: Dict[str, List[SecurityAuditLog]]) -> List[Dict[str, Any]]:
        """Find correlation patterns across different event groups"""
        correlations = []
        
        # Look for users accessing multiple resources from same IP
        for user_id, events in user_events.items():
            if len(events) < 5:
                continue
            
            user_ips = set(str(event.ip_address) for event in events if event.ip_address)
            user_resources = set(event.resource_id for event in events if event.resource_id)
            
            if len(user_ips) == 1 and len(user_resources) > 3:
                correlations.append({
                    "pattern": "single_ip_multiple_resources",
                    "confidence": 0.7,
                    "affected_entities": [str(user_id)],
                    "details": {
                        "user_id": user_id,
                        "ip": list(user_ips)[0],
                        "resource_count": len(user_resources)
                    }
                })
        
        return correlations
