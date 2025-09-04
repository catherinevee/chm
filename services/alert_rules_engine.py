"""
CHM Alert Rules Engine
Service for evaluating and executing alert rules with support for multiple rule types
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import statistics
from collections import defaultdict
import re

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, func, text
from sqlalchemy.orm import selectinload

from ..models import AlertRule, Alert, Metric, Device, User
from ..models.alert_rule import RuleStatus, RuleType, ConditionOperator
from ..models.alert import AlertSeverity, AlertCategory, AlertSource
from ..models.result_objects import OperationStatus
from ..services.notification_service import NotificationService
from ..core.database import Base

logger = logging.getLogger(__name__)

@dataclass
class RuleEvaluationResult:
    """Result of rule evaluation"""
    rule_id: int
    rule_name: str
    triggered: bool
    conditions_met: List[Dict[str, Any]]
    alerts_created: int
    execution_time_ms: float
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

@dataclass
class ConditionEvaluationResult:
    """Result of condition evaluation"""
    condition_id: str
    condition_type: str
    met: bool
    value: Any
    threshold: Any
    operator: str
    error_message: Optional[str] = None

@dataclass
class RuleExecutionConfig:
    """Configuration for rule execution"""
    enable_parallel_execution: bool = True
    max_concurrent_rules: int = 5
    execution_timeout_seconds: int = 300
    enable_condition_caching: bool = True
    cache_ttl_seconds: int = 60
    enable_rule_chaining: bool = True
    max_chain_depth: int = 3

class AlertRulesEngine:
    """Engine for evaluating and executing alert rules"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.notification_service = NotificationService(db_session)
        self.config = RuleExecutionConfig()
        self._condition_cache = {}
        self._cache_timestamps = {}
        self._execution_semaphore = asyncio.Semaphore(self.config.max_concurrent_rules)
    
    async def evaluate_all_rules(self, force_evaluation: bool = False) -> List[RuleEvaluationResult]:
        """Evaluate all active rules"""
        try:
            # Get active rules
            result = await self.db_session.execute(
                select(AlertRule).where(
                    and_(
                        AlertRule.status == RuleStatus.ACTIVE,
                        AlertRule.is_deleted == False
                    )
                )
            )
            
            active_rules = result.scalars().all()
            
            if not active_rules:
                logger.info("No active rules found")
                return []
            
            # Filter rules that can be executed
            executable_rules = [
                rule for rule in active_rules 
                if rule.can_execute and rule.is_in_active_hours
            ]
            
            if not executable_rules:
                logger.info("No executable rules found")
                return []
            
            logger.info(f"Evaluating {len(executable_rules)} active rules")
            
            # Execute rules
            if self.config.enable_parallel_execution:
                results = await self._evaluate_rules_parallel(executable_rules)
            else:
                results = []
                for rule in executable_rules:
                    result = await self._evaluate_single_rule(rule)
                    results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Failed to evaluate rules: {str(e)}")
            return []
    
    async def evaluate_rule(
        self, 
        rule_id: int, 
        force_evaluation: bool = False
    ) -> Optional[RuleEvaluationResult]:
        """Evaluate a specific rule"""
        try:
            result = await self.db_session.execute(
                select(AlertRule).where(AlertRule.id == rule_id)
            )
            rule = result.scalar_one_or_none()
            
            if not rule:
                logger.warning(f"Rule {rule_id} not found")
                return None
            
            if not rule.can_execute and not force_evaluation:
                logger.info(f"Rule {rule_id} cannot be executed")
                return None
            
            return await self._evaluate_single_rule(rule)
            
        except Exception as e:
            logger.error(f"Failed to evaluate rule {rule_id}: {str(e)}")
            return None
    
    async def _evaluate_rules_parallel(self, rules: List[AlertRule]) -> List[RuleEvaluationResult]:
        """Evaluate multiple rules in parallel"""
        async with self._execution_semaphore:
            tasks = []
            for rule in rules:
                task = self._evaluate_single_rule(rule)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Convert exceptions to error results
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append(RuleEvaluationResult(
                        rule_id=rules[i].id,
                        rule_name=rules[i].name,
                        triggered=False,
                        conditions_met=[],
                        alerts_created=0,
                        execution_time_ms=0,
                        error_message=str(result)
                    ))
                else:
                    processed_results.append(result)
            
            return processed_results
    
    async def _evaluate_single_rule(self, rule: AlertRule) -> RuleEvaluationResult:
        """Evaluate a single rule"""
        start_time = datetime.now()
        
        try:
            logger.debug(f"Evaluating rule: {rule.name} (ID: {rule.id})")
            
            # Evaluate rule conditions
            conditions_result = await self._evaluate_rule_conditions(rule)
            
            if not conditions_result:
                # Rule conditions not met
                execution_time = (datetime.now() - start_time).total_seconds() * 1000
                rule.record_execution(execution_time, 0, True)
                await self.db_session.commit()
                
                return RuleEvaluationResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    triggered=False,
                    conditions_met=[],
                    alerts_created=0,
                    execution_time_ms=execution_time
                )
            
            # Rule conditions met - execute actions
            alerts_created = await self._execute_rule_actions(rule, conditions_result)
            
            # Record execution statistics
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            rule.record_execution(execution_time, alerts_created, True)
            await self.db_session.commit()
            
            return RuleEvaluationResult(
                rule_id=rule.id,
                rule_name=rule.name,
                triggered=True,
                conditions_met=conditions_result,
                alerts_created=alerts_created,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            logger.error(f"Rule evaluation failed for {rule.name}: {str(e)}")
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            rule.record_execution(execution_time, 0, False)
            await self.db_session.commit()
            
            return RuleEvaluationResult(
                rule_id=rule.id,
                rule_name=rule.name,
                triggered=False,
                conditions_met=[],
                alerts_created=0,
                execution_time_ms=execution_time,
                error_message=str(e)
            )
    
    async def _evaluate_rule_conditions(self, rule: AlertRule) -> Optional[List[Dict[str, Any]]]:
        """Evaluate all conditions for a rule"""
        try:
            if not rule.conditions or "conditions" not in rule.conditions:
                logger.warning(f"Rule {rule.id} has no conditions")
                return None
            
            conditions = rule.conditions["conditions"]
            operator = rule.conditions.get("operator", "AND")
            
            if not conditions:
                return None
            
            # Evaluate each condition
            condition_results = []
            for condition in conditions:
                if not condition.get("enabled", True):
                    continue
                
                result = await self._evaluate_condition(rule, condition)
                condition_results.append(result)
                
                if result.error_message:
                    logger.warning(f"Condition evaluation error: {result.error_message}")
            
            # Apply logical operator
            if operator == "AND":
                all_met = all(result.met for result in condition_results)
            elif operator == "OR":
                all_met = any(result.met for result in condition_results)
            else:
                logger.warning(f"Unknown operator: {operator}")
                all_met = False
            
            if all_met:
                return [result.__dict__ for result in condition_results]
            else:
                return None
                
        except Exception as e:
            logger.error(f"Failed to evaluate rule conditions: {str(e)}")
            return None
    
    async def _evaluate_condition(self, rule: AlertRule, condition: Dict[str, Any]) -> ConditionEvaluationResult:
        """Evaluate a single condition"""
        try:
            condition_type = condition.get("type")
            condition_id = condition.get("id", "unknown")
            
            if condition_type == "metric_threshold":
                return await self._evaluate_metric_threshold_condition(rule, condition)
            elif condition_type == "anomaly_detection":
                return await self._evaluate_anomaly_detection_condition(rule, condition)
            elif condition_type == "pattern_matching":
                return await self._evaluate_pattern_matching_condition(rule, condition)
            elif condition_type == "trend_analysis":
                return await self._evaluate_trend_analysis_condition(rule, condition)
            else:
                return ConditionEvaluationResult(
                    condition_id=condition_id,
                    condition_type=condition_type or "unknown",
                    met=False,
                    value=None,
                    threshold=None,
                    operator="unknown",
                    error_message=f"Unknown condition type: {condition_type}"
                )
                
        except Exception as e:
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type=condition.get("type", "unknown"),
                met=False,
                value=None,
                threshold=None,
                operator="unknown",
                error_message=str(e)
            )
    
    async def _evaluate_metric_threshold_condition(
        self, 
        rule: AlertRule, 
        condition: Dict[str, Any]
    ) -> ConditionEvaluationResult:
        """Evaluate metric threshold condition"""
        try:
            metric_name = condition.get("metric_name")
            operator = condition.get("operator")
            threshold_value = condition.get("value")
            
            if not all([metric_name, operator, threshold_value is not None]):
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="metric_threshold",
                    met=False,
                    value=None,
                    threshold=threshold_value,
                    operator=operator,
                    error_message="Missing required condition parameters"
                )
            
            # Get current metric values for target devices
            current_values = await self._get_current_metric_values(
                rule.device_ids, 
                metric_name, 
                rule.evaluation_window
            )
            
            if not current_values:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="metric_threshold",
                    met=False,
                    value=None,
                    threshold=threshold_value,
                    operator=operator,
                    error_message="No metric data available"
                )
            
            # Check if any value meets the threshold
            condition_met = False
            for device_id, value in current_values.items():
                if self._compare_values(value, operator, threshold_value):
                    condition_met = True
                    break
            
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="metric_threshold",
                met=condition_met,
                value=current_values,
                threshold=threshold_value,
                operator=operator
            )
            
        except Exception as e:
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="metric_threshold",
                met=False,
                value=None,
                threshold=condition.get("value"),
                operator=condition.get("operator"),
                error_message=str(e)
            )
    
    async def _evaluate_anomaly_detection_condition(
        self, 
        rule: AlertRule, 
        condition: Dict[str, Any]
    ) -> ConditionEvaluationResult:
        """Evaluate anomaly detection condition"""
        try:
            metric_name = condition.get("metric_name")
            sensitivity = condition.get("sensitivity", 0.95)
            
            if not metric_name:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="anomaly_detection",
                    met=False,
                    value=None,
                    threshold=sensitivity,
                    operator="anomaly",
                    error_message="Missing metric name"
                )
            
            # Get historical metric data for baseline calculation
            baseline_data = await self._get_metric_baseline_data(
                rule.device_ids, 
                metric_name, 
                hours=24
            )
            
            if not baseline_data:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="anomaly_detection",
                    met=False,
                    value=None,
                    threshold=sensitivity,
                    operator="anomaly",
                    error_message="Insufficient baseline data"
                )
            
            # Get current values
            current_values = await self._get_current_metric_values(
                rule.device_ids, 
                metric_name, 
                rule.evaluation_window
            )
            
            if not current_values:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="anomaly_detection",
                    met=False,
                    value=None,
                    threshold=sensitivity,
                    operator="anomaly",
                    error_message="No current metric data"
                )
            
            # Detect anomalies
            anomalies = []
            for device_id, current_value in current_values.items():
                if device_id in baseline_data:
                    baseline_mean = baseline_data[device_id]["mean"]
                    baseline_std = baseline_data[device_id]["std"]
                    
                    if baseline_std > 0:
                        z_score = abs(current_value - baseline_mean) / baseline_std
                        if z_score > (2.0 * (1.0 - sensitivity)):  # Adjust threshold based on sensitivity
                            anomalies.append({
                                "device_id": device_id,
                                "value": current_value,
                                "baseline_mean": baseline_mean,
                                "z_score": z_score
                            })
            
            condition_met = len(anomalies) > 0
            
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="anomaly_detection",
                met=condition_met,
                value=anomalies,
                threshold=sensitivity,
                operator="anomaly"
            )
            
        except Exception as e:
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="anomaly_detection",
                met=False,
                value=None,
                threshold=condition.get("sensitivity"),
                operator="anomaly",
                error_message=str(e)
            )
    
    async def _evaluate_pattern_matching_condition(
        self, 
        rule: AlertRule, 
        condition: Dict[str, Any]
    ) -> ConditionEvaluationResult:
        """Evaluate pattern matching condition"""
        try:
            pattern = condition.get("pattern")
            field = condition.get("field", "message")
            
            if not pattern:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="pattern_matching",
                    met=False,
                    value=None,
                    threshold=pattern,
                    operator="regex",
                    error_message="Missing pattern"
                )
            
            # This is a simplified pattern matching implementation
            # In production, you might want to match against log messages, event data, etc.
            condition_met = False
            
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="pattern_matching",
                met=condition_met,
                value=None,
                threshold=pattern,
                operator="regex"
            )
            
        except Exception as e:
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="pattern_matching",
                met=False,
                value=None,
                threshold=condition.get("pattern"),
                operator="regex",
                error_message=str(e)
            )
    
    async def _evaluate_trend_analysis_condition(
        self, 
        rule: AlertRule, 
        condition: Dict[str, Any]
    ) -> ConditionEvaluationResult:
        """Evaluate trend analysis condition"""
        try:
            metric_name = condition.get("metric_name")
            trend_direction = condition.get("trend_direction", "increasing")
            time_window = condition.get("time_window", 3600)  # 1 hour
            
            if not metric_name:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="trend_analysis",
                    met=False,
                    value=None,
                    threshold=trend_direction,
                    operator="trend",
                    error_message="Missing metric name"
                )
            
            # Get metric data over time window
            trend_data = await self._get_metric_trend_data(
                rule.device_ids, 
                metric_name, 
                time_window
            )
            
            if not trend_data:
                return ConditionEvaluationResult(
                    condition_id=condition.get("id", "unknown"),
                    condition_type="trend_analysis",
                    met=False,
                    value=None,
                    threshold=trend_direction,
                    operator="trend",
                    error_message="Insufficient trend data"
                )
            
            # Analyze trend
            trend_met = False
            for device_id, data in trend_data.items():
                if len(data) >= 2:
                    values = [point["value"] for point in data]
                    if trend_direction == "increasing" and values[-1] > values[0]:
                        trend_met = True
                        break
                    elif trend_direction == "decreasing" and values[-1] < values[0]:
                        trend_met = True
                        break
            
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="trend_analysis",
                met=trend_met,
                value=trend_data,
                threshold=trend_direction,
                operator="trend"
            )
            
        except Exception as e:
            return ConditionEvaluationResult(
                condition_id=condition.get("id", "unknown"),
                condition_type="trend_analysis",
                met=False,
                value=None,
                threshold=condition.get("trend_direction"),
                operator="trend",
                error_message=str(e)
            )
    
    def _compare_values(self, value: float, operator: str, threshold: float) -> bool:
        """Compare values based on operator"""
        try:
            if operator == "gt":
                return value > threshold
            elif operator == "gte":
                return value >= threshold
            elif operator == "lt":
                return value < threshold
            elif operator == "lte":
                return value <= threshold
            elif operator == "equals":
                return value == threshold
            elif operator == "not_equals":
                return value != threshold
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
        except Exception:
            return False
    
    async def _execute_rule_actions(
        self, 
        rule: AlertRule, 
        conditions_result: List[Dict[str, Any]]
    ) -> int:
        """Execute actions for a triggered rule"""
        try:
            if not rule.actions or "actions" not in rule.actions:
                logger.warning(f"Rule {rule.id} has no actions")
                return 0
            
            actions = rule.actions["actions"]
            alerts_created = 0
            
            for action in actions:
                if not action.get("enabled", True):
                    continue
                
                action_type = action.get("type")
                
                if action_type == "create_alert":
                    alert_count = await self._execute_create_alert_action(rule, action, conditions_result)
                    alerts_created += alert_count
                elif action_type == "send_notification":
                    await self._execute_send_notification_action(rule, action, conditions_result)
                elif action_type == "webhook":
                    await self._execute_webhook_action(rule, action, conditions_result)
                else:
                    logger.warning(f"Unknown action type: {action_type}")
            
            return alerts_created
            
        except Exception as e:
            logger.error(f"Failed to execute rule actions: {str(e)}")
            return 0
    
    async def _execute_create_alert_action(
        self, 
        rule: AlertRule, 
        action: Dict[str, Any], 
        conditions_result: List[Dict[str, Any]]
    ) -> int:
        """Execute create alert action"""
        try:
            config = action.get("config", {})
            severity = AlertSeverity(config.get("severity", rule.default_severity))
            category = AlertCategory(config.get("category", "performance"))
            
            alerts_created = 0
            
            # Create alerts for each device
            for device_id in (rule.device_ids or []):
                # Check if similar alert already exists (deduplication)
                if await self._should_create_alert(rule, device_id, conditions_result):
                    alert = Alert(
                        title=rule.name,
                        message=f"Rule '{rule.name}' triggered",
                        severity=severity,
                        category=category,
                        source=AlertSource.METRIC_THRESHOLD,
                        device_id=device_id,
                        correlation_id=f"rule_{rule.id}",
                        context={
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "conditions": conditions_result,
                            "triggered_at": datetime.now().isoformat()
                        },
                        tags=["rule_triggered", f"rule_{rule.id}"]
                    )
                    
                    self.db_session.add(alert)
                    alerts_created += 1
            
            if alerts_created > 0:
                await self.db_session.commit()
                logger.info(f"Created {alerts_created} alerts for rule {rule.name}")
            
            return alerts_created
            
        except Exception as e:
            logger.error(f"Failed to execute create alert action: {str(e)}")
            await self.db_session.rollback()
            return 0
    
    async def _execute_send_notification_action(
        self, 
        rule: AlertRule, 
        action: Dict[str, Any], 
        conditions_result: List[Dict[str, Any]]
    ) -> None:
        """Execute send notification action"""
        try:
            config = action.get("config", {})
            channels = config.get("channels", rule.notification_channels or ["email"])
            recipients = config.get("recipients", [])
            
            if not recipients:
                logger.warning(f"No recipients specified for notification action in rule {rule.id}")
                return
            
            # Create notifications for each recipient and channel
            for recipient in recipients:
                for channel in channels:
                    notification = Notification.create_email_notification(
                        recipient=recipient,
                        subject=f"Alert: {rule.name}",
                        message=f"Rule '{rule.name}' has been triggered",
                        notification_type=NotificationType.ALERT,
                        priority=NotificationPriority.HIGH if rule.default_severity in ["critical", "high"] else NotificationPriority.NORMAL,
                        alert_id=None,
                        device_id=None
                    )
                    
                    self.db_session.add(notification)
            
            await self.db_session.commit()
            logger.info(f"Created notifications for rule {rule.name}")
            
        except Exception as e:
            logger.error(f"Failed to execute send notification action: {str(e)}")
            await self.db_session.rollback()
    
    async def _execute_webhook_action(
        self, 
        rule: AlertRule, 
        action: Dict[str, Any], 
        conditions_result: List[Dict[str, Any]]
    ) -> None:
        """Execute webhook action"""
        try:
            config = action.get("config", {})
            webhook_url = config.get("url")
            
            if not webhook_url:
                logger.warning(f"No webhook URL specified for webhook action in rule {rule.id}")
                return
            
            # Create webhook notification
            webhook_data = {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "triggered_at": datetime.now().isoformat(),
                "conditions": conditions_result,
                "device_ids": rule.device_ids
            }
            
            notification = Notification.create_webhook_notification(
                webhook_url=webhook_url,
                message=f"Rule '{rule.name}' triggered",
                payload=webhook_data,
                notification_type=NotificationType.ALERT,
                priority=NotificationPriority.HIGH
            )
            
            self.db_session.add(notification)
            await self.db_session.commit()
            logger.info(f"Created webhook notification for rule {rule.name}")
            
        except Exception as e:
            logger.error(f"Failed to execute webhook action: {str(e)}")
            await self.db_session.rollback()
    
    async def _should_create_alert(
        self, 
        rule: AlertRule, 
        device_id: int, 
        conditions_result: List[Dict[str, Any]]
    ) -> bool:
        """Check if alert should be created (deduplication logic)"""
        try:
            # Check for recent similar alerts
            since = datetime.now() - timedelta(seconds=rule.deduplication_window)
            
            result = await self.db_session.execute(
                select(Alert).where(
                    and_(
                        Alert.device_id == device_id,
                        Alert.correlation_id == f"rule_{rule.id}",
                        Alert.created_at >= since,
                        Alert.is_deleted == False
                    )
                )
            )
            
            existing_alerts = result.scalars().all()
            return len(existing_alerts) == 0
            
        except Exception as e:
            logger.error(f"Failed to check alert deduplication: {str(e)}")
            return True
    
    async def _get_current_metric_values(
        self, 
        device_ids: Optional[List[int]], 
        metric_name: str, 
        time_window: int
    ) -> Dict[int, float]:
        """Get current metric values for devices"""
        try:
            since = datetime.now() - timedelta(seconds=time_window)
            
            query = select(Metric).where(
                and_(
                    Metric.name == metric_name,
                    Metric.timestamp >= since,
                    Metric.is_deleted == False
                )
            )
            
            if device_ids:
                query = query.where(Metric.device_id.in_(device_ids))
            
            query = query.order_by(Metric.timestamp.desc())
            
            result = await self.db_session.execute(query)
            metrics = result.scalars().all()
            
            # Get latest value for each device
            current_values = {}
            for metric in metrics:
                if metric.device_id not in current_values:
                    current_values[metric.device_id] = metric.value
            
            return current_values
            
        except Exception as e:
            logger.error(f"Failed to get current metric values: {str(e)}")
            return {}
    
    async def _get_metric_baseline_data(
        self, 
        device_ids: Optional[List[int]], 
        metric_name: str, 
        hours: int
    ) -> Dict[int, Dict[str, float]]:
        """Get baseline data for anomaly detection"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            query = select(Metric).where(
                and_(
                    Metric.name == metric_name,
                    Metric.timestamp >= since,
                    Metric.is_deleted == False
                )
            )
            
            if device_ids:
                query = query.where(Metric.device_id.in_(device_ids))
            
            result = await self.db_session.execute(query)
            metrics = result.scalars().all()
            
            # Calculate baseline statistics per device
            baseline_data = defaultdict(list)
            for metric in metrics:
                baseline_data[metric.device_id].append(metric.value)
            
            # Calculate mean and std for each device
            baseline_stats = {}
            for device_id, values in baseline_data.items():
                if len(values) >= 3:  # Need at least 3 points for meaningful statistics
                    baseline_stats[device_id] = {
                        "mean": statistics.mean(values),
                        "std": statistics.stdev(values) if len(values) > 1 else 0
                    }
            
            return baseline_stats
            
        except Exception as e:
            logger.error(f"Failed to get metric baseline data: {str(e)}")
            return {}
    
    async def _get_metric_trend_data(
        self, 
        device_ids: Optional[List[int]], 
        metric_name: str, 
        time_window: int
    ) -> Dict[int, List[Dict[str, Any]]]:
        """Get metric data for trend analysis"""
        try:
            since = datetime.now() - timedelta(seconds=time_window)
            
            query = select(Metric).where(
                and_(
                    Metric.name == metric_name,
                    Metric.timestamp >= since,
                    Metric.is_deleted == False
                )
            )
            
            if device_ids:
                query = query.where(Metric.device_id.in_(device_ids))
            
            query = query.order_by(Metric.timestamp.asc())
            
            result = await self.db_session.execute(query)
            metrics = result.scalars().all()
            
            # Group by device and create time series
            trend_data = defaultdict(list)
            for metric in metrics:
                trend_data[metric.device_id].append({
                    "timestamp": metric.timestamp,
                    "value": metric.value
                })
            
            return dict(trend_data)
            
        except Exception as e:
            logger.error(f"Failed to get metric trend data: {str(e)}")
            return {}
    
    def update_config(self, config: RuleExecutionConfig):
        """Update rule execution configuration"""
        self.config = config
        logger.info(f"Updated rule execution config: {config}")
    
    async def get_rule_execution_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get rule execution statistics"""
        try:
            since = datetime.now() - timedelta(hours=hours)
            
            # Get rules executed in time range
            result = await self.db_session.execute(
                select(AlertRule).where(
                    and_(
                        AlertRule.last_execution >= since,
                        AlertRule.is_deleted == False
                    )
                )
            )
            
            rules = result.scalars().all()
            
            if not rules:
                return {
                    "total_rules": 0,
                    "execution_count": 0,
                    "alerts_created": 0,
                    "success_rate": 0.0,
                    "average_execution_time": 0.0
                }
            
            # Calculate statistics
            total_rules = len(rules)
            total_executions = sum(rule.execution_count for rule in rules)
            total_alerts = sum(rule.alert_count for rule in rules)
            
            success_rates = [rule.success_rate for rule in rules if rule.success_rate > 0]
            average_success_rate = sum(success_rates) / len(success_rates) if success_rates else 0
            
            execution_times = [rule.average_execution_time for rule in rules if rule.average_execution_time]
            average_execution_time = sum(execution_times) / len(execution_times) if execution_times else 0
            
            return {
                "total_rules": total_rules,
                "execution_count": total_executions,
                "alerts_created": total_alerts,
                "success_rate": round(average_success_rate, 3),
                "average_execution_time": round(average_execution_time, 2),
                "time_range_hours": hours
            }
            
        except Exception as e:
            logger.error(f"Failed to get rule execution stats: {str(e)}")
            return {
                "total_rules": 0,
                "execution_count": 0,
                "alerts_created": 0,
                "success_rate": 0.0,
                "average_execution_time": 0.0
            }
