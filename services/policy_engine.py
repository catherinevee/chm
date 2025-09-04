"""
Policy Engine Service for CHM Security & Compliance System

This service provides advanced policy evaluation and automation capabilities including:
- Rule-based policy evaluation and enforcement
- Automated policy compliance checking
- Policy violation detection and response
- Dynamic policy updates and versioning
- Policy performance monitoring and optimization
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import uuid
from collections import defaultdict, Counter
import re
import operator
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload

from ..models.security import SecurityPolicy, SecurityAuditLog, SecurityIncident
from ..models.result_objects import CollectionResult, OperationStatus

logger = logging.getLogger(__name__)


class PolicyOperator(str, Enum):
    """Policy evaluation operators"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    GREATER_EQUAL = "greater_equal"
    LESS_EQUAL = "less_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"
    BETWEEN = "between"
    IS_NULL = "is_null"
    IS_NOT_NULL = "is_not_null"


class PolicyAction(str, Enum):
    """Policy enforcement actions"""
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    LOG = "log"
    ALERT = "alert"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ESCALATE = "escalate"
    NOTIFY = "notify"
    AUTO_REMEDIATE = "auto_remediate"


class PolicySeverity(str, Enum):
    """Policy violation severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class PolicyRule:
    """Policy rule definition"""
    rule_id: str
    name: str
    description: str
    conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    priority: int
    enabled: bool
    tags: List[str]
    created_at: datetime
    updated_at: datetime


@dataclass
class PolicyEvaluationContext:
    """Context for policy evaluation"""
    user_id: Optional[int] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    action: Optional[str] = None
    timestamp: Optional[datetime] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class PolicyEvaluationResult:
    """Result of policy evaluation"""
    rule_id: str
    rule_name: str
    evaluation_result: bool
    matched_conditions: List[Dict[str, Any]]
    actions_taken: List[Dict[str, Any]]
    severity: PolicySeverity
    message: str
    execution_time_ms: float
    evaluated_at: datetime


@dataclass
class PolicyViolation:
    """Policy violation details"""
    violation_id: str
    rule_id: str
    rule_name: str
    severity: PolicySeverity
    description: str
    context: PolicyEvaluationContext
    detected_at: datetime
    actions_taken: List[Dict[str, Any]]
    resolved: bool
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[int] = None


class PolicyEngine:
    """Advanced policy evaluation and enforcement engine"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._policy_cache = {}
        self._rule_cache = {}
        self._evaluation_cache = {}
        self._operator_functions = self._initialize_operators()
        self._action_handlers = self._initialize_action_handlers()
        self.cache_ttl = 300  # 5 minutes
    
    async def evaluate_policies(self, context: PolicyEvaluationContext) -> List[PolicyEvaluationResult]:
        """Evaluate all applicable policies against the given context"""
        try:
            start_time = datetime.now()
            
            # Get applicable policies
            applicable_policies = await self._get_applicable_policies(context)
            
            evaluation_results = []
            
            for policy in applicable_policies:
                result = await self._evaluate_policy(policy, context)
                if result:
                    evaluation_results.append(result)
            
            # Sort by priority (higher priority first)
            evaluation_results.sort(key=lambda x: x.rule_id, reverse=True)
            
            # Execute actions for matched policies
            for result in evaluation_results:
                if result.evaluation_result:
                    await self._execute_policy_actions(result, context)
            
            total_time = (datetime.now() - start_time).total_seconds() * 1000
            logger.info(f"Policy evaluation completed in {total_time:.2f}ms, {len(evaluation_results)} policies evaluated")
            
            return evaluation_results
            
        except Exception as e:
            logger.error(f"Error evaluating policies: {str(e)}")
            return []
    
    async def create_policy_rule(self, rule_data: Dict[str, Any], created_by: int) -> CollectionResult:
        """Create a new policy rule"""
        try:
            # Validate rule data
            validation_result = await self._validate_policy_rule(rule_data)
            if not validation_result.success:
                return validation_result
            
            # Create policy rule
            rule = PolicyRule(
                rule_id=f"POL-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                conditions=rule_data["conditions"],
                actions=rule_data["actions"],
                priority=rule_data.get("priority", 100),
                enabled=rule_data.get("enabled", True),
                tags=rule_data.get("tags", []),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            # Store rule (in production, this would be saved to database)
            self._rule_cache[rule.rule_id] = rule
            
            # Log rule creation
            await self._log_policy_event(
                event_type="rule_created",
                rule_id=rule.rule_id,
                user_id=created_by,
                event_data={"rule_data": rule_data}
            )
            
            return CollectionResult(
                success=True,
                data={"rule_id": rule.rule_id, "rule": rule},
                message=f"Created policy rule: {rule.name}"
            )
            
        except Exception as e:
            logger.error(f"Error creating policy rule: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to create policy rule: {str(e)}"
            )
    
    async def update_policy_rule(self, rule_id: str, updates: Dict[str, Any], updated_by: int) -> CollectionResult:
        """Update an existing policy rule"""
        try:
            # Get existing rule
            rule = self._rule_cache.get(rule_id)
            if not rule:
                return CollectionResult(
                    success=False,
                    error=f"Policy rule {rule_id} not found"
                )
            
            # Validate updates
            validation_result = await self._validate_policy_rule(updates, is_update=True)
            if not validation_result.success:
                return validation_result
            
            # Update rule
            if "name" in updates:
                rule.name = updates["name"]
            if "description" in updates:
                rule.description = updates["description"]
            if "conditions" in updates:
                rule.conditions = updates["conditions"]
            if "actions" in updates:
                rule.actions = updates["actions"]
            if "priority" in updates:
                rule.priority = updates["priority"]
            if "enabled" in updates:
                rule.enabled = updates["enabled"]
            if "tags" in updates:
                rule.tags = updates["tags"]
            
            rule.updated_at = datetime.now()
            
            # Update cache
            self._rule_cache[rule_id] = rule
            
            # Log rule update
            await self._log_policy_event(
                event_type="rule_updated",
                rule_id=rule_id,
                user_id=updated_by,
                event_data={"updates": updates}
            )
            
            return CollectionResult(
                success=True,
                message=f"Updated policy rule: {rule.name}"
            )
            
        except Exception as e:
            logger.error(f"Error updating policy rule {rule_id}: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to update policy rule: {str(e)}"
            )
    
    async def delete_policy_rule(self, rule_id: str, deleted_by: int) -> CollectionResult:
        """Delete a policy rule"""
        try:
            # Get existing rule
            rule = self._rule_cache.get(rule_id)
            if not rule:
                return CollectionResult(
                    success=False,
                    error=f"Policy rule {rule_id} not found"
                )
            
            # Remove from cache
            del self._rule_cache[rule_id]
            
            # Log rule deletion
            await self._log_policy_event(
                event_type="rule_deleted",
                rule_id=rule_id,
                user_id=deleted_by,
                event_data={"rule_name": rule.name}
            )
            
            return CollectionResult(
                success=True,
                message=f"Deleted policy rule: {rule.name}"
            )
            
        except Exception as e:
            logger.error(f"Error deleting policy rule {rule_id}: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to delete policy rule: {str(e)}"
            )
    
    async def get_policy_violations(self, time_window_hours: int = 24) -> CollectionResult:
        """Get policy violations within time window"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=time_window_hours)
            
            # In production, this would query the database
            # For now, return mock violations
            violations = await self._get_mock_violations(start_time, end_time)
            
            return CollectionResult(
                success=True,
                data=violations,
                message=f"Retrieved {len(violations)} policy violations"
            )
            
        except Exception as e:
            logger.error(f"Error getting policy violations: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get policy violations: {str(e)}"
            )
    
    async def get_policy_performance_metrics(self, time_window_hours: int = 24) -> CollectionResult:
        """Get policy performance metrics"""
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=time_window_hours)
            
            # Calculate performance metrics
            metrics = {
                "total_evaluations": 0,
                "total_violations": 0,
                "average_evaluation_time_ms": 0.0,
                "most_triggered_rules": [],
                "violation_severity_distribution": {},
                "time_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                }
            }
            
            # In production, this would analyze actual evaluation data
            # For now, return mock metrics
            metrics.update({
                "total_evaluations": 1250,
                "total_violations": 45,
                "average_evaluation_time_ms": 12.5,
                "most_triggered_rules": [
                    {"rule_id": "POL-001", "trigger_count": 25},
                    {"rule_id": "POL-002", "trigger_count": 18},
                    {"rule_id": "POL-003", "trigger_count": 12}
                ],
                "violation_severity_distribution": {
                    "critical": 2,
                    "high": 8,
                    "medium": 20,
                    "low": 15
                }
            })
            
            return CollectionResult(
                success=True,
                data=metrics,
                message="Retrieved policy performance metrics"
            )
            
        except Exception as e:
            logger.error(f"Error getting policy performance metrics: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get performance metrics: {str(e)}"
            )
    
    async def test_policy_rule(self, rule_data: Dict[str, Any], test_context: PolicyEvaluationContext) -> CollectionResult:
        """Test a policy rule against test context"""
        try:
            # Create temporary rule for testing
            temp_rule = PolicyRule(
                rule_id="TEST-" + str(uuid.uuid4())[:8],
                name=rule_data["name"],
                description=rule_data.get("description", ""),
                conditions=rule_data["conditions"],
                actions=rule_data["actions"],
                priority=rule_data.get("priority", 100),
                enabled=True,
                tags=rule_data.get("tags", []),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            # Evaluate rule
            result = await self._evaluate_policy(temp_rule, test_context)
            
            return CollectionResult(
                success=True,
                data={
                    "rule_id": temp_rule.rule_id,
                    "evaluation_result": result,
                    "test_context": test_context
                },
                message="Policy rule test completed"
            )
            
        except Exception as e:
            logger.error(f"Error testing policy rule: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to test policy rule: {str(e)}"
            )
    
    # Private helper methods
    
    def _initialize_operators(self) -> Dict[str, callable]:
        """Initialize operator functions for policy evaluation"""
        return {
            PolicyOperator.EQUALS: operator.eq,
            PolicyOperator.NOT_EQUALS: operator.ne,
            PolicyOperator.GREATER_THAN: operator.gt,
            PolicyOperator.LESS_THAN: operator.lt,
            PolicyOperator.GREATER_EQUAL: operator.ge,
            PolicyOperator.LESS_EQUAL: operator.le,
            PolicyOperator.CONTAINS: lambda a, b: b in a if isinstance(a, (str, list, dict)) else False,
            PolicyOperator.NOT_CONTAINS: lambda a, b: b not in a if isinstance(a, (str, list, dict)) else True,
            PolicyOperator.REGEX: lambda a, b: bool(re.search(b, str(a))),
            PolicyOperator.IN: lambda a, b: a in b if isinstance(b, (list, tuple, set)) else False,
            PolicyOperator.NOT_IN: lambda a, b: a not in b if isinstance(b, (list, tuple, set)) else True,
            PolicyOperator.EXISTS: lambda a, b: a is not None,
            PolicyOperator.NOT_EXISTS: lambda a, b: a is None,
            PolicyOperator.BETWEEN: lambda a, b: b[0] <= a <= b[1] if isinstance(b, (list, tuple)) and len(b) == 2 else False,
            PolicyOperator.IS_NULL: lambda a, b: a is None,
            PolicyOperator.IS_NOT_NULL: lambda a, b: a is not None
        }
    
    def _initialize_action_handlers(self) -> Dict[str, callable]:
        """Initialize action handlers for policy enforcement"""
        return {
            PolicyAction.ALLOW: self._handle_allow_action,
            PolicyAction.DENY: self._handle_deny_action,
            PolicyAction.WARN: self._handle_warn_action,
            PolicyAction.LOG: self._handle_log_action,
            PolicyAction.ALERT: self._handle_alert_action,
            PolicyAction.BLOCK: self._handle_block_action,
            PolicyAction.QUARANTINE: self._handle_quarantine_action,
            PolicyAction.ESCALATE: self._handle_escalate_action,
            PolicyAction.NOTIFY: self._handle_notify_action,
            PolicyAction.AUTO_REMEDIATE: self._handle_auto_remediate_action
        }
    
    async def _get_applicable_policies(self, context: PolicyEvaluationContext) -> List[PolicyRule]:
        """Get policies applicable to the given context"""
        applicable_rules = []
        
        for rule in self._rule_cache.values():
            if not rule.enabled:
                continue
            
            # Check if rule applies to context
            if await self._rule_applies_to_context(rule, context):
                applicable_rules.append(rule)
        
        # Sort by priority (higher priority first)
        applicable_rules.sort(key=lambda x: x.priority, reverse=True)
        
        return applicable_rules
    
    async def _rule_applies_to_context(self, rule: PolicyRule, context: PolicyEvaluationContext) -> bool:
        """Check if rule applies to the given context"""
        # Simple context matching - in production, this would be more sophisticated
        for condition in rule.conditions:
            if condition.get("type") == "context_filter":
                field = condition.get("field")
                value = condition.get("value")
                
                if field == "resource_type" and context.resource_type != value:
                    return False
                elif field == "action" and context.action != value:
                    return False
                elif field == "user_id" and context.user_id != value:
                    return False
        
        return True
    
    async def _evaluate_policy(self, rule: PolicyRule, context: PolicyEvaluationContext) -> Optional[PolicyEvaluationResult]:
        """Evaluate a single policy rule against context"""
        try:
            start_time = datetime.now()
            
            # Evaluate conditions
            matched_conditions = []
            all_conditions_met = True
            
            for condition in rule.conditions:
                if condition.get("type") == "context_filter":
                    continue  # Skip context filters
                
                condition_result = await self._evaluate_condition(condition, context)
                if condition_result:
                    matched_conditions.append(condition)
                else:
                    all_conditions_met = False
                    break  # Short-circuit evaluation
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            if all_conditions_met:
                return PolicyEvaluationResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    evaluation_result=True,
                    matched_conditions=matched_conditions,
                    actions_taken=rule.actions,
                    severity=PolicySeverity.MEDIUM,  # Default severity
                    message=f"Policy rule '{rule.name}' matched",
                    execution_time_ms=execution_time,
                    evaluated_at=datetime.now()
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Error evaluating policy rule {rule.rule_id}: {str(e)}")
            return None
    
    async def _evaluate_condition(self, condition: Dict[str, Any], context: PolicyEvaluationContext) -> bool:
        """Evaluate a single condition against context"""
        try:
            condition_type = condition.get("type")
            
            if condition_type == "field_comparison":
                return await self._evaluate_field_comparison(condition, context)
            elif condition_type == "time_based":
                return await self._evaluate_time_based_condition(condition, context)
            elif condition_type == "ip_based":
                return await self._evaluate_ip_based_condition(condition, context)
            elif condition_type == "user_based":
                return await self._evaluate_user_based_condition(condition, context)
            elif condition_type == "resource_based":
                return await self._evaluate_resource_based_condition(condition, context)
            else:
                logger.warning(f"Unknown condition type: {condition_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error evaluating condition: {str(e)}")
            return False
    
    async def _evaluate_field_comparison(self, condition: Dict[str, Any], context: PolicyEvaluationContext) -> bool:
        """Evaluate field comparison condition"""
        field_path = condition.get("field")
        operator_name = condition.get("operator")
        expected_value = condition.get("value")
        
        # Get actual value from context
        actual_value = self._get_field_value(context, field_path)
        
        # Get operator function
        operator_func = self._operator_functions.get(operator_name)
        if not operator_func:
            logger.warning(f"Unknown operator: {operator_name}")
            return False
        
        try:
            return operator_func(actual_value, expected_value)
        except Exception as e:
            logger.error(f"Error applying operator {operator_name}: {str(e)}")
            return False
    
    async def _evaluate_time_based_condition(self, condition: Dict[str, Any], context: PolicyEvaluationContext) -> bool:
        """Evaluate time-based condition"""
        time_restriction = condition.get("time_restriction", {})
        allowed_hours = time_restriction.get("allowed_hours", [])
        allowed_days = time_restriction.get("allowed_days", [])
        
        current_time = context.timestamp or datetime.now()
        current_hour = current_time.hour
        current_day = current_time.weekday()  # 0 = Monday, 6 = Sunday
        
        if allowed_hours and current_hour not in allowed_hours:
            return False
        
        if allowed_days and current_day not in allowed_days:
            return False
        
        return True
    
    async def _evaluate_ip_based_condition(self, condition: Dict[str, Any], context: PolicyEvaluationContext) -> bool:
        """Evaluate IP-based condition"""
        ip_restriction = condition.get("ip_restriction", {})
        allowed_ips = ip_restriction.get("allowed_ips", [])
        blocked_ips = ip_restriction.get("blocked_ips", [])
        
        if not context.ip_address:
            return True  # No IP to check
        
        # Check blocked IPs first
        if blocked_ips and context.ip_address in blocked_ips:
            return False
        
        # Check allowed IPs
        if allowed_ips and context.ip_address not in allowed_ips:
            return False
        
        return True
    
    async def _evaluate_user_based_condition(self, condition: Dict[str, Any], context: PolicyEvaluationContext) -> bool:
        """Evaluate user-based condition"""
        user_restriction = condition.get("user_restriction", {})
        allowed_users = user_restriction.get("allowed_users", [])
        blocked_users = user_restriction.get("blocked_users", [])
        allowed_roles = user_restriction.get("allowed_roles", [])
        
        if not context.user_id:
            return True  # No user to check
        
        # Check blocked users
        if blocked_users and context.user_id in blocked_users:
            return False
        
        # Check allowed users
        if allowed_users and context.user_id not in allowed_users:
            return False
        
        # Check allowed roles (would need to query user roles)
        if allowed_roles:
            # In production, this would query user roles from database
            pass
        
        return True
    
    async def _evaluate_resource_based_condition(self, condition: Dict[str, Any], context: PolicyEvaluationContext) -> bool:
        """Evaluate resource-based condition"""
        resource_restriction = condition.get("resource_restriction", {})
        allowed_resources = resource_restriction.get("allowed_resources", [])
        blocked_resources = resource_restriction.get("blocked_resources", [])
        
        if not context.resource_type:
            return True  # No resource to check
        
        # Check blocked resources
        if blocked_resources and context.resource_type in blocked_resources:
            return False
        
        # Check allowed resources
        if allowed_resources and context.resource_type not in allowed_resources:
            return False
        
        return True
    
    def _get_field_value(self, context: PolicyEvaluationContext, field_path: str) -> Any:
        """Get field value from context using dot notation"""
        try:
            value = context
            for field in field_path.split('.'):
                if hasattr(value, field):
                    value = getattr(value, field)
                elif isinstance(value, dict) and field in value:
                    value = value[field]
                else:
                    return None
            return value
        except Exception:
            return None
    
    async def _execute_policy_actions(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext):
        """Execute actions for a matched policy"""
        try:
            for action in result.actions_taken:
                action_type = action.get("type")
                action_params = action.get("params", {})
                
                handler = self._action_handlers.get(action_type)
                if handler:
                    await handler(result, context, action_params)
                else:
                    logger.warning(f"Unknown action type: {action_type}")
                    
        except Exception as e:
            logger.error(f"Error executing policy actions: {str(e)}")
    
    # Action handlers
    
    async def _handle_allow_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle allow action"""
        logger.info(f"Policy ALLOW: {result.rule_name}")
    
    async def _handle_deny_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle deny action"""
        logger.warning(f"Policy DENY: {result.rule_name}")
        await self._create_policy_violation(result, context, PolicySeverity.HIGH)
    
    async def _handle_warn_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle warn action"""
        logger.warning(f"Policy WARN: {result.rule_name}")
        await self._create_policy_violation(result, context, PolicySeverity.MEDIUM)
    
    async def _handle_log_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle log action"""
        logger.info(f"Policy LOG: {result.rule_name}")
        await self._log_policy_event(
            event_type="policy_log",
            rule_id=result.rule_id,
            user_id=context.user_id,
            event_data={"context": context.__dict__, "result": result.__dict__}
        )
    
    async def _handle_alert_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle alert action"""
        logger.warning(f"Policy ALERT: {result.rule_name}")
        await self._create_policy_violation(result, context, PolicySeverity.HIGH)
    
    async def _handle_block_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle block action"""
        logger.error(f"Policy BLOCK: {result.rule_name}")
        await self._create_policy_violation(result, context, PolicySeverity.CRITICAL)
    
    async def _handle_quarantine_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle quarantine action"""
        logger.error(f"Policy QUARANTINE: {result.rule_name}")
        await self._create_policy_violation(result, context, PolicySeverity.CRITICAL)
    
    async def _handle_escalate_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle escalate action"""
        logger.error(f"Policy ESCALATE: {result.rule_name}")
        await self._create_policy_violation(result, context, PolicySeverity.HIGH)
    
    async def _handle_notify_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle notify action"""
        logger.info(f"Policy NOTIFY: {result.rule_name}")
        # In production, this would send notifications
    
    async def _handle_auto_remediate_action(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, params: Dict[str, Any]):
        """Handle auto-remediate action"""
        logger.info(f"Policy AUTO_REMEDIATE: {result.rule_name}")
        # In production, this would trigger automated remediation
    
    async def _create_policy_violation(self, result: PolicyEvaluationResult, context: PolicyEvaluationContext, severity: PolicySeverity):
        """Create policy violation record"""
        violation = PolicyViolation(
            violation_id=f"VIOL-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            severity=severity,
            description=f"Policy violation: {result.rule_name}",
            context=context,
            detected_at=datetime.now(),
            actions_taken=result.actions_taken,
            resolved=False
        )
        
        # In production, this would be saved to database
        logger.info(f"Created policy violation: {violation.violation_id}")
    
    async def _validate_policy_rule(self, rule_data: Dict[str, Any], is_update: bool = False) -> CollectionResult:
        """Validate policy rule data"""
        try:
            required_fields = ["name", "conditions", "actions"]
            
            for field in required_fields:
                if field not in rule_data:
                    return CollectionResult(
                        success=False,
                        error=f"Missing required field: {field}"
                    )
            
            # Validate conditions
            if not isinstance(rule_data["conditions"], list):
                return CollectionResult(
                    success=False,
                    error="Conditions must be a list"
                )
            
            for condition in rule_data["conditions"]:
                if not isinstance(condition, dict):
                    return CollectionResult(
                        success=False,
                        error="Each condition must be a dictionary"
                    )
                
                if "type" not in condition:
                    return CollectionResult(
                        success=False,
                        error="Each condition must have a type"
                    )
            
            # Validate actions
            if not isinstance(rule_data["actions"], list):
                return CollectionResult(
                    success=False,
                    error="Actions must be a list"
                )
            
            for action in rule_data["actions"]:
                if not isinstance(action, dict):
                    return CollectionResult(
                        success=False,
                        error="Each action must be a dictionary"
                    )
                
                if "type" not in action:
                    return CollectionResult(
                        success=False,
                        error="Each action must have a type"
                    )
            
            return CollectionResult(success=True, message="Policy rule validation passed")
            
        except Exception as e:
            return CollectionResult(
                success=False,
                error=f"Policy rule validation failed: {str(e)}"
            )
    
    async def _get_mock_violations(self, start_time: datetime, end_time: datetime) -> List[PolicyViolation]:
        """Get mock policy violations for testing"""
        violations = []
        
        # Create some mock violations
        for i in range(5):
            violation = PolicyViolation(
                violation_id=f"VIOL-{datetime.now().strftime('%Y%m%d')}-{i:03d}",
                rule_id=f"POL-{i+1:03d}",
                rule_name=f"Test Policy Rule {i+1}",
                severity=PolicySeverity.MEDIUM,
                description=f"Mock policy violation {i+1}",
                context=PolicyEvaluationContext(
                    user_id=1,
                    resource_type="device",
                    action="read"
                ),
                detected_at=start_time + timedelta(hours=i),
                actions_taken=[{"type": "log", "params": {}}],
                resolved=False
            )
            violations.append(violation)
        
        return violations
    
    async def _log_policy_event(self, event_type: str, rule_id: str, user_id: Optional[int] = None,
                               event_data: Optional[Dict[str, Any]] = None):
        """Log policy-related event"""
        logger.info(f"Policy event: {event_type} for rule {rule_id}")
        if user_id:
            logger.info(f"User: {user_id}")
        if event_data:
            logger.info(f"Event data: {event_data}")
