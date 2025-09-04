"""
Security Orchestration Service for CHM Security & Compliance System

This service provides security orchestration and automated response capabilities including:
- Security orchestration workflows and playbooks
- Automated response and remediation
- Integration with security tools and systems
- Workflow execution and monitoring
- Custom automation scripts and actions
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import uuid
from collections import defaultdict, Counter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload

from ..models.security import SecurityIncident, SecurityAuditLog, ThreatLevel
from ..models.result_objects import CollectionResult, OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class SecurityPlaybook:
    """Security orchestration playbook"""
    playbook_id: str
    name: str
    description: str
    trigger_conditions: List[Dict[str, Any]]
    workflow_steps: List[Dict[str, Any]]
    execution_mode: str  # manual, automatic, semi_automatic
    is_active: bool
    created_at: datetime
    updated_at: datetime


@dataclass
class WorkflowExecution:
    """Workflow execution instance"""
    execution_id: str
    playbook_id: str
    trigger_event: Dict[str, Any]
    status: str  # running, completed, failed, paused
    started_at: datetime
    completed_at: Optional[datetime] = None
    current_step: int = 0
    execution_log: List[Dict[str, Any]] = None
    error_message: Optional[str] = None


@dataclass
class AutomationAction:
    """Automation action definition"""
    action_id: str
    name: str
    action_type: str  # script, api_call, webhook, notification
    parameters: Dict[str, Any]
    timeout_seconds: int = 300
    retry_count: int = 3
    is_active: bool = True


class SecurityOrchestrationService:
    """Service for security orchestration and automation"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._playbooks = {}
        self._automation_actions = {}
        self._workflow_executions = {}
        self._integration_connectors = {}
        self._load_default_playbooks()
        self._load_automation_actions()
        self._initialize_integration_connectors()
    
    async def execute_playbook(self, playbook_id: str, trigger_event: Dict[str, Any],
                             execution_mode: str = "automatic") -> CollectionResult:
        """Execute a security playbook"""
        try:
            # Get playbook
            playbook = self._playbooks.get(playbook_id)
            if not playbook:
                return CollectionResult(
                    success=False,
                    error=f"Playbook {playbook_id} not found"
                )
            
            if not playbook.is_active:
                return CollectionResult(
                    success=False,
                    error=f"Playbook {playbook_id} is not active"
                )
            
            # Check trigger conditions
            if not await self._check_trigger_conditions(playbook, trigger_event):
                return CollectionResult(
                    success=False,
                    error="Trigger conditions not met"
                )
            
            # Create workflow execution
            execution = WorkflowExecution(
                execution_id=f"EXEC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                playbook_id=playbook_id,
                trigger_event=trigger_event,
                status="running",
                started_at=datetime.now(),
                execution_log=[]
            )
            
            # Store execution
            self._workflow_executions[execution.execution_id] = execution
            
            # Execute workflow steps
            execution_result = await self._execute_workflow_steps(playbook, execution)
            
            # Update execution status
            execution.status = "completed" if execution_result["success"] else "failed"
            execution.completed_at = datetime.now()
            execution.error_message = execution_result.get("error_message")
            
            return CollectionResult(
                success=execution_result["success"],
                data={
                    "execution_id": execution.execution_id,
                    "execution": execution,
                    "result": execution_result
                },
                message=f"Executed playbook {playbook.name}"
            )
            
        except Exception as e:
            logger.error(f"Error executing playbook: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to execute playbook: {str(e)}"
            )
    
    async def create_playbook(self, playbook_data: Dict[str, Any], created_by: int) -> CollectionResult:
        """Create a new security playbook"""
        try:
            playbook_id = f"PB-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            
            # Validate playbook data
            validation_result = await self._validate_playbook_data(playbook_data)
            if not validation_result["valid"]:
                return CollectionResult(
                    success=False,
                    error=f"Invalid playbook data: {validation_result['errors']}"
                )
            
            # Create playbook
            playbook = SecurityPlaybook(
                playbook_id=playbook_id,
                name=playbook_data["name"],
                description=playbook_data.get("description", ""),
                trigger_conditions=playbook_data["trigger_conditions"],
                workflow_steps=playbook_data["workflow_steps"],
                execution_mode=playbook_data.get("execution_mode", "manual"),
                is_active=playbook_data.get("is_active", True),
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
            
            # Store playbook
            self._playbooks[playbook_id] = playbook
            
            # Log playbook creation
            await self._log_orchestration_event(
                event_type="playbook_created",
                playbook_id=playbook_id,
                user_id=created_by,
                event_data={"playbook_data": playbook_data}
            )
            
            return CollectionResult(
                success=True,
                data={"playbook_id": playbook_id, "playbook": playbook},
                message=f"Created playbook: {playbook.name}"
            )
            
        except Exception as e:
            logger.error(f"Error creating playbook: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to create playbook: {str(e)}"
            )
    
    async def execute_automation_action(self, action_id: str, parameters: Dict[str, Any],
                                      execution_context: Dict[str, Any]) -> CollectionResult:
        """Execute an automation action"""
        try:
            # Get automation action
            action = self._automation_actions.get(action_id)
            if not action:
                return CollectionResult(
                    success=False,
                    error=f"Automation action {action_id} not found"
                )
            
            if not action.is_active:
                return CollectionResult(
                    success=False,
                    error=f"Automation action {action_id} is not active"
                )
            
            # Execute action based on type
            execution_result = await self._execute_action_by_type(action, parameters, execution_context)
            
            # Log action execution
            await self._log_orchestration_event(
                event_type="action_executed",
                action_id=action_id,
                event_data={
                    "action_type": action.action_type,
                    "parameters": parameters,
                    "execution_result": execution_result
                }
            )
            
            return CollectionResult(
                success=execution_result["success"],
                data=execution_result,
                message=f"Executed automation action: {action.name}"
            )
            
        except Exception as e:
            logger.error(f"Error executing automation action: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to execute action: {str(e)}"
            )
    
    async def get_workflow_execution_status(self, execution_id: str) -> CollectionResult:
        """Get workflow execution status"""
        try:
            execution = self._workflow_executions.get(execution_id)
            if not execution:
                return CollectionResult(
                    success=False,
                    error=f"Workflow execution {execution_id} not found"
                )
            
            return CollectionResult(
                success=True,
                data=execution,
                message=f"Retrieved execution status for {execution_id}"
            )
            
        except Exception as e:
            logger.error(f"Error getting execution status: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get execution status: {str(e)}"
            )
    
    async def pause_workflow_execution(self, execution_id: str, paused_by: int) -> CollectionResult:
        """Pause workflow execution"""
        try:
            execution = self._workflow_executions.get(execution_id)
            if not execution:
                return CollectionResult(
                    success=False,
                    error=f"Workflow execution {execution_id} not found"
                )
            
            if execution.status != "running":
                return CollectionResult(
                    success=False,
                    error=f"Cannot pause execution in status: {execution.status}"
                )
            
            # Pause execution
            execution.status = "paused"
            
            # Log pause event
            await self._log_orchestration_event(
                event_type="execution_paused",
                execution_id=execution_id,
                user_id=paused_by,
                event_data={"paused_at": datetime.now().isoformat()}
            )
            
            return CollectionResult(
                success=True,
                message=f"Paused workflow execution {execution_id}"
            )
            
        except Exception as e:
            logger.error(f"Error pausing execution: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to pause execution: {str(e)}"
            )
    
    async def resume_workflow_execution(self, execution_id: str, resumed_by: int) -> CollectionResult:
        """Resume paused workflow execution"""
        try:
            execution = self._workflow_executions.get(execution_id)
            if not execution:
                return CollectionResult(
                    success=False,
                    error=f"Workflow execution {execution_id} not found"
                )
            
            if execution.status != "paused":
                return CollectionResult(
                    success=False,
                    error=f"Cannot resume execution in status: {execution.status}"
                )
            
            # Resume execution
            execution.status = "running"
            
            # Continue workflow execution
            playbook = self._playbooks.get(execution.playbook_id)
            if playbook:
                execution_result = await self._execute_workflow_steps(playbook, execution, resume_from=execution.current_step)
                execution.status = "completed" if execution_result["success"] else "failed"
                execution.completed_at = datetime.now()
            
            # Log resume event
            await self._log_orchestration_event(
                event_type="execution_resumed",
                execution_id=execution_id,
                user_id=resumed_by,
                event_data={"resumed_at": datetime.now().isoformat()}
            )
            
            return CollectionResult(
                success=True,
                message=f"Resumed workflow execution {execution_id}"
            )
            
        except Exception as e:
            logger.error(f"Error resuming execution: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to resume execution: {str(e)}"
            )
    
    async def get_orchestration_dashboard(self) -> CollectionResult:
        """Get security orchestration dashboard data"""
        try:
            dashboard_data = {
                "playbooks": {
                    "total": len(self._playbooks),
                    "active": len([p for p in self._playbooks.values() if p.is_active]),
                    "recent_executions": len([e for e in self._workflow_executions.values() 
                                            if e.started_at > datetime.now() - timedelta(hours=24)])
                },
                "automation_actions": {
                    "total": len(self._automation_actions),
                    "active": len([a for a in self._automation_actions.values() if a.is_active])
                },
                "workflow_executions": {
                    "total": len(self._workflow_executions),
                    "running": len([e for e in self._workflow_executions.values() if e.status == "running"]),
                    "completed": len([e for e in self._workflow_executions.values() if e.status == "completed"]),
                    "failed": len([e for e in self._workflow_executions.values() if e.status == "failed"])
                },
                "integration_connectors": {
                    "total": len(self._integration_connectors),
                    "active": len([c for c in self._integration_connectors.values() if c.get("is_active", True)])
                }
            }
            
            return CollectionResult(
                success=True,
                data=dashboard_data,
                message="Retrieved orchestration dashboard data"
            )
            
        except Exception as e:
            logger.error(f"Error getting orchestration dashboard: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get dashboard data: {str(e)}"
            )
    
    # Private helper methods
    
    def _load_default_playbooks(self):
        """Load default security playbooks"""
        self._playbooks = {
            "malware_containment": SecurityPlaybook(
                playbook_id="malware_containment",
                name="Malware Containment Playbook",
                description="Automated response to malware incidents",
                trigger_conditions=[
                    {"event_type": "threat_detection", "threat_type": "malware", "severity": "high"}
                ],
                workflow_steps=[
                    {"step": 1, "action": "isolate_system", "description": "Isolate affected system"},
                    {"step": 2, "action": "collect_evidence", "description": "Collect forensic evidence"},
                    {"step": 3, "action": "notify_team", "description": "Notify security team"},
                    {"step": 4, "action": "update_firewall", "description": "Update firewall rules"}
                ],
                execution_mode="automatic",
                is_active=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            "data_breach_response": SecurityPlaybook(
                playbook_id="data_breach_response",
                name="Data Breach Response Playbook",
                description="Automated response to data breach incidents",
                trigger_conditions=[
                    {"event_type": "threat_detection", "threat_type": "data_exfiltration", "severity": "critical"}
                ],
                workflow_steps=[
                    {"step": 1, "action": "contain_breach", "description": "Contain data breach"},
                    {"step": 2, "action": "assess_scope", "description": "Assess breach scope"},
                    {"step": 3, "action": "notify_legal", "description": "Notify legal team"},
                    {"step": 4, "action": "regulatory_notification", "description": "Prepare regulatory notifications"}
                ],
                execution_mode="semi_automatic",
                is_active=True,
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        }
    
    def _load_automation_actions(self):
        """Load automation actions"""
        self._automation_actions = {
            "isolate_system": AutomationAction(
                action_id="isolate_system",
                name="Isolate System",
                action_type="api_call",
                parameters={"endpoint": "/api/systems/{system_id}/isolate", "method": "POST"}
            ),
            "collect_evidence": AutomationAction(
                action_id="collect_evidence",
                action_type="script",
                name="Collect Forensic Evidence",
                parameters={"script_path": "/scripts/collect_evidence.sh", "timeout": 600}
            ),
            "notify_team": AutomationAction(
                action_id="notify_team",
                name="Notify Security Team",
                action_type="webhook",
                parameters={"webhook_url": "https://hooks.slack.com/security-team", "message_template": "incident_alert"}
            ),
            "update_firewall": AutomationAction(
                action_id="update_firewall",
                name="Update Firewall Rules",
                action_type="api_call",
                parameters={"endpoint": "/api/firewall/rules", "method": "PUT"}
            )
        }
    
    def _initialize_integration_connectors(self):
        """Initialize integration connectors"""
        self._integration_connectors = {
            "siem": {"type": "siem", "endpoint": "https://siem.company.com/api", "is_active": True},
            "firewall": {"type": "firewall", "endpoint": "https://firewall.company.com/api", "is_active": True},
            "slack": {"type": "notification", "endpoint": "https://hooks.slack.com", "is_active": True},
            "email": {"type": "notification", "endpoint": "smtp://mail.company.com", "is_active": True}
        }
    
    async def _check_trigger_conditions(self, playbook: SecurityPlaybook, trigger_event: Dict[str, Any]) -> bool:
        """Check if trigger conditions are met"""
        for condition in playbook.trigger_conditions:
            if not self._evaluate_condition(condition, trigger_event):
                return False
        return True
    
    def _evaluate_condition(self, condition: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Evaluate a single condition"""
        for key, expected_value in condition.items():
            if key not in event or event[key] != expected_value:
                return False
        return True
    
    async def _execute_workflow_steps(self, playbook: SecurityPlaybook, execution: WorkflowExecution,
                                    resume_from: int = 0) -> Dict[str, Any]:
        """Execute workflow steps"""
        try:
            execution_log = []
            
            for i, step in enumerate(playbook.workflow_steps[resume_from:], start=resume_from):
                execution.current_step = i
                
                # Execute step
                step_result = await self._execute_workflow_step(step, execution.trigger_event)
                
                # Log step execution
                log_entry = {
                    "step": i + 1,
                    "action": step["action"],
                    "description": step["description"],
                    "result": step_result,
                    "timestamp": datetime.now().isoformat()
                }
                execution_log.append(log_entry)
                execution.execution_log = execution_log
                
                # Check if step failed
                if not step_result["success"]:
                    return {
                        "success": False,
                        "error_message": f"Step {i + 1} failed: {step_result.get('error', 'Unknown error')}",
                        "execution_log": execution_log
                    }
                
                # Add delay between steps
                await asyncio.sleep(1)
            
            return {
                "success": True,
                "execution_log": execution_log,
                "total_steps": len(playbook.workflow_steps)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error_message": str(e),
                "execution_log": execution_log
            }
    
    async def _execute_workflow_step(self, step: Dict[str, Any], trigger_event: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single workflow step"""
        action_id = step["action"]
        action = self._automation_actions.get(action_id)
        
        if not action:
            return {
                "success": False,
                "error": f"Action {action_id} not found"
            }
        
        # Execute action
        result = await self._execute_action_by_type(action, {}, trigger_event)
        
        return {
            "success": result["success"],
            "action_id": action_id,
            "result": result
        }
    
    async def _execute_action_by_type(self, action: AutomationAction, parameters: Dict[str, Any],
                                    execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute action based on type"""
        try:
            if action.action_type == "api_call":
                return await self._execute_api_call_action(action, parameters, execution_context)
            elif action.action_type == "script":
                return await self._execute_script_action(action, parameters, execution_context)
            elif action.action_type == "webhook":
                return await self._execute_webhook_action(action, parameters, execution_context)
            elif action.action_type == "notification":
                return await self._execute_notification_action(action, parameters, execution_context)
            else:
                return {
                    "success": False,
                    "error": f"Unknown action type: {action.action_type}"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _execute_api_call_action(self, action: AutomationAction, parameters: Dict[str, Any],
                                     execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute API call action"""
        # Simulate API call
        await asyncio.sleep(1)
        
        return {
            "success": True,
            "action_type": "api_call",
            "endpoint": action.parameters.get("endpoint"),
            "method": action.parameters.get("method", "GET"),
            "response": {"status": "success", "message": "API call completed"}
        }
    
    async def _execute_script_action(self, action: AutomationAction, parameters: Dict[str, Any],
                                   execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute script action"""
        # Simulate script execution
        await asyncio.sleep(2)
        
        return {
            "success": True,
            "action_type": "script",
            "script_path": action.parameters.get("script_path"),
            "output": "Script executed successfully",
            "exit_code": 0
        }
    
    async def _execute_webhook_action(self, action: AutomationAction, parameters: Dict[str, Any],
                                    execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute webhook action"""
        # Simulate webhook call
        await asyncio.sleep(0.5)
        
        return {
            "success": True,
            "action_type": "webhook",
            "webhook_url": action.parameters.get("webhook_url"),
            "response": {"status": "sent", "message": "Webhook notification sent"}
        }
    
    async def _execute_notification_action(self, action: AutomationAction, parameters: Dict[str, Any],
                                         execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute notification action"""
        # Simulate notification
        await asyncio.sleep(0.5)
        
        return {
            "success": True,
            "action_type": "notification",
            "notification_type": "email",
            "recipients": ["security-team@company.com"],
            "message": "Security incident notification sent"
        }
    
    async def _validate_playbook_data(self, playbook_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate playbook data"""
        errors = []
        
        # Check required fields
        required_fields = ["name", "trigger_conditions", "workflow_steps"]
        for field in required_fields:
            if field not in playbook_data:
                errors.append(f"Missing required field: {field}")
        
        # Validate trigger conditions
        if "trigger_conditions" in playbook_data:
            if not isinstance(playbook_data["trigger_conditions"], list):
                errors.append("trigger_conditions must be a list")
        
        # Validate workflow steps
        if "workflow_steps" in playbook_data:
            if not isinstance(playbook_data["workflow_steps"], list):
                errors.append("workflow_steps must be a list")
            else:
                for i, step in enumerate(playbook_data["workflow_steps"]):
                    if not isinstance(step, dict):
                        errors.append(f"workflow_steps[{i}] must be a dictionary")
                    elif "action" not in step:
                        errors.append(f"workflow_steps[{i}] missing 'action' field")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def _log_orchestration_event(self, event_type: str, **kwargs):
        """Log orchestration event"""
        logger.info(f"Orchestration event: {event_type}")
        for key, value in kwargs.items():
            logger.info(f"{key}: {value}")
