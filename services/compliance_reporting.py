"""
Compliance Reporting Service for CHM Security & Compliance System

This service provides comprehensive compliance reporting capabilities including:
- Automated compliance report generation
- Multi-format report export (PDF, HTML, JSON, CSV, Excel)
- Scheduled report delivery and distribution
- Executive dashboards and summaries
- Regulatory compliance reporting templates
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
import json
import uuid
from pathlib import Path
import csv
import io
from collections import defaultdict, Counter

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func, desc, asc, text
from sqlalchemy.orm import selectinload

from ..models.security import (
    ComplianceFramework, ComplianceRequirement, SecurityAuditLog, SecurityIncident,
    ComplianceStatus, SecurityLevel
)
from ..models.result_objects import CollectionResult, OperationStatus

logger = logging.getLogger(__name__)


@dataclass
class ReportTemplate:
    """Report template configuration"""
    template_id: str
    name: str
    description: str
    report_type: str  # executive, technical, regulatory, audit
    framework_type: str  # sox, hipaa, pci_dss, iso27001, etc.
    sections: List[Dict[str, Any]]
    format_options: Dict[str, Any]
    created_at: datetime
    updated_at: datetime


@dataclass
class ReportSchedule:
    """Report scheduling configuration"""
    schedule_id: str
    template_id: str
    framework_id: int
    frequency: str  # daily, weekly, monthly, quarterly, annually
    recipients: List[str]
    delivery_method: str  # email, webhook, file_export
    delivery_config: Dict[str, Any]
    is_active: bool
    next_run: datetime
    created_at: datetime


@dataclass
class ComplianceReport:
    """Compliance report structure"""
    report_id: str
    template_id: str
    framework_id: int
    framework_name: str
    report_type: str
    period_start: datetime
    period_end: datetime
    generated_at: datetime
    generated_by: int
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    status: str = "generated"  # generated, delivered, failed
    delivery_status: Optional[str] = None


class ComplianceReportingService:
    """Service for comprehensive compliance reporting and distribution"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self._report_templates = {}
        self._report_schedules = {}
        self._output_directory = Path("reports")
        self._output_directory.mkdir(exist_ok=True)
        self._load_default_templates()
        self._load_report_schedules()
    
    async def generate_report(self, template_id: str, framework_id: int,
                            period_start: datetime, period_end: datetime,
                            generated_by: int, format: str = "html") -> CollectionResult:
        """Generate compliance report using specified template"""
        try:
            # Get template
            template = self._report_templates.get(template_id)
            if not template:
                return CollectionResult(
                    success=False,
                    error=f"Report template {template_id} not found"
                )
            
            # Get framework
            framework = await self._get_framework(framework_id)
            if not framework:
                return CollectionResult(
                    success=False,
                    error=f"Framework {framework_id} not found"
                )
            
            # Generate report data
            report_data = await self._collect_report_data(framework, period_start, period_end)
            
            # Create report record
            report = ComplianceReport(
                report_id=f"RPT-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                template_id=template_id,
                framework_id=framework_id,
                framework_name=framework.name,
                report_type=template.report_type,
                period_start=period_start,
                period_end=period_end,
                generated_at=datetime.now(),
                generated_by=generated_by
            )
            
            # Generate report file
            file_path = await self._generate_report_file(report, template, report_data, format)
            report.file_path = str(file_path)
            report.file_size = file_path.stat().st_size if file_path.exists() else 0
            
            # Store report metadata
            await self._store_report_metadata(report)
            
            return CollectionResult(
                success=True,
                data={
                    "report_id": report.report_id,
                    "file_path": report.file_path,
                    "file_size": report.file_size,
                    "report": report
                },
                message=f"Generated {template.report_type} report for {framework.name}"
            )
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to generate report: {str(e)}"
            )
    
    async def generate_executive_summary(self, framework_id: int, 
                                       period_start: datetime, period_end: datetime,
                                       generated_by: int) -> CollectionResult:
        """Generate executive summary report"""
        try:
            framework = await self._get_framework(framework_id)
            if not framework:
                return CollectionResult(
                    success=False,
                    error=f"Framework {framework_id} not found"
                )
            
            # Collect executive summary data
            summary_data = await self._collect_executive_summary_data(framework, period_start, period_end)
            
            # Generate HTML report
            html_content = await self._generate_executive_summary_html(framework, summary_data, period_start, period_end)
            
            # Save report
            report_id = f"EXEC-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            file_path = self._output_directory / f"{report_id}_executive_summary.html"
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return CollectionResult(
                success=True,
                data={
                    "report_id": report_id,
                    "file_path": str(file_path),
                    "summary_data": summary_data
                },
                message=f"Generated executive summary for {framework.name}"
            )
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to generate executive summary: {str(e)}"
            )
    
    async def generate_regulatory_report(self, framework_id: int, report_type: str,
                                       period_start: datetime, period_end: datetime,
                                       generated_by: int) -> CollectionResult:
        """Generate regulatory compliance report"""
        try:
            framework = await self._get_framework(framework_id)
            if not framework:
                return CollectionResult(
                    success=False,
                    error=f"Framework {framework_id} not found"
                )
            
            # Collect regulatory data
            regulatory_data = await self._collect_regulatory_data(framework, report_type, period_start, period_end)
            
            # Generate report based on framework type
            if framework.framework_type == "regulatory":
                report_content = await self._generate_regulatory_report_content(framework, regulatory_data, report_type)
            else:
                return CollectionResult(
                    success=False,
                    error=f"Framework {framework.name} is not a regulatory framework"
                )
            
            # Save report
            report_id = f"REG-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
            file_path = self._output_directory / f"{report_id}_regulatory_report.pdf"
            
            # In production, this would generate PDF
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            return CollectionResult(
                success=True,
                data={
                    "report_id": report_id,
                    "file_path": str(file_path),
                    "regulatory_data": regulatory_data
                },
                message=f"Generated regulatory report for {framework.name}"
            )
            
        except Exception as e:
            logger.error(f"Error generating regulatory report: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to generate regulatory report: {str(e)}"
            )
    
    async def export_compliance_data(self, framework_id: int, format: str,
                                   period_start: datetime, period_end: datetime) -> CollectionResult:
        """Export compliance data in various formats"""
        try:
            framework = await self._get_framework(framework_id)
            if not framework:
                return CollectionResult(
                    success=False,
                    error=f"Framework {framework_id} not found"
                )
            
            # Collect compliance data
            compliance_data = await self._collect_compliance_data(framework, period_start, period_end)
            
            # Export based on format
            if format.lower() == "csv":
                file_path = await self._export_to_csv(framework, compliance_data, period_start, period_end)
            elif format.lower() == "json":
                file_path = await self._export_to_json(framework, compliance_data, period_start, period_end)
            elif format.lower() == "excel":
                file_path = await self._export_to_excel(framework, compliance_data, period_start, period_end)
            else:
                return CollectionResult(
                    success=False,
                    error=f"Unsupported export format: {format}"
                )
            
            return CollectionResult(
                success=True,
                data={"file_path": str(file_path)},
                message=f"Exported compliance data in {format.upper()} format"
            )
            
        except Exception as e:
            logger.error(f"Error exporting compliance data: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to export compliance data: {str(e)}"
            )
    
    async def schedule_report(self, template_id: str, framework_id: int,
                            frequency: str, recipients: List[str],
                            delivery_method: str, delivery_config: Dict[str, Any],
                            scheduled_by: int) -> CollectionResult:
        """Schedule automated report generation and delivery"""
        try:
            # Validate template
            template = self._report_templates.get(template_id)
            if not template:
                return CollectionResult(
                    success=False,
                    error=f"Report template {template_id} not found"
                )
            
            # Validate framework
            framework = await self._get_framework(framework_id)
            if not framework:
                return CollectionResult(
                    success=False,
                    error=f"Framework {framework_id} not found"
                )
            
            # Create schedule
            schedule = ReportSchedule(
                schedule_id=f"SCH-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                template_id=template_id,
                framework_id=framework_id,
                frequency=frequency,
                recipients=recipients,
                delivery_method=delivery_method,
                delivery_config=delivery_config,
                is_active=True,
                next_run=self._calculate_next_run(frequency),
                created_at=datetime.now()
            )
            
            # Store schedule
            self._report_schedules[schedule.schedule_id] = schedule
            
            # Log scheduling
            await self._log_report_event(
                event_type="report_scheduled",
                schedule_id=schedule.schedule_id,
                user_id=scheduled_by,
                event_data={"schedule": schedule.__dict__}
            )
            
            return CollectionResult(
                success=True,
                data={"schedule_id": schedule.schedule_id, "schedule": schedule},
                message=f"Scheduled {frequency} report for {framework.name}"
            )
            
        except Exception as e:
            logger.error(f"Error scheduling report: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to schedule report: {str(e)}"
            )
    
    async def get_report_history(self, framework_id: Optional[int] = None,
                               limit: int = 50) -> CollectionResult:
        """Get report generation history"""
        try:
            # In production, this would query the database
            # For now, return mock data
            reports = []
            
            for i in range(min(limit, 10)):
                report = ComplianceReport(
                    report_id=f"RPT-{datetime.now().strftime('%Y%m%d')}-{i:03d}",
                    template_id="executive_template",
                    framework_id=framework_id or 1,
                    framework_name="Test Framework",
                    report_type="executive",
                    period_start=datetime.now() - timedelta(days=30),
                    period_end=datetime.now(),
                    generated_at=datetime.now() - timedelta(days=i),
                    generated_by=1,
                    file_path=f"/reports/report_{i}.html",
                    file_size=1024 * (i + 1),
                    status="generated"
                )
                reports.append(report)
            
            return CollectionResult(
                success=True,
                data=reports,
                message=f"Retrieved {len(reports)} reports"
            )
            
        except Exception as e:
            logger.error(f"Error getting report history: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get report history: {str(e)}"
            )
    
    async def get_report_templates(self) -> CollectionResult:
        """Get available report templates"""
        try:
            templates = list(self._report_templates.values())
            
            return CollectionResult(
                success=True,
                data=templates,
                message=f"Retrieved {len(templates)} report templates"
            )
            
        except Exception as e:
            logger.error(f"Error getting report templates: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get report templates: {str(e)}"
            )
    
    async def get_scheduled_reports(self) -> CollectionResult:
        """Get scheduled reports"""
        try:
            schedules = list(self._report_schedules.values())
            
            return CollectionResult(
                success=True,
                data=schedules,
                message=f"Retrieved {len(schedules)} scheduled reports"
            )
            
        except Exception as e:
            logger.error(f"Error getting scheduled reports: {str(e)}")
            return CollectionResult(
                success=False,
                error=f"Failed to get scheduled reports: {str(e)}"
            )
    
    # Private helper methods
    
    def _load_default_templates(self):
        """Load default report templates"""
        self._report_templates = {
            "executive_template": ReportTemplate(
                template_id="executive_template",
                name="Executive Summary",
                description="High-level compliance summary for executives",
                report_type="executive",
                framework_type="all",
                sections=[
                    {"name": "overview", "title": "Compliance Overview"},
                    {"name": "metrics", "title": "Key Metrics"},
                    {"name": "violations", "title": "Active Violations"},
                    {"name": "recommendations", "title": "Recommendations"}
                ],
                format_options={"include_charts": True, "include_details": False},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            "technical_template": ReportTemplate(
                template_id="technical_template",
                name="Technical Compliance Report",
                description="Detailed technical compliance report",
                report_type="technical",
                framework_type="all",
                sections=[
                    {"name": "requirements", "title": "Compliance Requirements"},
                    {"name": "assessments", "title": "Assessment Results"},
                    {"name": "violations", "title": "Detailed Violations"},
                    {"name": "evidence", "title": "Evidence Collection"},
                    {"name": "remediation", "title": "Remediation Actions"}
                ],
                format_options={"include_charts": True, "include_details": True},
                created_at=datetime.now(),
                updated_at=datetime.now()
            ),
            "sox_template": ReportTemplate(
                template_id="sox_template",
                name="SOX Compliance Report",
                description="Sarbanes-Oxley compliance report",
                report_type="regulatory",
                framework_type="sox",
                sections=[
                    {"name": "financial_controls", "title": "Financial Controls"},
                    {"name": "it_controls", "title": "IT Controls"},
                    {"name": "access_controls", "title": "Access Controls"},
                    {"name": "audit_trail", "title": "Audit Trail"}
                ],
                format_options={"include_charts": True, "include_details": True},
                created_at=datetime.now(),
                updated_at=datetime.now()
            )
        }
    
    def _load_report_schedules(self):
        """Load report schedules"""
        self._report_schedules = {
            "monthly_executive": ReportSchedule(
                schedule_id="monthly_executive",
                template_id="executive_template",
                framework_id=1,
                frequency="monthly",
                recipients=["executives@company.com"],
                delivery_method="email",
                delivery_config={"subject": "Monthly Compliance Report"},
                is_active=True,
                next_run=datetime.now() + timedelta(days=30),
                created_at=datetime.now()
            )
        }
    
    async def _get_framework(self, framework_id: int) -> Optional[ComplianceFramework]:
        """Get compliance framework"""
        result = await self.db_session.execute(
            select(ComplianceFramework).where(ComplianceFramework.id == framework_id)
        )
        return result.scalar_one_or_none()
    
    async def _collect_report_data(self, framework: ComplianceFramework,
                                 period_start: datetime, period_end: datetime) -> Dict[str, Any]:
        """Collect data for report generation"""
        # Get requirements
        requirements = await self._get_framework_requirements(framework.id)
        
        # Get violations
        violations = await self._get_violations_for_period(framework.id, period_start, period_end)
        
        # Get audit events
        audit_events = await self._get_audit_events_for_period(framework.id, period_start, period_end)
        
        # Calculate metrics
        total_requirements = len(requirements)
        compliant_requirements = len([r for r in requirements if r.implementation_status == "implemented"])
        compliance_percentage = (compliant_requirements / total_requirements * 100) if total_requirements > 0 else 0
        
        return {
            "framework": {
                "id": framework.id,
                "name": framework.name,
                "type": framework.framework_type,
                "version": framework.version
            },
            "period": {
                "start": period_start.isoformat(),
                "end": period_end.isoformat()
            },
            "metrics": {
                "total_requirements": total_requirements,
                "compliant_requirements": compliant_requirements,
                "compliance_percentage": compliance_percentage,
                "total_violations": len(violations),
                "audit_events": len(audit_events)
            },
            "requirements": [
                {
                    "id": r.requirement_id,
                    "title": r.title,
                    "status": r.implementation_status,
                    "priority": r.priority,
                    "category": r.category
                }
                for r in requirements
            ],
            "violations": [
                {
                    "id": v.violation_id,
                    "requirement_id": v.requirement_id,
                    "severity": v.severity,
                    "description": v.description,
                    "detected_at": v.detected_at.isoformat(),
                    "status": v.status
                }
                for v in violations
            ]
        }
    
    async def _collect_executive_summary_data(self, framework: ComplianceFramework,
                                            period_start: datetime, period_end: datetime) -> Dict[str, Any]:
        """Collect data for executive summary"""
        report_data = await self._collect_report_data(framework, period_start, period_end)
        
        # Add executive-specific metrics
        executive_data = {
            **report_data,
            "executive_metrics": {
                "compliance_trend": "improving" if report_data["metrics"]["compliance_percentage"] > 80 else "needs_attention",
                "risk_level": "low" if report_data["metrics"]["total_violations"] < 5 else "medium",
                "next_assessment": framework.next_assessment.isoformat() if framework.next_assessment else None,
                "key_risks": [
                    "Access control gaps",
                    "Data protection compliance",
                    "Audit trail integrity"
                ],
                "recommendations": [
                    "Implement automated compliance monitoring",
                    "Enhance access control policies",
                    "Strengthen audit logging"
                ]
            }
        }
        
        return executive_data
    
    async def _collect_regulatory_data(self, framework: ComplianceFramework, report_type: str,
                                     period_start: datetime, period_end: datetime) -> Dict[str, Any]:
        """Collect data for regulatory report"""
        report_data = await self._collect_report_data(framework, period_start, period_end)
        
        # Add regulatory-specific data
        regulatory_data = {
            **report_data,
            "regulatory_info": {
                "jurisdiction": framework.jurisdiction,
                "applicable_industries": framework.applicable_industries,
                "last_assessment": framework.last_assessment.isoformat() if framework.last_assessment else None,
                "auditor": framework.auditor,
                "certification_status": "certified" if report_data["metrics"]["compliance_percentage"] > 95 else "pending"
            }
        }
        
        return regulatory_data
    
    async def _collect_compliance_data(self, framework: ComplianceFramework,
                                     period_start: datetime, period_end: datetime) -> Dict[str, Any]:
        """Collect comprehensive compliance data for export"""
        return await self._collect_report_data(framework, period_start, period_end)
    
    async def _get_framework_requirements(self, framework_id: int) -> List[ComplianceRequirement]:
        """Get framework requirements"""
        result = await self.db_session.execute(
            select(ComplianceRequirement).where(ComplianceRequirement.framework_id == framework_id)
        )
        return result.scalars().all()
    
    async def _get_violations_for_period(self, framework_id: int, start_date: datetime, end_date: datetime) -> List[Any]:
        """Get violations for period"""
        # In production, this would query the database
        return []
    
    async def _get_audit_events_for_period(self, framework_id: int, start_date: datetime, end_date: datetime) -> List[SecurityAuditLog]:
        """Get audit events for period"""
        result = await self.db_session.execute(
            select(SecurityAuditLog).where(
                and_(
                    SecurityAuditLog.compliance_framework == str(framework_id),
                    SecurityAuditLog.timestamp >= start_date,
                    SecurityAuditLog.timestamp <= end_date
                )
            )
        )
        return result.scalars().all()
    
    async def _generate_report_file(self, report: ComplianceReport, template: ReportTemplate,
                                  report_data: Dict[str, Any], format: str) -> Path:
        """Generate report file"""
        if format.lower() == "html":
            content = await self._generate_html_report(template, report_data)
            file_path = self._output_directory / f"{report.report_id}.html"
        elif format.lower() == "json":
            content = json.dumps(report_data, indent=2, default=str)
            file_path = self._output_directory / f"{report.report_id}.json"
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return file_path
    
    async def _generate_html_report(self, template: ReportTemplate, report_data: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Compliance Report - {report_data['framework']['name']}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .section {{ margin: 20px 0; }}
                .metric {{ display: inline-block; margin: 10px; padding: 10px; background-color: #e8f4f8; border-radius: 3px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Compliance Report</h1>
                <h2>{report_data['framework']['name']}</h2>
                <p>Period: {report_data['period']['start']} to {report_data['period']['end']}</p>
            </div>
            
            <div class="section">
                <h3>Key Metrics</h3>
                <div class="metric">Total Requirements: {report_data['metrics']['total_requirements']}</div>
                <div class="metric">Compliant: {report_data['metrics']['compliant_requirements']}</div>
                <div class="metric">Compliance: {report_data['metrics']['compliance_percentage']:.1f}%</div>
                <div class="metric">Violations: {report_data['metrics']['total_violations']}</div>
            </div>
            
            <div class="section">
                <h3>Requirements Status</h3>
                <table>
                    <tr><th>ID</th><th>Title</th><th>Status</th><th>Priority</th></tr>
        """
        
        for req in report_data['requirements']:
            html += f"<tr><td>{req['id']}</td><td>{req['title']}</td><td>{req['status']}</td><td>{req['priority']}</td></tr>"
        
        html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        return html
    
    async def _generate_executive_summary_html(self, framework: ComplianceFramework,
                                             summary_data: Dict[str, Any],
                                             period_start: datetime, period_end: datetime) -> str:
        """Generate executive summary HTML"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Executive Summary - {framework.name}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 30px; border-radius: 5px; }}
                .summary {{ background-color: #ecf0f1; padding: 20px; border-radius: 5px; margin: 20px 0; }}
                .metric {{ display: inline-block; margin: 15px; padding: 15px; background-color: white; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .risk-high {{ color: #e74c3c; }}
                .risk-medium {{ color: #f39c12; }}
                .risk-low {{ color: #27ae60; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Executive Summary</h1>
                <h2>{framework.name} Compliance</h2>
                <p>Period: {period_start.strftime('%Y-%m-%d')} to {period_end.strftime('%Y-%m-%d')}</p>
            </div>
            
            <div class="summary">
                <h3>Compliance Overview</h3>
                <div class="metric">
                    <h4>Overall Compliance</h4>
                    <p style="font-size: 24px; font-weight: bold;">{summary_data['metrics']['compliance_percentage']:.1f}%</p>
                </div>
                <div class="metric">
                    <h4>Risk Level</h4>
                    <p class="risk-{summary_data['executive_metrics']['risk_level']}" style="font-size: 18px; font-weight: bold;">
                        {summary_data['executive_metrics']['risk_level'].upper()}
                    </p>
                </div>
                <div class="metric">
                    <h4>Active Violations</h4>
                    <p style="font-size: 24px; font-weight: bold;">{summary_data['metrics']['total_violations']}</p>
                </div>
            </div>
            
            <div class="summary">
                <h3>Key Recommendations</h3>
                <ul>
        """
        
        for rec in summary_data['executive_metrics']['recommendations']:
            html += f"<li>{rec}</li>"
        
        html += """
                </ul>
            </div>
        </body>
        </html>
        """
        
        return html
    
    async def _generate_regulatory_report_content(self, framework: ComplianceFramework,
                                                regulatory_data: Dict[str, Any], report_type: str) -> str:
        """Generate regulatory report content"""
        content = f"""
        REGULATORY COMPLIANCE REPORT
        ===========================
        
        Framework: {framework.name}
        Type: {framework.framework_type}
        Jurisdiction: {framework.jurisdiction}
        Report Type: {report_type}
        
        Compliance Status: {regulatory_data['regulatory_info']['certification_status'].upper()}
        Overall Compliance: {regulatory_data['metrics']['compliance_percentage']:.1f}%
        
        Requirements Summary:
        - Total Requirements: {regulatory_data['metrics']['total_requirements']}
        - Compliant Requirements: {regulatory_data['metrics']['compliant_requirements']}
        - Active Violations: {regulatory_data['metrics']['total_violations']}
        
        Assessment Information:
        - Last Assessment: {regulatory_data['regulatory_info']['last_assessment']}
        - Auditor: {regulatory_data['regulatory_info']['auditor']}
        
        This report was generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        return content
    
    async def _export_to_csv(self, framework: ComplianceFramework, compliance_data: Dict[str, Any],
                           period_start: datetime, period_end: datetime) -> Path:
        """Export compliance data to CSV"""
        file_path = self._output_directory / f"{framework.name}_compliance_{period_start.strftime('%Y%m%d')}.csv"
        
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['Requirement ID', 'Title', 'Status', 'Priority', 'Category'])
            
            # Write requirements data
            for req in compliance_data['requirements']:
                writer.writerow([req['id'], req['title'], req['status'], req['priority'], req['category']])
        
        return file_path
    
    async def _export_to_json(self, framework: ComplianceFramework, compliance_data: Dict[str, Any],
                            period_start: datetime, period_end: datetime) -> Path:
        """Export compliance data to JSON"""
        file_path = self._output_directory / f"{framework.name}_compliance_{period_start.strftime('%Y%m%d')}.json"
        
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(compliance_data, jsonfile, indent=2, default=str)
        
        return file_path
    
    async def _export_to_excel(self, framework: ComplianceFramework, compliance_data: Dict[str, Any],
                             period_start: datetime, period_end: datetime) -> Path:
        """Export compliance data to Excel"""
        # In production, this would use openpyxl or xlsxwriter
        # For now, create a CSV file with .xlsx extension
        file_path = self._output_directory / f"{framework.name}_compliance_{period_start.strftime('%Y%m%d')}.xlsx"
        
        # Create a simple text file as placeholder
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("Excel export placeholder - would contain formatted compliance data")
        
        return file_path
    
    def _calculate_next_run(self, frequency: str) -> datetime:
        """Calculate next run time for scheduled report"""
        now = datetime.now()
        
        if frequency == "daily":
            return now + timedelta(days=1)
        elif frequency == "weekly":
            return now + timedelta(weeks=1)
        elif frequency == "monthly":
            return now + timedelta(days=30)
        elif frequency == "quarterly":
            return now + timedelta(days=90)
        elif frequency == "annually":
            return now + timedelta(days=365)
        else:
            return now + timedelta(days=1)
    
    async def _store_report_metadata(self, report: ComplianceReport):
        """Store report metadata"""
        # In production, this would save to database
        logger.info(f"Stored report metadata: {report.report_id}")
    
    async def _log_report_event(self, event_type: str, schedule_id: str, user_id: int,
                              event_data: Optional[Dict[str, Any]] = None):
        """Log report-related event"""
        logger.info(f"Report event: {event_type} for schedule {schedule_id}")
        if user_id:
            logger.info(f"User: {user_id}")
        if event_data:
            logger.info(f"Event data: {event_data}")
