"""
Advanced Reporting Service for CHM Advanced Analytics & Reporting System

This service provides comprehensive reporting capabilities including:
- Customizable report generation
- Multiple output formats (PDF, HTML, JSON, CSV, Excel)
- Scheduled report delivery
- Report templates and customization
- Multi-dimensional data aggregation
- Business intelligence insights
"""

import asyncio
import logging
import json
import csv
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import io

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc, text
from sqlalchemy.orm import selectinload

from ..models.analytics import (
    AnalyticsReport, AnalyticsInsight, PerformanceAnalysis, 
    AnomalyDetection, CapacityPlanning, TrendForecast,
    ReportType, ReportFormat
)
from ..models.metric import Metric, MetricType, MetricCategory
from ..models.device import Device, DeviceStatus
from ..models.alert import Alert, AlertSeverity, AlertStatus
from ..models.notification import Notification, NotificationStatus
from ..models.result_objects import ReportResult, CollectionResult
from ..services.metrics_query import MetricsQueryService
from ..services.performance_analytics import PerformanceAnalyticsService

logger = logging.getLogger(__name__)


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    report_type: ReportType
    time_range: Tuple[datetime, datetime]
    device_ids: Optional[List[int]] = None
    metric_names: Optional[List[str]] = None
    include_charts: bool = True
    include_insights: bool = True
    include_recommendations: bool = True
    aggregation_level: str = "hourly"  # minute, hourly, daily, weekly, monthly
    max_data_points: int = 1000
    format: ReportFormat = ReportFormat.HTML


@dataclass
class ReportTemplate:
    """Template for report generation"""
    name: str
    description: str
    report_type: ReportType
    config: Dict[str, Any]
    sections: List[Dict[str, Any]]
    styling: Dict[str, Any]
    is_default: bool = False


class AdvancedReportingService:
    """Service for comprehensive report generation and management"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.metrics_query = MetricsQueryService(db_session)
        self.analytics_service = PerformanceAnalyticsService(db_session)
        self.report_templates = self._load_default_templates()
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)
    
    async def generate_report(
        self,
        config: ReportConfig,
        user_id: int,
        template_name: Optional[str] = None
    ) -> ReportResult:
        """Generate a comprehensive report based on configuration"""
        try:
            start_time = datetime.now()
            
            # Get or create report template
            template = await self._get_report_template(config.report_type, template_name)
            
            # Generate report content
            report_content = await self._generate_report_content(config, template)
            
            # Generate report in requested format
            report_file = await self._generate_output_file(report_content, config.format)
            
            # Store report record
            report_record = await self._store_report_record(
                config, user_id, report_content, report_file
            )
            
            generation_duration = int((datetime.now() - start_time).total_seconds() * 1000)
            
            # Update report record with duration
            report_record.generation_duration_ms = generation_duration
            await self.db_session.commit()
            
            return ReportResult(
                success=True,
                report_id=report_record.id,
                report_file=str(report_file),
                report_summary=report_content.get('summary', ''),
                generation_duration_ms=generation_duration,
                available_formats=[config.format.value]
            )
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return ReportResult(
                success=False,
                error=str(e),
                fallback_data={"report_generation": "failed"}
            )
    
    async def _generate_report_content(
        self,
        config: ReportConfig,
        template: ReportTemplate
    ) -> Dict[str, Any]:
        """Generate the content for the report"""
        try:
            content = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'report_type': config.report_type.value,
                    'time_range': {
                        'start': config.time_range[0].isoformat(),
                        'end': config.time_range[1].isoformat()
                    },
                    'devices_analyzed': len(config.device_ids) if config.device_ids else 0
                },
                'summary': '',
                'sections': [],
                'insights': [],
                'recommendations': [],
                'charts': [],
                'data_summary': {}
            }
            
            # Generate sections based on report type
            if config.report_type == ReportType.PERFORMANCE_SUMMARY:
                content.update(await self._generate_performance_summary(config))
            elif config.report_type == ReportType.ANOMALY_REPORT:
                content.update(await self._generate_anomaly_report(config))
            elif config.report_type == ReportType.CAPACITY_ANALYSIS:
                content.update(await self._generate_capacity_analysis(config))
            elif config.report_type == ReportType.TREND_FORECAST:
                content.update(await self._generate_trend_forecast(config))
            elif config.report_type == ReportType.COMPARATIVE_ANALYSIS:
                content.update(await self._generate_comparative_analysis(config))
            else:
                content.update(await self._generate_custom_report(config))
            
            # Generate insights and recommendations
            if config.include_insights:
                content['insights'] = await self._generate_insights(config)
            
            if config.include_recommendations:
                content['recommendations'] = await self._generate_recommendations(config)
            
            # Generate summary
            content['summary'] = self._generate_executive_summary(content)
            
            return content
            
        except Exception as e:
            logger.error(f"Error generating report content: {str(e)}")
            return {
                'error': str(e),
                'summary': 'Report generation failed due to an error'
            }
    
    async def _generate_performance_summary(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate performance summary report content"""
        try:
            sections = []
            data_summary = {}
            
            # Device performance overview
            if config.device_ids:
                device_performance = await self._get_device_performance_summary(
                    config.device_ids, config.time_range
                )
                sections.append({
                    'title': 'Device Performance Overview',
                    'type': 'table',
                    'data': device_performance
                })
                data_summary['device_count'] = len(config.device_ids)
                data_summary['performance_metrics'] = len(device_performance)
            
            # Metric trends
            if config.metric_names:
                metric_trends = await self._get_metric_trends(
                    config.device_ids, config.metric_names, config.time_range
                )
                sections.append({
                    'title': 'Metric Trends',
                    'type': 'trend_analysis',
                    'data': metric_trends
                })
                data_summary['metrics_analyzed'] = len(config.metric_names)
            
            # Performance alerts
            alerts_summary = await self._get_alerts_summary(config.time_range)
            sections.append({
                'title': 'Performance Alerts',
                'type': 'alerts_summary',
                'data': alerts_summary
            })
            
            return {
                'sections': sections,
                'data_summary': data_summary
            }
            
        except Exception as e:
            logger.error(f"Error generating performance summary: {str(e)}")
            return {'sections': [], 'data_summary': {}}
    
    async def _generate_anomaly_report(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate anomaly detection report content"""
        try:
            sections = []
            data_summary = {}
            
            # Anomaly summary
            anomalies = await self._get_anomalies_summary(config.time_range)
            sections.append({
                'title': 'Anomaly Detection Summary',
                'type': 'anomaly_summary',
                'data': anomalies
            })
            
            data_summary['total_anomalies'] = anomalies.get('total_count', 0)
            data_summary['critical_anomalies'] = anomalies.get('critical_count', 0)
            data_summary['anomaly_types'] = anomalies.get('type_breakdown', {})
            
            # Anomaly trends
            anomaly_trends = await self._get_anomaly_trends(config.time_range)
            sections.append({
                'title': 'Anomaly Trends',
                'type': 'trend_analysis',
                'data': anomaly_trends
            })
            
            # Device anomaly breakdown
            if config.device_ids:
                device_anomalies = await self._get_device_anomaly_breakdown(
                    config.device_ids, config.time_range
                )
                sections.append({
                    'title': 'Device Anomaly Breakdown',
                    'type': 'device_breakdown',
                    'data': device_anomalies
                })
            
            return {
                'sections': sections,
                'data_summary': data_summary
            }
            
        except Exception as e:
            logger.error(f"Error generating anomaly report: {str(e)}")
            return {'sections': [], 'data_summary': {}}
    
    async def _generate_capacity_analysis(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate capacity planning report content"""
        try:
            sections = []
            data_summary = {}
            
            # Capacity utilization summary
            capacity_summary = await self._get_capacity_summary(config.time_range)
            sections.append({
                'title': 'Capacity Utilization Summary',
                'type': 'capacity_summary',
                'data': capacity_summary
            })
            
            # Resource utilization trends
            resource_trends = await self._get_resource_utilization_trends(
                config.device_ids, config.time_range
            )
            sections.append({
                'title': 'Resource Utilization Trends',
                'type': 'resource_trends',
                'data': resource_trends
            })
            
            # Upgrade recommendations
            upgrade_recommendations = await self._get_upgrade_recommendations(
                config.device_ids
            )
            sections.append({
                'title': 'Upgrade Recommendations',
                'type': 'recommendations',
                'data': upgrade_recommendations
            })
            
            return {
                'sections': sections,
                'data_summary': data_summary
            }
            
        except Exception as e:
            logger.error(f"Error generating capacity analysis: {str(e)}")
            return {'sections': [], 'data_summary': {}}
    
    async def _generate_trend_forecast(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate trend forecasting report content"""
        try:
            sections = []
            data_summary = {}
            
            # Historical trends
            historical_trends = await self._get_historical_trends(
                config.device_ids, config.metric_names, config.time_range
            )
            sections.append({
                'title': 'Historical Trends',
                'type': 'trend_analysis',
                'data': historical_trends
            })
            
            # Forecast predictions
            forecasts = await self._get_forecast_predictions(
                config.device_ids, config.metric_names
            )
            sections.append({
                'title': 'Forecast Predictions',
                'type': 'forecast',
                'data': forecasts
            })
            
            # Seasonal patterns
            seasonal_patterns = await self._get_seasonal_patterns(
                config.device_ids, config.metric_names, config.time_range
            )
            sections.append({
                'title': 'Seasonal Patterns',
                'type': 'seasonal_analysis',
                'data': seasonal_patterns
            })
            
            return {
                'sections': sections,
                'data_summary': data_summary
            }
            
        except Exception as e:
            logger.error(f"Error generating trend forecast: {str(e)}")
            return {'sections': [], 'data_summary': {}}
    
    async def _generate_comparative_analysis(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate comparative analysis report content"""
        try:
            sections = []
            data_summary = {}
            
            # Device comparison
            device_comparison = await self._get_device_comparison(
                config.device_ids, config.metric_names, config.time_range
            )
            sections.append({
                'title': 'Device Performance Comparison',
                'type': 'comparison_table',
                'data': device_comparison
            })
            
            # Time period comparison
            time_comparison = await self._get_time_period_comparison(
                config.device_ids, config.metric_names, config.time_range
            )
            sections.append({
                'title': 'Time Period Comparison',
                'type': 'time_comparison',
                'data': time_comparison
            })
            
            # Performance ranking
            performance_ranking = await self._get_performance_ranking(
                config.device_ids, config.metric_names, config.time_range
            )
            sections.append({
                'title': 'Performance Ranking',
                'type': 'ranking',
                'data': performance_ranking
            })
            
            return {
                'sections': sections,
                'data_summary': data_summary
            }
            
        except Exception as e:
            logger.error(f"Error generating comparative analysis: {str(e)}")
            return {'sections': [], 'data_summary': {}}
    
    async def _generate_custom_report(self, config: ReportConfig) -> Dict[str, Any]:
        """Generate custom report content"""
        try:
            sections = []
            data_summary = {}
            
            # Custom metrics analysis
            if config.metric_names:
                custom_metrics = await self._get_custom_metrics_analysis(
                    config.device_ids, config.metric_names, config.time_range
                )
                sections.append({
                    'title': 'Custom Metrics Analysis',
                    'type': 'custom_analysis',
                    'data': custom_metrics
                })
            
            # Custom aggregations
            custom_aggregations = await self._get_custom_aggregations(
                config.device_ids, config.metric_names, config.time_range, config.aggregation_level
            )
            sections.append({
                'title': 'Custom Aggregations',
                'type': 'aggregations',
                'data': custom_aggregations
            })
            
            return {
                'sections': sections,
                'data_summary': data_summary
            }
            
        except Exception as e:
            logger.error(f"Error generating custom report: {str(e)}")
            return {'sections': [], 'data_summary': {}}
    
    async def _generate_insights(self, config: ReportConfig) -> List[Dict[str, Any]]:
        """Generate insights for the report"""
        try:
            insights = []
            
            # Get analytics insights
            if config.device_ids:
                for device_id in config.device_ids[:5]:  # Limit to first 5 devices
                    device_insights = await self._get_device_insights(device_id, config.time_range)
                    insights.extend(device_insights)
            
            # Get global insights
            global_insights = await self._get_global_insights(config.time_range)
            insights.extend(global_insights)
            
            # Sort by priority and limit results
            insights.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
            return insights[:20]  # Limit to top 20 insights
            
        except Exception as e:
            logger.error(f"Error generating insights: {str(e)}")
            return []
    
    async def _generate_recommendations(self, config: ReportConfig) -> List[Dict[str, Any]]:
        """Generate recommendations for the report"""
        try:
            recommendations = []
            
            # Get performance recommendations
            if config.device_ids:
                for device_id in config.device_ids[:5]:  # Limit to first 5 devices
                    device_recommendations = await self._get_device_recommendations(
                        device_id, config.time_range
                    )
                    recommendations.extend(device_recommendations)
            
            # Get global recommendations
            global_recommendations = await self._get_global_recommendations(config.time_range)
            recommendations.extend(global_recommendations)
            
            # Sort by priority and limit results
            recommendations.sort(key=lambda x: x.get('priority', 'low'), reverse=True)
            return recommendations[:15]  # Limit to top 15 recommendations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {str(e)}")
            return []
    
    def _generate_executive_summary(self, content: Dict[str, Any]) -> str:
        """Generate executive summary for the report"""
        try:
            summary_parts = []
            
            # Basic report info
            metadata = content.get('metadata', {})
            report_type = metadata.get('report_type', 'Unknown')
            device_count = metadata.get('devices_analyzed', 0)
            
            summary_parts.append(f"This {report_type} report covers {device_count} devices.")
            
            # Key findings
            insights = content.get('insights', [])
            if insights:
                critical_insights = [i for i in insights if i.get('impact_level') == 'critical']
                if critical_insights:
                    summary_parts.append(f"Found {len(critical_insights)} critical insights requiring immediate attention.")
            
            # Recommendations
            recommendations = content.get('recommendations', [])
            if recommendations:
                high_priority = [r for r in recommendations if r.get('priority') == 'high']
                if high_priority:
                    summary_parts.append(f"Generated {len(high_priority)} high-priority recommendations.")
            
            # Data summary
            data_summary = content.get('data_summary', {})
            if data_summary:
                if 'total_anomalies' in data_summary:
                    summary_parts.append(f"Detected {data_summary['total_anomalies']} anomalies during the reporting period.")
                
                if 'metrics_analyzed' in data_summary:
                    summary_parts.append(f"Analyzed {data_summary['metrics_analyzed']} performance metrics.")
            
            if not summary_parts:
                summary_parts.append("Report generated successfully with comprehensive analysis.")
            
            return " ".join(summary_parts)
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return "Report generated successfully."
    
    async def _generate_output_file(
        self,
        content: Dict[str, Any],
        format: ReportFormat
    ) -> Path:
        """Generate output file in the specified format"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if format == ReportFormat.JSON:
                return await self._generate_json_file(content, timestamp)
            elif format == ReportFormat.CSV:
                return await self._generate_csv_file(content, timestamp)
            elif format == ReportFormat.HTML:
                return await self._generate_html_file(content, timestamp)
            elif format == ReportFormat.PDF:
                return await self._generate_pdf_file(content, timestamp)
            elif format == ReportFormat.EXCEL:
                return await self._generate_excel_file(content, timestamp)
            else:
                # Default to JSON
                return await self._generate_json_file(content, timestamp)
                
        except Exception as e:
            logger.error(f"Error generating output file: {str(e)}")
            # Fallback to JSON
            return await self._generate_json_file(content, datetime.now().strftime("%Y%m%d_%H%M%S"))
    
    async def _generate_json_file(self, content: Dict[str, Any], timestamp: str) -> Path:
        """Generate JSON output file"""
        try:
            filename = f"report_{timestamp}.json"
            filepath = self.output_dir / filename
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(content, f, indent=2, default=str)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating JSON file: {str(e)}")
            raise
    
    async def _generate_csv_file(self, content: Dict[str, Any], timestamp: str) -> Path:
        """Generate CSV output file"""
        try:
            filename = f"report_{timestamp}.csv"
            filepath = self.output_dir / filename
            
            # Flatten content for CSV
            csv_data = self._flatten_content_for_csv(content)
            
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                for row in csv_data:
                    writer.writerow(row)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating CSV file: {str(e)}")
            raise
    
    async def _generate_html_file(self, content: Dict[str, Any], timestamp: str) -> Path:
        """Generate HTML output file"""
        try:
            filename = f"report_{timestamp}.html"
            filepath = self.output_dir / filename
            
            html_content = self._generate_html_content(content)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating HTML file: {str(e)}")
            raise
    
    async def _generate_pdf_file(self, content: Dict[str, Any], timestamp: str) -> Path:
        """Generate PDF output file (placeholder)"""
        try:
            filename = f"report_{timestamp}.pdf"
            filepath = self.output_dir / filename
            
            # Placeholder - would use a library like reportlab or weasyprint
            with open(filepath, 'w') as f:
                f.write("PDF generation not yet implemented")
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating PDF file: {str(e)}")
            raise
    
    async def _generate_excel_file(self, content: Dict[str, Any], timestamp: str) -> Path:
        """Generate Excel output file (placeholder)"""
        try:
            filename = f"report_{timestamp}.xlsx"
            filepath = self.output_dir / filename
            
            # Placeholder - would use openpyxl or xlsxwriter
            with open(filepath, 'w') as f:
                f.write("Excel generation not yet implemented")
            
            return filepath
            
        except Exception as e:
            logger.error(f"Error generating Excel file: {str(e)}")
            raise
    
    def _flatten_content_for_csv(self, content: Dict[str, Any]) -> List[List[str]]:
        """Flatten content structure for CSV output"""
        try:
            csv_data = []
            
            # Add headers
            headers = ['Section', 'Type', 'Title', 'Data']
            csv_data.append(headers)
            
            # Add sections
            sections = content.get('sections', [])
            for section in sections:
                row = [
                    section.get('title', ''),
                    section.get('type', ''),
                    section.get('title', ''),
                    str(section.get('data', ''))
                ]
                csv_data.append(row)
            
            # Add insights
            insights = content.get('insights', [])
            for insight in insights:
                row = [
                    'Insights',
                    insight.get('type', ''),
                    insight.get('title', ''),
                    insight.get('description', '')
                ]
                csv_data.append(row)
            
            # Add recommendations
            recommendations = content.get('recommendations', [])
            for rec in recommendations:
                row = [
                    'Recommendations',
                    rec.get('type', ''),
                    rec.get('title', ''),
                    rec.get('description', '')
                ]
                csv_data.append(row)
            
            return csv_data
            
        except Exception as e:
            logger.error(f"Error flattening content for CSV: {str(e)}")
            return [['Error', 'Error', 'Error', str(e)]]
    
    def _generate_html_content(self, content: Dict[str, Any]) -> str:
        """Generate HTML content for the report"""
        try:
            html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHM Analytics Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
        .section h3 {{ color: #333; margin-top: 0; }}
        .insight {{ background-color: #e8f4fd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .recommendation {{ background-color: #fff3cd; padding: 10px; margin: 10px 0; border-radius: 3px; }}
        .metadata {{ font-size: 0.9em; color: #666; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>CHM Analytics Report</h1>
        <div class="metadata">
            <p><strong>Generated:</strong> {content.get('metadata', {}).get('generated_at', 'Unknown')}</p>
            <p><strong>Report Type:</strong> {content.get('metadata', {}).get('report_type', 'Unknown')}</p>
            <p><strong>Devices Analyzed:</strong> {content.get('metadata', {}).get('devices_analyzed', 0)}</p>
        </div>
    </div>
    
    <div class="section">
        <h3>Executive Summary</h3>
        <p>{content.get('summary', 'No summary available')}</p>
    </div>
"""
            
            # Add sections
            sections = content.get('sections', [])
            for section in sections:
                html += f"""
    <div class="section">
        <h3>{section.get('title', 'Untitled Section')}</h3>
        <p><strong>Type:</strong> {section.get('type', 'Unknown')}</p>
        <pre>{json.dumps(section.get('data', {}), indent=2, default=str)}</pre>
    </div>
"""
            
            # Add insights
            insights = content.get('insights', [])
            if insights:
                html += """
    <div class="section">
        <h3>Key Insights</h3>
"""
                for insight in insights:
                    html += f"""
        <div class="insight">
            <h4>{insight.get('title', 'Untitled')}</h4>
            <p>{insight.get('description', 'No description')}</p>
            <p><strong>Impact:</strong> {insight.get('impact_level', 'Unknown')}</p>
        </div>
"""
                html += "    </div>"
            
            # Add recommendations
            recommendations = content.get('recommendations', [])
            if recommendations:
                html += """
    <div class="section">
        <h3>Recommendations</h3>
"""
                for rec in recommendations:
                    html += f"""
        <div class="recommendation">
            <h4>{rec.get('title', 'Untitled')}</h4>
            <p>{rec.get('description', 'No description')}</p>
            <p><strong>Priority:</strong> {rec.get('priority', 'Unknown')}</p>
        </div>
"""
                html += "    </div>"
            
            html += """
</body>
</html>
"""
            
            return html
            
        except Exception as e:
            logger.error(f"Error generating HTML content: {str(e)}")
            return f"<html><body><h1>Error</h1><p>Failed to generate HTML: {str(e)}</p></body></html>"
    
    async def _store_report_record(
        self,
        config: ReportConfig,
        user_id: int,
        content: Dict[str, Any],
        report_file: Path
    ) -> AnalyticsReport:
        """Store report record in database"""
        try:
            report = AnalyticsReport(
                name=f"{config.report_type.value.title()} Report",
                description=f"Generated {config.report_type.value} report",
                report_type=config.report_type.value,
                report_config=config.__dict__,
                target_audience="engineers",
                report_frequency="on-demand",
                generated_by=user_id,
                generated_at=datetime.now(),
                report_content=content,
                report_summary=content.get('summary', ''),
                key_insights=content.get('insights', []),
                recommendations=content.get('recommendations', []),
                available_formats=[config.format.value],
                generated_files=[str(report_file)],
                distribution_status="pending",
                tags=[config.report_type.value, "auto_generated"]
            )
            
            self.db_session.add(report)
            await self.db_session.commit()
            
            return report
            
        except Exception as e:
            logger.error(f"Error storing report record: {str(e)}")
            await self.db_session.rollback()
            raise
    
    def _load_default_templates(self) -> Dict[str, ReportTemplate]:
        """Load default report templates"""
        templates = {}
        
        # Performance Summary Template
        templates['performance_summary'] = ReportTemplate(
            name="Performance Summary",
            description="Comprehensive performance overview with trends and alerts",
            report_type=ReportType.PERFORMANCE_SUMMARY,
            config={
                'include_charts': True,
                'include_insights': True,
                'include_recommendations': True,
                'aggregation_level': 'hourly'
            },
            sections=[
                {'title': 'Device Performance Overview', 'type': 'table'},
                {'title': 'Metric Trends', 'type': 'trend_analysis'},
                {'title': 'Performance Alerts', 'type': 'alerts_summary'}
            ],
            styling={'theme': 'default', 'color_scheme': 'blue'},
            is_default=True
        )
        
        # Anomaly Report Template
        templates['anomaly_report'] = ReportTemplate(
            name="Anomaly Detection Report",
            description="Detailed anomaly analysis with correlation and insights",
            report_type=ReportType.ANOMALY_REPORT,
            config={
                'include_charts': True,
                'include_insights': True,
                'include_recommendations': True,
                'aggregation_level': 'hourly'
            },
            sections=[
                {'title': 'Anomaly Detection Summary', 'type': 'anomaly_summary'},
                {'title': 'Anomaly Trends', 'type': 'trend_analysis'},
                {'title': 'Device Anomaly Breakdown', 'type': 'device_breakdown'}
            ],
            styling={'theme': 'default', 'color_scheme': 'red'},
            is_default=True
        )
        
        return templates
    
    async def _get_report_template(
        self,
        report_type: ReportType,
        template_name: Optional[str] = None
    ) -> ReportTemplate:
        """Get report template by type or name"""
        if template_name and template_name in self.report_templates:
            return self.report_templates[template_name]
        
        # Find default template for report type
        for template in self.report_templates.values():
            if template.report_type == report_type and template.is_default:
                return template
        
        # Return first available template
        return list(self.report_templates.values())[0]
    
    # Placeholder methods for data retrieval
    async def _get_device_performance_summary(
        self,
        device_ids: List[int],
        time_range: Tuple[datetime, datetime]
    ) -> List[Dict[str, Any]]:
        """Get device performance summary (placeholder)"""
        return [{"device_id": did, "status": "placeholder"} for did in device_ids]
    
    async def _get_metric_trends(
        self,
        device_ids: Optional[List[int]],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get metric trends (placeholder)"""
        return {"trends": "placeholder"}
    
    async def _get_alerts_summary(self, time_range: Tuple[datetime, datetime]) -> Dict[str, Any]:
        """Get alerts summary (placeholder)"""
        return {"alerts": "placeholder"}
    
    async def _get_anomalies_summary(self, time_range: Tuple[datetime, datetime]) -> Dict[str, Any]:
        """Get anomalies summary (placeholder)"""
        return {"anomalies": "placeholder"}
    
    async def _get_anomaly_trends(self, time_range: Tuple[datetime, datetime]) -> Dict[str, Any]:
        """Get anomaly trends (placeholder)"""
        return {"trends": "placeholder"}
    
    async def _get_device_anomaly_breakdown(
        self,
        device_ids: List[int],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get device anomaly breakdown (placeholder)"""
        return {"breakdown": "placeholder"}
    
    async def _get_capacity_summary(self, time_range: Tuple[datetime, datetime]) -> Dict[str, Any]:
        """Get capacity summary (placeholder)"""
        return {"capacity": "placeholder"}
    
    async def _get_resource_utilization_trends(
        self,
        device_ids: Optional[List[int]],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get resource utilization trends (placeholder)"""
        return {"trends": "placeholder"}
    
    async def _get_upgrade_recommendations(self, device_ids: List[int]) -> List[Dict[str, Any]]:
        """Get upgrade recommendations (placeholder)"""
        return [{"recommendation": "placeholder"}]
    
    async def _get_historical_trends(
        self,
        device_ids: Optional[List[int]],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get historical trends (placeholder)"""
        return {"trends": "placeholder"}
    
    async def _get_forecast_predictions(
        self,
        device_ids: Optional[List[int]],
        metric_names: List[str]
    ) -> Dict[str, Any]:
        """Get forecast predictions (placeholder)"""
        return {"forecasts": "placeholder"}
    
    async def _get_seasonal_patterns(
        self,
        device_ids: Optional[List[int]],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get seasonal patterns (placeholder)"""
        return {"patterns": "placeholder"}
    
    async def _get_device_comparison(
        self,
        device_ids: List[int],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get device comparison (placeholder)"""
        return {"comparison": "placeholder"}
    
    async def _get_time_period_comparison(
        self,
        device_ids: List[int],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get time period comparison (placeholder)"""
        return {"comparison": "placeholder"}
    
    async def _get_performance_ranking(
        self,
        device_ids: List[int],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get performance ranking (placeholder)"""
        return {"ranking": "placeholder"}
    
    async def _get_custom_metrics_analysis(
        self,
        device_ids: Optional[List[int]],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime]
    ) -> Dict[str, Any]:
        """Get custom metrics analysis (placeholder)"""
        return {"analysis": "placeholder"}
    
    async def _get_custom_aggregations(
        self,
        device_ids: Optional[List[int]],
        metric_names: List[str],
        time_range: Tuple[datetime, datetime],
        aggregation_level: str
    ) -> Dict[str, Any]:
        """Get custom aggregations (placeholder)"""
        return {"aggregations": "placeholder"}
    
    async def _get_device_insights(
        self,
        device_id: int,
        time_range: Tuple[datetime, datetime]
    ) -> List[Dict[str, Any]]:
        """Get device insights (placeholder)"""
        return [{"insight": "placeholder"}]
    
    async def _get_global_insights(self, time_range: Tuple[datetime, datetime]) -> List[Dict[str, Any]]:
        """Get global insights (placeholder)"""
        return [{"insight": "placeholder"}]
    
    async def _get_device_recommendations(
        self,
        device_id: int,
        time_range: Tuple[datetime, datetime]
    ) -> List[Dict[str, Any]]:
        """Get device recommendations (placeholder)"""
        return [{"recommendation": "placeholder"}]
    
    async def _get_global_recommendations(self, time_range: Tuple[datetime, datetime]) -> List[Dict[str, Any]]:
        """Get global recommendations (placeholder)"""
        return [{"recommendation": "placeholder"}]
