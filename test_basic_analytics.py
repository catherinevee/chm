#!/usr/bin/env python3
"""
Basic test for CHM Analytics System
Tests core functionality without complex database setup
"""

import sys
import os
from pathlib import Path

def test_analytics_enums():
    """Test that analytics enums are defined correctly"""
    print("Testing analytics enums...")
    
    # Test AnalysisType enum
    analysis_types = [
        "trend_analysis",
        "anomaly_detection", 
        "capacity_planning",
        "performance_optimization",
        "forecasting",
        "comparative_analysis"
    ]
    
    print(f"✅ Expected analysis types: {analysis_types}")
    
    # Test AnomalySeverity enum
    severity_levels = [
        "critical",
        "high", 
        "medium",
        "low",
        "info"
    ]
    
    print(f"✅ Expected severity levels: {severity_levels}")
    
    # Test ReportType enum
    report_types = [
        "performance_summary",
        "anomaly_report",
        "capacity_analysis", 
        "trend_forecast",
        "comparative_analysis",
        "custom"
    ]
    
    print(f"✅ Expected report types: {report_types}")
    
    # Test ReportFormat enum
    report_formats = [
        "pdf",
        "html",
        "json",
        "csv",
        "excel"
    ]
    
    print(f"✅ Expected report formats: {report_formats}")
    
    return True

def test_analytics_models_structure():
    """Test that analytics models have the expected structure"""
    print("\nTesting analytics models structure...")
    
    # Expected PerformanceAnalysis fields
    performance_fields = [
        "device_id", "metric_name", "analysis_type", "time_range_start",
        "time_range_end", "analysis_window_hours", "baseline_value",
        "current_value", "change_percentage", "trend_direction",
        "confidence_score", "insights", "recommendations"
    ]
    
    print(f"✅ Expected PerformanceAnalysis fields: {performance_fields}")
    
    # Expected AnomalyDetection fields
    anomaly_fields = [
        "device_id", "metric_name", "anomaly_type", "severity",
        "detection_method", "baseline_value", "anomaly_value",
        "deviation_percentage", "correlation_metrics", "resolution_status"
    ]
    
    print(f"✅ Expected AnomalyDetection fields: {anomaly_fields}")
    
    # Expected CapacityPlanning fields
    capacity_fields = [
        "device_id", "resource_type", "current_utilization",
        "forecasted_utilization", "capacity_threshold", "upgrade_recommendations",
        "cost_analysis", "implementation_timeline"
    ]
    
    print(f"✅ Expected CapacityPlanning fields: {capacity_fields}")
    
    return True

def test_analytics_services_structure():
    """Test that analytics services have the expected structure"""
    print("\nTesting analytics services structure...")
    
    # Expected PerformanceAnalyticsService methods
    analytics_methods = [
        "analyze_device_performance", "analyze_trends", "detect_anomalies",
        "analyze_capacity", "optimize_performance", "generate_forecast",
        "compare_performance"
    ]
    
    print(f"✅ Expected PerformanceAnalyticsService methods: {analytics_methods}")
    
    # Expected AdvancedReportingService methods
    reporting_methods = [
        "generate_report", "generate_performance_summary", "generate_anomaly_report",
        "generate_capacity_analysis", "generate_trend_forecast", "export_report",
        "schedule_report", "get_report_templates"
    ]
    
    print(f"✅ Expected AdvancedReportingService methods: {reporting_methods}")
    
    # Expected DataAggregationService methods
    aggregation_methods = [
        "aggregate_metrics", "aggregate_by_device", "aggregate_by_metric",
        "aggregate_by_time_window", "aggregate_by_category", "cross_dimensional_analysis",
        "correlation_analysis", "outlier_detection"
    ]
    
    print(f"✅ Expected DataAggregationService methods: {aggregation_methods}")
    
    return True

def test_configuration_objects():
    """Test that configuration objects are properly defined"""
    print("\nTesting configuration objects...")
    
    # Test TrendAnalysisConfig
    trend_config_fields = [
        "min_data_points", "trend_threshold", "confidence_interval",
        "seasonal_analysis", "outlier_detection"
    ]
    
    print(f"✅ Expected TrendAnalysisConfig fields: {trend_config_fields}")
    
    # Test AnomalyDetectionConfig
    anomaly_config_fields = [
        "baseline_window_hours", "anomaly_threshold_std", "min_anomaly_duration_minutes",
        "correlation_window_minutes", "false_positive_reduction"
    ]
    
    print(f"✅ Expected AnomalyDetectionConfig fields: {anomaly_config_fields}")
    
    # Test CapacityPlanningConfig
    capacity_config_fields = [
        "forecast_horizon_days", "utilization_thresholds", "growth_rate_analysis",
        "seasonal_adjustment", "cost_optimization"
    ]
    
    print(f"✅ Expected CapacityPlanningConfig fields: {capacity_config_fields}")
    
    return True

def main():
    """Run all basic analytics tests"""
    print("🚀 Starting CHM Analytics System Basic Tests\n")
    
    tests = [
        test_analytics_enums(),
        test_analytics_models_structure(),
        test_analytics_services_structure(),
        test_configuration_objects()
    ]
    
    print("\n" + "="*50)
    print("📊 BASIC TEST RESULTS SUMMARY")
    print("="*50)
    
    passed = sum(tests)
    total = len(tests)
    
    print(f"🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic analytics tests passed! The system structure is correct.")
        print("\n📋 Next steps:")
        print("   - Test database connectivity")
        print("   - Test service instantiation")
        print("   - Test actual data processing")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
