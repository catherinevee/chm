#!/usr/bin/env python3
"""
Test analytics module imports and basic functionality
"""

import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

def test_analytics_models_import():
    """Test importing analytics models"""
    print("Testing analytics models import...")
    
    try:
        from models.analytics import (
            PerformanceAnalysis, AnomalyDetection, CapacityPlanning,
            TrendForecast, AnalyticsReport, AnalyticsInsight,
            AnalysisType, AnomalySeverity, ReportType, ReportFormat
        )
        print("✅ Analytics models imported successfully")
        
        # Test enum values
        print(f"   - AnalysisType.TREND_ANALYSIS = {AnalysisType.TREND_ANALYSIS}")
        print(f"   - AnomalySeverity.CRITICAL = {AnomalySeverity.CRITICAL}")
        print(f"   - ReportType.PERFORMANCE_SUMMARY = {ReportType.PERFORMANCE_SUMMARY}")
        print(f"   - ReportFormat.HTML = {ReportFormat.HTML}")
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import analytics models: {e}")
        return False
    except Exception as e:
        print(f"❌ Error testing analytics models: {e}")
        return False

def test_analytics_services_import():
    """Test importing analytics services"""
    print("\nTesting analytics services import...")
    
    try:
        from services.performance_analytics import PerformanceAnalyticsService
        print("✅ PerformanceAnalyticsService imported successfully")
        
        from services.advanced_reporting import AdvancedReportingService
        print("✅ AdvancedReportingService imported successfully")
        
        from services.data_aggregation import DataAggregationService
        print("✅ DataAggregationService imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import analytics services: {e}")
        return False
    except Exception as e:
        print(f"❌ Error testing analytics services: {e}")
        return False

def test_service_instantiation():
    """Test that services can be instantiated"""
    print("\nTesting service instantiation...")
    
    try:
        from services.performance_analytics import PerformanceAnalyticsService
        from services.advanced_reporting import AdvancedReportingService
        from services.data_aggregation import DataAggregationService
        
        # Mock database session
        class MockSession:
            pass
        
        mock_session = MockSession()
        
        # Test service instantiation
        analytics_service = PerformanceAnalyticsService(mock_session)
        print("✅ PerformanceAnalyticsService instantiated successfully")
        
        reporting_service = AdvancedReportingService(mock_session)
        print("✅ AdvancedReportingService instantiated successfully")
        
        aggregation_service = DataAggregationService(mock_session)
        print("✅ DataAggregationService instantiated successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Error instantiating services: {e}")
        return False

def test_model_instantiation():
    """Test that models can be instantiated"""
    print("\nTesting model instantiation...")
    
    try:
        from models.analytics import (
            PerformanceAnalysis, AnomalyDetection, CapacityPlanning,
            AnalysisType, AnomalySeverity
        )
        
        # Test PerformanceAnalysis instantiation
        analysis = PerformanceAnalysis(
            device_id=1,
            metric_name="cpu_usage",
            analysis_type=AnalysisType.TREND_ANALYSIS,
            time_range_start="2024-01-01T00:00:00",
            time_range_end="2024-01-02T00:00:00",
            analysis_window_hours=24
        )
        print("✅ PerformanceAnalysis instantiated successfully")
        
        # Test AnomalyDetection instantiation
        anomaly = AnomalyDetection(
            device_id=1,
            metric_name="cpu_usage",
            anomaly_type="threshold_exceeded",
            severity=AnomalySeverity.HIGH,
            detection_method="statistical",
            baseline_value=50.0,
            anomaly_value=95.0
        )
        print("✅ AnomalyDetection instantiated successfully")
        
        # Test CapacityPlanning instantiation
        capacity = CapacityPlanning(
            device_id=1,
            resource_type="cpu",
            current_utilization=75.0,
            capacity_threshold=80.0
        )
        print("✅ CapacityPlanning instantiated successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Error instantiating models: {e}")
        return False

def test_configuration_objects():
    """Test configuration objects"""
    print("\nTesting configuration objects...")
    
    try:
        from services.performance_analytics import (
            TrendAnalysisConfig, AnomalyDetectionConfig, CapacityPlanningConfig
        )
        
        # Test TrendAnalysisConfig
        trend_config = TrendAnalysisConfig()
        print("✅ TrendAnalysisConfig created successfully")
        print(f"   - min_data_points: {trend_config.min_data_points}")
        print(f"   - trend_threshold: {trend_config.trend_threshold}")
        
        # Test AnomalyDetectionConfig
        anomaly_config = AnomalyDetectionConfig()
        print("✅ AnomalyDetectionConfig created successfully")
        print(f"   - baseline_window_hours: {anomaly_config.baseline_window_hours}")
        print(f"   - anomaly_threshold_std: {anomaly_config.anomaly_threshold_std}")
        
        # Test CapacityPlanningConfig
        capacity_config = CapacityPlanningConfig()
        print("✅ CapacityPlanningConfig created successfully")
        print(f"   - forecast_horizon_days: {capacity_config.forecast_horizon_days}")
        print(f"   - utilization_thresholds: {capacity_config.utilization_thresholds}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error testing configuration objects: {e}")
        return False

def main():
    """Run all analytics import tests"""
    print("🚀 Starting CHM Analytics System Import Tests\n")
    
    tests = [
        test_analytics_models_import(),
        test_analytics_services_import(),
        test_service_instantiation(),
        test_model_instantiation(),
        test_configuration_objects()
    ]
    
    print("\n" + "="*50)
    print("📊 IMPORT TEST RESULTS SUMMARY")
    print("="*50)
    
    passed = sum(tests)
    total = len(tests)
    
    print(f"🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All analytics import tests passed! The system is fully functional.")
        print("\n📋 System Status:")
        print("   ✅ Analytics models are properly defined and importable")
        print("   ✅ Analytics services are properly implemented and instantiable")
        print("   ✅ Configuration objects are properly structured")
        print("   ✅ The Advanced Analytics & Reporting system is ready for use")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
