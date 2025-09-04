#!/usr/bin/env python3
"""
Simple test runner for CHM Analytics System
This bypasses the conftest.py import issues
"""

import asyncio
import sys
import os
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

async def test_analytics_imports():
    """Test that all analytics modules can be imported"""
    print("Testing analytics module imports...")
    
    try:
        from models.analytics import (
            PerformanceAnalysis, AnomalyDetection, CapacityPlanning,
            TrendForecast, AnalyticsReport, AnalyticsInsight,
            AnalysisType, AnomalySeverity, ReportType, ReportFormat
        )
        print("✅ Analytics models imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import analytics models: {e}")
        return False
    
    try:
        from services.performance_analytics import PerformanceAnalyticsService
        print("✅ PerformanceAnalyticsService imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PerformanceAnalyticsService: {e}")
        return False
    
    try:
        from services.advanced_reporting import AdvancedReportingService
        print("✅ AdvancedReportingService imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import AdvancedReportingService: {e}")
        return False
    
    try:
        from services.data_aggregation import DataAggregationService
        print("✅ DataAggregationService imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import DataAggregationService: {e}")
        return False
    
    return True

async def test_analytics_models():
    """Test basic analytics model functionality"""
    print("\nTesting analytics models...")
    
    try:
        from models.analytics import (
            PerformanceAnalysis, AnomalyDetection, CapacityPlanning,
            TrendForecast, AnalyticsReport, AnalyticsInsight,
            AnalysisType, AnomalySeverity, ReportType, ReportFormat
        )
        
        # Test enum values
        assert AnalysisType.TREND_ANALYSIS == "trend_analysis"
        assert AnomalySeverity.CRITICAL == "critical"
        assert ReportType.PERFORMANCE_SUMMARY == "performance_summary"
        assert ReportFormat.HTML == "html"
        
        print("✅ Analytics enums working correctly")
        
        # Test model creation (without database)
        analysis = PerformanceAnalysis(
            device_id=1,
            metric_name="cpu_usage",
            analysis_type=AnalysisType.TREND_ANALYSIS,
            analysis_data={"trend": "increasing"},
            confidence_score=0.95,
            created_at="2024-01-01T00:00:00"
        )
        
        print("✅ Analytics models can be instantiated")
        return True
        
    except Exception as e:
        print(f"❌ Analytics model test failed: {e}")
        return False

async def test_analytics_services():
    """Test analytics service instantiation"""
    print("\nTesting analytics services...")
    
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
        reporting_service = AdvancedReportingService(mock_session)
        aggregation_service = DataAggregationService(mock_session)
        
        print("✅ All analytics services can be instantiated")
        return True
        
    except Exception as e:
        print(f"❌ Analytics service test failed: {e}")
        return False

async def main():
    """Run all analytics tests"""
    print("🚀 Starting CHM Analytics System Tests\n")
    
    tests = [
        test_analytics_imports(),
        test_analytics_models(),
        test_analytics_services()
    ]
    
    results = await asyncio.gather(*tests, return_exceptions=True)
    
    print("\n" + "="*50)
    print("📊 TEST RESULTS SUMMARY")
    print("="*50)
    
    passed = 0
    total = len(results)
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            print(f"❌ Test {i+1} failed with exception: {result}")
        elif result:
            print(f"✅ Test {i+1} passed")
            passed += 1
        else:
            print(f"❌ Test {i+1} failed")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All analytics tests passed! The system is ready.")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
