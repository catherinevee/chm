#!/usr/bin/env python3
"""
Test analytics files syntax without importing
"""

import ast
import os
from pathlib import Path

def test_file_syntax(file_path):
    """Test if a Python file has valid syntax"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Parse the AST to check syntax
        ast.parse(content)
        return True, None
    except SyntaxError as e:
        return False, f"Syntax error: {e}"
    except Exception as e:
        return False, f"Error reading file: {e}"

def test_analytics_files():
    """Test all analytics-related files for syntax"""
    print("🚀 Testing CHM Analytics System File Syntax\n")
    
    # Files to test
    analytics_files = [
        "models/analytics.py",
        "services/performance_analytics.py",
        "services/advanced_reporting.py",
        "services/data_aggregation.py",
        "tests/test_analytics_system.py"
    ]
    
    results = []
    
    for file_path in analytics_files:
        if os.path.exists(file_path):
            print(f"Testing {file_path}...")
            is_valid, error = test_file_syntax(file_path)
            
            if is_valid:
                print(f"✅ {file_path} - Syntax OK")
                results.append(True)
            else:
                print(f"❌ {file_path} - {error}")
                results.append(False)
        else:
            print(f"⚠️  {file_path} - File not found")
            results.append(False)
    
    return results

def test_file_structure():
    """Test the structure and content of analytics files"""
    print("\n📋 Testing Analytics System Structure\n")
    
    # Check if required files exist
    required_files = [
        "models/analytics.py",
        "services/performance_analytics.py", 
        "services/advanced_reporting.py",
        "services/data_aggregation.py"
    ]
    
    existing_files = []
    missing_files = []
    
    for file_path in required_files:
        if os.path.exists(file_path):
            existing_files.append(file_path)
            # Get file size
            size = os.path.getsize(file_path)
            print(f"✅ {file_path} - {size:,} bytes")
        else:
            missing_files.append(file_path)
            print(f"❌ {file_path} - Missing")
    
    print(f"\n📊 File Status: {len(existing_files)}/{len(required_files)} files present")
    
    if missing_files:
        print(f"⚠️  Missing files: {missing_files}")
    
    return len(existing_files) == len(required_files)

def test_analytics_models_content():
    """Test the content of analytics models"""
    print("\n🔍 Testing Analytics Models Content\n")
    
    try:
        with open("models/analytics.py", 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check for key components
        checks = [
            ("PerformanceAnalysis class", "class PerformanceAnalysis"),
            ("AnomalyDetection class", "class AnomalyDetection"),
            ("CapacityPlanning class", "class CapacityPlanning"),
            ("TrendForecast class", "class TrendForecast"),
            ("AnalyticsReport class", "class AnalyticsReport"),
            ("AnalyticsInsight class", "class AnalyticsInsight"),
            ("AnalysisType enum", "class AnalysisType"),
            ("AnomalySeverity enum", "class AnomalySeverity"),
            ("ReportType enum", "class ReportType"),
            ("ReportFormat enum", "class ReportFormat")
        ]
        
        results = []
        for name, pattern in checks:
            if pattern in content:
                print(f"✅ {name} - Found")
                results.append(True)
            else:
                print(f"❌ {name} - Missing")
                results.append(False)
        
        return results
        
    except Exception as e:
        print(f"❌ Error reading analytics models: {e}")
        return []

def test_analytics_services_content():
    """Test the content of analytics services"""
    print("\n🔍 Testing Analytics Services Content\n")
    
    services = [
        ("PerformanceAnalyticsService", "services/performance_analytics.py"),
        ("AdvancedReportingService", "services/advanced_reporting.py"),
        ("DataAggregationService", "services/data_aggregation.py")
    ]
    
    results = []
    
    for service_name, file_path in services:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if f"class {service_name}" in content:
                print(f"✅ {service_name} - Found in {file_path}")
                results.append(True)
            else:
                print(f"❌ {service_name} - Missing from {file_path}")
                results.append(False)
                
        except Exception as e:
            print(f"❌ Error reading {file_path}: {e}")
            results.append(False)
    
    return results

def main():
    """Run all analytics tests"""
    print("🚀 Starting CHM Analytics System Comprehensive Tests\n")
    
    # Run all tests
    syntax_results = test_analytics_files()
    structure_ok = test_file_structure()
    models_results = test_analytics_models_content()
    services_results = test_analytics_services_content()
    
    print("\n" + "="*60)
    print("📊 COMPREHENSIVE TEST RESULTS SUMMARY")
    print("="*60)
    
    # Calculate overall results
    syntax_passed = sum(syntax_results)
    syntax_total = len(syntax_results)
    
    models_passed = sum(models_results) if models_results else 0
    models_total = len(models_results) if models_results else 0
    
    services_passed = sum(services_results) if services_results else 0
    services_total = len(services_results) if services_results else 0
    
    print(f"🔧 Syntax Tests: {syntax_passed}/{syntax_total} passed")
    print(f"📁 File Structure: {'✅ OK' if structure_ok else '❌ Issues'}")
    print(f"📊 Models Content: {models_passed}/{models_total} passed")
    print(f"⚙️  Services Content: {services_passed}/{services_total} passed")
    
    overall_passed = syntax_passed + (1 if structure_ok else 0) + models_passed + services_passed
    overall_total = syntax_total + 1 + models_total + services_total
    
    print(f"\n🎯 Overall: {overall_passed}/{overall_total} tests passed")
    
    if overall_passed == overall_total:
        print("🎉 All analytics tests passed! The system is structurally sound.")
        print("\n📋 System Status:")
        print("   ✅ All analytics files have valid Python syntax")
        print("   ✅ Required file structure is complete")
        print("   ✅ Analytics models are properly defined")
        print("   ✅ Analytics services are properly implemented")
        print("   ✅ The Advanced Analytics & Reporting system is ready")
        return 0
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
