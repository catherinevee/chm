"""
Advanced Test Runner with Comprehensive Coverage and Performance Monitoring
Optimized test execution with detailed reporting and analysis
"""

import asyncio
import sys
import time
import json
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import pytest
import coverage
from dataclasses import dataclass, asdict


@dataclass
class TestResult:
    """Test result data structure"""
    name: str
    status: str  # passed, failed, skipped, error
    duration: float
    file_path: str
    line_number: int
    error_message: Optional[str] = None
    error_traceback: Optional[str] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


@dataclass
class CoverageResult:
    """Coverage result data structure"""
    total_statements: int
    covered_statements: int
    missing_statements: int
    coverage_percentage: float
    branch_coverage: Optional[float] = None
    files: Dict[str, Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.files is None:
            self.files = {}


@dataclass
class PerformanceMetric:
    """Performance metric data structure"""
    operation: str
    duration: float
    memory_usage: Optional[float] = None
    cpu_usage: Optional[float] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class TestExecutionMonitor:
    """Monitor test execution for performance and reliability metrics"""
    
    def __init__(self):
        self.test_results: List[TestResult] = []
        self.performance_metrics: List[PerformanceMetric] = []
        self.coverage_history: List[CoverageResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    def start_monitoring(self):
        """Start monitoring test execution"""
        self.start_time = datetime.utcnow()
        self.test_results.clear()
        self.performance_metrics.clear()
    
    def stop_monitoring(self):
        """Stop monitoring test execution"""
        self.end_time = datetime.utcnow()
    
    def record_test_result(self, result: TestResult):
        """Record a test result"""
        self.test_results.append(result)
    
    def record_performance_metric(self, metric: PerformanceMetric):
        """Record a performance metric"""
        self.performance_metrics.append(metric)
    
    def record_coverage_result(self, result: CoverageResult):
        """Record coverage result"""
        self.coverage_history.append(result)
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get comprehensive execution summary"""
        if not self.start_time or not self.end_time:
            return {"error": "Monitoring not properly started/stopped"}
        
        total_duration = (self.end_time - self.start_time).total_seconds()
        
        # Test statistics
        total_tests = len(self.test_results)
        passed_tests = len([r for r in self.test_results if r.status == "passed"])
        failed_tests = len([r for r in self.test_results if r.status == "failed"])
        skipped_tests = len([r for r in self.test_results if r.status == "skipped"])
        error_tests = len([r for r in self.test_results if r.status == "error"])
        
        # Performance statistics
        avg_test_duration = sum(r.duration for r in self.test_results) / total_tests if total_tests > 0 else 0
        slowest_test = max(self.test_results, key=lambda x: x.duration) if self.test_results else None
        fastest_test = min(self.test_results, key=lambda x: x.duration) if self.test_results else None
        
        # Coverage statistics
        latest_coverage = self.coverage_history[-1] if self.coverage_history else None
        
        return {
            "execution_summary": {
                "total_duration": total_duration,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat()
            },
            "test_statistics": {
                "total_tests": total_tests,
                "passed_tests": passed_tests,
                "failed_tests": failed_tests,
                "skipped_tests": skipped_tests,
                "error_tests": error_tests,
                "pass_rate": (passed_tests / total_tests) * 100 if total_tests > 0 else 0,
                "failure_rate": (failed_tests / total_tests) * 100 if total_tests > 0 else 0
            },
            "performance_statistics": {
                "average_test_duration": avg_test_duration,
                "slowest_test": {
                    "name": slowest_test.name,
                    "duration": slowest_test.duration
                } if slowest_test else None,
                "fastest_test": {
                    "name": fastest_test.name,
                    "duration": fastest_test.duration
                } if fastest_test else None,
                "total_performance_metrics": len(self.performance_metrics)
            },
            "coverage_statistics": {
                "coverage_percentage": latest_coverage.coverage_percentage if latest_coverage else 0,
                "total_statements": latest_coverage.total_statements if latest_coverage else 0,
                "covered_statements": latest_coverage.covered_statements if latest_coverage else 0,
                "missing_statements": latest_coverage.missing_statements if latest_coverage else 0
            }
        }
    
    def get_failed_tests_report(self) -> List[Dict[str, Any]]:
        """Get detailed report of failed tests"""
        failed_tests = [r for r in self.test_results if r.status in ["failed", "error"]]
        return [
            {
                "name": test.name,
                "status": test.status,
                "file_path": test.file_path,
                "line_number": test.line_number,
                "error_message": test.error_message,
                "duration": test.duration,
                "timestamp": test.timestamp.isoformat()
            }
            for test in failed_tests
        ]
    
    def export_results(self, output_file: Path):
        """Export results to JSON file"""
        results = {
            "summary": self.get_execution_summary(),
            "failed_tests": self.get_failed_tests_report(),
            "all_test_results": [asdict(result) for result in self.test_results],
            "performance_metrics": [asdict(metric) for metric in self.performance_metrics],
            "coverage_history": [asdict(cov) for cov in self.coverage_history]
        }
        
        # Convert datetime objects to ISO format strings
        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            elif isinstance(obj, dict):
                return {k: convert_datetime(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_datetime(item) for item in obj]
            return obj
        
        results = convert_datetime(results)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)


class AdvancedTestRunner:
    """Advanced test runner with comprehensive monitoring and reporting"""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.tests_dir = project_root / "tests"
        self.monitor = TestExecutionMonitor()
        self.coverage_config_file = project_root / ".coveragerc"
        
    def create_coverage_config(self):
        """Create comprehensive coverage configuration"""
        config_content = """
[run]
source = backend
omit = 
    */tests/*
    */test_*
    */conftest.py
    */venv/*
    */env/*
    */__pycache__/*
    */migrations/*
    */scripts/*
    */docs/*
    */htmlcov/*
    setup.py
    
branch = True
parallel = True

[report]
exclude_lines =
    pragma: no cover
    def __repr__
    if self.debug:
    if settings.DEBUG
    raise AssertionError
    raise NotImplementedError
    if 0:
    if __name__ == .__main__.:
    class .*\\bProtocol\\):
    @(abc\\.)?abstractmethod
    
show_missing = True
skip_covered = False
precision = 2

[html]
directory = htmlcov
title = CHM Coverage Report

[xml]
output = coverage.xml
"""
        
        with open(self.coverage_config_file, 'w') as f:
            f.write(config_content.strip())
    
    async def run_test_suite(
        self,
        test_patterns: List[str] = None,
        coverage_enabled: bool = True,
        parallel_execution: bool = True,
        verbose: bool = True,
        generate_reports: bool = True
    ) -> Dict[str, Any]:
        """Run comprehensive test suite with monitoring"""
        
        print("🚀 Starting Advanced CHM Test Suite")
        print(f"Project Root: {self.project_root}")
        print(f"Tests Directory: {self.tests_dir}")
        
        self.monitor.start_monitoring()
        
        try:
            # Create coverage configuration
            if coverage_enabled:
                self.create_coverage_config()
                print("📊 Coverage configuration created")
            
            # Prepare pytest arguments
            pytest_args = self._prepare_pytest_args(
                test_patterns, coverage_enabled, parallel_execution, verbose
            )
            
            print(f"🔧 Running pytest with args: {' '.join(pytest_args)}")
            
            # Run tests
            start_time = time.time()
            return_code = pytest.main(pytest_args)
            end_time = time.time()
            
            # Record performance metric
            execution_metric = PerformanceMetric(
                operation="full_test_suite",
                duration=end_time - start_time
            )
            self.monitor.record_performance_metric(execution_metric)
            
            # Generate coverage report if enabled
            if coverage_enabled:
                await self._generate_coverage_report()
            
            # Generate comprehensive reports
            if generate_reports:
                await self._generate_comprehensive_reports()
            
            self.monitor.stop_monitoring()
            
            # Print summary
            summary = self.monitor.get_execution_summary()
            self._print_execution_summary(summary, return_code)
            
            return {
                "return_code": return_code,
                "summary": summary,
                "success": return_code == 0
            }
            
        except Exception as e:
            self.monitor.stop_monitoring()
            print(f"❌ Test execution failed: {str(e)}")
            return {
                "return_code": 1,
                "error": str(e),
                "success": False
            }
    
    def _prepare_pytest_args(
        self,
        test_patterns: List[str] = None,
        coverage_enabled: bool = True,
        parallel_execution: bool = True,
        verbose: bool = True
    ) -> List[str]:
        """Prepare pytest command line arguments"""
        args = []
        
        # Test patterns
        if test_patterns:
            args.extend(test_patterns)
        else:
            args.append(str(self.tests_dir))
        
        # Verbosity
        if verbose:
            args.append("-v")
        
        # Coverage
        if coverage_enabled:
            args.extend([
                "--cov=backend",
                "--cov-config=.coveragerc",
                "--cov-report=term-missing",
                "--cov-report=html:htmlcov",
                "--cov-report=xml:coverage.xml",
                "--cov-branch"
            ])
        
        # Parallel execution
        if parallel_execution:
            import os
            cpu_count = os.cpu_count() or 1
            args.extend(["-n", str(min(cpu_count, 4))])  # Limit to 4 workers max
        
        # Additional options
        args.extend([
            "--tb=short",  # Short traceback format
            "--strict-markers",  # Strict marker checking
            "--durations=10",  # Show 10 slowest tests
            "--maxfail=5",  # Stop after 5 failures
            "-ra"  # Show short test summary for all
        ])
        
        return args
    
    async def _generate_coverage_report(self):
        """Generate detailed coverage report"""
        try:
            # Load coverage data
            cov = coverage.Coverage(config_file=str(self.coverage_config_file))
            cov.load()
            
            # Get coverage statistics
            total_statements = 0
            covered_statements = 0
            missing_statements = 0
            files_coverage = {}
            
            for filename in cov.get_data().measured_files():
                analysis = cov.analysis2(filename)
                file_total = len(analysis.statements)
                file_missing = len(analysis.missing)
                file_covered = file_total - file_missing
                
                total_statements += file_total
                covered_statements += file_covered
                missing_statements += file_missing
                
                files_coverage[filename] = {
                    "total_statements": file_total,
                    "covered_statements": file_covered,
                    "missing_statements": file_missing,
                    "coverage_percentage": (file_covered / file_total) * 100 if file_total > 0 else 0,
                    "missing_lines": list(analysis.missing)
                }
            
            coverage_percentage = (covered_statements / total_statements) * 100 if total_statements > 0 else 0
            
            coverage_result = CoverageResult(
                total_statements=total_statements,
                covered_statements=covered_statements,
                missing_statements=missing_statements,
                coverage_percentage=coverage_percentage,
                files=files_coverage
            )
            
            self.monitor.record_coverage_result(coverage_result)
            print(f"📈 Coverage recorded: {coverage_percentage:.2f}%")
            
        except Exception as e:
            print(f"⚠️ Coverage report generation failed: {str(e)}")
    
    async def _generate_comprehensive_reports(self):
        """Generate comprehensive test reports"""
        try:
            reports_dir = self.project_root / "test_reports"
            reports_dir.mkdir(exist_ok=True)
            
            # Export detailed results
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            results_file = reports_dir / f"test_results_{timestamp}.json"
            self.monitor.export_results(results_file)
            
            # Generate HTML report
            html_report = self._generate_html_report()
            html_file = reports_dir / f"test_report_{timestamp}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            print(f"📋 Comprehensive reports generated in: {reports_dir}")
            print(f"   - JSON Report: {results_file}")
            print(f"   - HTML Report: {html_file}")
            
        except Exception as e:
            print(f"⚠️ Report generation failed: {str(e)}")
    
    def _generate_html_report(self) -> str:
        """Generate HTML test report"""
        summary = self.monitor.get_execution_summary()
        failed_tests = self.monitor.get_failed_tests_report()
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CHM Test Execution Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .card {{ background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .metric {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .success {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .error {{ color: #dc3545; }}
        .failed-test {{ background: #f8d7da; border-left: 4px solid #dc3545; padding: 10px; margin: 10px 0; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f8f9fa; font-weight: 600; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🧪 CHM Test Execution Report</h1>
        <p>Generated on {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </div>
    
    <div class="summary">
        <div class="card">
            <h3>Test Statistics</h3>
            <div class="metric success">{summary['test_statistics']['passed_tests']}</div>
            <p>Tests Passed</p>
        </div>
        
        <div class="card">
            <h3>Coverage</h3>
            <div class="metric">{summary['coverage_statistics']['coverage_percentage']:.1f}%</div>
            <p>Code Coverage</p>
        </div>
        
        <div class="card">
            <h3>Execution Time</h3>
            <div class="metric">{summary['execution_summary']['total_duration']:.2f}s</div>
            <p>Total Duration</p>
        </div>
        
        <div class="card">
            <h3>Pass Rate</h3>
            <div class="metric {'success' if summary['test_statistics']['pass_rate'] >= 90 else 'warning' if summary['test_statistics']['pass_rate'] >= 70 else 'error'}">{summary['test_statistics']['pass_rate']:.1f}%</div>
            <p>Success Rate</p>
        </div>
    </div>
"""
        
        if failed_tests:
            html += f"""
    <h2>❌ Failed Tests ({len(failed_tests)})</h2>
"""
            for test in failed_tests:
                html += f"""
    <div class="failed-test">
        <h4>{test['name']}</h4>
        <p><strong>File:</strong> {test['file_path']}:{test['line_number']}</p>
        <p><strong>Error:</strong> {test['error_message'] or 'No error message'}</p>
        <p><strong>Duration:</strong> {test['duration']:.3f}s</p>
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
    
    def _print_execution_summary(self, summary: Dict[str, Any], return_code: int):
        """Print execution summary to console"""
        print("\n" + "="*80)
        print("🧪 CHM TEST EXECUTION SUMMARY")
        print("="*80)
        
        # Test statistics
        test_stats = summary['test_statistics']
        print(f"📊 Tests: {test_stats['total_tests']} total")
        print(f"   ✅ Passed: {test_stats['passed_tests']}")
        print(f"   ❌ Failed: {test_stats['failed_tests']}")
        print(f"   ⏭️  Skipped: {test_stats['skipped_tests']}")
        print(f"   ⚠️  Errors: {test_stats['error_tests']}")
        print(f"   📈 Pass Rate: {test_stats['pass_rate']:.1f}%")
        
        # Coverage statistics
        cov_stats = summary['coverage_statistics']
        print(f"\n📈 Coverage: {cov_stats['coverage_percentage']:.2f}%")
        print(f"   📝 Total Statements: {cov_stats['total_statements']}")
        print(f"   ✅ Covered: {cov_stats['covered_statements']}")
        print(f"   ❌ Missing: {cov_stats['missing_statements']}")
        
        # Performance statistics
        perf_stats = summary['performance_statistics']
        exec_stats = summary['execution_summary']
        print(f"\n⚡ Performance:")
        print(f"   ⏱️  Total Duration: {exec_stats['total_duration']:.2f}s")
        print(f"   📊 Avg Test Duration: {perf_stats['average_test_duration']:.3f}s")
        
        if perf_stats['slowest_test']:
            print(f"   🐌 Slowest Test: {perf_stats['slowest_test']['name']} ({perf_stats['slowest_test']['duration']:.3f}s)")
        
        # Final status
        print(f"\n🎯 FINAL RESULT: {'✅ SUCCESS' if return_code == 0 else '❌ FAILURE'}")
        print("="*80)


async def main():
    """Main entry point for advanced test runner"""
    project_root = Path(__file__).parent.parent.parent
    runner = AdvancedTestRunner(project_root)
    
    # Configuration
    test_patterns = []  # Run all tests
    coverage_enabled = True
    parallel_execution = True
    verbose = True
    generate_reports = True
    
    # Override with command line arguments if needed
    if len(sys.argv) > 1:
        if "--no-coverage" in sys.argv:
            coverage_enabled = False
        if "--no-parallel" in sys.argv:
            parallel_execution = False
        if "--quiet" in sys.argv:
            verbose = False
        if "--no-reports" in sys.argv:
            generate_reports = False
    
    # Run the test suite
    result = await runner.run_test_suite(
        test_patterns=test_patterns,
        coverage_enabled=coverage_enabled,
        parallel_execution=parallel_execution,
        verbose=verbose,
        generate_reports=generate_reports
    )
    
    # Exit with appropriate code
    sys.exit(result["return_code"])


if __name__ == "__main__":
    asyncio.run(main())