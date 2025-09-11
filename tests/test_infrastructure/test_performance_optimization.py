"""
Test Performance Optimization and Analysis
Tools for optimizing test execution speed and identifying bottlenecks
"""

import asyncio
import time
import psutil
# import memory_profiler  # Optional dependency
from datetime import datetime, timedelta
from typing import Dict, List, Any, Callable, Optional
from dataclasses import dataclass, field
from functools import wraps
import pytest
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class PerformanceProfile:
    """Performance profile for a test or operation"""
    name: str
    duration: float
    memory_usage_mb: float
    cpu_percent: float
    disk_io_reads: int = 0
    disk_io_writes: int = 0
    network_io_sent: int = 0
    network_io_recv: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "name": self.name,
            "duration": self.duration,
            "memory_usage_mb": self.memory_usage_mb,
            "cpu_percent": self.cpu_percent,
            "disk_io_reads": self.disk_io_reads,
            "disk_io_writes": self.disk_io_writes,
            "network_io_sent": self.network_io_sent,
            "network_io_recv": self.network_io_recv,
            "timestamp": self.timestamp.isoformat()
        }


class PerformanceProfiler:
    """Advanced performance profiler for tests"""
    
    def __init__(self):
        self.profiles: List[PerformanceProfile] = []
        self.active_profiles: Dict[str, Dict[str, Any]] = {}
        self.process = psutil.Process()
        
    def start_profiling(self, name: str) -> str:
        """Start profiling an operation"""
        profile_id = f"{name}_{int(time.time() * 1000)}"
        
        # Get initial system stats
        cpu_percent = self.process.cpu_percent()
        memory_info = self.process.memory_info()
        io_counters = self.process.io_counters() if hasattr(self.process, 'io_counters') else None
        
        self.active_profiles[profile_id] = {
            "name": name,
            "start_time": time.time(),
            "start_memory": memory_info.rss / 1024 / 1024,  # MB
            "start_cpu": cpu_percent,
            "start_io": io_counters
        }
        
        return profile_id
    
    def stop_profiling(self, profile_id: str) -> PerformanceProfile:
        """Stop profiling and return the profile"""
        if profile_id not in self.active_profiles:
            raise ValueError(f"No active profile found for ID: {profile_id}")
        
        start_data = self.active_profiles[profile_id]
        end_time = time.time()
        
        # Get final system stats
        memory_info = self.process.memory_info()
        io_counters = self.process.io_counters() if hasattr(self.process, 'io_counters') else None
        
        # Calculate metrics
        duration = end_time - start_data["start_time"]
        memory_usage = memory_info.rss / 1024 / 1024  # MB
        cpu_percent = self.process.cpu_percent()
        
        # Calculate I/O differences
        disk_reads = 0
        disk_writes = 0
        if io_counters and start_data["start_io"]:
            disk_reads = io_counters.read_count - start_data["start_io"].read_count
            disk_writes = io_counters.write_count - start_data["start_io"].write_count
        
        profile = PerformanceProfile(
            name=start_data["name"],
            duration=duration,
            memory_usage_mb=memory_usage,
            cpu_percent=cpu_percent,
            disk_io_reads=disk_reads,
            disk_io_writes=disk_writes
        )
        
        self.profiles.append(profile)
        del self.active_profiles[profile_id]
        
        return profile
    
    def profile_function(self, func: Callable, *args, **kwargs) -> tuple:
        """Profile a function execution"""
        profile_id = self.start_profiling(func.__name__)
        
        try:
            result = func(*args, **kwargs)
            return result, self.stop_profiling(profile_id)
        except Exception as e:
            self.stop_profiling(profile_id)
            raise e
    
    async def profile_async_function(self, func: Callable, *args, **kwargs) -> tuple:
        """Profile an async function execution"""
        profile_id = self.start_profiling(func.__name__)
        
        try:
            result = await func(*args, **kwargs)
            return result, self.stop_profiling(profile_id)
        except Exception as e:
            self.stop_profiling(profile_id)
            raise e
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary"""
        if not self.profiles:
            return {"message": "No performance data available"}
        
        # Calculate statistics
        durations = [p.duration for p in self.profiles]
        memory_usages = [p.memory_usage_mb for p in self.profiles]
        cpu_usages = [p.cpu_percent for p in self.profiles]
        
        return {
            "total_operations": len(self.profiles),
            "duration_stats": {
                "total": sum(durations),
                "average": sum(durations) / len(durations),
                "min": min(durations),
                "max": max(durations),
                "median": sorted(durations)[len(durations) // 2]
            },
            "memory_stats": {
                "average_mb": sum(memory_usages) / len(memory_usages),
                "peak_mb": max(memory_usages),
                "min_mb": min(memory_usages)
            },
            "cpu_stats": {
                "average_percent": sum(cpu_usages) / len(cpu_usages),
                "peak_percent": max(cpu_usages),
                "min_percent": min(cpu_usages)
            },
            "slowest_operations": sorted(
                [{"name": p.name, "duration": p.duration} for p in self.profiles],
                key=lambda x: x["duration"],
                reverse=True
            )[:10]
        }
    
    def export_profiles(self) -> List[Dict[str, Any]]:
        """Export all profiles as JSON-serializable data"""
        return [profile.to_dict() for profile in self.profiles]


def performance_monitor(name: Optional[str] = None):
    """Decorator for monitoring function performance"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            profiler = PerformanceProfiler()
            monitor_name = name or func.__name__
            
            result, profile = profiler.profile_function(func, *args, **kwargs)
            
            # Store profile in global storage or log it
            if hasattr(func, '_performance_profiles'):
                func._performance_profiles.append(profile)
            else:
                func._performance_profiles = [profile]
            
            return result
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            profiler = PerformanceProfiler()
            monitor_name = name or func.__name__
            
            result, profile = await profiler.profile_async_function(func, *args, **kwargs)
            
            # Store profile in global storage or log it
            if hasattr(func, '_performance_profiles'):
                func._performance_profiles.append(profile)
            else:
                func._performance_profiles = [profile]
            
            return result
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return wrapper
    
    return decorator


class TestOptimizer:
    """Optimize test execution and identify bottlenecks"""
    
    def __init__(self):
        self.test_timings: Dict[str, List[float]] = {}
        self.slow_tests: List[Dict[str, Any]] = []
        self.optimization_suggestions: List[str] = []
        
    def record_test_timing(self, test_name: str, duration: float):
        """Record test execution timing"""
        if test_name not in self.test_timings:
            self.test_timings[test_name] = []
        
        self.test_timings[test_name].append(duration)
        
        # Flag slow tests (> 5 seconds)
        if duration > 5.0:
            self.slow_tests.append({
                "test_name": test_name,
                "duration": duration,
                "timestamp": datetime.utcnow()
            })
    
    def analyze_test_performance(self) -> Dict[str, Any]:
        """Analyze test performance and provide optimization suggestions"""
        if not self.test_timings:
            return {"message": "No test timing data available"}
        
        analysis = {
            "total_tests": len(self.test_timings),
            "slow_tests_count": len(self.slow_tests),
            "slowest_tests": sorted(
                [(name, max(times)) for name, times in self.test_timings.items()],
                key=lambda x: x[1],
                reverse=True
            )[:10],
            "average_execution_times": {
                name: sum(times) / len(times)
                for name, times in self.test_timings.items()
            }
        }
        
        # Generate optimization suggestions
        suggestions = []
        
        # Check for consistently slow tests
        consistent_slow = [
            name for name, times in self.test_timings.items()
            if all(t > 2.0 for t in times)
        ]
        
        if consistent_slow:
            suggestions.append(
                f"Consider optimizing consistently slow tests: {', '.join(consistent_slow[:5])}"
            )
        
        # Check for database-heavy tests
        db_tests = [
            name for name in self.test_timings.keys()
            if 'database' in name.lower() or 'db' in name.lower()
        ]
        
        if db_tests:
            avg_db_time = sum(
                sum(self.test_timings[name]) / len(self.test_timings[name])
                for name in db_tests
            ) / len(db_tests)
            
            if avg_db_time > 1.0:
                suggestions.append(
                    "Database tests are slow. Consider using database fixtures with transactions."
                )
        
        # Check for tests that could benefit from parallelization
        parallelizable_tests = [
            name for name, times in self.test_timings.items()
            if max(times) > 3.0 and 'integration' not in name.lower()
        ]
        
        if parallelizable_tests:
            suggestions.append(
                "Consider running independent tests in parallel using pytest-xdist."
            )
        
        analysis["optimization_suggestions"] = suggestions
        self.optimization_suggestions.extend(suggestions)
        
        return analysis
    
    def generate_performance_report(self) -> str:
        """Generate a detailed performance report"""
        analysis = self.analyze_test_performance()
        
        if "message" in analysis:
            return analysis["message"]
        
        report = []
        report.append("🚀 TEST PERFORMANCE ANALYSIS REPORT")
        report.append("=" * 50)
        report.append(f"Total Tests Analyzed: {analysis['total_tests']}")
        report.append(f"Slow Tests (>5s): {analysis['slow_tests_count']}")
        report.append("")
        
        # Slowest tests
        report.append("🐌 SLOWEST TESTS:")
        for name, duration in analysis['slowest_tests']:
            report.append(f"  • {name}: {duration:.2f}s")
        report.append("")
        
        # Optimization suggestions
        if analysis['optimization_suggestions']:
            report.append("💡 OPTIMIZATION SUGGESTIONS:")
            for i, suggestion in enumerate(analysis['optimization_suggestions'], 1):
                report.append(f"  {i}. {suggestion}")
            report.append("")
        
        # Performance categories
        fast_tests = [name for name, avg_time in analysis['average_execution_times'].items() if avg_time < 0.5]
        medium_tests = [name for name, avg_time in analysis['average_execution_times'].items() if 0.5 <= avg_time < 2.0]
        slow_tests = [name for name, avg_time in analysis['average_execution_times'].items() if avg_time >= 2.0]
        
        report.append("📊 PERFORMANCE DISTRIBUTION:")
        report.append(f"  Fast (<0.5s): {len(fast_tests)} tests")
        report.append(f"  Medium (0.5-2s): {len(medium_tests)} tests")
        report.append(f"  Slow (>2s): {len(slow_tests)} tests")
        
        return "\n".join(report)


class ParallelTestRunner:
    """Run tests in parallel with optimal resource utilization"""
    
    def __init__(self, max_workers: Optional[int] = None):
        self.max_workers = max_workers or min(4, (psutil.cpu_count() or 1))
        self.results: List[Dict[str, Any]] = []
        
    async def run_tests_parallel(self, test_functions: List[Callable]) -> List[Dict[str, Any]]:
        """Run test functions in parallel"""
        semaphore = asyncio.Semaphore(self.max_workers)
        
        async def run_single_test(test_func):
            async with semaphore:
                profiler = PerformanceProfiler()
                profile_id = profiler.start_profiling(test_func.__name__)
                
                try:
                    start_time = time.time()
                    
                    if asyncio.iscoroutinefunction(test_func):
                        result = await test_func()
                    else:
                        result = test_func()
                    
                    end_time = time.time()
                    profile = profiler.stop_profiling(profile_id)
                    
                    return {
                        "test_name": test_func.__name__,
                        "status": "passed",
                        "duration": end_time - start_time,
                        "result": result,
                        "profile": profile.to_dict()
                    }
                    
                except Exception as e:
                    end_time = time.time()
                    profile = profiler.stop_profiling(profile_id)
                    
                    return {
                        "test_name": test_func.__name__,
                        "status": "failed",
                        "duration": end_time - start_time,
                        "error": str(e),
                        "profile": profile.to_dict()
                    }
        
        # Run all tests concurrently
        tasks = [run_single_test(test_func) for test_func in test_functions]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        
        self.results.extend(results)
        return results
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary of parallel execution"""
        if not self.results:
            return {"message": "No execution results available"}
        
        passed = len([r for r in self.results if r["status"] == "passed"])
        failed = len([r for r in self.results if r["status"] == "failed"])
        total_duration = sum(r["duration"] for r in self.results)
        
        return {
            "total_tests": len(self.results),
            "passed": passed,
            "failed": failed,
            "pass_rate": (passed / len(self.results)) * 100,
            "total_duration": total_duration,
            "average_duration": total_duration / len(self.results),
            "max_workers_used": self.max_workers
        }


# Pytest fixtures for performance monitoring

@pytest.fixture(scope="session")
def performance_profiler():
    """Session-scoped performance profiler"""
    return PerformanceProfiler()


@pytest.fixture(scope="session")
def test_optimizer():
    """Session-scoped test optimizer"""
    return TestOptimizer()


@pytest.fixture(autouse=True)
def monitor_test_performance_auto(request, test_optimizer):
    """Automatically monitor test performance"""
    start_time = time.time()
    
    yield
    
    end_time = time.time()
    duration = end_time - start_time
    
    test_optimizer.record_test_timing(request.node.name, duration)


@pytest.fixture
def parallel_runner():
    """Parallel test runner"""
    return ParallelTestRunner()


# Performance testing utilities

class MemoryMonitor:
    """Monitor memory usage during test execution"""
    
    def __init__(self):
        self.snapshots = []
        self.monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self, interval: float = 0.1):
        """Start monitoring memory usage"""
        self.monitoring = True
        self.snapshots = []
        
        def monitor():
            process = psutil.Process()
            while self.monitoring:
                try:
                    memory_info = process.memory_info()
                    self.snapshots.append({
                        "timestamp": datetime.utcnow(),
                        "rss_mb": memory_info.rss / 1024 / 1024,
                        "vms_mb": memory_info.vms / 1024 / 1024
                    })
                    time.sleep(interval)
                except:
                    break
        
        self.monitor_thread = threading.Thread(target=monitor)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop monitoring memory usage"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
    
    def get_memory_stats(self) -> Dict[str, float]:
        """Get memory usage statistics"""
        if not self.snapshots:
            return {}
        
        rss_values = [s["rss_mb"] for s in self.snapshots]
        vms_values = [s["vms_mb"] for s in self.snapshots]
        
        return {
            "peak_rss_mb": max(rss_values),
            "average_rss_mb": sum(rss_values) / len(rss_values),
            "peak_vms_mb": max(vms_values),
            "average_vms_mb": sum(vms_values) / len(vms_values),
            "samples_count": len(self.snapshots)
        }


@pytest.fixture
def memory_monitor():
    """Memory monitoring fixture"""
    monitor = MemoryMonitor()
    monitor.start_monitoring()
    yield monitor
    monitor.stop_monitoring()