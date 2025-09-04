"""
Performance Tests for CHM Monitoring System
Tests system performance under various load conditions
"""

import pytest
import asyncio
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta

from backend.monitoring.monitoring_server import MonitoringServer
from backend.monitoring.connection_pool import SSHConnectionPool, SNMPConnectionPool
from backend.services.metrics_service import MetricsService
from backend.services.alert_engine import AlertEngine


class TestMonitoringPerformance:
    """Performance tests for monitoring system"""
    
    @pytest.fixture
    def monitoring_server(self):
        """Create monitoring server instance"""
        return MonitoringServer()
    
    @pytest.fixture
    def metrics_service(self):
        """Create metrics service instance"""
        return MetricsService()
    
    @pytest.fixture
    def alert_engine(self):
        """Create alert engine instance"""
        return AlertEngine()
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_snmp_polling_performance(self, benchmark):
        """Test SNMP polling performance under load"""
        # Mock SNMP connection pool
        with patch('backend.monitoring.connection_pool.SNMPConnectionPool') as mock_pool:
            mock_pool.return_value.get_connection.return_value = Mock()
            
            # Mock SNMP response
            mock_response = {
                'cpu_utilization': 45.2,
                'memory_utilization': 67.8,
                'interface_status': 'up',
                'temperature': 42.1
            }
            
            # Create monitoring server
            server = MonitoringServer()
            
            # Benchmark SNMP polling
            def snmp_poll():
                return server.poll_device_snmp("192.168.1.1", "public", "2c")
            
            result = benchmark(snmp_poll)
            
            # Verify performance metrics
            assert result.stats.mean < 0.1  # Should complete in under 100ms
            assert result.stats.max < 0.5   # Max should be under 500ms
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_ssh_connection_performance(self, benchmark):
        """Test SSH connection performance"""
        # Mock SSH connection
        with patch('backend.monitoring.connection_pool.SSHConnectionPool') as mock_pool:
            mock_pool.return_value.get_connection.return_value = Mock()
            
            # Create connection pool
            pool = SSHConnectionPool(min_size=5, max_size=20)
            
            # Benchmark connection acquisition
            def get_connection():
                return pool.get_connection("192.168.1.1", "admin", "password")
            
            result = benchmark(get_connection)
            
            # Verify performance
            assert result.stats.mean < 0.05  # Should complete in under 50ms
            assert result.stats.max < 0.2    # Max should be under 200ms
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_concurrent_device_polling(self, benchmark):
        """Test concurrent device polling performance"""
        # Mock device data
        devices = [
            {"ip": f"192.168.1.{i}", "protocol": "snmp", "community": "public"}
            for i in range(100)
        ]
        
        # Mock monitoring functions
        with patch('backend.monitoring.monitoring_server.MonitoringServer.poll_device_snmp') as mock_poll:
            mock_poll.return_value = {"status": "online", "response_time": 50}
            
            server = MonitoringServer()
            
            # Benchmark concurrent polling
            async def concurrent_poll():
                tasks = [
                    server.poll_device_snmp(device["ip"], device["community"], "2c")
                    for device in devices
                ]
                return await asyncio.gather(*tasks)
            
            def benchmark_concurrent():
                return asyncio.run(concurrent_poll())
            
            result = benchmark(benchmark_concurrent)
            
            # Verify performance
            assert result.stats.mean < 2.0   # Should complete in under 2 seconds
            assert result.stats.max < 5.0    # Max should be under 5 seconds
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_metrics_processing_performance(self, benchmark):
        """Test metrics processing performance"""
        # Create sample metrics data
        metrics_data = [
            {
                "device_id": f"device-{i}",
                "timestamp": datetime.utcnow(),
                "cpu_utilization": 45.2 + (i % 20),
                "memory_utilization": 67.8 + (i % 15),
                "interface_utilization": 23.4 + (i % 10)
            }
            for i in range(1000)
        ]
        
        service = MetricsService()
        
        # Benchmark metrics processing
        def process_metrics():
            return service.process_metrics_batch(metrics_data)
        
        result = benchmark(process_metrics)
        
        # Verify performance
        assert result.stats.mean < 0.5   # Should complete in under 500ms
        assert result.stats.max < 1.0    # Max should be under 1 second
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_alert_correlation_performance(self, benchmark):
        """Test alert correlation performance"""
        # Create sample alerts
        alerts = [
            {
                "id": f"alert-{i}",
                "device_id": f"device-{i % 100}",
                "severity": "high" if i % 10 == 0 else "medium",
                "message": f"Test alert {i}",
                "timestamp": datetime.utcnow()
            }
            for i in range(500)
        ]
        
        engine = AlertEngine()
        
        # Benchmark alert correlation
        def correlate_alerts():
            return engine.correlate_alerts(alerts)
        
        result = benchmark(correlate_alerts)
        
        # Verify performance
        assert result.stats.mean < 1.0   # Should complete in under 1 second
        assert result.stats.max < 2.0    # Max should be under 2 seconds
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_database_query_performance(self, benchmark):
        """Test database query performance"""
        # Mock database session
        with patch('backend.storage.database.get_session') as mock_session:
            mock_session.return_value.__aenter__.return_value = Mock()
            
            # Mock query results
            mock_results = [
                Mock(
                    id=f"device-{i}",
                    hostname=f"device-{i}",
                    ip_address=f"192.168.1.{i+1}",
                    status="online"
                )
                for i in range(1000)
            ]
            
            mock_session.return_value.__aenter__.return_value.execute.return_value.scalars.return_value = mock_results
            
            # Benchmark database query
            def query_devices():
                return asyncio.run(self._query_devices())
            
            result = benchmark(query_devices)
            
            # Verify performance
            assert result.stats.mean < 0.1   # Should complete in under 100ms
            assert result.stats.max < 0.5    # Max should be under 500ms
    
    async def _query_devices(self):
        """Helper method for database query"""
        from backend.storage.database import get_session
        from backend.storage.models import Device
        
        async with get_session() as session:
            result = await session.execute(
                "SELECT * FROM devices WHERE status = 'online'"
            )
            return result.scalars().all()
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_websocket_message_performance(self, benchmark):
        """Test WebSocket message processing performance"""
        # Mock WebSocket manager
        with patch('backend.services.websocket_manager.websocket_manager') as mock_manager:
            mock_manager.broadcast = AsyncMock()
            
            # Create sample messages
            messages = [
                {
                    "type": "device_status",
                    "device_id": f"device-{i}",
                    "status": "online",
                    "timestamp": datetime.utcnow().isoformat()
                }
                for i in range(100)
            ]
            
            # Benchmark message broadcasting
            async def broadcast_messages():
                for message in messages:
                    await mock_manager.broadcast(message)
            
            def benchmark_broadcast():
                return asyncio.run(broadcast_messages())
            
            result = benchmark(benchmark_broadcast)
            
            # Verify performance
            assert result.stats.mean < 0.5   # Should complete in under 500ms
            assert result.stats.max < 1.0    # Max should be under 1 second
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_memory_usage_performance(self, benchmark):
        """Test memory usage under load"""
        import psutil
        import os
        
        # Get current process
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Benchmark memory-intensive operation
        def memory_intensive_operation():
            # Create large data structures
            large_list = [i for i in range(100000)]
            large_dict = {f"key-{i}": f"value-{i}" for i in range(100000)}
            large_string = "x" * 1000000
            
            # Perform some operations
            result = sum(large_list)
            keys = list(large_dict.keys())
            string_length = len(large_string)
            
            return result, len(keys), string_length
        
        result = benchmark(memory_intensive_operation)
        
        # Check final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Verify memory usage is reasonable
        assert memory_increase < 100  # Should not increase by more than 100MB
        assert result.stats.mean < 0.1  # Should complete in under 100ms
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_cpu_usage_performance(self, benchmark):
        """Test CPU usage under load"""
        import psutil
        import os
        
        # Get current process
        process = psutil.Process(os.getpid())
        
        # Benchmark CPU-intensive operation
        def cpu_intensive_operation():
            # Perform CPU-intensive calculations
            result = 0
            for i in range(1000000):
                result += i * i
            return result
        
        result = benchmark(cpu_intensive_operation)
        
        # Get CPU usage
        cpu_percent = process.cpu_percent(interval=1)
        
        # Verify performance
        assert result.stats.mean < 0.5   # Should complete in under 500ms
        assert cpu_percent < 80          # CPU usage should be reasonable
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_network_io_performance(self, benchmark):
        """Test network I/O performance"""
        # Mock network operations
        with patch('asyncio.open_connection') as mock_connection:
            mock_connection.return_value = (Mock(), Mock())
            
            # Benchmark network operation
            async def network_operation():
                reader, writer = await asyncio.open_connection('localhost', 8080)
                writer.write(b"test data")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
            
            def benchmark_network():
                return asyncio.run(network_operation())
            
            result = benchmark(benchmark_network)
            
            # Verify performance
            assert result.stats.mean < 0.1   # Should complete in under 100ms
            assert result.stats.max < 0.5    # Max should be under 500ms
    
    @pytest.mark.benchmark
    @pytest.mark.asyncio
    async def test_file_io_performance(self, benchmark):
        """Test file I/O performance"""
        import tempfile
        import os
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
            temp_filename = temp_file.name
            
            # Write test data
            test_data = "x" * 1000000  # 1MB of data
            
            # Benchmark file write
            def file_write():
                with open(temp_filename, 'w') as f:
                    f.write(test_data)
            
            result = benchmark(file_write)
            
            # Verify performance
            assert result.stats.mean < 0.1   # Should complete in under 100ms
            assert result.stats.max < 0.5    # Max should be under 500ms
            
            # Clean up
            os.unlink(temp_filename)


# Load testing
class TestMonitoringLoad:
    """Load testing for monitoring system"""
    
    @pytest.mark.asyncio
    async def test_high_concurrency_device_polling(self):
        """Test high concurrency device polling"""
        # Mock monitoring server
        with patch('backend.monitoring.monitoring_server.MonitoringServer.poll_device_snmp') as mock_poll:
            mock_poll.return_value = {"status": "online", "response_time": 50}
            
            server = MonitoringServer()
            
            # Create 1000 concurrent polling tasks
            devices = [
                {"ip": f"192.168.1.{i}", "community": "public"}
                for i in range(1000)
            ]
            
            start_time = time.time()
            
            # Execute concurrent polling
            tasks = [
                server.poll_device_snmp(device["ip"], device["community"], "2c")
                for device in devices
            ]
            
            results = await asyncio.gather(*tasks)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Verify results
            assert len(results) == 1000
            assert all(result["status"] == "online" for result in results)
            assert total_time < 10.0  # Should complete in under 10 seconds
    
    @pytest.mark.asyncio
    async def test_memory_leak_detection(self):
        """Test for memory leaks during extended operation"""
        import psutil
        import os
        import gc
        
        # Get current process
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform extended operation
        for _ in range(100):
            # Create and destroy objects
            large_list = [i for i in range(10000)]
            large_dict = {f"key-{i}": f"value-{i}" for i in range(10000)}
            
            # Force garbage collection
            del large_list
            del large_dict
            gc.collect()
        
        # Check final memory usage
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Verify no significant memory leak
        assert memory_increase < 50  # Should not increase by more than 50MB
    
    @pytest.mark.asyncio
    async def test_connection_pool_stress(self):
        """Test connection pool under stress"""
        # Create connection pool
        pool = SSHConnectionPool(min_size=10, max_size=100)
        
        # Simulate high connection demand
        async def get_connection():
            connection = await pool.get_connection("192.168.1.1", "admin", "password")
            await asyncio.sleep(0.01)  # Simulate connection usage
            await pool.release_connection(connection)
            return connection
        
        # Create 200 concurrent connection requests
        start_time = time.time()
        
        tasks = [get_connection() for _ in range(200)]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Verify results
        assert len(results) == 200
        assert total_time < 5.0  # Should complete in under 5 seconds
        
        # Verify pool state
        assert pool.current_size <= pool.max_size
        assert pool.current_size >= pool.min_size


# Stress testing
class TestMonitoringStress:
    """Stress testing for monitoring system"""
    
    @pytest.mark.asyncio
    async def test_extreme_concurrency(self):
        """Test extreme concurrency conditions"""
        # Mock monitoring functions
        with patch('backend.monitoring.monitoring_server.MonitoringServer.poll_device_snmp') as mock_poll:
            mock_poll.return_value = {"status": "online", "response_time": 50}
            
            server = MonitoringServer()
            
            # Create 5000 concurrent tasks
            devices = [
                {"ip": f"192.168.1.{i}", "community": "public"}
                for i in range(5000)
            ]
            
            start_time = time.time()
            
            # Execute extreme concurrency
            tasks = [
                server.poll_device_snmp(device["ip"], device["community"], "2c")
                for device in devices
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # Verify results
            assert len(results) == 5000
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            assert success_count >= 4800  # At least 96% success rate
            assert total_time < 30.0  # Should complete in under 30 seconds
    
    @pytest.mark.asyncio
    async def test_resource_exhaustion_recovery(self):
        """Test system recovery from resource exhaustion"""
        import psutil
        import os
        
        # Get current process
        process = psutil.Process(os.getpid())
        
        # Simulate resource exhaustion
        large_objects = []
        
        try:
            # Consume memory
            for i in range(100):
                large_objects.append([i] * 100000)
            
            # Verify high memory usage
            memory_usage = process.memory_info().rss / 1024 / 1024  # MB
            assert memory_usage > 100  # Should have consumed significant memory
            
        finally:
            # Clean up
            del large_objects
            import gc
            gc.collect()
            
            # Verify recovery
            memory_usage = process.memory_info().rss / 1024 / 1024  # MB
            assert memory_usage < 100  # Should have recovered
    
    @pytest.mark.asyncio
    async def test_error_handling_under_stress(self):
        """Test error handling under stress conditions"""
        # Mock monitoring server with intermittent failures
        with patch('backend.monitoring.monitoring_server.MonitoringServer.poll_device_snmp') as mock_poll:
            def intermittent_failure(ip, community, version):
                if int(ip.split('.')[-1]) % 10 == 0:  # 10% failure rate
                    raise Exception("Simulated failure")
                return {"status": "online", "response_time": 50}
            
            mock_poll.side_effect = intermittent_failure
            
            server = MonitoringServer()
            
            # Create tasks with expected failures
            devices = [
                {"ip": f"192.168.1.{i}", "community": "public"}
                for i in range(100)
            ]
            
            # Execute with error handling
            results = await asyncio.gather(
                *[
                    server.poll_device_snmp(device["ip"], device["community"], "2c")
                    for device in devices
                ],
                return_exceptions=True
            )
            
            # Verify error handling
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            failure_count = sum(1 for r in results if isinstance(r, Exception))
            
            assert success_count >= 80   # At least 80% success
            assert failure_count >= 5    # At least 5% failure (due to 10% failure rate)
            assert len(results) == 100   # All tasks completed
