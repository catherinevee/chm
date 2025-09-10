"""
Basic tests for Catalyst Health Monitor
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

from backend.collector.protocols.snmp.session import SNMPSession, SNMPCredentials, ResponseMetrics
from backend.storage.models import Device, DeviceState, DeviceType

@pytest.fixture
def sample_device():
    """Create a sample device for testing"""
    return Device(
        id="test-device-1",
        hostname="test-switch-1",
        ip_address="192.168.1.1",
        device_type=DeviceType.C2960,
        current_state=DeviceState.HEALTHY,
        poll_interval=60,
        gentle_mode=True
    )

@pytest.fixture
def sample_credentials():
    """Create sample SNMP credentials"""
    return [
        SNMPCredentials(
            version="2c",
            community="public"
        ),
        SNMPCredentials(
            version="3",
            username="monitor",
            auth_protocol="SHA",
            auth_password="auth_pass"
        )
    ]

def test_response_metrics():
    """Test ResponseMetrics functionality"""
    metrics = ResponseMetrics()
    
    # Test adding responses
    metrics.add_response(0.5)
    metrics.add_response(0.8)
    metrics.add_response(1.2)
    
    assert len(metrics.response_times) == 3
    assert metrics.get_average() == pytest.approx(0.833, 0.01)
    assert metrics.get_percentile(95) == pytest.approx(1.2, 0.01)
    
    # Test timeouts
    metrics.add_timeout()
    assert metrics.consecutive_timeouts == 1
    assert metrics.timeout_count == 1
    
    # Test reset on success
    metrics.add_response(0.3)
    assert metrics.consecutive_timeouts == 0

def test_snmp_session_initialization(sample_credentials):
    """Test SNMP session initialization"""
    session = SNMPSession("192.168.1.1", sample_credentials)
    
    assert session.hostname == "192.168.1.1"
    assert len(session.credentials_list) == 2
    assert session.credentials_list[0].version == "2c"
    assert session.credentials_list[1].version == "3"
    assert not session.circuit_open

def test_circuit_breaker_logic(sample_credentials):
    """Test circuit breaker functionality"""
    session = SNMPSession("192.168.1.1", sample_credentials)
    
    # Initially should allow requests
    assert session.check_circuit_breaker() == True
    
    # Add 5 consecutive timeouts
    for _ in range(5):
        session.metrics.add_timeout()
    
    # Circuit should be open
    assert session.check_circuit_breaker() == False
    assert session.circuit_open == True

def test_timeout_calculation(sample_credentials):
    """Test adaptive timeout calculation"""
    session = SNMPSession("192.168.1.1", sample_credentials)
    
    # Test default timeout
    timeout = session.calculate_timeout()
    assert timeout == 5.0  # base_timeout
    
    # Add some response times
    session.metrics.add_response(0.5)
    session.metrics.add_response(0.8)
    session.metrics.add_response(10.0)  # Slow response
    
    # Timeout should be based on 95th percentile with safety margin
    timeout = session.calculate_timeout()
    assert timeout > 10.0  # Should be greater than slowest response
    assert timeout < 30.0  # Should not exceed max timeout

@pytest.mark.asyncio
async def test_device_state_transitions(sample_device):
    """Test device state transitions"""
    # Test healthy to degraded
    sample_device.consecutive_failures = 1
    # In a real implementation, this would be handled by the collector service
    assert sample_device.current_state == DeviceState.HEALTHY
    
    # Test degraded to critical
    sample_device.consecutive_failures = 3
    # This would be updated by the collector service
    
    # Test critical to unreachable
    sample_device.consecutive_failures = 5
    # This would trigger circuit breaker

def test_device_type_enum():
    """Test device type enumeration"""
    assert DeviceType.C2960.value == "2960"
    assert DeviceType.C3560.value == "3560"
    assert DeviceType.C4500.value == "4500"
    assert DeviceType.UNKNOWN.value == "unknown"

def test_device_state_enum():
    """Test device state enumeration"""
    assert DeviceState.HEALTHY.value == "healthy"
    assert DeviceState.DEGRADED.value == "degraded"
    assert DeviceState.CRITICAL.value == "critical"
    assert DeviceState.UNREACHABLE.value == "unreachable"
    assert DeviceState.RECOVERING.value == "recovering"

if __name__ == "__main__":
    pytest.main([__file__])
