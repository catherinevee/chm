# CHM Quick Start Guide

## Getting Started with CHM Implementation

This guide provides the essential steps to begin implementing the CHM application according to the design outlined in CLAUDE.md and the implementation plan in IMPLEMENTATION_PLAN.md.

## Prerequisites

### Required Software
- **Python 3.9+** with pip and virtualenv
- **Node.js 16+** with npm
- **PostgreSQL 13+** database
- **Redis 6+** for caching
- **Docker & Docker Compose** (optional but recommended)

### Development Tools
- **VS Code** or your preferred IDE
- **Git** for version control
- **Postman** or similar for API testing

## Initial Setup

### 1. Clone and Setup Repository
```bash
# Clone the repository
git clone <your-repo-url>
cd chm

# Create Python virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
pip install -r requirements.txt

# Setup frontend
cd frontend
npm install
cd ..
```

### 2. Environment Configuration
```bash
# Copy environment template
cp backend/env.example backend/.env

# Edit backend/.env with your configuration
DATABASE_URL=postgresql+asyncpg://username:password@localhost:5432/chm_db
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=your-secret-key-here-minimum-32-characters
ENCRYPTION_KEY=your-encryption-key-here
```

### 3. Database Setup
```bash
# Create PostgreSQL database
createdb chm_db

# Run database migrations
cd backend
python migrate_db.py
cd ..
```

## Development Workflow

### Phase 1: Enhanced Discovery (Week 1-2)

#### Day 1: Protocol Discovery Foundation
```bash
# Create new discovery protocol modules
mkdir -p backend/discovery/protocols
touch backend/discovery/protocols/__init__.py
touch backend/discovery/protocols/cdp_discovery.py
touch backend/discovery/protocols/lldp_discovery.py
touch backend/discovery/protocols/arp_discovery.py
```

**Start with CDP Discovery:**
```python
# backend/discovery/protocols/cdp_discovery.py
import asyncio
import socket
from typing import List, Optional
from dataclasses import dataclass

@dataclass
class CDPDevice:
    ip_address: str
    hostname: Optional[str]
    device_type: Optional[str]
    vendor: str = "cisco"
    interfaces: List[str] = None

class CDPDiscovery:
    def __init__(self):
        self.cdp_port = 2000  # CDP typically uses port 2000
        
    async def discover_cdp_devices(self, network_range: str) -> List[CDPDevice]:
        """Discover CDP devices in the network range"""
        devices = []
        # Implementation here
        return devices
        
    async def parse_cdp_packet(self, packet_data: bytes) -> Optional[CDPDevice]:
        """Parse CDP packet and extract device information"""
        # CDP packet parsing implementation
        pass
```

#### Day 2: Device Classification
```python
# backend/discovery/device_classifier.py
class DeviceClassifier:
    def __init__(self):
        self.vendor_signatures = {
            'cisco': ['cisco', 'ios', 'nx-os', 'catos'],
            'juniper': ['juniper', 'junos', 'ex', 'mx'],
            'arista': ['arista', 'eos'],
            'hp': ['hp', 'procurve', 'aruba']
        }
    
    def classify_device(self, system_desc: str, hostname: str) -> tuple[str, str]:
        """Classify device by vendor and model"""
        desc = (system_desc + " " + hostname).lower()
        
        for vendor, signatures in self.vendor_signatures.items():
            for sig in signatures:
                if sig in desc:
                    model = self.extract_model(desc, vendor)
                    return vendor, model
        return "unknown", "unknown"
```

### Phase 2: Enhanced Data Collection (Week 3-4)

#### Day 3: SNMP Enhancement
```python
# backend/collector/protocols/snmp/enhanced_poller.py
class EnhancedSNMPPoller:
    def __init__(self):
        self.session_pool = {}
        self.max_batch_size = 50
        
    async def poll_device(self, device: Device, oids: List[str]) -> DeviceMetrics:
        """Poll device with enhanced SNMP capabilities"""
        session = await self.get_session(device)
        
        # Split OIDs into manageable batches
        oid_batches = self.batch_oids(oids)
        all_metrics = {}
        
        for batch in oid_batches:
            batch_metrics = await self.poll_oid_batch(session, batch)
            all_metrics.update(batch_metrics)
            
        return DeviceMetrics(device_id=device.id, metrics=all_metrics)
        
    def batch_oids(self, oids: List[str], max_size: int = None) -> List[List[str]]:
        """Split OIDs into batches for efficient polling"""
        max_size = max_size or self.max_batch_size
        return [oids[i:i + max_size] for i in range(0, len(oids), max_size)]
```

#### Day 4: Protocol Fallback
```python
# backend/collector/protocol_fallback.py
class ProtocolFallback:
    def __init__(self):
        self.protocol_priority = ['snmp', 'ssh', 'rest', 'icmp']
        
    async def collect_metrics(self, device: Device) -> DeviceMetrics:
        """Try multiple protocols in order of preference"""
        for protocol in self.protocol_priority:
            try:
                metrics = await self.try_protocol(device, protocol)
                if metrics:
                    logger.info(f"Successfully collected metrics using {protocol}")
                    return metrics
            except Exception as e:
                logger.warning(f"Protocol {protocol} failed: {e}")
                continue
        
        raise ProtocolError("All monitoring protocols failed for device")
        
    async def try_protocol(self, device: Device, protocol: str) -> Optional[DeviceMetrics]:
        """Attempt to collect metrics using specific protocol"""
        if protocol == 'snmp':
            return await self.snmp_collector.collect(device)
        elif protocol == 'ssh':
            return await self.ssh_collector.collect(device)
        elif protocol == 'rest':
            return await self.rest_collector.collect(device)
        elif protocol == 'icmp':
            return await self.icmp_collector.collect(device)
        return None
```

## Testing Your Implementation

### 1. Unit Tests
```bash
# Create test files
mkdir -p backend/tests/unit/discovery
touch backend/tests/unit/discovery/test_cdp_discovery.py
touch backend/tests/unit/discovery/test_device_classifier.py

# Run tests
cd backend
python -m pytest tests/unit/discovery/ -v
```

**Example Test:**
```python
# backend/tests/unit/discovery/test_cdp_discovery.py
import pytest
from backend.discovery.protocols.cdp_discovery import CDPDiscovery, CDPDevice

class TestCDPDiscovery:
    def setup_method(self):
        self.discovery = CDPDiscovery()
    
    def test_parse_cdp_packet(self):
        # Test CDP packet parsing
        packet_data = b'...'  # Mock CDP packet data
        device = self.discovery.parse_cdp_packet(packet_data)
        
        assert device is not None
        assert device.vendor == "cisco"
        assert device.ip_address is not None
```

### 2. Integration Tests
```bash
# Test complete workflows
python -m pytest tests/integration/ -v
```

## Running the Application

### 1. Start Backend
```bash
cd backend
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### 2. Start Frontend
```bash
cd frontend
npm start
```

### 3. Access Application
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/api/docs

## Development Tips

### 1. Use Docker for Dependencies
```bash
# Start PostgreSQL and Redis with Docker
docker-compose up -d postgres redis
```

### 2. Hot Reloading
- Backend automatically reloads with `--reload` flag
- Frontend uses React's hot reloading
- Database migrations run automatically

### 3. Debugging
```python
# Add logging for debugging
import logging
logger = logging.getLogger(__name__)

logger.debug(f"Processing device: {device.hostname}")
logger.info(f"Successfully collected {len(metrics)} metrics")
logger.warning(f"Protocol {protocol} failed, trying fallback")
logger.error(f"Failed to collect metrics: {error}")
```

### 4. Performance Monitoring
```python
# Add timing for performance measurement
import time

start_time = time.time()
# ... your code ...
execution_time = time.time() - start_time
logger.info(f"Operation completed in {execution_time:.2f} seconds")
```

## Common Issues & Solutions

### 1. Database Connection Issues
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Verify connection string
psql -h localhost -U username -d chm_db
```

### 2. Redis Connection Issues
```bash
# Check Redis status
redis-cli ping

# Should return PONG
```

### 3. SNMP Timeout Issues
```python
# Increase SNMP timeout in configuration
SNMP_TIMEOUT = 10  # seconds
SNMP_RETRIES = 3
```

## Next Steps

1. **Complete Phase 1** (Enhanced Discovery) by end of Week 2
2. **Move to Phase 2** (Enhanced Data Collection) in Week 3
3. **Set up automated testing** for continuous validation
4. **Review progress** with team weekly
5. **Document any deviations** from the implementation plan

## Getting Help

- **Documentation**: Check CLAUDE.md for design details
- **Implementation Plan**: Follow IMPLEMENTATION_PLAN.md for step-by-step guidance
- **Code Examples**: Refer to existing code in the repository
- **Testing**: Use the test suite to validate your implementation

Remember: Start small, test frequently, and build incrementally. Each phase builds upon the previous one, so ensure each component is working before moving to the next.

