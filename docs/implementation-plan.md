# CHM Implementation Plan - Ensuring Design Compliance

## Overview

This document provides a step-by-step implementation plan to ensure the CHM application matches the comprehensive design outlined in CLAUDE.md. The plan focuses on practical implementation steps, code structure, and validation checkpoints.

## Current State Assessment

### What's Already Implemented
✅ **Backend Framework**: FastAPI with async support
✅ **Database**: PostgreSQL with SQLAlchemy ORM
✅ **Basic SNMP**: PySNMP with OID management
✅ **Basic SSH**: SSH client for command execution
✅ **Device Discovery**: Network scanning framework
✅ **Metrics Collection**: Basic performance monitoring
✅ **Frontend**: React with TypeScript and Material-UI
✅ **Authentication**: JWT with basic RBAC

### What Needs Enhancement
🔄 **Advanced Discovery**: CDP/LLDP/ARP protocols
🔄 **Protocol Fallback**: Automatic protocol switching
🔄 **Enhanced Visualization**: Advanced charting and dashboards
🔄 **Alert Correlation**: Intelligent alert grouping
🔄 **Performance Optimization**: Connection pooling and caching
🔄 **Enterprise Features**: SLA monitoring, maintenance windows

## Implementation Roadmap

### Phase 1: Enhanced Discovery & Protocols (Weeks 1-2)

#### Week 1: Protocol Discovery Enhancement
```bash
# Create new protocol discovery modules
mkdir -p chm/backend/discovery/protocols
touch chm/backend/discovery/protocols/__init__.py
touch chm/backend/discovery/protocols/cdp_discovery.py
touch chm/backend/discovery/protocols/lldp_discovery.py
touch chm/backend/discovery/protocols/arp_discovery.py
```

**Implementation Tasks:**
1. **CDP Discovery Module** (`cdp_discovery.py`)
   - Implement Cisco Discovery Protocol packet parsing
   - Extract device information and neighbor relationships
   - Handle CDP version differences (v1, v2)

2. **LLDP Discovery Module** (`lldp_discovery.py`)
   - Implement Link Layer Discovery Protocol support
   - Vendor-agnostic neighbor discovery
   - Extract port and system information

3. **ARP Discovery Module** (`arp_discovery.py`)
   - Parse ARP tables for IP-to-MAC mapping
   - Identify active devices on network segments
   - Cross-reference with other discovery methods

#### Week 2: Protocol Fallback System
```python
# chm/backend/collector/protocol_fallback.py
class ProtocolFallback:
    def __init__(self):
        self.protocol_priority = ['snmp', 'ssh', 'rest', 'icmp']
        
    async def collect_metrics(self, device: Device) -> DeviceMetrics:
        # Try SNMP first, fall back to SSH, then REST, finally ICMP
        for protocol in self.protocol_priority:
            try:
                metrics = await self.try_protocol(device, protocol)
                if metrics:
                    return metrics
            except Exception as e:
                logger.warning(f"Protocol {protocol} failed: {e}")
                continue
        
        # All protocols failed
        raise ProtocolError("All monitoring protocols failed")
```

### Phase 2: Enhanced Data Collection (Weeks 3-4)

#### Week 3: SNMP Enhancement
```python
# chm/backend/collector/protocols/snmp/enhanced_poller.py
class EnhancedSNMPPoller:
    def __init__(self):
        self.session_pool = {}
        self.oid_manager = OIDManager()
        
    async def poll_device(self, device: Device, oids: List[str]) -> DeviceMetrics:
        # Get or create SNMP session with connection pooling
        session = await self.get_session(device)
        
        # Poll multiple OIDs concurrently
        oid_batches = self.batch_oids(oids, max_batch_size=50)
        all_metrics = {}
        
        for batch in oid_batches:
            batch_metrics = await self.poll_oid_batch(session, batch)
            all_metrics.update(batch_metrics)
            
        return DeviceMetrics(device_id=device.id, metrics=all_metrics)
```

#### Week 4: SSH Enhancement
```python
# chm/backend/collector/protocols/ssh/enhanced_ssh.py
class EnhancedSSHClient:
    def __init__(self):
        self.connection_pool = {}
        self.vendor_commands = self.load_vendor_commands()
        
    async def execute_vendor_commands(self, device: Device) -> Dict[str, Any]:
        # Parse vendor type and execute appropriate commands
        commands = self.vendor_commands.get(device.vendor, [])
        
        # Execute commands concurrently
        tasks = [self.execute_command(device, cmd) for cmd in commands]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Parse and structure results
        return self.parse_command_results(results)
```

### Phase 3: Advanced Alerting & Correlation (Weeks 5-6)

#### Week 5: Alert Engine Enhancement
```python
# chm/backend/services/alert_engine.py
class AlertEngine:
    def __init__(self):
        self.correlation_engine = AlertCorrelationEngine()
        self.threshold_manager = ThresholdManager()
        
    async def evaluate_metric(self, metric: DeviceMetric) -> List[Alert]:
        # Check all applicable alert rules
        rules = await self.threshold_manager.get_applicable_rules(metric)
        triggered_alerts = []
        
        for rule in rules:
            if self.check_threshold(metric.value, rule):
                alert = await self.create_alert(rule, metric)
                triggered_alerts.append(alert)
                
                # Check for correlation
                correlated = await self.correlation_engine.correlate_alert(alert)
                if correlated:
                    alert.correlation_group = correlated.id
                    
        return triggered_alerts
```

#### Week 6: Alert Correlation Implementation
```python
# chm/backend/services/alert_correlation.py
class AlertCorrelationEngine:
    def __init__(self):
        self.correlation_rules = self.load_correlation_rules()
        
    async def correlate_alert(self, alert: Alert) -> Optional[CorrelationGroup]:
        # Check for existing correlation groups
        for rule in self.correlation_rules:
            if self.matches_correlation_rule(alert, rule):
                group = await self.find_or_create_group(alert, rule)
                return group
        return None
        
    def matches_correlation_rule(self, alert: Alert, rule: CorrelationRule) -> bool:
        # Check if alert matches correlation criteria
        # Device, metric type, time window, severity, etc.
        return (alert.device_id == rule.device_id and
                alert.metric_type == rule.metric_type and
                self.within_time_window(alert.timestamp, rule.time_window))
```

### Phase 4: Enhanced Visualization (Weeks 7-8)

#### Week 7: Advanced Charting
```typescript
// chm/frontend/src/components/Charts/PerformanceChart.tsx
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface PerformanceChartProps {
  data: PerformanceData[];
  metricType: string;
  timeRange: string;
  deviceId: string;
}

export const PerformanceChart: React.FC<PerformanceChartProps> = ({ 
  data, 
  metricType, 
  timeRange, 
  deviceId 
}) => {
  const [chartData, setChartData] = useState<ChartData[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  
  useEffect(() => {
    loadChartData();
  }, [deviceId, metricType, timeRange]);
  
  const loadChartData = async () => {
    setIsLoading(true);
    try {
      const response = await apiService.getPerformanceData(deviceId, metricType, timeRange);
      setChartData(response.data);
    } catch (error) {
      console.error('Failed to load chart data:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  return (
    <ResponsiveContainer width="100%" height={400}>
      <LineChart data={chartData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="timestamp" />
        <YAxis />
        <Tooltip />
        <Legend />
        <Line 
          type="monotone" 
          dataKey="value" 
          stroke="#8884d8" 
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 8 }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
};
```

#### Week 8: Dashboard Builder
```typescript
// chm/frontend/src/components/Dashboard/DashboardBuilder.tsx
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';

export const DashboardBuilder: React.FC = () => {
  const [widgets, setWidgets] = useState<Widget[]>([]);
  const [availableWidgets, setAvailableWidgets] = useState<WidgetTemplate[]>([]);
  
  const handleDragEnd = (result: DropResult) => {
    if (!result.destination) return;
    
    const items = Array.from(widgets);
    const [reorderedItem] = items.splice(result.source.index, 1);
    items.splice(result.destination.index, 0, reorderedItem);
    
    setWidgets(items);
  };
  
  const addWidget = (widgetType: string) => {
    const newWidget: Widget = {
      id: generateId(),
      type: widgetType,
      position: { x: 0, y: 0 },
      size: { width: 300, height: 200 },
      config: {}
    };
    setWidgets([...widgets, newWidget]);
  };
  
  return (
    <div className="dashboard-builder">
      <div className="widget-palette">
        {availableWidgets.map(widget => (
          <button key={widget.type} onClick={() => addWidget(widget.type)}>
            {widget.name}
          </button>
        ))}
      </div>
      
      <DragDropContext onDragEnd={handleDragEnd}>
        <Droppable droppableId="dashboard">
          {(provided) => (
            <div
              {...provided.droppableProps}
              ref={provided.innerRef}
              className="dashboard-grid"
            >
              {widgets.map((widget, index) => (
                <Draggable key={widget.id} draggableId={widget.id} index={index}>
                  {(provided) => (
                    <div
                      ref={provided.innerRef}
                      {...provided.draggableProps}
                      {...provided.dragHandleProps}
                      className="widget"
                    >
                      <WidgetRenderer widget={widget} />
                    </div>
                  )}
                </Draggable>
              ))}
              {provided.placeholder}
            </div>
          )}
        </Droppable>
      </DragDropContext>
    </div>
  );
};
```

### Phase 5: Performance Optimization (Weeks 9-10)

#### Week 9: Connection Pooling
```python
# chm/backend/services/connection_pool.py
class ConnectionPool:
    def __init__(self, max_connections: int = 100):
        self.snmp_sessions = {}
        self.ssh_connections = {}
        self.max_connections = max_connections
        self.lock = asyncio.Lock()
        
    async def get_snmp_session(self, device: Device) -> SNMPSession:
        async with self.lock:
            if device.id in self.snmp_sessions:
                session = self.snmp_sessions[device.id]
                if await self.is_session_healthy(session):
                    return session
                    
            # Create new session
            session = await self.create_snmp_session(device)
            self.snmp_sessions[device.id] = session
            
            # Clean up old sessions if pool is full
            if len(self.snmp_sessions) > self.max_connections:
                await self.cleanup_old_sessions()
                
            return session
            
    async def cleanup_old_sessions(self):
        # Remove oldest sessions to maintain pool size
        sorted_sessions = sorted(
            self.snmp_sessions.items(),
            key=lambda x: x[1].last_used
        )
        
        to_remove = len(self.snmp_sessions) - self.max_connections
        for device_id, _ in sorted_sessions[:to_remove]:
            await self.close_snmp_session(device_id)
            del self.snmp_sessions[device_id]
```

#### Week 10: Caching Implementation
```python
# chm/backend/services/cache_service.py
class CacheService:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client
        self.default_ttl = 300  # 5 minutes
        
    async def get_cached_metrics(self, device_id: str, metric_type: str, 
                                time_range: str) -> Optional[List[Metric]]:
        cache_key = f"metrics:{device_id}:{metric_type}:{time_range}"
        
        cached_data = await self.redis.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
        return None
        
    async def cache_metrics(self, device_id: str, metric_type: str, 
                           time_range: str, metrics: List[Metric], ttl: int = None):
        cache_key = f"metrics:{device_id}:{metric_type}:{time_range}"
        ttl = ttl or self.default_ttl
        
        await self.redis.setex(
            cache_key,
            ttl,
            json.dumps([metric.dict() for metric in metrics])
        )
        
    async def invalidate_device_cache(self, device_id: str):
        # Invalidate all cached data for a specific device
        pattern = f"metrics:{device_id}:*"
        keys = await self.redis.keys(pattern)
        if keys:
            await self.redis.delete(*keys)
```

## Validation Checkpoints

### After Phase 1 (Week 2)
- [ ] CDP/LLDP/ARP discovery working for test devices
- [ ] Protocol fallback system handles SNMP failures gracefully
- [ ] Device classification correctly identifies vendor and model

### After Phase 2 (Week 4)
- [ ] Enhanced SNMP polling supports 100+ OIDs per device
- [ ] SSH client executes vendor-specific commands successfully
- [ ] Connection pooling reduces connection overhead

### After Phase 3 (Week 6)
- [ ] Alert engine evaluates thresholds in <100ms
- [ ] Alert correlation groups related alerts effectively
- [ ] Notification system delivers alerts via multiple channels

### After Phase 4 (Week 8)
- [ ] Performance charts display real-time data with <1s latency
- [ ] Dashboard builder allows custom widget placement
- [ ] Charts support zoom, pan, and drill-down functionality

### After Phase 5 (Week 10)
- [ ] Connection pooling supports 1000+ concurrent devices
- [ ] Caching reduces database load by 70%+
- [ ] Overall system response time <2s for 95% of requests

## Testing Strategy

### Unit Testing
```bash
# Run unit tests for each module
cd chm/backend
python -m pytest tests/unit/discovery/ -v
python -m pytest tests/unit/collector/ -v
python -m pytest tests/unit/services/ -v
```

### Integration Testing
```bash
# Test complete workflows
python -m pytest tests/integration/ -v
python -m pytest tests/integration/test_discovery_to_alerting.py -v
```

### Performance Testing
```bash
# Load testing with multiple devices
python -m pytest tests/performance/ -v
locust -f tests/performance/locustfile.py --host=http://localhost:8000
```

## Deployment Checklist

### Development Environment
- [ ] Docker Compose setup with PostgreSQL and Redis
- [ ] Hot reloading for backend and frontend
- [ ] Mock network devices for testing
- [ ] Local SSL certificates for HTTPS testing

### Production Environment
- [ ] Kubernetes deployment manifests
- [ ] Helm charts for easy deployment
- [ ] Prometheus monitoring and alerting
- [ ] Load balancer configuration
- [ ] SSL certificate management

## Success Metrics

### Performance Targets
- **Device Discovery**: <30 seconds for 1000 devices
- **Metrics Collection**: <5 seconds for 1000 devices
- **Alert Generation**: <60 seconds from threshold violation
- **Dashboard Response**: <2 seconds for data display
- **API Response**: <500ms for 95% of requests

### Reliability Targets
- **System Uptime**: 99.9%
- **Data Collection**: 99.5% success rate
- **Alert Delivery**: 99.9% delivery rate
- **Data Retention**: 100% compliance with retention policies

## Next Steps

1. **Review this implementation plan** with development team
2. **Set up development environment** following the setup guide
3. **Begin Phase 1 implementation** starting with protocol discovery
4. **Establish weekly review meetings** to track progress
5. **Set up automated testing** for continuous validation
6. **Plan for user acceptance testing** and production deployment

This implementation plan ensures that CHM will meet all design requirements while maintaining code quality and system reliability.

