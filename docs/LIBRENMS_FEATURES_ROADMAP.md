# LibreNMS Features Integration Roadmap
# Catalyst Health Monitor Enhancement Plan

## Current CHM Capabilities Assessment

### ✅ **Already Implemented**
- Basic SNMP monitoring (v1/v2c/v3)
- Device discovery and inventory management
- Basic alerting system
- Performance metrics collection
- Dashboard with device statistics
- CSV bulk import/export
- REST API endpoints
- Docker containerization

### 🔄 **Partially Implemented**
- Graphing (basic performance graphs)
- Device relationships (basic topology)
- Threshold management
- SLA monitoring

## 🚀 LibreNMS Features to Implement

### **Phase 1: Core Monitoring Enhancements**

#### 1. **Advanced Network Discovery** 
*Priority: HIGH*

**Current State**: Basic SNMP discovery
**LibreNMS Feature**: Multi-protocol discovery (CDP, LLDP, FDP, OSPF, BGP)

```python
# Implementation Plan
class NetworkDiscovery:
    protocols = ['cdp', 'lldp', 'fdp', 'ospf', 'bgp', 'arp']
    
    async def discover_via_cdp(self, device):
        """Cisco Discovery Protocol"""
        # Get CDP neighbors table
        
    async def discover_via_lldp(self, device):
        """Link Layer Discovery Protocol"""
        # Get LLDP neighbors table
        
    async def auto_discover_network(self, seed_devices):
        """Recursive network discovery"""
        # Start from seed devices and discover entire network
```

**Benefits**: Automatic network topology mapping, neighbor discovery, protocol-aware discovery

#### 2. **Enhanced Alerting System**
*Priority: HIGH*

**Current State**: Basic threshold alerts
**LibreNMS Feature**: Rule-based alerting with templates, escalation, and multiple channels

```python
# Enhanced Alert Rules
class AlertRule:
    def __init__(self):
        self.conditions = []  # Multiple conditions with AND/OR logic
        self.severity_mapping = {}  # Dynamic severity based on conditions
        self.notification_channels = []  # Email, Slack, Teams, webhooks
        self.escalation_rules = []  # Time-based escalation
        self.maintenance_windows = []  # Suppress during maintenance
```

**New Features**:
- Rule builder UI with drag-drop conditions
- Alert templates for common scenarios
- Notification channels: Slack, Teams, PagerDuty, webhooks
- Alert escalation and acknowledgment
- Maintenance window support
- Alert correlation and grouping

#### 3. **Advanced Graphing & Visualization**
*Priority: MEDIUM*

**Current State**: Basic performance graphs
**LibreNMS Feature**: RRD-style graphs, custom dashboards, graph templates

```typescript
// Enhanced Graphing Component
interface GraphConfig {
    metrics: string[];
    timeRange: string;
    aggregation: 'avg' | 'max' | 'min' | 'sum';
    graphType: 'line' | 'area' | 'bar' | 'gauge';
    thresholds: Threshold[];
    customColors: string[];
}

// Graph Templates
const graphTemplates = {
    'interface-traffic': {
        metrics: ['ifInOctets', 'ifOutOctets'],
        type: 'area',
        stacked: true
    },
    'cpu-memory': {
        metrics: ['cpuUsage', 'memoryUsage'],
        type: 'line',
        dualAxis: true
    }
};
```

### **Phase 2: Advanced Features**

#### 4. **Distributed Polling**
*Priority: MEDIUM*

**LibreNMS Feature**: Multiple pollers for scalability

```python
class DistributedPoller:
    def __init__(self, poller_id, redis_client):
        self.poller_id = poller_id
        self.redis = redis_client
        self.device_queue = f"poller:{poller_id}:queue"
    
    async def claim_devices(self, max_devices=100):
        """Claim devices from shared queue"""
        
    async def poll_devices(self):
        """Poll assigned devices"""
        
    async def report_results(self, results):
        """Report results back to central system"""
```

**Benefits**: Scale to thousands of devices, geographic distribution, load balancing

#### 5. **Service Monitoring Integration**
*Priority: MEDIUM*

**LibreNMS Feature**: Nagios plugin support for service checks

```python
class ServiceMonitor:
    def __init__(self):
        self.plugins_dir = "/usr/lib/nagios/plugins"
        
    async def check_http(self, url, expected_status=200):
        """HTTP/HTTPS service check"""
        
    async def check_dns(self, hostname, nameserver):
        """DNS resolution check"""
        
    async def check_port(self, host, port):
        """Port connectivity check"""
        
    async def run_custom_plugin(self, plugin_name, args):
        """Run custom Nagios plugin"""
```

#### 6. **Network Topology Mapping**
*Priority: HIGH*

**Current State**: Basic device relationships
**LibreNMS Feature**: Interactive network maps with real-time status

```typescript
interface NetworkTopology {
    nodes: NetworkNode[];
    links: NetworkLink[];
    layout: 'force' | 'hierarchical' | 'circular';
    
    // Interactive features
    onNodeClick: (node: NetworkNode) => void;
    onLinkClick: (link: NetworkLink) => void;
    showTraffic: boolean;
    showLabels: boolean;
}

interface NetworkNode {
    id: string;
    label: string;
    type: 'router' | 'switch' | 'server' | 'firewall';
    status: 'up' | 'down' | 'warning';
    position?: { x: number; y: number };
    metrics: {
        cpu: number;
        memory: number;
        interfaces: InterfaceStatus[];
    };
}
```

### **Phase 3: Enterprise Features**

#### 7. **Billing & Usage Reporting**
*Priority: LOW*

**LibreNMS Feature**: Bandwidth billing and usage reports

```python
class BillingSystem:
    def __init__(self):
        self.billing_rules = []
        
    async def calculate_usage(self, device_id, interface, start_date, end_date):
        """Calculate bandwidth usage for billing"""
        
    async def generate_invoice(self, customer_id, billing_period):
        """Generate usage-based invoice"""
        
    def create_billing_rule(self, customer, interfaces, rate_limit, cost_per_gb):
        """Create billing rule for customer"""
```

#### 8. **Plugin System**
*Priority: MEDIUM*

**LibreNMS Feature**: Extensible plugin architecture

```python
class PluginManager:
    def __init__(self):
        self.plugins = {}
        self.hooks = {}
    
    def register_plugin(self, plugin_class):
        """Register new plugin"""
        
    def register_hook(self, event_name, callback):
        """Register hook for events"""
        
    async def trigger_hook(self, event_name, data):
        """Trigger all hooks for event"""

# Example Plugin
class CustomMetricsPlugin:
    def __init__(self):
        self.name = "custom_metrics"
        self.version = "1.0.0"
    
    async def collect_metrics(self, device):
        """Custom metric collection"""
        
    def get_graph_definitions(self):
        """Define custom graphs"""
```

#### 9. **Advanced Authentication & RBAC**
*Priority: MEDIUM*

**Current State**: Basic authentication
**LibreNMS Feature**: LDAP, AD, SAML, role-based access control

```python
class AuthenticationManager:
    def __init__(self):
        self.providers = {
            'ldap': LDAPProvider(),
            'ad': ActiveDirectoryProvider(),
            'saml': SAMLProvider(),
            'oauth': OAuthProvider()
        }
    
    async def authenticate(self, username, password, provider='local'):
        """Multi-provider authentication"""
        
class RoleBasedAccess:
    roles = {
        'admin': ['*'],
        'operator': ['device.read', 'device.update', 'alert.acknowledge'],
        'viewer': ['device.read', 'graph.read'],
        'billing': ['billing.*', 'device.read']
    }
```

### **Phase 4: Advanced Analytics**

#### 10. **Machine Learning & Anomaly Detection**
*Priority: LOW*

**Enhancement**: Predictive analytics and anomaly detection

```python
class AnomalyDetector:
    def __init__(self):
        self.models = {}
        
    async def train_model(self, device_id, metric_name, historical_data):
        """Train ML model for anomaly detection"""
        
    async def detect_anomalies(self, device_id, current_metrics):
        """Detect anomalies in real-time"""
        
    async def predict_capacity(self, device_id, metric_name, forecast_days=30):
        """Predict capacity requirements"""
```

## 🛠️ Implementation Priority Matrix

### **Immediate (Next 2-4 weeks)**
1. ✅ Enhanced alerting with multiple channels
2. ✅ Network topology mapping
3. ✅ Advanced discovery protocols (CDP/LLDP)

### **Short Term (1-2 months)**
4. ✅ Distributed polling architecture  
5. ✅ Service monitoring integration
6. ✅ Enhanced graphing system

### **Medium Term (2-4 months)**
7. ✅ Plugin system architecture
8. ✅ Advanced authentication (LDAP/AD)
9. ✅ Billing system

### **Long Term (4+ months)**
10. ✅ Machine learning integration
11. ✅ Advanced reporting system
12. ✅ Mobile application

## 📋 Technical Implementation Plan

### **Database Schema Enhancements**

```sql
-- Network topology tables
CREATE TABLE network_links (
    id UUID PRIMARY KEY,
    source_device_id UUID REFERENCES devices(id),
    target_device_id UUID REFERENCES devices(id),
    source_interface VARCHAR(255),
    target_interface VARCHAR(255),
    protocol VARCHAR(50), -- cdp, lldp, etc.
    discovered_at TIMESTAMP,
    last_seen TIMESTAMP
);

-- Alert rules and templates
CREATE TABLE alert_rules (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    conditions JSONB NOT NULL,
    severity VARCHAR(50),
    notification_channels JSONB,
    escalation_rules JSONB,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Service monitoring
CREATE TABLE services (
    id UUID PRIMARY KEY,
    device_id UUID REFERENCES devices(id),
    service_name VARCHAR(255),
    service_type VARCHAR(100), -- http, dns, port, etc.
    configuration JSONB,
    status VARCHAR(50),
    last_check TIMESTAMP,
    response_time FLOAT
);

-- Billing system
CREATE TABLE billing_rules (
    id UUID PRIMARY KEY,
    customer_id VARCHAR(255),
    device_interfaces JSONB,
    rate_limit BIGINT,
    cost_per_gb DECIMAL(10,4),
    billing_cycle VARCHAR(50)
);
```

### **API Endpoints to Add**

```python
# Network Discovery
POST /api/v1/discovery/cdp/{device_id}
POST /api/v1/discovery/lldp/{device_id}
GET /api/v1/topology/map
GET /api/v1/topology/path/{source_id}/{target_id}

# Enhanced Alerting  
POST /api/v1/alerts/rules
PUT /api/v1/alerts/rules/{rule_id}
POST /api/v1/alerts/{alert_id}/acknowledge
POST /api/v1/alerts/test-notification

# Service Monitoring
POST /api/v1/services
GET /api/v1/services/{device_id}
POST /api/v1/services/{service_id}/check

# Distributed Polling
POST /api/v1/pollers/register
GET /api/v1/pollers/{poller_id}/queue
POST /api/v1/pollers/{poller_id}/results

# Billing
GET /api/v1/billing/usage/{customer_id}
POST /api/v1/billing/rules
GET /api/v1/billing/invoice/{customer_id}/{period}
```

## 🎯 Expected Benefits

### **Operational Benefits**
- **Scalability**: Support for 10,000+ devices with distributed polling
- **Automation**: Automatic network discovery and topology mapping
- **Reliability**: Advanced alerting with escalation and correlation
- **Visibility**: Comprehensive network topology and service monitoring

### **Business Benefits**
- **Cost Optimization**: Usage-based billing and capacity planning
- **Compliance**: Detailed reporting and audit trails
- **Integration**: Plugin system for custom extensions
- **User Experience**: Role-based access and customizable dashboards

### **Technical Benefits**
- **Performance**: Distributed architecture for better performance
- **Extensibility**: Plugin system for custom functionality  
- **Security**: Advanced authentication and authorization
- **Maintainability**: Modular architecture with clear separation

## 🚀 Getting Started

To begin implementing these features, I recommend starting with:

1. **Enhanced Alerting System** - Most immediate business value
2. **Network Topology Mapping** - High visual impact
3. **CDP/LLDP Discovery** - Enables automatic topology discovery

Would you like me to implement any of these features first? I can start with the enhanced alerting system or network topology mapping as they provide the most immediate value.
