# Catalyst Health Monitor - Startup Guide

This guide will help you get the Catalyst Health Monitor up and running quickly.

## Prerequisites

- Python 3.11 or higher
- Docker and Docker Compose
- Git

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd universal-health-monitor
```

### 2. Environment Configuration

```bash
# Copy environment template
cp env.example .env

# Edit the .env file with your settings
# At minimum, update these values:
# - DATABASE_URL (if not using Docker Compose)
# - SECRET_KEY (generate a secure random key)
# - JWT_SECRET_KEY (generate a secure random key)
```

### 3. Start Infrastructure Services

```bash
# Start PostgreSQL, Redis, InfluxDB, and Neo4j
docker-compose up -d

# Wait for services to be ready (about 30 seconds)
sleep 30
```

### 4. Initialize Database

```bash
# Run the initialization script
python scripts/start.py
```

This will:
- Create all database tables
- Add sample devices and thresholds
- Set up initial configuration

### 5. Start the Services

#### Option A: Development Mode

```bash
# Terminal 1: Start the collector service
python -m backend.collector.service

# Terminal 2: Start the API server
uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000
```

#### Option B: Production Mode

```bash
# Start both services with proper logging
python -m backend.collector.service &
uvicorn backend.api.main:app --host 0.0.0.0 --port 8000 --workers 4 &
```

### 6. Verify Installation

1. **Check API Health**: http://localhost:8000/health
2. **View API Documentation**: http://localhost:8000/api/docs
3. **Check Database**: Connect to PostgreSQL on localhost:5432
4. **Check Metrics**: http://localhost:8000/metrics

## Adding Your First Device

### Via API

```bash
curl -X POST "http://localhost:8000/api/v1/devices" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "my-switch-1",
    "ip_address": "192.168.1.100",
    "device_type": "2960",
    "location": "Data Center 1",
    "credentials": [
      {
        "protocol": "snmp",
        "version": "2c",
        "community": "public",
        "priority": 0
      }
    ]
  }'
```

### Via Database

```sql
-- Insert device
INSERT INTO devices (id, hostname, ip_address, device_type, location, poll_interval)
VALUES (
  gen_random_uuid(),
  'my-switch-1',
  '192.168.1.100',
  '2960',
  'Data Center 1',
  60
);

-- Insert credentials
INSERT INTO device_credentials (id, device_id, protocol, version, priority, credentials)
VALUES (
  gen_random_uuid(),
  (SELECT id FROM devices WHERE hostname = 'my-switch-1'),
  'snmp',
  '2c',
  0,
  '{"community": "public"}'
);
```

## Configuration

### Device Polling Intervals

- **Healthy devices**: 60 seconds (default)
- **Degraded devices**: 120 seconds
- **Critical devices**: 300 seconds
- **Unreachable devices**: 600 seconds

### Thresholds

Set up monitoring thresholds:

```sql
-- CPU threshold
INSERT INTO thresholds (device_type, metric_name, warning_value, critical_value, comparison)
VALUES ('2960', 'cpu', 60, 80, 'greater');

-- Memory threshold
INSERT INTO thresholds (device_type, metric_name, warning_value, critical_value, comparison)
VALUES ('2960', 'ciscoMemoryPoolFree', 5000000, 2000000, 'less');
```

## Monitoring

### Key Metrics

- **SNMP Response Times**: Track device responsiveness
- **Circuit Breaker Status**: Monitor device health
- **Alert Generation**: Track threshold violations
- **Emergency Responses**: Monitor automatic remediation

### Logs

- **Collector Service**: Device polling and SNMP operations
- **API Service**: HTTP requests and WebSocket connections
- **Database**: Connection pooling and query performance

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Check if PostgreSQL is running: `docker-compose ps`
   - Verify DATABASE_URL in .env file
   - Check logs: `docker-compose logs postgres`

2. **SNMP Timeouts**
   - Verify device IP and SNMP credentials
   - Check network connectivity
   - Review device SNMP configuration

3. **High CPU Usage**
   - Reduce MAX_WORKERS in .env
   - Increase poll intervals for struggling devices
   - Check for circuit breaker trips

### Performance Tuning

```bash
# For high device counts (>100 devices)
export MAX_WORKERS=20
export BATCH_SIZE=200
export SNMP_CONNECTION_POOL_SIZE=200

# For slow networks
export DEFAULT_SNMP_TIMEOUT=10
export GENTLE_MODE_DELAY=5
```

## Next Steps

1. **Add Real Devices**: Configure your actual network devices
2. **Set Up Alerts**: Configure notification channels (Slack, email)
3. **Customize Thresholds**: Adjust based on your environment
4. **Scale Up**: Deploy to production with Kubernetes
5. **Monitor**: Set up Prometheus/Grafana for metrics visualization

## Support

- Check the logs for detailed error messages
- Review the API documentation at `/api/docs`
- Open an issue on GitHub for bugs or feature requests
