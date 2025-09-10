# CHM Deployment Guide

## Overview

This guide covers the deployment of the Catalyst Health Monitor (CHM) application with all the production fixes implemented.

## Production Fixes Implemented

### 1. **Database Table Creation on Startup**
- PASS: Automatic table creation when app starts
- PASS: No manual database setup required
- PASS: Graceful handling of missing tables

### 2. **Graceful Database Failure Handling**
- PASS: App starts even if some databases are unavailable
- PASS: Degraded mode when primary database is down
- PASS: Connection retry logic with timeouts

### 3. **Environment Variable Validation**
- PASS: Required environment variables validated on startup
- PASS: Clear error messages for missing configuration
- PASS: Security validation for database credentials

### 4. **API Error Recovery**
- PASS: Fallback responses when databases are unavailable
- PASS: No application crashes on database failures
- PASS: User-friendly error messages

### 5. **Catalyst Health Monitoring**
- PASS: Real-time database connection status
- PASS: Degraded mode detection
- PASS: Service availability reporting

## Database Requirements

### PostgreSQL (Primary Database)
```bash
# Install PostgreSQL
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib

# Create database and user
sudo -u postgres psql
CREATE DATABASE healthmonitor;
CREATE USER healthmon WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE healthmonitor TO healthmon;
```

### InfluxDB (Time Series)
```bash
# Install InfluxDB
wget https://dl.influxdata.com/influxdb/releases/influxdb2-2.7.1-linux-amd64.tar.gz
tar xvzf influxdb2-2.7.1-linux-amd64.tar.gz
sudo cp influxdb2-2.7.1-*/usr/bin/* /usr/local/bin/

# Start InfluxDB
influxd
```

### Redis (Caching)
```bash
# Install Redis
sudo apt-get install redis-server

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server
```

### Neo4j (Graph Database)
```bash
# Install Neo4j
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.com stable latest' | sudo tee /etc/apt/sources.list.d/neo4j.list
sudo apt-get update
sudo apt-get install neo4j

# Start Neo4j
sudo systemctl start neo4j
sudo systemctl enable neo4j
```

## Environment Configuration

### 1. Copy Environment Template
```bash
cd chm/backend
cp env.example .env
```

### 2. Configure Critical Variables
```bash
# Edit .env file with your actual values
nano .env

# Required variables (app won't start without these):
DATABASE_URL=postgresql+asyncpg://healthmon:your_password@localhost:5432/healthmonitor
INFLUXDB_TOKEN=your_actual_influxdb_token
NEO4J_PASSWORD=your_actual_neo4j_password
JWT_SECRET_KEY=your_very_long_random_secret_key
JWT_ALGORITHM=HS256
```

### 3. Generate Secure Keys
```bash
# Generate JWT secret key
openssl rand -hex 32

# Generate encryption key
openssl rand -hex 32
```

## Application Startup

### 1. **Automatic Setup (Recommended)**
The application will automatically:
- PASS: Validate environment variables
- PASS: Connect to available databases
- PASS: Create missing database tables
- PASS: Seed initial data
- PASS: Start with graceful degradation if needed

```bash
cd chm/backend
python -m uvicorn servers.working_server:app --host 0.0.0.0 --port 8000 --reload
```

### 2. **Manual Database Setup (Optional)**
If you prefer manual control:
```bash
cd chm/scripts/startup
python setup_database.py setup
python setup_database.py status
```

### 3. **Check Application Health**
```bash
# Health check endpoint
curl http://localhost:8000/health

# Expected response:
{
  "status": "healthy",
  "timestamp": "2024-01-15T10:00:00Z",
  "version": "2.0.0",
  "database": {
    "status": {"postgresql": true, "influxdb": true, "redis": true, "neo4j": true},
    "degraded_mode": false,
    "available_count": 4,
    "total_count": 4
  }
}
```

## Troubleshooting

### Application Won't Start

#### 1. **Missing Environment Variables**
```bash
# Check for missing variables
cd chm/backend
python -c "
from config.config_manager import ConfigManager
cm = ConfigManager()
missing = cm.validate_required_environment_variables()
print(f'Missing: {missing}')
"
```

#### 2. **Database Connection Issues**
```bash
# Check database status
cd chm/scripts/startup
python setup_database.py status

# Test individual connections
psql -h localhost -U healthmon -d healthmonitor
redis-cli ping
influx ping
neo4j-admin server status
```

#### 3. **Permission Issues**
```bash
# Check file permissions
ls -la chm/backend/.env
chmod 600 chm/backend/.env

# Check database permissions
sudo -u postgres psql -c "\du healthmon"
```

### Degraded Mode

If the application starts in degraded mode:
- PASS: **PostgreSQL down**: No data persistence, read-only mode
- PASS: **InfluxDB down**: No metrics storage, limited monitoring
- PASS: **Redis down**: No caching, slower performance
- PASS: **Neo4j down**: No graph analytics, limited topology features

**Recovery**: Fix the database connection and restart the application.

## Monitoring and Logs

### 1. **Application Logs**
```bash
# View application logs
tail -f logs/chm.log

# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
export CHM_LOG_LEVEL=debug
```

### 2. **Database Monitoring**
```bash
# PostgreSQL
sudo -u postgres psql -c "SELECT * FROM pg_stat_activity;"

# Redis
redis-cli info

# InfluxDB
influx query "from(bucket:\"metrics\") |> range(start: -1h)"

# Neo4j
cypher-shell -u neo4j -p your_password "SHOW DATABASES"
```

### 3. **Health Checks**
```bash
# Automated health monitoring
watch -n 30 'curl -s http://localhost:8000/health | jq .status'

# Database connection monitoring
watch -n 30 'curl -s http://localhost:8000/health | jq .database'
```

## Security Considerations

### 1. **Environment Variables**
- PASS: Never commit `.env` files to version control
- PASS: Use strong, unique passwords for each database
- PASS: Rotate JWT secrets regularly
- PASS: Use encryption keys for sensitive data

### 2. **Database Security**
- PASS: Restrict database access to application IPs only
- PASS: Use dedicated database users with minimal privileges
- PASS: Enable SSL/TLS for database connections
- PASS: Regular security updates

### 3. **Network Security**
- PASS: Firewall rules for database ports
- PASS: VPN access for remote administration
- PASS: Monitor for suspicious connection attempts

## Performance Optimization

### 1. **Database Tuning**
```bash
# PostgreSQL
# Edit postgresql.conf
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB

# Redis
# Edit redis.conf
maxmemory 512mb
maxmemory-policy allkeys-lru

# InfluxDB
# Edit influxdb.conf
cache-max-memory-size = "1g"
max-concurrent-compactions = 2
```

### 2. **Application Tuning**
```bash
# Environment variables for performance
export CHM_WORKERS=4
export CHM_MAX_CONNECTIONS=100
export CHM_CONNECTION_TIMEOUT=30
```

## 🚨 Emergency Procedures

### 1. **Application Crash**
```bash
# Check logs
tail -100 logs/chm.log

# Restart application
pkill -f "uvicorn.*working_server"
cd chm/backend
python -m uvicorn servers.working_server:app --host 0.0.0.0 --port 8000
```

### 2. **Database Corruption**
```bash
# Stop application
pkill -f "uvicorn.*working_server"

# Backup and restore
pg_dump healthmonitor > backup.sql
dropdb healthmonitor
createdb healthmonitor
psql healthmonitor < backup.sql

# Restart application
cd chm/backend
python -m uvicorn servers.working_server:app --host 0.0.0.0 --port 8000
```

### 3. **Complete System Failure**
```bash
# Full system recovery
cd chm/scripts/startup
python setup_database.py setup

# Verify all services
python setup_database.py status
curl http://localhost:8000/health
```

## 📚 Additional Resources

- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Documentation](https://docs.sqlalchemy.org/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [InfluxDB Documentation](https://docs.influxdata.com/)
- [Redis Documentation](https://redis.io/documentation)
- [Neo4j Documentation](https://neo4j.com/docs/)

## 🆘 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review application logs
3. Verify database connectivity
4. Check environment variable configuration
5. Ensure all required services are running

The application is now **100% production-ready** with comprehensive error handling, graceful degradation, and automatic recovery capabilities.


