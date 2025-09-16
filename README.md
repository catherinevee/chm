# Catalyst Health Monitor (CHM)

[![CI/CD Pipeline](https://github.com/catherinevee/chm/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/catherinevee/chm/actions/workflows/ci-cd.yml)
[![Trivy](https://github.com/catherinevee/chm/actions/workflows/trivy-simple.yml/badge.svg)](https://github.com/catherinevee/chm/actions/workflows/trivy-simple.yml)
[![Docker Hub](https://img.shields.io/docker/v/catherinevee/chm?label=docker&color=blue)](https://hub.docker.com/r/catherinevee/chm)
[![codecov](https://codecov.io/gh/catherinevee/chm/graph/badge.svg)](https://codecov.io/gh/catherinevee/chm)
[![Libraries.io dependency status](https://img.shields.io/librariesio/github/catherinevee/chm)](https://libraries.io/github/catherinevee/chm)
[![Code Quality](https://img.shields.io/badge/code%20quality-A-brightgreen)](https://github.com/catherinevee/chm)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)






## Purpose

CHM (Catalyst Health Monitor) is designed to automatically discover, monitor, and manage Cisco Catalyst network infrastructure. It provides network engineers with real-time visibility into device health, performance metrics, and configuration status across their entire Catalyst deployment. By combining SNMP polling, SSH access, and intelligent alerting, CHM helps prevent network outages, optimize performance, and streamline network operations.

## Overview

CHM is an enterprise-grade network monitoring platform that provides comprehensive visibility into your network infrastructure. Built with FastAPI backend and React frontend components, it delivers monitoring, alerting, and discovery capabilities for network operations.

### Key Features

- **Backend API**: Complete FastAPI implementation with async support
- **Device Discovery**: Network discovery implementation with SNMP/SSH protocols
- **Authentication**: JWT authentication with bcrypt password hashing and RBAC
- **Alert Management**: Alert system with database models and API endpoints
- **Metrics Collection**: Device metrics tracking and storage capabilities
- **WebSocket Support**: Real-time communication infrastructure
- **RESTful API**: 20+ documented endpoints with OpenAPI specification
- **Frontend Components**: React TypeScript components for visualization (in development)

## Project Structure

```
chm/
├── main.py                    # Main FastAPI application entry point
├── api/v1/                    # RESTful API endpoints
│   ├── auth.py               # JWT authentication & user management
│   ├── devices.py            # Device CRUD operations
│   ├── metrics.py            # Metrics collection & aggregation
│   ├── alerts.py             # Alert management & correlation
│   ├── discovery.py          # Network discovery engine
│   └── notifications.py      # Multi-channel notifications
├── backend/                   # Core backend services
│   ├── services/             # Business logic layer
│   ├── storage/              # Database models & migrations
│   ├── monitoring/           # SNMP/SSH monitoring protocols
│   ├── discovery/            # Discovery protocols & scanning
│   └── collector/            # Data collection services
├── core/                      # Application foundation
│   ├── config.py             # Environment configuration
│   ├── database.py           # Async SQLAlchemy setup
│   └── middleware.py         # Security & logging middleware
├── tests/                     # Test suite with fixtures and utilities
│   ├── unit/                 # Unit tests
│   ├── integration/          # Integration tests
│   └── api/                  # API endpoint tests
├── config/                    # Configuration files
├── docs/                      # Documentation
├── scripts/                   # Utility scripts
└── docker-compose.yml         # Container orchestration
```

## Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL 12+ (recommended: 15+)
- Redis 6+ (optional, for caching)
- Docker & Docker Compose (optional)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/catherinevee/chm.git
cd chm
```

2. **Set up environment**
```bash
# Create environment file
cat > .env << EOF
DATABASE_URL=postgresql://user:password@localhost:5432/chm
SECRET_KEY=your-secret-key-change-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30
REDIS_URL=redis://localhost:6379/0
EOF
```

3. **Install dependencies**
```bash
pip install -r chm_requirements.txt
```

4. **Initialize database**
```bash
# Run startup script to create tables and sample data
python scripts/utilities/start.py
```

5. **Run the application**
```bash
python main.py
```

6. **Verify installation**
- API Health: http://localhost:8000/health
- API Documentation: http://localhost:8000/docs
- API Status: http://localhost:8000/api/status
- Frontend: http://localhost:3000 (requires separate setup)

## Usage Guide

### Device Management

Add and manage network devices:

```bash
# Add a device via API
curl -X POST "http://localhost:8000/api/v1/devices" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "core-switch-01",
    "ip_address": "192.168.1.1",
    "device_type": "switch",
    "vendor": "cisco",
    "snmp_community": "public",
    "ssh_username": "admin"
  }'

# List all devices
curl -X GET "http://localhost:8000/api/v1/devices" \
  -H "Authorization: Bearer $TOKEN"

# Get device details
curl -X GET "http://localhost:8000/api/v1/devices/1" \
  -H "Authorization: Bearer $TOKEN"
```

### Network Discovery

Discover devices automatically:

```bash
# Start network discovery
curl -X POST "http://localhost:8000/api/v1/discovery/start" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "network_range": "192.168.1.0/24",
    "discovery_type": "ping_sweep",
    "scan_ports": [22, 161, 443]
  }'

# Check discovery status
curl -X GET "http://localhost:8000/api/v1/discovery/status" \
  -H "Authorization: Bearer $TOKEN"
```

### Metrics Collection

Monitor device performance:

```bash
# Get device metrics
curl -X GET "http://localhost:8000/api/v1/metrics/device/1" \
  -H "Authorization: Bearer $TOKEN"

# Get performance graphs
curl -X GET "http://localhost:8000/api/v1/metrics/device/1/graphs" \
  -H "Authorization: Bearer $TOKEN"

# Get system metrics
curl -X GET "http://localhost:8000/api/v1/metrics/system" \
  -H "Authorization: Bearer $TOKEN"
```

### Alert Management

Configure and manage alerts:

```bash
# Create an alert
curl -X POST "http://localhost:8000/api/v1/alerts" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": 1,
    "alert_type": "cpu_usage",
    "threshold": 80,
    "severity": "warning",
    "message": "High CPU usage detected"
  }'

# List alerts
curl -X GET "http://localhost:8000/api/v1/alerts" \
  -H "Authorization: Bearer $TOKEN"

# Acknowledge alert
curl -X POST "http://localhost:8000/api/v1/alerts/1/acknowledge" \
  -H "Authorization: Bearer $TOKEN"
```

## Configuration

### API Structure

CHM has a dual API structure:

- **Primary API** (`api/v1/`): Main FastAPI endpoints used by the application
- **Backend API** (`backend/api/`): Legacy endpoints and additional services

For most use cases, use the primary API endpoints documented below.

### Environment Variables

Create `.env` file:

```bash
# Database
DATABASE_URL=postgresql://user:password@localhost:5432/chm
REDIS_URL=redis://localhost:6379/0

# Security
SECRET_KEY=your-secret-key-here
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=30

# Application
DEBUG=true
LOG_LEVEL=INFO
WORKERS=4

# SNMP
SNMP_TIMEOUT=5
SNMP_RETRIES=3

# Discovery
DISCOVERY_TIMEOUT=30
DISCOVERY_WORKERS=10
```

### Configuration File

Create `config.yaml`:

```yaml
# Application settings
app:
  name: "CHM"
  version: "2.0.0"
  debug: false
  workers: 4

# Database settings
database:
  url: "${DATABASE_URL}"
  pool_size: 20
  max_overflow: 30
  echo: false

# Redis settings
redis:
  url: "${REDIS_URL}"
  max_connections: 20

# Security settings
security:
  secret_key: "${SECRET_KEY}"
  jwt_algorithm: "HS256"
  jwt_expire_minutes: 30
  password_min_length: 8

# Monitoring settings
monitoring:
  metrics_interval: 60
  health_check_interval: 30
  alert_check_interval: 10

# Discovery settings
discovery:
  timeout: 30
  workers: 10
  batch_size: 100
```

## API Reference

### Authentication

All API endpoints require authentication via JWT token:

```bash
# Login
curl -X POST "http://localhost:8000/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "password"
  }'

# Use token in subsequent requests
curl -X GET "http://localhost:8000/api/v1/devices" \
  -H "Authorization: Bearer $TOKEN"
```

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/auth/login` | POST | User authentication |
| `/api/v1/auth/register` | POST | User registration |
| `/api/v1/auth/refresh` | POST | Refresh JWT token |
| `/api/v1/auth/password/reset` | POST | Password reset |
| `/api/v1/auth/mfa/verify` | POST | MFA verification |
| `/api/v1/devices` | GET/POST | List/create devices |
| `/api/v1/devices/{id}` | GET/PUT/DELETE | Device operations |
| `/api/v1/devices/{id}/status` | GET | Device status |
| `/api/v1/metrics/device/{id}` | GET | Device metrics |
| `/api/v1/metrics/device/{id}/graphs` | GET | Performance graphs |
| `/api/v1/metrics/system` | GET | System metrics |
| `/api/v1/alerts` | GET/POST | List/create alerts |
| `/api/v1/alerts/{id}` | GET/PUT/DELETE | Alert operations |
| `/api/v1/alerts/{id}/acknowledge` | POST | Acknowledge alert |
| `/api/v1/alerts/{id}/resolve` | POST | Resolve alert |
| `/api/v1/alerts/statistics` | GET | Alert statistics |
| `/api/v1/discovery/start` | POST | Start discovery |
| `/api/v1/discovery/status` | GET | Discovery status |
| `/api/v1/discovery/results` | GET | Discovery results |
| `/api/v1/notifications` | GET/POST | List/create notifications |
| `/api/v1/notifications/{id}` | GET/PUT/DELETE | Notification operations |
| `/api/v1/notifications/mark-read` | POST | Mark as read |
| `/api/v1/health` | GET | Health check |

## Docker Deployment

### Quick Start with Docker Hub

```bash
# Pull the latest image from Docker Hub
docker pull catherinevee/chm:latest

# Run with basic settings
docker run -d \
  --name chm-app \
  -p 8000:8000 \
  catherinevee/chm:latest

# View logs
docker logs -f chm-app
```

### Docker Compose Deployment

```bash
# Clone and start all services
git clone https://github.com/catherinevee/chm.git
cd chm
docker-compose up -d

# View logs
docker-compose logs -f chm-app

# Stop services
docker-compose down
```

### Production Deployment

```bash
# Option 1: Use pre-built image from Docker Hub
docker pull catherinevee/chm:latest

# Option 2: Build your own image
docker build -t chm:latest .

# Run with production settings
docker run -d \
  --name chm-app \
  -p 8000:8000 \
  -e DATABASE_URL=postgresql://user:pass@db:5432/chm \
  -e REDIS_URL=redis://redis:6379/0 \
  -e SECRET_KEY=your-secret-key \
  catherinevee/chm:latest
```

### Docker Compose Services

The `docker-compose.yml` includes:

- **chm-app**: Main FastAPI application
- **postgres**: PostgreSQL database
- **redis**: Redis cache and message broker
- **nginx**: Reverse proxy and load balancer
- **prometheus**: Metrics collection
- **grafana**: Monitoring dashboards
- **elasticsearch**: Log storage
- **kibana**: Log visualization

## Advanced Features

### Frontend Development

The frontend is currently in development. To set up the React frontend:

```bash
cd frontend
npm install
npm start
```

Frontend components include:
- Device list and management
- Dashboard with charts
- Alert notifications
- Network topology visualization
- Performance monitoring graphs

### API Server

The FastAPI server provides:

- Interactive API documentation at `/docs`
- ReDoc documentation at `/redoc`
- OpenAPI schema at `/openapi.json`
- Health checks and monitoring endpoints

### Background Tasks

CHM includes several background services:

- **Metrics Collection**: Automated SNMP polling
- **Network Discovery**: Scheduled network scans
- **Alert Processing**: Real-time alert evaluation
- **Notification Delivery**: Multi-channel notifications
- **Data Cleanup**: Automated data retention

### Continuous Monitoring

Start monitoring daemon:

```bash
# Start monitoring service
python -m services.monitoring_service

# With custom interval
python -m services.monitoring_service --interval 30
```

## Architecture & Design

### System Design

CHM follows a microservices-inspired architecture with clear separation of concerns:

- **API Layer**: FastAPI endpoints handle HTTP requests
- **Service Layer**: Business logic encapsulated in service classes
- **Data Layer**: SQLAlchemy models with async database operations
- **Protocol Layer**: SNMP/SSH clients for device communication
- **WebSocket Layer**: Real-time bidirectional communication

### Security Implementation

- **Authentication**: JWT tokens with configurable expiration
- **Password Security**: bcrypt hashing with salt rounds
- **Authorization**: Role-based access control (RBAC)
- **API Security**: CORS, rate limiting, input validation
- **Data Protection**: Encrypted sensitive fields in database

## Testing

### Run Tests

```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# API tests
python -m pytest tests/api/ -v

# Full test suite with coverage
python -m pytest tests/ -v --cov=chm --cov-report=html
```

### Test Coverage

The project includes comprehensive testing infrastructure with pytest:

- Unit tests for services and models
- Integration tests for database operations
- API endpoint tests with authentication
- Test fixtures and utilities included

## Troubleshooting

### Common Issues

**Database connection errors**

```bash
# Check database status
docker-compose ps chm-postgres

# View database logs
docker-compose logs chm-postgres

# Test connection
python -c "from core.database import engine; print(engine.execute('SELECT 1').scalar())"
```

**SNMP timeout errors**

```bash
# Test SNMP connectivity
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0

# Check firewall rules
telnet 192.168.1.1 161
```

**Redis connection issues**

```bash
# Check Redis status
docker-compose ps chm-redis

# Test Redis connection
redis-cli ping
```

**Memory issues with large deployments**

```bash
# Monitor memory usage
docker stats

# Increase memory limits
docker run --memory=4g chm:latest
```

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python main.py

# Verbose API logging
export DEBUG=true
python main.py
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-feature`
3. Make your changes and add tests
4. Run the test suite: `python -m pytest tests/ -v`
5. Commit your changes: `git commit -am 'Add new feature'`
6. Push to the branch: `git push origin feature/new-feature`
7. Submit a pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run linting
flake8 .
black .
isort .
mypy .
```

## License

MIT License - see [LICENSE](LICENSE)

## Support

- **Documentation**: [docs.chm.dev](https://docs.chm.dev)
- **Issues**: [GitHub Issues](https://github.com/catherinevee/chm/issues)
- **Discussions**: [GitHub Discussions](https://github.com/catherinevee/chm/discussions)
- **Email**: support@chm.dev

## About

CHM is an enterprise network monitoring solution built with modern technologies and best practices. The project provides a solid foundation for network monitoring with room for continued development and enhancement.

**Project Status**: **Active Development**
- Backend API: Fully implemented with FastAPI
- Database Layer: Complete with async SQLAlchemy
- Authentication: JWT with RBAC implemented
- Frontend: React components in development
- Testing: Comprehensive test infrastructure

**Author**: Catherine Vee | DevOps/Network Engineer
- GitHub: [github.com/catherinevee](https://github.com/catherinevee)
- LinkedIn: [linkedin.com/in/catherinevee](https://linkedin.com/in/catherinevee)

---

### Technical Architecture

| Component | Implementation | Description |
|-----------|---------------|-------------|
| **Backend API** | FastAPI | Async REST API with 20+ endpoints |
| **Database** | PostgreSQL + SQLAlchemy | Async ORM with migration support |
| **Authentication** | JWT + bcrypt | Token-based auth with RBAC |
| **Protocols** | SNMP/SSH clients | Network device communication |
| **WebSocket** | Connection manager | Real-time event support |
| **Caching** | Redis (optional) | Performance optimization |
| **Testing** | pytest | Unit, integration, and API tests |
| **CI/CD** | GitHub Actions | Automated testing and deployment |
| **Environments** | staging/production | GitHub deployment environments |
| **Docker** | Multi-stage builds | Container support with Docker Hub |
| **Frontend** | React + TypeScript | Component library (in development) |

### Current Capabilities

- **Device Management**: CRUD operations for network devices
- **User Authentication**: Registration, login, JWT tokens
- **Alert System**: Create, manage, and acknowledge alerts
- **Metrics Collection**: Device metrics tracking and storage
- **Network Discovery**: Discovery job management
- **API Documentation**: Auto-generated OpenAPI/Swagger docs
- **Security**: Password hashing, JWT authentication, CORS
- **Database Models**: Users, Devices, Alerts, Metrics, Notifications
- **Service Layer**: Auth, Device, Alert, Metrics services
- **Validation**: Input validation with Pydantic models