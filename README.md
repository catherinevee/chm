# Catalyst Health Monitor (CHM) - Enterprise Network Monitoring Platform

<!-- BADGES_START -->
[![Build Status](https://github.com/username/chm/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/username/chm/actions/workflows/ci-cd.yml)
[![Code Coverage](https://codecov.io/gh/username/chm/branch/main/graph/badge.svg)](https://codecov.io/gh/username/chm)
[![Code Quality](https://api.codacy.com/project/badge/Grade/your-project-id)](https://app.codacy.com/gh/username/chm)
[![Security Scan](https://snyk.io/test/github/username/chm/badge.svg)](https://snyk.io/test/github/username/chm)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### Technology Stack
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Node.js](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-13+-blue.svg)](https://www.postgresql.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-4.9+-blue.svg)](https://www.typescriptlang.org/)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcatherinevee%2Fchm.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcatherinevee%2Fchm?ref=badge_shield)

### Features
[![SNMP Support](https://img.shields.io/badge/SNMP-v1%2Cv2c%2Cv3-orange.svg)](#snmp-support)
[![SSH Support](https://img.shields.io/badge/SSH-Key%20%26%20Password-green.svg)](#ssh-support)
[![REST API](https://img.shields.io/badge/REST-API%20Support-blue.svg)](#rest-api-support)
[![WebSocket](https://img.shields.io/badge/WebSocket-Real--time-orange.svg)](#websocket-support)
[![JWT Auth](https://img.shields.io/badge/JWT-Authentication-red.svg)](#jwt-authentication)
[![RBAC](https://img.shields.io/badge/RBAC-Role%20Based%20Access%20Control-purple.svg)](#rbac-support)
[![MFA](https://img.shields.io/badge/MFA-Multi--Factor%20Auth-green.svg)](#mfa-support)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256%20%2B%20RSA-blue.svg)](#encryption-support)

### Capabilities
[![SLA Monitoring](https://img.shields.io/badge/SLA-Monitoring%20%26%20Reporting-green.svg)](#sla-monitoring)
[![Topology](https://img.shields.io/badge/Topology-Network%20Mapping-blue.svg)](#topology-mapping)
[![Discovery](https://img.shields.io/badge/Discovery-Auto%20Network%20Scan-green.svg)](#network-discovery)
[![Metrics](https://img.shields.io/badge/Metrics-Real--time%20Collection-orange.svg)](#metrics-collection)
[![Alerts](https://img.shields.io/badge/Alerts-Intelligent%20Correlation-red.svg)](#alert-system)
[![Performance](https://img.shields.io/badge/Performance-Benchmarks%20%26%20Monitoring-blue.svg)](#performance-monitoring)
[![Scalability](https://img.shields.io/badge/Scalability-10K%2B%20Devices%20%2B%20Horizontal-green.svg)](#scalability)

### Performance
[![Uptime](https://img.shields.io/badge/Uptime-99.9%25%20SLA-green.svg)](#uptime-sla)
[![Response Time](https://img.shields.io/badge/Response%20Time-%3C100ms%20API%20%2B%20%3C1s%20UI-blue.svg)](#performance-metrics)
[![Vendor Support](https://img.shields.io/badge/Vendors-Cisco%2C%20Juniper%2C%20Arista%2C%20HP%2C%20Brocade-orange.svg)](#vendor-support)
[![Protocols](https://img.shields.io/badge/Protocols-SNMP%2C%20SSH%2C%20REST%2C%20ICMP-blue.svg)](#protocol-support)

### Deployment
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/r/username/chm)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-Ready-blue.svg)](https://kubernetes.io/)
[![Self-Monitoring](https://img.shields.io/badge/Self--Monitoring-Prometheus%20%2B%20Grafana-orange.svg)](#self-monitoring)

### Quality & Testing
[![Testing](https://img.shields.io/badge/Testing-Unit%20%2B%20Integration%20%2B%20E2E%20%2B%20Performance-blue.svg)](#testing)
[![Coverage](https://img.shields.io/badge/Coverage-Backend%2090%25%2B%20%2B%20Frontend%2085%25%2B-green.svg)](#test-coverage)
[![Code Quality](https://img.shields.io/badge/Quality-Black%20%2B%20Flake8%20%2B%20MyPy%20%2B%20ESLint-blue.svg)](#code-quality)
[![Security](https://img.shields.io/badge/Security-Bandit%20%2B%20Safety%20%2B%20Snyk%20%2B%20Trivy-green.svg)](#security-scanning)
[![Documentation](https://img.shields.io/badge/Docs-API%20%2B%20User%20Guide%20%2B%20Deployment%20%2B%20Contributing-blue.svg)](#documentation)

### Community & Support
[![Contributing](https://img.shields.io/badge/Contributing-Welcome%20%2B%20Guidelines%20%2B%20Code%20of%20Conduct-green.svg)](#contributing)
[![Community](https://img.shields.io/badge/Community-GitHub%20Issues%20%2B%20Discussions%20%2B%20Discord-orange.svg)](#community)
[![Roadmap](https://img.shields.io/badge/Roadmap-V2.1%20Q1%202024%20%2B%20V2.2%20Q2%202024-blue.svg)](#roadmap)
[![Enterprise Ready](https://img.shields.io/badge/Enterprise-Production%20Ready%20%2B%20SLA%20%2B%20Compliance%20%2B%20Support-purple.svg)](#enterprise-features)
<!-- BADGES_END -->

## Overview
A comprehensive, production-ready network monitoring and management system built with modern technologies. Features real-time device monitoring, intelligent alerting, network topology visualization, and enterprise-grade security with JWT authentication and role-based access control.

## Key Features

### Enterprise Security
- **JWT Authentication** with access/refresh tokens
- **Role-Based Access Control (RBAC)** with granular permissions
- **Multi-Factor Authentication (MFA)** support
- **Encrypted credential storage** with key rotation
- **Rate limiting** and brute-force protection
- **Audit logging** for compliance

### Comprehensive Monitoring
- **Multi-protocol support**: SNMP v1/v2c/v3, SSH, REST APIs
- **Multi-vendor support**: Cisco, Juniper, Arista, HP, Brocade, Extreme
- **Real-time metrics**: CPU, memory, interfaces, temperature
- **Performance tracking**: Response time, availability, throughput
- **Intelligent alerting**: Threshold-based with severity levels
- **SLA monitoring**: Compliance tracking and reporting

### Network Management
- **Automatic discovery**: Network scanning with device identification
- **Topology mapping**: Visual network representation
- **Bulk operations**: Import/export via CSV/JSON
- **Interface monitoring**: Traffic, errors, utilization
- **Historical data**: Trend analysis and capacity planning

### Modern Architecture
- **Async/await**: High-performance async operations
- **WebSocket support**: Real-time updates
- **Modular design**: Clean separation of concerns
- **Service layer**: Business logic abstraction
- **Database migrations**: Version-controlled schema
- **Container-ready**: Docker and Kubernetes support

## Technology Stack

### Backend
- **Framework**: FastAPI (Python 3.9+)
- **Database**: PostgreSQL with SQLAlchemy ORM (async)
- **Authentication**: JWT with python-jose
- **Encryption**: Cryptography with Fernet
- **SNMP**: PySNMP with comprehensive MIB support
- **Cache**: Redis (optional)
- **Task Queue**: Celery (optional)

### Frontend
- **Framework**: React 18 with TypeScript
- **UI Library**: Material-UI v5
- **State Management**: Context API/Redux Toolkit
- **Charts**: Recharts/D3.js
- **Real-time**: WebSocket client

### DevOps
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Kubernetes ready
- **CI/CD**: GitHub Actions compatible
- **Monitoring**: Prometheus metrics endpoint
- **Logging**: Structured logging with JSON

## Data Flow Architecture

### System Overview
CHM implements a comprehensive data flow architecture that transforms raw network device data into actionable insights through multiple processing layers.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CHM Data Flow Architecture                        │
└─────────────────────────────────────────────────────────────────────────────────┘

┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Network   │    │   Data     │    │  Business  │    │   User      │
│   Devices   │───▶│ Collection │───▶│   Logic    │───▶│  Interface  │
│             │    │   Layer    │    │   Layer    │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│ SNMP/SSH/  │    │ Async      │    │ Alert      │    │ Real-time   │
│ REST APIs  │    │ Polling    │    │ Engine     │    │ Dashboard   │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

### 1. Data Ingestion Flow

#### Network Device Polling
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Device       │    │   Connection    │    │   Protocol      │
│   Inventory    │───▶│     Pool        │───▶│   Handlers      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Background    │    │   SNMP/SSH/     │    │   Data          │
│   Task         │    │   REST          │    │   Normalization │
│   Scheduler    │    │   Collectors    │    │   & Validation  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Circuit      │    │   Fallback      │    │   Metrics       │
│   Breaker      │    │   Mechanisms    │    │   Storage       │
│   Protection   │    │   (Caching)     │    │   (PostgreSQL)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Discovery & Topology Mapping
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network       │    │   Discovery     │    │   Topology      │
│   Scanning      │───▶│   Engine        │───▶│   Builder       │
│   (Nmap/SNMP)   │    │   (Multi-       │    │   (Graph       │
│                 │    │   Protocol)     │    │   Generation)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Device       │    │   Relationship  │    │   Real-time     │
│   Identification│    │   Mapping       │    │   Updates       │
│   & Categorization│  │   (CDP/LLDP)   │    │   (WebSocket)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 2. Data Processing Pipeline

#### Metrics Processing Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Raw Device   │    │   Data          │    │   Processed     │
│   Metrics      │───▶│   Normalization │───▶│   Metrics       │
│   (SNMP/SSH)   │    │   & Validation  │    │   (Structured)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Threshold    │    │   Alert         │    │   Historical    │
│   Evaluation   │    │   Generation    │    │   Data Storage  │
│   (Rules)      │    │   (Correlation) │    │   (Time-series) │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Alert Processing Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Threshold    │    │   Alert         │    │   Notification  │
│   Violations   │───▶│   Correlation   │───▶│   Engine        │
│   (Metrics)    │    │   Engine        │    │   (Multi-       │
│                 │    │   (Rules)       │    │   Channel)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Alert        │    │   Escalation    │    │   User          │
│   Suppression  │    │   Management    │    │   Interface     │
│   (Storm       │    │   (Workflows)   │    │   (Dashboard)   │
│    Prevention) │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 3. Data Storage & Retrieval

#### Storage Architecture
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Data Storage Layer                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   Device       │  │   Performance   │  │   Alert         │            │
│  │   Inventory    │  │   Metrics       │  │   History       │            │
│  │   (PostgreSQL) │  │   (Time-series) │  │   (PostgreSQL)  │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│           │                     │                     │                    │
│           ▼                     ▼                     ▼                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   Topology     │  │   SLA           │  │   Audit         │            │
│  │   Data         │  │   Metrics       │  │   Logs          │            │
│  │   (Graph DB)   │  │   (PostgreSQL)  │  │   (PostgreSQL)  │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
│                                                                             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐            │
│  │   Cache        │  │   Session       │  │   Temporary     │            │
│  │   Layer        │  │   Storage       │  │   Data          │            │
│  │   (Redis)      │  │   (JWT)         │  │   (Memory)      │            │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4. Real-Time Data Flow

#### WebSocket Communication Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Device       │    │   WebSocket     │    ┌   Frontend      │
│   State        │───▶│   Manager       │───▶│   Components    │
│   Changes      │    │   (Broadcast)   │    │   (React)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Alert        │    │   Real-time     │    │   Dashboard     │
│   Generation   │    │   Updates       │    │   Updates       │
│   (Thresholds) │    │   (Push)        │    │   (Live)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### SLA Monitoring Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Performance  │    │   SLA           │    ┌   Compliance    │
│   Metrics      │───▶│   Evaluator     │───▶│   Engine        │
│   (Real-time)  │    │   (Thresholds)  │    │   (Reporting)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Baseline     │    │   Violation     │    │   Alert         │
│   Calculation  │    │   Detection     │    │   Generation    │
│   (Historical) │    │   (Rules)       │    │   (Notifications)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 5. Data Transformation & Analytics

#### Metrics Aggregation Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Raw Metrics  │    │   Aggregation   │    │   Analytics     │
│   (Device      │───▶│   Engine        │───▶│   Engine        │
│    Level)      │    │   (Time-based)  │    │   (Trends)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Data         │    │   Statistical   │    │   Business      │
│   Validation   │    │   Processing    │    │   Intelligence  │
│   (Quality)    │    │   (Functions)   │    │   (Insights)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

#### Asset Health Assessment Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Monitoring   │    │   Health        │    │   Maintenance   │
│   Data         │───▶│   Scoring       │───▶│   Recommendations│
│   (Multi-source)│   │   Engine        │    │   (AI/ML)       │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Performance  │    │   Trend         │    │   Cost          │
│   Analysis     │    │   Analysis      │    │   Optimization  │
│   (Metrics)    │    │   (Historical)  │    │   (ROI)         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 6. Data Security & Compliance Flow

#### Security Data Flow
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User         │    │   Authentication│    │   Authorization │
│   Credentials  │───▶│   Service       │───▶│   Engine        │
│   (Login)      │    │   (JWT)         │    │   (RBAC)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Credential   │    │   Session       │    │   Audit         │
│   Encryption   │    │   Management    │    │   Logging       │
│   (AES-256)    │    │   (Tokens)      │    │   (Compliance)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 7. Data Flow Performance Characteristics

#### Throughput & Latency
```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Performance Metrics                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  Data Ingestion:    10,000+ devices × 30-60s intervals                     │
│  Metrics Processing: 1M+ metrics/minute with <100ms latency                │
│  Alert Generation:   <5s from threshold violation to notification          │
│  Dashboard Updates:  Real-time with <1s refresh intervals                  │
│  Data Retention:    1 year hot data, 7 years cold data                     │
│  Scalability:       Horizontal scaling with load balancing                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 8. Data Flow Monitoring & Observability

#### System Health Monitoring
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application  │    │   Infrastructure│    │   Business      │
│   Metrics      │───▶│   Monitoring    │───▶│   Metrics       │
│   (FastAPI)    │    │   (Prometheus)  │    │   (KPI)         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Log          │    │   Tracing       │    │   Alerting      │
│   Aggregation  │    │   (Distributed) │    │   (SLA)         │
│   (Structured) │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## API Documentation

### Authentication Endpoints
```http
POST   /api/v1/auth/register         # Register new user
POST   /api/v1/auth/login            # Login with credentials
POST   /api/v1/auth/logout           # Logout and invalidate token
POST   /api/v1/auth/refresh          # Refresh access token
GET    /api/v1/auth/me               # Get current user profile
PUT    /api/v1/auth/me               # Update profile
POST   /api/v1/auth/password/change  # Change password
POST   /api/v1/auth/mfa/setup        # Setup 2FA
```

### Device Management
```http
GET    /api/v1/devices                # List devices (paginated)
POST   /api/v1/devices                # Create device
GET    /api/v1/devices/{id}           # Get device details
PUT    /api/v1/devices/{id}           # Update device
DELETE /api/v1/devices/{id}           # Delete device
POST   /api/v1/devices/{id}/poll      # Trigger immediate polling
```

### Metrics & Performance
```http
POST   /api/v1/metrics                           # Submit metrics
GET    /api/v1/metrics/performance/summary       # Overall summary
GET    /api/v1/metrics/performance/{device_id}   # Device metrics
GET    /api/v1/metrics/performance/{id}/graph    # Time-series data
```

### Alert Management
```http
GET    /api/v1/alerts                    # List alerts
POST   /api/v1/alerts                    # Create alert
GET    /api/v1/alerts/statistics         # Alert stats
POST   /api/v1/alerts/{id}/acknowledge   # Acknowledge
POST   /api/v1/alerts/{id}/resolve       # Resolve
```

### Network Discovery
```http
POST   /api/v1/discovery/start           # Start discovery
GET    /api/v1/discovery                 # List jobs
GET    /api/v1/discovery/{id}/results    # Get results
```

### Additional Endpoints
- **Notifications**: `/api/v1/notifications`
- **SLA Monitoring**: `/api/v1/sla`
- **Topology**: `/api/v1/topology`
- **Import/Export**: `/api/v1/import`, `/api/v1/export`
- **Health Checks**: `/api/v1/health`
- **WebSocket**: `ws://localhost:8000/ws`

### API Documentation
- **Swagger UI**: http://localhost:8000/api/docs
- **ReDoc**: http://localhost:8000/api/redoc
- **OpenAPI Schema**: http://localhost:8000/api/openapi.json

## Quick Start

### Prerequisites
- Python 3.9 or higher
- PostgreSQL 13+
- Node.js 16+ (for frontend)
- Redis (optional, for caching)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/chm.git
cd chm
```

2. **Set up Python environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. **Set up the database**
```bash
# Create PostgreSQL database
createdb chm_db

# Run migrations
alembic upgrade head
```

5. **Start the backend**
```bash
uvicorn backend.api.main:app --reload --host 0.0.0.0 --port 8000
```

6. **Set up the frontend** (in a new terminal)
```bash
cd frontend
npm install
npm start
```

7. **Access the application**
- Frontend: http://localhost:3000
- API: http://localhost:8000
- API Docs: http://localhost:8000/api/docs

## Docker Deployment

### Using Docker Compose
```bash
# Development environment
docker-compose up -d

# Production environment
docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Building Images
```bash
# Backend
docker build -t chm-backend:latest ./backend

# Frontend
docker build -t chm-frontend:latest ./frontend
```

## Configuration

### Essential Environment Variables
```env
# Application
APP_NAME=Catalyst Health Monitor
ENVIRONMENT=production
DEBUG=False

# Database
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/chm_db

# Security (MUST CHANGE IN PRODUCTION)
JWT_SECRET_KEY=your-secret-key-here-minimum-32-characters
ENCRYPTION_KEY=your-encryption-key-here

# SNMP Defaults
SNMP_DEFAULT_COMMUNITY=public
SNMP_DEFAULT_VERSION=2c

# Redis (optional)
REDIS_URL=redis://localhost:6379/0

# Email Notifications (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=notifications@example.com
SMTP_PASSWORD=your-app-password
```

See `.env.example` for complete configuration options.

## Database Schema

### Core Tables
- **users** - User accounts with encrypted passwords
- **roles** - RBAC roles
- **permissions** - Granular permissions
- **user_sessions** - JWT session management
- **audit_logs** - Compliance audit trail

### Monitoring Tables
- **devices** - Device inventory with encrypted credentials
- **device_metrics** - Time-series performance data
- **alerts** - Alert management
- **network_interfaces** - Interface details

### Discovery & Topology
- **discovery_jobs** - Network discovery tasks
- **topology_nodes** - Network nodes
- **topology_edges** - Network connections

## Security Features

### Authentication & Authorization
- JWT tokens with refresh mechanism
- Role-based access control (RBAC)
- Multi-factor authentication (MFA)
- Password policies and complexity requirements
- Account lockout after failed attempts
- Session management and token invalidation

### Data Protection
- AES-256 encryption for credentials
- Encrypted storage for SNMP communities
- SSH key encryption
- API key management
- SQL injection prevention
- XSS protection
- CORS configuration

### Network Security
- Rate limiting per endpoint
- IP-based access control
- Audit logging for compliance
- Secure WebSocket connections
- HTTPS enforcement in production

## Monitoring Capabilities

### Device Metrics
- **Performance**: CPU, memory, disk usage
- **Network**: Interface statistics, bandwidth, errors
- **Availability**: Uptime, response time
- **Environmental**: Temperature, power, fans

### Supported Protocols
- **SNMP**: v1, v2c, v3 with encryption
- **SSH**: Key-based and password auth
- **REST APIs**: HTTP/HTTPS endpoints
- **ICMP**: Ping monitoring

### Vendor Support
- **Cisco**: Catalyst, Nexus, ISR, ASR
- **Juniper**: EX, MX, SRX series
- **Arista**: 7000 series
- **HP/Aruba**: ProCurve, Aruba
- **Others**: Brocade, Extreme, Dell

## Testing

### Running Tests
```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Coverage report
pytest --cov=backend --cov-report=html

# Linting
flake8 backend/
black backend/ --check
mypy backend/
```

### Test Coverage Areas
- API endpoints
- Authentication flows
- Database operations
- SNMP operations
- WebSocket connections
- Service layer logic

## Performance

### Scalability
- Async operations for high concurrency
- Connection pooling for database
- Redis caching for frequently accessed data
- Horizontal scaling with multiple workers
- Background task processing

### Optimization
- Database query optimization with indexes
- Bulk operations for device polling
- Efficient SNMP session management
- WebSocket connection pooling
- Lazy loading for large datasets

## Roadmap

### Version 2.1 (Q1 2024)
- [ ] Kubernetes operator for auto-discovery
- [ ] Grafana integration
- [ ] Custom dashboard builder
- [ ] Mobile application

### Version 2.2 (Q2 2024)
- [ ] Machine learning for anomaly detection
- [ ] Predictive maintenance
- [ ] Capacity planning tools
- [ ] Plugin system for custom monitors

### Future Enhancements
- [ ] Distributed monitoring agents
- [ ] GraphQL API
- [ ] Terraform provider
- [ ] Ansible modules
- [ ] NetBox integration

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Code Style
- Python: Black, flake8, mypy
- TypeScript: ESLint, Prettier
- Commits: Conventional Commits

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2Fcatherinevee%2Fchm.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2Fcatherinevee%2Fchm?ref=badge_large)

## Support

### Documentation
- [User Guide](docs/user-guide.md)
- [API Reference](docs/api-reference.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)

### Community
- [GitHub Issues](https://github.com/yourusername/chm/issues)
- [Discussions](https://github.com/yourusername/chm/discussions)
- [Discord Server](https://discord.gg/chm)

### Commercial Support
For enterprise support, please contact: enterprise@chm-monitor.com

## Team

- **Lead Developer**: [Your Name]
- **Contributors**: See [CONTRIBUTORS.md](CONTRIBUTORS.md)

## 🙏 Acknowledgments

- FastAPI for the excellent web framework
- SQLAlchemy for the powerful ORM
- React team for the frontend framework
- All open-source contributors

---

**Built with ❤️ for the DevOps and Network Engineering community**