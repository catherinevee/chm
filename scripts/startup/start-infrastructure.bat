@echo off
echo 🚀 Starting Catalyst Health Monitor Infrastructure...

REM Check if Docker is running
docker info >nul 2>&1
if errorlevel 1 (
    echo ❌ Docker is not running. Please start Docker and try again.
    pause
    exit /b 1
)

REM Start infrastructure services only
echo 🔧 Starting infrastructure services (PostgreSQL, Redis, InfluxDB, Neo4j)...
docker-compose up -d postgres redis influxdb neo4j

REM Wait for services to be healthy
echo ⏳ Waiting for services to be ready...
timeout /t 30 /nobreak >nul

REM Check if services are healthy
echo 🔍 Checking service health...
docker-compose ps

echo ✅ Infrastructure services started!
echo 🌐 Access points:
echo    PostgreSQL: localhost:5432
echo    Redis: localhost:6379
echo    InfluxDB: localhost:8086
echo    Neo4j: localhost:7474 (browser) / localhost:7687 (bolt)
echo.
echo 📝 Next steps:
echo    1. Initialize database: python scripts/start.py
echo    2. Start backend: python -m uvicorn backend.api.main:app --reload
echo    3. Start frontend: cd frontend ^&^& npm start

pause
