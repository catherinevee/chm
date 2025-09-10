#!/bin/bash

echo " Starting Catalyst Health Monitor Infrastructure..."

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo " Docker is not running. Please start Docker and try again."
    exit 1
fi

# Start infrastructure services only
echo " Starting infrastructure services (PostgreSQL, Redis, InfluxDB, Neo4j)..."
docker-compose up -d postgres redis influxdb neo4j

# Wait for services to be healthy
echo " Waiting for services to be ready..."
sleep 30

# Check if services are healthy
echo " Checking service health..."
docker-compose ps

echo "PASS: Infrastructure services started!"
echo " Access points:"
echo "   PostgreSQL: localhost:5432"
echo "   Redis: localhost:6379"
echo "   InfluxDB: localhost:8086"
echo "   Neo4j: localhost:7474 (browser) / localhost:7687 (bolt)"
echo ""
echo " Next steps:"
echo "   1. Initialize database: python scripts/start.py"
echo "   2. Start backend: python -m uvicorn backend.api.main:app --reload"
echo "   3. Start frontend: cd frontend && npm start"
