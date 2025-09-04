#!/bin/bash

echo "🚀 Rebuilding Docker images with Comprehensive SNMP Support"
echo "=========================================================="

# Stop existing containers
echo "📦 Stopping existing containers..."
docker compose down

# Remove old images to ensure clean rebuild
echo "🧹 Removing old images..."
docker rmi healthmon-backend healthmon-frontend healthmon-discovery 2>/dev/null || true

# Rebuild all services with comprehensive SNMP support
echo "🔨 Rebuilding services with enhanced SNMP monitoring..."
docker compose build --no-cache

# Start services
echo "🚀 Starting services with comprehensive SNMP support..."
docker compose up -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 30

# Check service status
echo "📊 Checking service status..."
docker compose ps

echo ""
echo "✅ Docker images updated with comprehensive SNMP support!"
echo ""
echo "🔍 Available services:"
echo "   - Backend API: http://localhost:8000"
echo "   - Frontend: http://localhost:3000"
echo "   - Discovery Service: http://localhost:8001"
echo "   - API Documentation: http://localhost:8000/docs"
echo ""
echo "📋 SNMP Monitoring Features:"
echo "   ✅ Complete MIB coverage (RFC 1213, RFC 2863)"
echo "   ✅ Vendor-specific OIDs (Cisco, Juniper, Arista)"
echo "   ✅ Performance monitoring (CPU, memory, temperature)"
echo "   ✅ Interface and network statistics"
echo "   ✅ Threshold management and alerting"
echo "   ✅ Network discovery with SNMP integration"
echo ""
echo "🎯 Test the enhanced SNMP monitoring:"
echo "   curl -X POST http://localhost:8001/api/v1/snmp/monitor/essential \\"
echo "     -F 'ip_address=192.168.1.1' \\"
echo "     -F 'community=public'"
