#!/usr/bin/env python3
"""
Quick status check for CHM services
"""
import socket
import subprocess
import json
import sys

def check_port(host, port, service_name):
    """Check if a port is open"""
    try:
        with socket.create_connection((host, port), timeout=3):
            return f"✅ {service_name} ({host}:{port}) - Running"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return f"❌ {service_name} ({host}:{port}) - Not accessible"

def check_docker_containers():
    """Check Docker container status"""
    try:
        result = subprocess.run(['docker', 'ps', '--format', 'json'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            containers = []
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    try:
                        container = json.loads(line)
                        containers.append(f"✅ {container['Names']} - {container['Status']}")
                    except json.JSONDecodeError:
                        pass
            return containers if containers else ["❌ No containers running"]
        else:
            return ["❌ Docker not accessible or no containers"]
    except Exception as e:
        return [f"❌ Error checking Docker: {e}"]

def main():
    print("🏥 CHM Service Status Check")
    print("=" * 50)
    
    # Check infrastructure services
    print("\n📊 Infrastructure Services:")
    services = [
        ('localhost', 5432, 'PostgreSQL'),
        ('localhost', 6379, 'Redis'),
        ('localhost', 8086, 'InfluxDB'),
        ('localhost', 7474, 'Neo4j Browser'),
        ('localhost', 7687, 'Neo4j Bolt')
    ]
    
    for host, port, name in services:
        print(f"  {check_port(host, port, name)}")
    
    # Check application services
    print("\n🚀 Application Services:")
    app_services = [
        ('localhost', 8000, 'Backend API'),
        ('localhost', 8001, 'Discovery Service'),
        ('localhost', 3000, 'Frontend')
    ]
    
    for host, port, name in app_services:
        print(f"  {check_port(host, port, name)}")
    
    # Check Docker containers
    print("\n🐳 Docker Containers:")
    containers = check_docker_containers()
    for container in containers[:10]:  # Limit to first 10
        print(f"  {container}")
    
    # Test API health endpoint
    print("\n🔍 API Health Check:")
    try:
        import urllib.request
        import urllib.error
        
        with urllib.request.urlopen('http://localhost:8000/api/v1/health', timeout=5) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                print(f"  ✅ API Health: {data.get('status', 'unknown')}")
                if 'database' in data:
                    db_status = data['database'].get('healthy', False)
                    print(f"  ✅ Database: {'healthy' if db_status else 'unhealthy'}")
            else:
                print(f"  ❌ API returned status {response.status}")
    except urllib.error.URLError:
        print("  ❌ API not accessible")
    except Exception as e:
        print(f"  ❌ API health check failed: {e}")
    
    print("\n" + "=" * 50)
    print("💡 Next Steps:")
    print("  • If infrastructure services are down: docker-compose up -d postgres redis influxdb neo4j")
    print("  • If application services are down: docker-compose up -d")
    print("  • Check logs: docker-compose logs --tail=20")
    print("  • Access points:")
    print("    - Frontend: http://localhost:3000")
    print("    - Backend API: http://localhost:8000")
    print("    - API Docs: http://localhost:8000/docs")

if __name__ == "__main__":
    main()



