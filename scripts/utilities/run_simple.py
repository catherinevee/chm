#!/usr/bin/env python3
"""
Simple startup script for CHM - runs with minimal dependencies
"""
import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Set environment variables
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://healthmon:password@localhost:5432/healthmonitor")

def check_dependencies():
    """Check if minimum dependencies are available"""
    required_packages = ['fastapi', 'uvicorn', 'sqlalchemy', 'asyncpg']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} - OK")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - Missing")
    
    if missing_packages:
        print(f"\n🚨 Missing packages: {', '.join(missing_packages)}")
        print("Install with: python -m pip install " + " ".join(missing_packages))
        return False
    
    print("\n✅ All required packages are available!")
    return True

def check_infrastructure():
    """Check if infrastructure services are running"""
    import socket
    
    services = {
        'PostgreSQL': ('localhost', 5432),
        'Redis': ('localhost', 6379),
        'InfluxDB': ('localhost', 8086),
        'Neo4j': ('localhost', 7474)
    }
    
    print("\n🔍 Checking infrastructure services:")
    all_good = True
    
    for service, (host, port) in services.items():
        try:
            with socket.create_connection((host, port), timeout=3):
                print(f"✅ {service} ({host}:{port}) - Running")
        except (socket.timeout, ConnectionRefusedError, OSError):
            print(f"❌ {service} ({host}:{port}) - Not accessible")
            if service == 'PostgreSQL':
                all_good = False  # PostgreSQL is critical
    
    return all_good

def run_api():
    """Run the FastAPI application"""
    try:
        import uvicorn
        from backend.api.main import app
        
        print("\n🚀 Starting CHM API server...")
        print("📍 API will be available at: http://localhost:8000")
        print("📖 API docs will be available at: http://localhost:8000/docs")
        print("🔍 Health check: http://localhost:8000/api/v1/health")
        print("\n⏹️  Press Ctrl+C to stop the server")
        
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        return False

def main():
    """Main function"""
    print("🏥 CHM (Catalyst Health Monitor) - Simple Startup")
    print("=" * 60)
    
    # Check dependencies
    if not check_dependencies():
        return 1
    
    # Check infrastructure
    if not check_infrastructure():
        print("\n⚠️  Some infrastructure services are not running.")
        print("   The API will start but some features may not work.")
        response = input("\n   Continue anyway? (y/N): ").lower().strip()
        if response != 'y':
            print("\n💡 Start infrastructure with: docker-compose up -d postgres redis influxdb neo4j")
            return 1
    
    # Run the API
    try:
        run_api()
        return 0
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down CHM API server...")
        return 0
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())



