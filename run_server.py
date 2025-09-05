#!/usr/bin/env python3
"""
CHM Server Startup Script
Run the CHM application locally
"""

import uvicorn
from app import app

if __name__ == "__main__":
    print("🚀 Starting CHM - Catalyst Health Monitor")
    print("📍 Server will be available at: http://127.0.0.1:8000")
    print("📚 API Documentation: http://127.0.0.1:8000/docs")
    print("🔍 Health Check: http://127.0.0.1:8000/health")
    print("=" * 50)
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )
