#!/usr/bin/env python3
"""
CHM Build Verification Script
Tests that the application can start and core components work
"""

import sys
import os
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

def main():
    print("CHM Build Verification")
    print("=" * 50)
    
    # Test 1: Core dependencies
    print("\n1. Checking core dependencies...")
    try:
        import fastapi
        import sqlalchemy
        import pydantic
        import jwt
        import bcrypt
        print("   [PASS] All core dependencies installed")
    except ImportError as e:
        print(f"   [FAIL] Missing dependency: {e}")
        return False
    
    # Test 2: Configuration
    print("\n2. Checking configuration...")
    try:
        # Clear any cached modules
        for module in list(sys.modules.keys()):
            if module.startswith('core.') or module.startswith('backend.'):
                del sys.modules[module]
        
        from core.config import get_settings
        settings = get_settings()
        print(f"   [PASS] Configuration loaded")
        print(f"   - App: {settings.app_name}")
        print(f"   - Version: {settings.version}")
    except Exception as e:
        print(f"   [FAIL] Configuration error: {e}")
        return False
    
    # Test 3: Database models
    print("\n3. Checking database models...")
    try:
        from models.user import User, UserRole
        from models.device import Device
        from models.metric import Metric
        from models.alert import Alert
        print("   [PASS] All models imported")
    except ImportError as e:
        print(f"   [FAIL] Model import error: {e}")
        return False
    
    # Test 4: Services
    print("\n4. Checking services...")
    try:
        from backend.services.auth_service import AuthService
        from backend.services.device_service import DeviceService
        from backend.services.alert_service import AlertService
        print("   [PASS] Core services available")
    except ImportError as e:
        print(f"   [FAIL] Service import error: {e}")
        return False
    
    # Test 5: API endpoints
    print("\n5. Checking API endpoints...")
    try:
        from api.v1 import auth, devices, metrics, alerts
        print("   [PASS] API modules loaded")
    except ImportError as e:
        print(f"   [FAIL] API import error: {e}")
        return False
    
    # Test 6: Main application
    print("\n6. Checking main application...")
    try:
        # Redirect stderr to suppress template directory warning
        import io
        old_stderr = sys.stderr
        sys.stderr = io.StringIO()
        
        import main
        app = main.create_app()
        
        # Restore stderr
        sys.stderr = old_stderr
        
        # Check app properties
        if not app.title or not app.version:
            print("   [WARN] App metadata incomplete")
        
        # Count routes
        routes = [r for r in app.routes if hasattr(r, 'path')]
        api_routes = [r for r in routes if '/api/' in str(r.path)]
        
        print(f"   [PASS] Application created")
        print(f"   - Total routes: {len(routes)}")
        print(f"   - API routes: {len(api_routes)}")
        
    except Exception as e:
        sys.stderr = old_stderr
        print(f"   [FAIL] Application error: {e}")
        return False
    
    return True

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.')
    
    success = main()
    
    print("\n" + "=" * 50)
    if success:
        print("BUILD STATUS: PASS")
        print("CHM application is ready for deployment")
        sys.exit(0)
    else:
        print("BUILD STATUS: FAIL")
        print("Please fix the errors above")
        sys.exit(1)