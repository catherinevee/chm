"""
Validation tests to ensure all fixes are working correctly
"""

import pytest
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_import_main_app():
    """Test that main app can be imported correctly"""
    try:
        from main import create_app, app
        assert app is not None
        assert create_app is not None
        print("✅ PASS: Main app imports work correctly")
    except ImportError as e:
        pytest.fail(f"❌ FAIL: Cannot import main app: {e}")

def test_import_core_config():
    """Test that core config can be imported correctly"""
    try:
        from core.config import get_settings, Settings
        settings = get_settings()
        assert settings is not None
        assert isinstance(settings, Settings)
        print("✅ PASS: Core config imports work correctly")
    except ImportError as e:
        pytest.fail(f"❌ FAIL: Cannot import core config: {e}")

def test_import_pydantic_settings():
    """Test that pydantic-settings is available"""
    try:
        from pydantic_settings import BaseSettings
        assert BaseSettings is not None
        print("✅ PASS: pydantic-settings is available")
    except ImportError as e:
        pytest.fail(f"❌ FAIL: pydantic-settings not available: {e}")

def test_app_creation():
    """Test that app can be created successfully"""
    try:
        from main import create_app
        app = create_app()
        assert app is not None
        assert app.title == "CHM - Catalyst Health Monitor"
        assert app.version == "2.0.0"
        print("✅ PASS: App creation works correctly")
    except Exception as e:
        pytest.fail(f"❌ FAIL: App creation failed: {e}")

def test_basic_imports():
    """Test that all basic imports work"""
    try:
        import fastapi
        import pydantic
        import sqlalchemy
        import pytest
        import asyncio
        print("✅ PASS: All basic imports work correctly")
    except ImportError as e:
        pytest.fail(f"❌ FAIL: Basic import failed: {e}")

def test_pytest_configuration():
    """Test that pytest configuration is working"""
    try:
        import pytest_asyncio
        assert pytest_asyncio is not None
        print("✅ PASS: pytest-asyncio is available")
    except ImportError as e:
        pytest.fail(f"❌ FAIL: pytest-asyncio not available: {e}")

if __name__ == "__main__":
    # Run basic validation
    print("🧪 Running CHM validation tests...")
    
    try:
        test_import_main_app()
        test_import_core_config()
        test_import_pydantic_settings()
        test_app_creation()
        test_basic_imports()
        test_pytest_configuration()
        print("\n🎉 All validation tests passed!")
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        sys.exit(1)
