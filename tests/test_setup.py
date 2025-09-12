"""
Test setup module to fix import paths and configure environment
This must be imported at the top of every test file
"""
import sys
import os

# Get the project root directory
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Add all necessary paths to Python path
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'backend'))
sys.path.insert(0, os.path.join(project_root, 'api'))
sys.path.insert(0, os.path.join(project_root, 'models'))
sys.path.insert(0, os.path.join(project_root, 'core'))

# Set test environment variables
os.environ['TESTING'] = 'true'
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key-for-testing'
os.environ['JWT_SECRET_KEY'] = 'test-jwt-secret'
os.environ['ENVIRONMENT'] = 'testing'
os.environ['LOG_LEVEL'] = 'DEBUG'

# Disable external services during testing
os.environ['EMAIL_ENABLED'] = 'false'
os.environ['SMS_ENABLED'] = 'false'
os.environ['WEBHOOK_ENABLED'] = 'false'
os.environ['REDIS_URL'] = 'redis://localhost:6379/15'

# Ensure the application can find all modules
def setup_test_paths():
    """Ensure all paths are properly configured"""
    return project_root

# Helper function to import application modules
def import_app_module(module_path):
    """Safely import application modules"""
    try:
        parts = module_path.split('.')
        module = __import__(module_path)
        for part in parts[1:]:
            module = getattr(module, part)
        return module
    except ImportError as e:
        print(f"Failed to import {module_path}: {e}")
        return None

# Initialize paths when this module is imported
PROJECT_ROOT = setup_test_paths()