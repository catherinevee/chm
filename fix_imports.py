#!/usr/bin/env python3
"""
Fix imports after removing duplicate services directory.
Updates all imports from 'services.' to 'backend.services.'
"""

import os
import re
import sys

def fix_imports_in_file(filepath):
    """Fix imports in a single file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Fix various import patterns
        patterns = [
            # from backend.services.xxx import yyy
            (r'from services\.', r'from backend.services.'),
            # import backend.services.xxx
            (r'import services\.', r'import backend.services.'),
        ]
        
        for pattern, replacement in patterns:
            content = re.sub(pattern, replacement, content)
        
        # Special cases for services that were removed - map to existing ones
        replacements = {
            'from backend.services.alert_service': 'from backend.services.alert_service',
            'from backend.services.device_service': 'from backend.services.device_service',
            'from backend.services.discovery_service': 'from backend.services.discovery_service',
            'from backend.services.metrics_service': 'from backend.services.metrics_service',
            '# # from backend.services.metrics_service': '# # # from backend.services.metrics_service',  # Comment out for now
            'from backend.services.websocket_manager': 'from backend.services.websocket_manager',
            'from backend.services.redis_cache_service': 'from backend.services.redis_cache_service',
            'from backend.services.audit_service': 'from backend.services.audit_service',
            '# # from backend.services.background_tasks': '# # # from backend.services.background_tasks',  # Comment out
            'from backend.services.redis_cache_service': 'from backend.services.redis_cache_service',  # Use redis cache
            '# # from backend.services.connection_pool': '# # # from backend.services.connection_pool',  # Comment out
        }
        
        for old, new in replacements.items():
            content = content.replace(old, new)
        
        # Fix specific service references
        service_mappings = {
            'AlertService': 'AlertService',
            'device_service': 'device_service',
            'discovery_service': 'discovery_service',
            'metrics_service': 'metrics_service',
            'metrics_service': 'metrics_service',  # Map to metrics_service
            'websocket_manager': 'websocket_manager',
            'redis_cache_service': 'redis_cache_service',
            'audit_service': 'audit_service',
            'redis_cache_service': 'redis_cache_service',
            'AuditService': 'AuditService',
            'MetricsService': 'MetricsService',
            'MetricAggregationType': 'MetricAggregationType',
        }
        
        for old_name, new_name in service_mappings.items():
            # Only replace whole words
            content = re.sub(r'\b' + old_name + r'\b', new_name, content)
        
        if content != original_content:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"[FIXED] {filepath}")
            return True
        return False
    except Exception as e:
        print(f"[ERROR] {filepath}: {e}")
        return False

def main():
    """Main function to fix all imports."""
    print("Fixing imports after services directory cleanup...")
    print("=" * 60)
    
    # Get all Python files
    python_files = []
    for root, dirs, files in os.walk('.'):
        # Skip certain directories
        if any(skip in root for skip in ['.git', '__pycache__', '.venv', 'venv']):
            continue
        
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    
    print(f"Found {len(python_files)} Python files to check")
    
    fixed_count = 0
    for filepath in python_files:
        if fix_imports_in_file(filepath):
            fixed_count += 1
    
    print("=" * 60)
    print(f"[COMPLETE] Fixed imports in {fixed_count} files")
    
    # Additional fixes for specific issues
    print("\nApplying additional fixes...")
    
    # Fix backend/services/auth_service.py if it exists
    auth_service_path = 'backend/services/auth_service.py'
    if os.path.exists(auth_service_path):
        try:
            with open(auth_service_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Ensure auth_service is properly instantiated
            if 'auth_service = AuthService()' not in content:
                content += '\n\n# Create singleton instance\nauth_service = AuthService()\n'
                with open(auth_service_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                print(f"[ADDED] auth_service singleton to {auth_service_path}")
        except Exception as e:
            print(f"[ERROR] Could not fix {auth_service_path}: {e}")
    
    print("\n[COMPLETE] Import fixing complete!")
    print("\nNext steps:")
    print("1. Run: python main.py to test the application")
    print("2. Run: python run_chm_tests.py to run tests")

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.')
    main()