#!/usr/bin/env python3
"""
Fix backend.core imports to use correct paths
"""

import os
import re

def fix_imports_in_file(filepath):
    """Fix imports in a single file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Map of incorrect imports to correct ones
    replacements = [
        (r'from backend\.core\.database import', 'from core.database import'),
        (r'from backend\.core\.auth import', 'from backend.services.auth_service import'),
        (r'from backend\.core\.logging import get_logger', 'import logging\nlogger = logging.getLogger(__name__)'),
        (r'from backend\.core\.logging import', 'import logging'),
        (r'from backend\.core\.exceptions import', 'from backend.common.exceptions import'),
        (r'from backend\.core\.orchestrator import', 'from backend.core.orchestrator import'),  # Keep this one
        (r'import backend\.core\.', 'import backend.'),
    ]
    
    for pattern, replacement in replacements:
        content = re.sub(pattern, replacement, content)
    
    # Handle get_logger usage
    if 'logger = logging.getLogger(__name__)' in content:
        content = re.sub(r'logger = get_logger\(__name__\)', '', content)
        content = re.sub(r'get_logger\(__name__\)', 'logging.getLogger(__name__)', content)
    
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"Fixed imports in {filepath}")
        return True
    return False

def main():
    """Fix all imports"""
    files_to_fix = [
        'backend/api/v1/system.py',
        'backend/core/orchestrator.py',
        'backend/services/monitoring_engine.py',
        'backend/services/permission_service.py',
        'backend/services/rbac_service.py',
        'backend/services/snmp_service.py',
        'backend/services/ssh_service.py',
        'backend/services/websocket_service.py',
        'backend/services/redis_cache_service.py',
        'backend/api/websocket_handler.py',
        'backend/tasks/celery_app.py',
        'backend/migrations/env.py',
    ]
    
    fixed_count = 0
    for filepath in files_to_fix:
        if os.path.exists(filepath):
            if fix_imports_in_file(filepath):
                fixed_count += 1
        else:
            print(f"File not found: {filepath}")
    
    print(f"\nFixed {fixed_count} files")

if __name__ == "__main__":
    main()