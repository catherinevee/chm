"""
Test runner that ensures clean imports with UUID patching
"""

import os
import sys

# Set test environment BEFORE any imports
os.environ['TESTING'] = 'true'
os.environ['DATABASE_URL'] = 'sqlite+aiosqlite:///:memory:'

# Remove any cached imports of models
modules_to_remove = []
for module_name in list(sys.modules.keys()):
    if 'backend.database.models' in module_name or \
       'backend.database.user_models' in module_name or \
       'backend.models' in module_name or \
       'sqlalchemy.dialects.postgresql' in module_name:
        modules_to_remove.append(module_name)

for module_name in modules_to_remove:
    del sys.modules[module_name]

# Now run a simple test
import pytest

if __name__ == "__main__":
    sys.exit(pytest.main([
        "tests/test_100_percent_coverage_real.py::TestPhase1APIEndpoints::test_register_endpoint_success",
        "-xvs"
    ]))