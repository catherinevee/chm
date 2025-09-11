#!/usr/bin/env python
"""
Test runner that ensures UUID patching happens before any imports
Run this instead of pytest directly to ensure proper SQLite compatibility
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Apply UUID patch BEFORE any model imports
import patch_uuid

# Now we can safely import and run pytest
import pytest

if __name__ == "__main__":
    # Run pytest with our test file
    sys.exit(pytest.main([
        "tests/test_100_percent_coverage_real.py",
        "-xvs",
        "--tb=short",
        "--cov=.",
        "--cov-report=term",
        "--cov-branch"
    ]))