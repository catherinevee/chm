"""
DEPRECATED - This file has been consolidated into /main.py

For backwards compatibility only. Will be removed in future versions.
"""

import warnings
import sys
import os

warnings.warn(
    "backend/main.py is deprecated. Use /main.py instead.",
    DeprecationWarning,
    stacklevel=2
)

# Add parent directory to path to import from root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import everything from the main entry point
from main import *

# Inform about the deprecation when run directly
if __name__ == "__main__":
    print("="*60)
    print("WARNING: backend/main.py is deprecated!")
    print("Please use 'python main.py' from the project root instead.")
    print("="*60)
    print()
    
    # Still run the app for compatibility
    import uvicorn
    from main import app
    uvicorn.run(app, host="0.0.0.0", port=8000)