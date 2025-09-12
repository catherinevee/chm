"""
Unified UUID type for database models with SQLite compatibility
"""

import os
import uuid
from sqlalchemy import String

# Check if we're in testing mode (SQLite) or production (PostgreSQL)
# Also check if pytest is running
import sys
is_testing = (
    os.environ.get("TESTING") == "true" or 
    os.environ.get("DATABASE_URL", "").startswith("sqlite") or
    "pytest" in sys.modules or
    "test" in sys.argv[0] if sys.argv else False
)

if is_testing:
    # Use String for SQLite
    def UUID(as_uuid=True):
        """String-based UUID for SQLite compatibility"""
        return String(36)
    
    def generate_uuid():
        """Generate string UUID for SQLite"""
        return str(uuid.uuid4())
else:
    # Use PostgreSQL UUID
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID
    UUID = PG_UUID
    
    def generate_uuid():
        """Generate UUID for PostgreSQL"""
        return uuid.uuid4()