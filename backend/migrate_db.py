#!/usr/bin/env python3
"""
Database migration script to add missing columns to the devices table
"""

import os
import sys

from sqlalchemy import create_engine, text
from sqlalchemy.exc import ProgrammingError


def migrate_database():
    """Add missing columns to the devices table"""
    
    # Get database URL from environment
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        print("Error: DATABASE_URL environment variable not set")
        sys.exit(1)
    
    # Convert async URL to sync URL
    sync_url = database_url.replace("+asyncpg", "")
    
    # Create engine
    engine = create_engine(sync_url)
    
    # Columns to add
    columns_to_add = [
        ("manufacturer", "VARCHAR(255)"),
        ("firmware_version", "VARCHAR(255)"),
        ("os_version", "VARCHAR(255)"),
        ("purchase_date", "TIMESTAMP"),
        ("warranty_expiry", "TIMESTAMP"),
        ("rack_position", "VARCHAR(100)"),
        ("data_center", "VARCHAR(255)"),
        ("department", "VARCHAR(255)"),
        ("owner", "VARCHAR(255)"),
        ("cost", "FLOAT"),
        ("asset_tag", "VARCHAR(255)"),
        ("asset_status", "VARCHAR(50)"),
        ("notes", "TEXT"),
        ("device_group", "VARCHAR(50)"),
        ("custom_group", "VARCHAR(255)"),
        ("last_maintenance", "TIMESTAMP"),
        ("next_maintenance", "TIMESTAMP"),
    ]
    
    with engine.connect() as conn:
        # Check if columns exist and add them if they don't
        for column_name, column_type in columns_to_add:
            try:
                # Try to add the column
                alter_sql = f"ALTER TABLE devices ADD COLUMN {column_name} {column_type}"
                conn.execute(text(alter_sql))
                conn.commit()
                print(f"✓ Added column: {column_name}")
            except ProgrammingError as e:
                if "already exists" in str(e):
                    print(f"✓ Column already exists: {column_name}")
                else:
                    print(f"✗ Error adding column {column_name}: {e}")
                    conn.rollback()
        
        # Add unique constraints if they don't exist
        try:
            conn.execute(text("ALTER TABLE devices ADD CONSTRAINT devices_asset_tag_unique UNIQUE (asset_tag)"))
            conn.commit()
            print("✓ Added unique constraint on asset_tag")
        except ProgrammingError as e:
            if "already exists" in str(e):
                print("✓ Unique constraint on asset_tag already exists")
            else:
                print(f"✗ Error adding unique constraint on asset_tag: {e}")
                conn.rollback()
    
    print("\nDatabase migration completed!")

if __name__ == "__main__":
    migrate_database()
