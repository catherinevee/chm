#!/usr/bin/env python
"""
Database migration utility script
"""

import asyncio
import sys
import os
from pathlib import Path

# Add project root to path
sys.path.append(str(Path(__file__).parents[2]))

from alembic.config import Config
from alembic import command
from backend.config import settings
import logging

logger = logging.getLogger(__name__)


def get_alembic_config() -> Config:
    """Get Alembic configuration"""
    # Get the directory containing this script
    script_dir = Path(__file__).parent.parent.parent
    alembic_cfg = Config(script_dir / "alembic.ini")
    
    # Set the database URL
    database_url = (
        f"postgresql+asyncpg://{settings.database_user}:{settings.database_password}@"
        f"{settings.database_host}:{settings.database_port}/{settings.database_name}"
    )
    
    # Override the sqlalchemy.url in the config
    alembic_cfg.set_main_option("sqlalchemy.url", database_url)
    
    # Set environment variables for the migration environment
    os.environ["DB_USER"] = settings.database_user
    os.environ["DB_PASSWORD"] = settings.database_password
    os.environ["DB_HOST"] = settings.database_host
    os.environ["DB_PORT"] = str(settings.database_port)
    os.environ["DB_NAME"] = settings.database_name
    
    return alembic_cfg


def create_initial_migration():
    """Create the initial migration"""
    try:
        alembic_cfg = get_alembic_config()
        
        print("Creating initial migration...")
        command.revision(
            alembic_cfg,
            message="Initial database schema",
            autogenerate=True
        )
        print("✅ Initial migration created successfully")
        
    except Exception as e:
        print(f"❌ Error creating initial migration: {e}")
        sys.exit(1)


def upgrade_database(revision: str = "head"):
    """Upgrade database to specified revision"""
    try:
        alembic_cfg = get_alembic_config()
        
        print(f"Upgrading database to revision: {revision}")
        command.upgrade(alembic_cfg, revision)
        print("✅ Database upgraded successfully")
        
    except Exception as e:
        print(f"❌ Error upgrading database: {e}")
        sys.exit(1)


def downgrade_database(revision: str):
    """Downgrade database to specified revision"""
    try:
        alembic_cfg = get_alembic_config()
        
        print(f"Downgrading database to revision: {revision}")
        command.downgrade(alembic_cfg, revision)
        print("✅ Database downgraded successfully")
        
    except Exception as e:
        print(f"❌ Error downgrading database: {e}")
        sys.exit(1)


def show_current_revision():
    """Show current database revision"""
    try:
        alembic_cfg = get_alembic_config()
        
        print("Current database revision:")
        command.current(alembic_cfg)
        
    except Exception as e:
        print(f"❌ Error getting current revision: {e}")
        sys.exit(1)


def show_revision_history():
    """Show revision history"""
    try:
        alembic_cfg = get_alembic_config()
        
        print("Migration history:")
        command.history(alembic_cfg)
        
    except Exception as e:
        print(f"❌ Error getting revision history: {e}")
        sys.exit(1)


def create_new_migration(message: str):
    """Create a new migration with autogenerate"""
    try:
        alembic_cfg = get_alembic_config()
        
        print(f"Creating new migration: {message}")
        command.revision(
            alembic_cfg,
            message=message,
            autogenerate=True
        )
        print("✅ New migration created successfully")
        
    except Exception as e:
        print(f"❌ Error creating new migration: {e}")
        sys.exit(1)


def main():
    """Main CLI interface"""
    if len(sys.argv) < 2:
        print("""
Database Migration Utility

Usage:
    python migrate.py init                    # Create initial migration
    python migrate.py upgrade [revision]     # Upgrade to revision (default: head)
    python migrate.py downgrade <revision>   # Downgrade to revision
    python migrate.py current                # Show current revision
    python migrate.py history                # Show revision history
    python migrate.py create <message>       # Create new migration

Examples:
    python migrate.py init
    python migrate.py upgrade
    python migrate.py upgrade +1
    python migrate.py downgrade -1
    python migrate.py create "Add user preferences"
        """)
        sys.exit(1)
    
    command_name = sys.argv[1]
    
    if command_name == "init":
        create_initial_migration()
    elif command_name == "upgrade":
        revision = sys.argv[2] if len(sys.argv) > 2 else "head"
        upgrade_database(revision)
    elif command_name == "downgrade":
        if len(sys.argv) < 3:
            print("❌ Downgrade requires a revision argument")
            sys.exit(1)
        downgrade_database(sys.argv[2])
    elif command_name == "current":
        show_current_revision()
    elif command_name == "history":
        show_revision_history()
    elif command_name == "create":
        if len(sys.argv) < 3:
            print("❌ Create requires a message argument")
            sys.exit(1)
        create_new_migration(sys.argv[2])
    else:
        print(f"❌ Unknown command: {command_name}")
        sys.exit(1)


if __name__ == "__main__":
    main()