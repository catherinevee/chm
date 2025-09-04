"""
Database connection management for CHM application
Integrates PostgreSQL, InfluxDB, Redis, and Neo4j
"""

import os
import asyncio
import logging
from typing import Optional, Dict, Any
from contextlib import asynccontextmanager

# PostgreSQL
import asyncpg
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

# InfluxDB
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

# Redis
import redis.asyncio as redis

# Neo4j
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages connections to all databases used by CHM"""
    
    def __init__(self):
        self.postgres_engine: Optional[Any] = None
        self.influx_client: Optional[InfluxDBClient] = None
        self.redis_client: Optional[redis.Redis] = None
        self.neo4j_driver: Optional[GraphDatabase] = None
        
        # Connection configurations
        self.postgres_url = os.getenv(
            "DATABASE_URL", 
            "postgresql+asyncpg://healthmon:password@localhost:5432/healthmonitor"
        )
        self.influx_url = os.getenv("INFLUXDB_URL", "http://localhost:8086")
        self.influx_token = os.getenv("INFLUXDB_TOKEN", "your-super-secret-auth-token")
        self.influx_org = os.getenv("INFLUXDB_ORG", "healthmonitor")
        self.influx_bucket = os.getenv("INFLUXDB_BUCKET", "metrics")
        
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        
        self.neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD", "password")
    
    async def initialize(self):
        """Initialize all database connections with graceful degradation"""
        self.connection_status = {
            'postgresql': False,
            'influxdb': False,
            'redis': False,
            'neo4j': False
        }
        
        # Initialize PostgreSQL with retry logic
        try:
            self.postgres_engine = create_async_engine(
                self.postgres_url,
                echo=False,
                pool_size=10,
                max_overflow=20,
                connect_args={"connect_timeout": 10}
            )
            # Test connection
            async with self.postgres_engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            self.connection_status['postgresql'] = True
            logger.info("PostgreSQL engine initialized and connected")
        except Exception as e:
            logger.warning(f"PostgreSQL connection failed: {e}")
            self.postgres_engine = None
        
        # Initialize InfluxDB with retry logic
        try:
            self.influx_client = InfluxDBClient(
                url=self.influx_url,
                token=self.influx_token,
                org=self.influx_org,
                timeout=10_000
            )
            # Test connection
            health = self.influx_client.health()
            if health.status == "pass":
                self.connection_status['influxdb'] = True
                logger.info("InfluxDB client initialized and connected")
            else:
                raise Exception(f"InfluxDB health check failed: {health.message}")
        except Exception as e:
            logger.warning(f"InfluxDB connection failed: {e}")
            self.influx_client = None
        
        # Initialize Redis with retry logic
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                socket_connect_timeout=10,
                socket_timeout=10
            )
            # Test connection
            await self.redis_client.ping()
            self.connection_status['redis'] = True
            logger.info("Redis client initialized and connected")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
        
        # Initialize Neo4j with retry logic
        try:
            self.neo4j_driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password),
                connection_timeout=10
            )
            # Test connection
            with self.neo4j_driver.session() as session:
                result = session.run("RETURN 1 as test")
                result.single()
            self.connection_status['neo4j'] = True
            logger.info("Neo4j driver initialized and connected")
        except Exception as e:
            logger.warning(f"Neo4j connection failed: {e}")
            self.neo4j_driver = None
        
        # Log connection summary
        connected_count = sum(self.connection_status.values())
        total_count = len(self.connection_status)
        logger.info(f"Database connection summary: {connected_count}/{total_count} connected")
        
        # Enable degraded mode if primary database (PostgreSQL) is down
        if not self.connection_status['postgresql']:
            logger.warning("PostgreSQL is down - enabling degraded mode")
            self._enable_degraded_mode()
        
        # Don't raise exception - allow app to start with degraded functionality
        if connected_count == 0:
            logger.error("No database connections available - app will have limited functionality")
        elif connected_count < total_count:
            logger.warning("Some database connections failed - app running with degraded functionality")
    
    def _enable_degraded_mode(self):
        """Enable degraded mode when primary database is unavailable"""
        self.degraded_mode = True
        logger.warning("Degraded mode enabled - some functionality will be limited")
    
    def is_available(self, db_type: str) -> bool:
        """Check if a specific database type is available"""
        return self.connection_status.get(db_type, False)
    
    def get_connection_summary(self) -> dict:
        """Get current connection status summary"""
        return {
            'status': self.connection_status,
            'degraded_mode': getattr(self, 'degraded_mode', False),
            'available_count': sum(self.connection_status.values()),
            'total_count': len(self.connection_status)
        }
    
    async def test_connections(self):
        """Test all database connections"""
        # Test PostgreSQL
        async with self.postgres_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("PostgreSQL health check passed")
        
        # Test InfluxDB
        health = self.influx_client.health()
        if health.status != "pass":
            raise Exception(f"InfluxDB health check failed: {health.message}")
        logger.info("InfluxDB health check passed")
        
        # Test Redis
        await self.redis_client.ping()
        logger.info("Redis health check passed")
        
        # Test Neo4j
        with self.neo4j_driver.session() as session:
            result = session.run("RETURN 1 as test")
            result.single()
        logger.info("Neo4j health check passed")
    
    async def close(self):
        """Close all database connections"""
        if self.postgres_engine:
            await self.postgres_engine.dispose()
            logger.info("PostgreSQL connection closed")
        
        if self.influx_client:
            self.influx_client.close()
            logger.info("InfluxDB connection closed")
        
        if self.redis_client:
            await self.redis_client.close()
            logger.info("Redis connection closed")
        
        if self.neo4j_driver:
            self.neo4j_driver.close()
            logger.info("Neo4j connection closed")
    
    @asynccontextmanager
    async def get_postgres_session(self):
        """Get PostgreSQL session"""
        if not self.postgres_engine:
            logger.warning("PostgreSQL not available - cannot provide session")
            yield None
            return
        
        async_session = sessionmaker(
            self.postgres_engine, class_=AsyncSession, expire_on_commit=False
        )
        async with async_session() as session:
            yield session
    
    def get_influx_write_api(self):
        """Get InfluxDB write API"""
        if not self.influx_client:
            logger.warning("InfluxDB not available - cannot provide write API")
            # Return fallback write API when InfluxDB not available
            fallback_data = FallbackData(
                data=None,
                source="influx_write_api_fallback",
                confidence=0.0,
                metadata={"reason": "InfluxDB not available"}
            )
            
            return create_failure_result(
                error="InfluxDB not available",
                error_code="INFLUXDB_NOT_AVAILABLE",
                fallback_data=fallback_data,
                suggestions=[
                    "InfluxDB not available",
                    "Check InfluxDB connection",
                    "Verify InfluxDB configuration",
                    "Enable InfluxDB service"
                ]
            )
        return self.influx_client.write_api(write_options=SYNCHRONOUS)
    
    def get_influx_query_api(self):
        """Get InfluxDB query API"""
        if not self.influx_client:
            logger.warning("InfluxDB not available - cannot provide query API")
            # Return fallback query API when InfluxDB not available
            fallback_data = FallbackData(
                data=None,
                source="influx_query_api_fallback",
                confidence=0.0,
                metadata={"reason": "InfluxDB not available"}
            )
            
            return create_failure_result(
                error="InfluxDB not available",
                error_code="INFLUXDB_NOT_AVAILABLE",
                fallback_data=fallback_data,
                suggestions=[
                    "InfluxDB not available",
                    "Check InfluxDB connection",
                    "Verify InfluxDB configuration",
                    "Enable InfluxDB service"
                ]
            )
        return self.influx_client.query_api()
    
    async def get_redis_client(self):
        """Get Redis client"""
        if not self.redis_client:
            logger.warning("Redis not available - cannot provide client")
            # Return fallback Redis client when Redis not available
            fallback_data = FallbackData(
                data=None,
                source="redis_client_fallback",
                confidence=0.0,
                metadata={"reason": "Redis not available"}
            )
            
            return create_failure_result(
                error="Redis not available",
                error_code="REDIS_NOT_AVAILABLE",
                fallback_data=fallback_data,
                suggestions=[
                    "Redis not available",
                    "Check Redis connection",
                    "Verify Redis configuration",
                    "Enable Redis service"
                ]
            )
        return self.redis_client
    
    def get_neo4j_session(self):
        """Get Neo4j session"""
        if not self.neo4j_driver:
            logger.warning("Neo4j not available - cannot provide session")
            # Return fallback Neo4j session when Neo4j not available
            fallback_data = FallbackData(
                data=None,
                source="neo4j_session_fallback",
                confidence=0.0,
                metadata={"reason": "Neo4j not available"}
            )
            
            return create_failure_result(
                error="Neo4j not available",
                error_code="NEO4J_NOT_AVAILABLE",
                fallback_data=fallback_data,
                suggestions=[
                    "Neo4j not available",
                    "Check Neo4j connection",
                    "Verify Neo4j configuration",
                    "Enable Neo4j service"
                ]
            )
        return self.neo4j_driver.session()

# Global database manager instance
db_manager = DatabaseManager()

async def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance"""
    return db_manager
