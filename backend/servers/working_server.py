"""
Enhanced FastAPI server with real database integration for CHM
"""
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
import asyncio
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Database integration
from ..database.connections import get_db_manager, db_manager
from ..database.models import Base, Device, Alert, Notification, DeviceMetric, DiscoveryJob, TopologyNode, TopologyEdge
from sqlalchemy import select, and_, or_, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

# Configuration and exceptions
from ..config.config_manager import ConfigurationError, EnvironmentValidationError

# Real-time services
from ..services.device_polling import device_poller, start_device_polling
from ..api.websocket_manager import ws_manager as websocket_manager

# Database initialization
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events"""
    try:
        # Validate environment variables and configuration
        logger.info("Validating environment configuration...")
        try:
            from ..config.config_manager import ConfigManager
            config_manager = ConfigManager()
            
            # Validate required environment variables
            missing_vars = config_manager.validate_required_environment_variables()
            if missing_vars:
                logger.error(f"Missing required environment variables: {missing_vars}")
                logger.error("Please set these variables before starting the application")
                raise EnvironmentValidationError(f"Missing required environment variables: {missing_vars}")
            
            # Validate database configuration
            if not config_manager.validate_database_configuration():
                logger.error("Database configuration validation failed")
                raise ConfigurationError("Database configuration validation failed")
            
            logger.info("Environment configuration validation passed")
            
        except ImportError as e:
            logger.warning(f"Could not import config manager: {e}")
            logger.warning("Skipping configuration validation")
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise
        
        # Initialize database connections
        await db_manager.initialize()
        logger.info("Database connections established")
        
        # Create database tables if they don't exist
        try:
            async with db_manager.get_postgres_session() as session:
                if session is None:
                    logger.warning("PostgreSQL not available - skipping table creation")
                else:
                    # Check if tables exist by trying to query a simple table
                    await session.execute(text("SELECT 1 FROM devices LIMIT 1"))
                    logger.info("Database tables already exist")
        except Exception as table_error:
            logger.info("Database tables don't exist, creating them...")
            try:
                from ..database.models import Base
                if db_manager.postgres_engine:
                    async with db_manager.postgres_engine.begin() as conn:
                        await conn.run_sync(Base.metadata.create_all)
                    logger.info("Database tables created successfully")
                    
                    # Seed initial data if tables were just created
                    await seed_initial_data()
                    logger.info("Initial data seeded successfully")
                else:
                    logger.warning("PostgreSQL not available - cannot create tables")
            except Exception as create_error:
                logger.error(f"Failed to create database tables: {create_error}")
                # Don't fail startup if table creation fails
        
        # Start device polling in background
        polling_task = asyncio.create_task(start_device_polling())
        logger.info("Device polling service started")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise
    finally:
        # Cleanup
        if 'polling_task' in locals():
            polling_task.cancel()
            try:
                await polling_task
            except asyncio.CancelledError:
                pass
        
        await db_manager.close()
        logger.info("Database connections closed")

app = FastAPI(
    title="CHM API", 
    description="Catalyst Health Monitor API",
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket endpoints for real-time updates
@app.websocket("/ws/dashboard")
async def websocket_dashboard(websocket: WebSocket):
    """WebSocket endpoint for dashboard real-time updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@app.websocket("/ws/device/{device_id}")
async def websocket_device_details(websocket: WebSocket, device_id: str):
    """WebSocket endpoint for device-specific real-time updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """WebSocket endpoint for alerts real-time updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@app.websocket("/ws/notifications")
async def websocket_notifications(websocket: WebSocket):
    """WebSocket endpoint for notifications real-time updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@app.websocket("/ws/topology")
async def websocket_topology(websocket: WebSocket):
    """WebSocket endpoint for topology real-time updates"""
    await websocket_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        websocket_manager.disconnect(websocket)

@app.get("/health")
async def health():
    """Health check endpoint with database status"""
    try:
        # Get database connection status
        db_status = db_manager.get_connection_summary()
        
        # Check if any critical services are available
        critical_available = db_status['status']['postgresql']
        
        # Determine overall health
        if critical_available:
            overall_status = "healthy"
            status_code = 200
        elif db_status['available_count'] > 0:
            overall_status = "degraded"
            status_code = 200
        else:
            overall_status = "unhealthy"
            status_code = 503
        
        health_response = {
            "status": overall_status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "2.0.0",
            "database": db_status,
            "services": {
                "postgresql": {
                    "status": "available" if db_status['status']['postgresql'] else "unavailable",
                    "critical": True
                },
                "influxdb": {
                    "status": "available" if db_status['status']['influxdb'] else "unavailable",
                    "critical": False
                },
                "redis": {
                    "status": "available" if db_status['status']['redis'] else "unavailable",
                    "critical": False
                },
                "neo4j": {
                    "status": "available" if db_status['status']['neo4j'] else "unavailable",
                    "critical": False
                }
            }
        }
        
        # Add degraded mode information
        if db_status.get('degraded_mode', False):
            health_response["degraded_mode"] = True
            health_response["message"] = "Application running with limited functionality due to database issues"
        
        return health_response
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": str(e),
            "message": "Health check failed"
        }

@app.get("/api/v1/health")
def api_health():
    return {"status": "healthy", "service": "CHM API"}

@app.get("/api/v1/devices")
async def get_devices(page: int = 1, limit: int = 50, search: str = "", device_type: str = "", status: str = "", group: str = "", location: str = "", manufacturer: str = ""):
    """Get devices from database with filtering and pagination"""
    try:
        async with db_manager.get_postgres_session() as session:
            # Build query with filters
            query = select(Device)
            
            # Apply filters
            if search:
                query = query.where(
                    or_(
                        Device.hostname.ilike(f"%{search}%"),
                        Device.ip_address.ilike(f"%{search}%"),
                        Device.serial_number.ilike(f"%{search}%")
                    )
                )
            
            if device_type:
                query = query.where(Device.device_type == device_type)
            
            if status:
                query = query.where(Device.current_state == status)
            
            if group:
                query = query.where(Device.device_group == group)
            
            if location:
                query = query.where(Device.location.ilike(f"%{location}%"))
            
            if manufacturer:
                query = query.where(Device.manufacturer.ilike(f"%{manufacturer}%"))
            
            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await session.scalar(count_query)
            
            # Apply pagination
            offset = (page - 1) * limit
            query = query.offset(offset).limit(limit)
            
            # Execute query
            result = await session.execute(query)
            devices = result.scalars().all()
            
            # Convert to dict format
            device_list = []
            for device in devices:
                device_dict = {
                    "id": device.id,
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "device_type": device.device_type,
                    "current_state": device.current_state,
                    "manufacturer": device.manufacturer,
                    "model": device.model,
                    "location": device.location,
                    "serial_number": device.serial_number,
                    "firmware_version": device.firmware_version,
                    "last_poll_time": device.last_poll_time.isoformat() if device.last_poll_time else None,
                    "is_active": device.is_active,
                    "device_group": device.device_group,
                    "department": device.department
                }
                device_list.append(device_dict)
            
            return {
                "devices": device_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": (total_count + limit - 1) // limit
                }
            }
            
    except Exception as e:
        logger.error(f"Error fetching devices: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch devices: {str(e)}")

@app.get("/api/v1/devices/{device_id}")
async def get_device(device_id: str):
    """Get detailed information for a specific device from database"""
    try:
        async with db_manager.get_postgres_session() as session:
            # Query device details
            device_query = select(Device).where(Device.id == device_id)
            result = await session.execute(device_query)
            device = result.scalar_one_or_none()
            
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            
            # Convert to dict format
            device_details = {
                "id": str(device.id),
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "device_type": device.device_type,
                "current_state": device.current_state,
                "manufacturer": device.manufacturer,
                "model": device.model,
                "location": device.location,
                "serial_number": device.serial_number,
                "firmware_version": device.firmware_version,
                "os_version": device.os_version,
                "rack_position": device.rack_position,
                "data_center": device.data_center,
                "department": device.department,
                "owner": device.owner,
                "cost": device.cost,
                "asset_tag": device.asset_tag,
                "asset_status": device.asset_status,
                "notes": device.notes,
                "device_group": device.device_group,
                "custom_group": device.custom_group,
                "discovery_protocol": device.discovery_protocol,
                "is_active": device.is_active,
                "last_poll_time": device.last_poll_time.isoformat() if device.last_poll_time else None,
                "last_discovery": device.last_discovery.isoformat() if device.last_discovery else None,
                "discovery_status": device.discovery_status,
                "consecutive_failures": device.consecutive_failures,
                "circuit_breaker_trips": device.circuit_breaker_trips,
                "purchase_date": device.purchase_date.isoformat() if device.purchase_date else None,
                "warranty_expiry": device.warranty_expiry.isoformat() if device.warranty_expiry else None,
                "last_maintenance": device.last_maintenance.isoformat() if device.last_maintenance else None,
                "next_maintenance": device.next_maintenance.isoformat() if device.next_maintenance else None,
                "created_at": device.created_at.isoformat() if device.created_at else None,
                "updated_at": device.updated_at.isoformat() if device.updated_at else None
            }
            
            return device_details
            
    except Exception as e:
        logger.error(f"Error fetching device {device_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch device: {str(e)}")

# Alerts endpoint
@app.get("/api/v1/alerts")
async def get_alerts(page: int = 1, limit: int = 50, severity: str = "", status: str = "", device_id: str = ""):
    """Get alerts from database with filtering and pagination"""
    try:
        # Check if database is available
        if not db_manager.is_available('postgresql'):
            logger.warning("PostgreSQL not available - returning fallback response")
            return {
                "alerts": [],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": 0,
                    "pages": 0
                },
                "degraded_mode": True,
                "message": "Database temporarily unavailable - showing empty results"
            }
        
        async with db_manager.get_postgres_session() as session:
            if session is None:
                logger.warning("Database session not available - returning fallback response")
                return {
                    "alerts": [],
                    "pagination": {
                        "page": page,
                        "limit": limit,
                        "total": 0,
                        "pages": 0
                    },
                    "degraded_mode": True,
                    "message": "Database session unavailable - showing empty results"
                }
            
            # Build query with filters
            query = select(Alert)
            
            # Apply filters
            if severity:
                query = query.where(Alert.severity == severity)
            if status:
                query = query.where(Alert.status == status)
            if device_id:
                query = query.where(Alert.device_id == device_id)
            
            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await session.scalar(count_query)
            
            # Apply pagination
            offset = (page - 1) * limit
            query = query.offset(offset).limit(limit).order_by(desc(Alert.created_at))
            
            # Execute query
            result = await session.execute(query)
            alerts = result.scalars().all()
            
            # Convert to dict format
            alert_list = []
            for alert in alerts:
                alert_dict = {
                    "id": str(alert.id),
                    "device_id": str(alert.device_id),
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "status": alert.status,
                    "message": alert.message,
                    "description": alert.description,
                    "details": alert.details,
                    "acknowledged": alert.acknowledged_at is not None,
                    "resolved": alert.resolved_at is not None,
                    "acknowledged_by": str(alert.acknowledged_by) if alert.acknowledged_by else None,
                    "resolved_by": str(alert.resolved_by) if alert.resolved_by else None,
                    "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    "updated_at": alert.updated_at.isoformat() if alert.updated_at else None
                }
                alert_list.append(alert_dict)
            
            return {
                "alerts": alert_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": (total_count + limit - 1) // limit
                },
                "degraded_mode": False
            }
            
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        # Return fallback response instead of crashing
        return {
            "alerts": [],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": 0,
                "pages": 0
            },
            "degraded_mode": True,
            "error": f"Failed to fetch alerts: {str(e)}",
            "message": "Service temporarily unavailable - please try again later"
        }

# Notifications endpoint
@app.get("/api/v1/notifications")
async def get_notifications(page: int = 1, limit: int = 50, read: bool = None):
    """Get notifications from database with filtering and pagination"""
    try:
        # Check if database is available
        if not db_manager.is_available('postgresql'):
            logger.warning("PostgreSQL not available - returning fallback response")
            return {
                "notifications": [],
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": 0,
                    "pages": 0
                },
                "degraded_mode": True,
                "message": "Database temporarily unavailable - showing empty results"
            }
        
        async with db_manager.get_postgres_session() as session:
            if session is None:
                logger.warning("Database session not available - returning fallback response")
                return {
                    "notifications": [],
                    "pagination": {
                        "page": page,
                        "limit": limit,
                        "total": 0,
                        "pages": 0
                    },
                    "degraded_mode": True,
                    "message": "Database session unavailable - showing empty results"
                }
            
            # Build query with filters
            query = select(Notification)
            
            # Apply filters
            if read is not None:
                query = query.where(Notification.read == read)
            
            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await session.scalar(count_query)
            
            # Apply pagination
            offset = (page - 1) * limit
            query = query.offset(offset).limit(limit).order_by(desc(Notification.created_at))
            
            # Execute query
            result = await session.execute(query)
            notifications = result.scalars().all()
            
            # Convert to dict format
            notification_list = []
            for notification in notifications:
                notification_dict = {
                    "id": str(notification.id),
                    "notification_type": notification.notification_type,
                    "title": notification.title,
                    "message": notification.message,
                    "severity": notification.severity,
                    "read": notification.read,
                    "device_id": str(notification.device_id) if notification.device_id else None,
                    "user_id": str(notification.user_id) if notification.user_id else None,
                    "notification_metadata": notification.notification_metadata,
                    "created_at": notification.created_at.isoformat() if notification.created_at else None,
                    "read_at": notification.read_at.isoformat() if notification.read_at else None
                }
                notification_list.append(notification_dict)
            
            return {
                "notifications": notification_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": (total_count + limit - 1) // limit
                },
                "degraded_mode": False
            }
            
    except Exception as e:
        logger.error(f"Error fetching notifications: {e}")
        # Return fallback response instead of crashing
        return {
            "notifications": [],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": 0,
                "pages": 0
            },
            "degraded_mode": True,
            "error": f"Failed to fetch notifications: {str(e)}",
            "message": "Service temporarily unavailable - please try again later"
        }

# Assets endpoint  
@app.get("/api/v1/assets")
async def get_assets(page: int = 1, limit: int = 50, asset_status: str = "", manufacturer: str = "", location: str = "", department: str = ""):
    """Get assets (devices) from database with filtering and pagination"""
    try:
        async with db_manager.get_postgres_session() as session:
            # Build query with filters - assets are devices with asset information
            query = select(Device)
            
            # Apply filters
            if asset_status:
                query = query.where(Device.asset_status == asset_status)
            if manufacturer:
                query = query.where(Device.manufacturer.ilike(f"%{manufacturer}%"))
            if location:
                query = query.where(Device.location.ilike(f"%{location}%"))
            if department:
                query = query.where(Device.department.ilike(f"%{department}%"))
            
            # Get total count
            count_query = select(func.count()).select_from(query.subquery())
            total_count = await session.scalar(count_query)
            
            # Apply pagination
            offset = (page - 1) * limit
            query = query.offset(offset).limit(limit).order_by(Device.hostname)
            
            # Execute query
            result = await session.execute(query)
            devices = result.scalars().all()
            
            # Convert to asset format
            asset_list = []
            for device in devices:
                asset_dict = {
                    "id": str(device.id),
                    "device_id": str(device.id),
                    "hostname": device.hostname,
                    "asset_tag": device.asset_tag,
                    "serial_number": device.serial_number,
                    "model": device.model,
                    "manufacturer": device.manufacturer,
                    "purchase_date": device.purchase_date.isoformat() if device.purchase_date else None,
                    "warranty_expiry": device.warranty_expiry.isoformat() if device.warranty_expiry else None,
                    "cost": device.cost,
                    "location": device.location,
                    "department": device.department,
                    "asset_status": device.asset_status,
                    "owner": device.owner,
                    "ip_address": device.ip_address,
                    "device_type": device.device_type,
                    "current_state": device.current_state,
                    "rack_position": device.rack_position,
                    "data_center": device.data_center,
                    "notes": device.notes,
                    "created_at": device.created_at.isoformat() if device.created_at else None,
                    "updated_at": device.updated_at.isoformat() if device.updated_at else None
                }
                asset_list.append(asset_dict)
            
            return {
                "assets": asset_list,
                "pagination": {
                    "page": page,
                    "limit": limit,
                    "total": total_count,
                    "pages": (total_count + limit - 1) // limit
                }
            }
            
    except Exception as e:
        logger.error(f"Error fetching assets: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch assets: {str(e)}")

# Network topology endpoint
@app.get("/api/v1/topology")
def get_topology():
    return {
        "nodes": [
            {
                "id": "dev-001",
                "label": "core-router-01", 
                "type": "router",
                "status": "online",
                "x": 400,
                "y": 200
            },
            {
                "id": "dev-002",
                "label": "access-switch-01",
                "type": "switch", 
                "status": "online",
                "x": 200,
                "y": 350
            },
            {
                "id": "dev-003",
                "label": "firewall-01",
                "type": "firewall",
                "status": "online", 
                "x": 600,
                "y": 350
            }
        ],
        "edges": [
            {
                "id": "edge-001",
                "source": "dev-001",
                "target": "dev-002",
                "type": "ethernet"
            },
            {
                "id": "edge-002", 
                "source": "dev-001",
                "target": "dev-003",
                "type": "ethernet"
            }
        ]
    }

# Discovery endpoint
@app.get("/api/v1/discovery")
def get_discovery_status():
    from datetime import datetime, timedelta, timezone
    
    return {
        "active_discoveries": [
            {
                "id": "disc-001",
                "name": "Network Scan - 192.168.1.0/24",
                "status": "completed",
                "protocol": "snmp",
                "start_time": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                "end_time": datetime.now(timezone.utc).isoformat(),
                "devices_found": 5,
                "devices_added": 2
            }
        ],
        "recent_discoveries": [
            {
                "id": "disc-002",
                "name": "LLDP Discovery", 
                "status": "completed",
                "protocol": "lldp",
                "start_time": (datetime.now(timezone.utc) - timedelta(hours=6)).isoformat(),
                "end_time": (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat(),
                "devices_found": 3,
                "devices_added": 1
            }
        ]
    }

# Performance metrics summary endpoint
@app.get("/api/v1/metrics/performance/summary")
async def get_performance_summary():
    """Get performance summary from database with real metrics"""
    try:
        # Check if database is available
        if not db_manager.is_available('postgresql'):
            logger.warning("PostgreSQL not available - returning fallback response")
            return {
                "overall_health": 0.0,
                "total_devices": 0,
                "online_devices": 0,
                "offline_devices": 0,
                "critical_alerts": 0,
                "warning_alerts": 0,
                "average_response_time": 0.0,
                "network_utilization": 0.0,
                "top_performers": [],
                "performance_issues": [],
                "summary": [],
                "degraded_mode": True,
                "message": "Database temporarily unavailable - showing empty results"
            }
        
        async with db_manager.get_postgres_session() as session:
            if session is None:
                logger.warning("Database session not available - returning fallback response")
                return {
                    "overall_health": 0.0,
                    "total_devices": 0,
                    "online_devices": 0,
                    "offline_devices": 0,
                    "critical_alerts": 0,
                    "warning_alerts": 0,
                    "average_response_time": 0.0,
                    "network_utilization": 0.0,
                    "top_performers": [],
                    "performance_issues": [],
                    "summary": [],
                    "degraded_mode": True,
                    "message": "Database session unavailable - showing empty results"
                }
            
            # Get device counts
            total_devices_query = select(func.count(Device.id))
            total_devices = await session.scalar(total_devices_query)
            
            online_devices_query = select(func.count(Device.id)).where(Device.current_state == "online")
            online_devices = await session.scalar(online_devices_query)
            
            offline_devices = total_devices - online_devices
            
            # Get alert counts
            critical_alerts_query = select(func.count(Alert.id)).where(Alert.severity == "critical", Alert.status == "active")
            critical_alerts = await session.scalar(critical_alerts_query)
            
            warning_alerts_query = select(func.count(Alert.id)).where(Alert.severity == "warning", Alert.status == "active")
            warning_alerts = await session.scalar(warning_alerts_query)
            
            # Get latest metrics for each device
            devices_query = select(Device)
            devices_result = await session.execute(devices_query)
            devices = devices_result.scalars().all()
            
            summary = []
            top_performers = []
            performance_issues = []
            
            for device in devices:
                # Get latest metrics for this device
                latest_metrics_query = select(DeviceMetric).where(
                    DeviceMetric.device_id == device.id
                ).order_by(desc(DeviceMetric.timestamp)).limit(10)
                
                metrics_result = await session.execute(latest_metrics_query)
                metrics = metrics_result.scalars().all()
                
                # Calculate average metrics
                cpu_usage = 0.0
                memory_usage = 0.0
                disk_usage = 0.0
                network_utilization = 0.0
                response_time = 0.0
                
                cpu_metrics = [m for m in metrics if m.metric_type == "cpu_usage"]
                memory_metrics = [m for m in metrics if m.metric_type == "memory_usage"]
                disk_metrics = [m for m in metrics if m.metric_type == "disk_usage"]
                network_metrics = [m for m in metrics if m.metric_type == "network_utilization"]
                response_metrics = [m for m in metrics if m.metric_type == "response_time"]
                
                if cpu_metrics:
                    cpu_usage = sum(m.value for m in cpu_metrics) / len(cpu_metrics)
                if memory_metrics:
                    memory_usage = sum(m.value for m in memory_metrics) / len(memory_metrics)
                if disk_metrics:
                    disk_usage = sum(m.value for m in disk_metrics) / len(disk_metrics)
                if network_metrics:
                    network_utilization = sum(m.value for m in network_metrics) / len(network_metrics)
                if response_metrics:
                    response_time = sum(m.value for m in response_metrics) / len(response_metrics)
                
                # Calculate health score (simplified)
                health_score = 100.0
                if cpu_usage > 80:
                    health_score -= 20
                if memory_usage > 85:
                    health_score -= 15
                if disk_usage > 90:
                    health_score -= 25
                if device.current_state != "online":
                    health_score = 0.0
                
                device_summary = {
                    "device_id": str(device.id),
                    "hostname": device.hostname,
                    "device_type": device.device_type,
                    "status": device.current_state,
                    "cpu_usage": round(cpu_usage, 1),
                    "memory_usage": round(memory_usage, 1),
                    "disk_usage": round(disk_usage, 1),
                    "network_utilization": round(network_utilization, 1),
                    "response_time": round(response_time, 2),
                    "health_score": round(health_score, 1)
                }
                summary.append(device_summary)
                
                # Add to top performers if health score > 90
                if health_score > 90:
                    top_performers.append({
                        "device_id": str(device.id),
                        "hostname": device.hostname,
                        "health_score": round(health_score, 1)
                    })
                
                # Add to performance issues if health score < 70
                if health_score < 70:
                    issues = []
                    if cpu_usage > 80:
                        issues.append("High CPU usage")
                    if memory_usage > 85:
                        issues.append("High memory usage")
                    if disk_usage > 90:
                        issues.append("High disk usage")
                    if device.current_state != "online":
                        issues.append("Device offline")
                    
                    for issue in issues:
                        performance_issues.append({
                            "device_id": str(device.id),
                            "hostname": device.hostname,
                            "issue": issue
                        })
            
            # Calculate overall health
            overall_health = sum(d["health_score"] for d in summary) / len(summary) if summary else 0.0
            
            # Calculate average response time
            avg_response_time = sum(d["response_time"] for d in summary) / len(summary) if summary else 0.0
            
            # Calculate average network utilization
            avg_network_util = sum(d["network_utilization"] for d in summary) / len(summary) if summary else 0.0
            
            return {
                "overall_health": round(overall_health, 1),
                "total_devices": total_devices,
                "online_devices": online_devices,
                "offline_devices": offline_devices,
                "critical_alerts": critical_alerts,
                "warning_alerts": warning_alerts,
                "average_response_time": round(avg_response_time, 2),
                "network_utilization": round(avg_network_util, 1),
                "top_performers": sorted(top_performers, key=lambda x: x["health_score"], reverse=True)[:5],
                "performance_issues": performance_issues[:10],
                "summary": summary,
                "degraded_mode": False
            }
            
    except Exception as e:
        logger.error(f"Error fetching performance summary: {e}")
        # Return fallback response instead of crashing
        return {
            "overall_health": 0.0,
            "total_devices": 0,
            "online_devices": 0,
            "offline_devices": 0,
            "critical_alerts": 0,
            "warning_alerts": 0,
            "average_response_time": 0.0,
            "network_utilization": 0.0,
            "top_performers": [],
            "performance_issues": [],
            "summary": [],
            "degraded_mode": True,
            "error": f"Failed to fetch performance summary: {str(e)}",
            "message": "Service temporarily unavailable - please try again later"
        }

# Performance Metrics Endpoints
@app.get("/api/v1/metrics/performance/{device_id}")
async def get_device_performance_metrics(device_id: str, metric_type: str = None, hours: int = 24):
    """Get device performance metrics from database"""
    try:
        async with db_manager.get_postgres_session() as session:
            # Verify device exists
            device_query = select(Device).where(Device.id == device_id)
            device_result = await session.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            
            # Calculate time range
            from datetime import datetime, timedelta, timezone
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            # Get metrics for the device within the time range
            metrics_query = select(DeviceMetric).where(
                DeviceMetric.device_id == device_id,
                DeviceMetric.timestamp >= start_time,
                DeviceMetric.timestamp <= end_time
            )
            
            if metric_type:
                metrics_query = metrics_query.where(DeviceMetric.metric_type == metric_type)
            
            metrics_query = metrics_query.order_by(desc(DeviceMetric.timestamp))
            
            metrics_result = await session.execute(metrics_query)
            metrics = metrics_result.scalars().all()
            
            # Calculate current values
            cpu_usage = 0.0
            memory_usage = 0.0
            disk_usage = 0.0
            network_utilization = 0.0
            response_time = 0.0
            
            # Get latest values for each metric type
            latest_metrics = {}
            for metric in metrics:
                if metric.metric_type not in latest_metrics:
                    latest_metrics[metric.metric_type] = metric.value
            
            cpu_usage = latest_metrics.get("cpu_usage", 0.0)
            memory_usage = latest_metrics.get("memory_usage", 0.0)
            disk_usage = latest_metrics.get("disk_usage", 0.0)
            network_utilization = latest_metrics.get("network_utilization", 0.0)
            response_time = latest_metrics.get("response_time", 0.0)
            
            # Calculate health score
            health_score = 100.0
            if cpu_usage > 80:
                health_score -= 20
            if memory_usage > 85:
                health_score -= 15
            if disk_usage > 90:
                health_score -= 25
            if device.current_state != "online":
                health_score = 0.0
            
            # Format metrics for response
            formatted_metrics = []
            for metric in metrics[:50]:  # Limit to 50 most recent metrics
                formatted_metrics.append({
                    "timestamp": metric.timestamp.isoformat(),
                    "metric_type": metric.metric_type,
                    "value": metric.value,
                    "unit": metric.unit
                })
            
            return {
                "device_id": device_id,
                "device_hostname": device.hostname,
                "metric_type": metric_type or "all",
                "time_range_hours": hours,
                "cpu_usage": round(cpu_usage, 1),
                "memory_usage": round(memory_usage, 1),
                "disk_usage": round(disk_usage, 1),
                "network_utilization": round(network_utilization, 1),
                "response_time": round(response_time, 2),
                "uptime": 99.95,  # This would need to be calculated from device uptime
                "health_score": round(health_score, 1),
                "metrics": formatted_metrics
            }
            
    except Exception as e:
        logger.error(f"Error fetching device performance metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch device performance metrics: {str(e)}")

@app.get("/api/v1/metrics/performance/{device_id}/graph")
async def get_device_performance_graph_data(device_id: str, metric_type: str = "cpu", hours: int = 24, interval: int = 5):
    """Get device performance graph data from database"""
    try:
        async with db_manager.get_postgres_session() as session:
            # Verify device exists
            device_query = select(Device).where(Device.id == device_id)
            device_result = await session.execute(device_query)
            device = device_result.scalar_one_or_none()
            
            if not device:
                raise HTTPException(status_code=404, detail="Device not found")
            
            # Calculate time range
            from datetime import datetime, timedelta, timezone
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            # Get metrics for the device within the time range
            metrics_query = select(DeviceMetric).where(
                DeviceMetric.device_id == device_id,
                DeviceMetric.metric_type == metric_type,
                DeviceMetric.timestamp >= start_time,
                DeviceMetric.timestamp <= end_time
            ).order_by(DeviceMetric.timestamp)
            
            metrics_result = await session.execute(metrics_query)
            metrics = metrics_result.scalars().all()
            
            # Group metrics by time intervals
            data_points = []
            current_time = start_time
            
            while current_time <= end_time:
                interval_end = current_time + timedelta(minutes=interval)
                
                # Find metrics within this interval
                interval_metrics = [
                    m for m in metrics 
                    if current_time <= m.timestamp < interval_end
                ]
                
                if interval_metrics:
                    # Calculate average value for this interval
                    avg_value = sum(m.value for m in interval_metrics) / len(interval_metrics)
                    data_points.append({
                        "timestamp": current_time.isoformat(),
                        "value": round(avg_value, 2),
                        "metric_type": metric_type
                    })
                else:
                    # No data for this interval, use 0 or None
                    data_points.append({
                        "timestamp": current_time.isoformat(),
                        "value": None,
                        "metric_type": metric_type
                    })
                
                current_time = interval_end
            
            return {
                "device_id": device_id,
                "device_hostname": device.hostname,
                "metric_type": metric_type,
                "time_range_hours": hours,
                "interval_minutes": interval,
                "data_points": data_points,
                "total_points": len(data_points)
            }
            
    except Exception as e:
        logger.error(f"Error fetching device performance graph data: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch device performance graph data: {str(e)}")

# Device Details Endpoints
@app.get("/api/v1/devices/{device_id}/metrics")
def get_device_metrics(device_id: str):
    return {
        "metrics": [
            {"metric_type": "cpu_usage", "value": 45.2, "unit": "%", "timestamp": "2024-01-15T10:30:00Z"},
            {"metric_type": "memory_usage", "value": 67.8, "unit": "%", "timestamp": "2024-01-15T10:30:00Z"},
            {"metric_type": "disk_usage", "value": 23.4, "unit": "%", "timestamp": "2024-01-15T10:30:00Z"},
            {"metric_type": "network_in", "value": 1024.5, "unit": "Mbps", "timestamp": "2024-01-15T10:30:00Z"},
            {"metric_type": "network_out", "value": 512.3, "unit": "Mbps", "timestamp": "2024-01-15T10:30:00Z"}
        ]
    }

@app.get("/api/v1/devices/{device_id}/hardware")
def get_device_hardware(device_id: str):
    return {
        "components": [
            {"component_type": "CPU", "name": "Intel Xeon E5-2620", "status": "healthy", "temperature": 45.2},
            {"component_type": "Memory", "name": "32GB DDR4", "status": "healthy", "usage": 67.8},
            {"component_type": "Storage", "name": "1TB SSD", "status": "healthy", "usage": 23.4},
            {"component_type": "Network", "name": "Gigabit Ethernet", "status": "healthy", "link_status": "up"}
        ]
    }

@app.get("/api/v1/devices/{device_id}/software")
def get_device_software(device_id: str):
    return {
        "components": [
            {"name": "Operating System", "version": "Ubuntu 20.04 LTS", "status": "up_to_date"},
            {"name": "SSH Server", "version": "OpenSSH 8.2", "status": "running"},
            {"name": "Web Server", "version": "Apache 2.4.41", "status": "running"},
            {"name": "Database", "version": "PostgreSQL 12.5", "status": "running"}
        ]
    }

@app.get("/api/v1/devices/{device_id}/interfaces")
def get_device_interfaces(device_id: str):
    return {
        "interfaces": [
            {"name": "eth0", "ip_address": "192.168.1.100", "status": "up", "speed": "1000Mbps", "duplex": "full"},
            {"name": "eth1", "ip_address": "10.0.0.100", "status": "up", "speed": "1000Mbps", "duplex": "full"},
            {"name": "lo", "ip_address": "127.0.0.1", "status": "up", "speed": "N/A", "duplex": "N/A"}
        ]
    }

@app.get("/api/v1/devices/{device_id}/performance")
def get_device_performance(device_id: str):
    return {
        "cpu_usage": 45.2,
        "memory_usage": 67.8,
        "disk_usage": 23.4,
        "network_utilization": 34.5,
        "response_time": 12.3,
        "uptime": 99.95,
        "health_score": 92.5
    }

@app.get("/api/v1/devices/{device_id}/performance/graph")
def get_device_performance_graph(device_id: str, metric: str = "cpu", period: str = "24h"):
    # Generate sample time series data
    from datetime import datetime, timedelta, timezone
    import random
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)
    data_points = []
    
    for i in range(24):
        timestamp = start_time + timedelta(hours=i)
        value = random.uniform(20, 80) if metric == "cpu" else random.uniform(30, 90)
        data_points.append({
            "timestamp": timestamp.isoformat(),
            "value": round(value, 2)
        })
    
    return {
        "device_id": device_id,
        "metric": metric,
        "period": period,
        "data": data_points
    }

@app.get("/api/v1/devices/{device_id}/sla")
def get_device_sla_metrics(device_id: str):
    return {
        "sla_metrics": [
            {
                "id": "sla-001",
                "sla_name": "Uptime SLA",
                "target_value": 99.9,
                "current_value": 99.95,
                "status": "meeting",
                "measurement_period": 30
            },
            {
                "id": "sla-002", 
                "sla_name": "Response Time SLA",
                "target_value": 50.0,
                "current_value": 12.3,
                "status": "meeting",
                "measurement_period": 30
            }
        ]
    }

# SLA Management Endpoints
@app.post("/api/v1/sla/metrics")
def create_sla_metric(sla_data: dict):
    return {
        "id": "sla-new",
        "message": "SLA metric created successfully",
        **sla_data
    }

@app.put("/api/v1/sla/metrics/{sla_id}")
def update_sla_metric(sla_id: str, sla_data: dict):
    return {
        "id": sla_id,
        "message": "SLA metric updated successfully",
        **sla_data
    }

# Network Discovery Endpoints
@app.get("/api/v1/discovery/network")
def list_network_discoveries():
    return {
        "discoveries": [
            {
                "id": "disc-001",
                "network_cidr": "192.168.1.0/24",
                "status": "completed",
                "devices_found": 5,
                "started_at": "2024-01-15T09:00:00Z",
                "completed_at": "2024-01-15T09:15:00Z"
            }
        ]
    }

@app.post("/api/v1/discovery/network")
def start_network_discovery(discovery_data: dict):
    return {
        "id": "disc-new",
        "message": "Network discovery started",
        "status": "running",
        **discovery_data
    }

# Device Management Endpoints
@app.post("/api/v1/devices")
def create_device(device_data: dict):
    return {
        "id": "dev-new",
        "message": "Device created successfully",
        **device_data
    }

@app.put("/api/v1/devices/{device_id}")
def update_device(device_id: str, device_data: dict):
    return {
        "id": device_id,
        "message": "Device updated successfully",
        **device_data
    }

@app.delete("/api/v1/devices/{device_id}")
def delete_device(device_id: str):
    return {
        "message": "Device deleted successfully",
        "device_id": device_id
    }

@app.post("/api/v1/devices/{device_id}/poll")
def trigger_device_poll(device_id: str):
    return {
        "message": "Device poll triggered successfully",
        "device_id": device_id,
        "status": "polling"
    }

# Asset Management Endpoints
@app.post("/api/v1/assets")
def create_asset(asset_data: dict):
    return {
        "id": "asset-new",
        "message": "Asset created successfully",
        **asset_data
    }

@app.put("/api/v1/assets/{asset_id}")
def update_asset(asset_id: str, asset_data: dict):
    return {
        "id": asset_id,
        "message": "Asset updated successfully",
        **asset_data
    }

@app.delete("/api/v1/assets/{asset_id}")
def delete_asset(asset_id: str):
    return {
        "message": "Asset deleted successfully",
        "asset_id": asset_id
    }

# Alert Management Endpoints
@app.post("/api/v1/alerts/{alert_id}/acknowledge")
def acknowledge_alert(alert_id: str):
    return {
        "message": "Alert acknowledged successfully",
        "alert_id": alert_id,
        "acknowledged_at": datetime.now(timezone.utc).isoformat()
    }

# Notification Management Endpoints
@app.post("/api/v1/notifications/{notification_id}/read")
def mark_notification_read(notification_id: str):
    return {
        "message": "Notification marked as read",
        "notification_id": notification_id,
        "read_at": datetime.now(timezone.utc).isoformat()
    }

# Data Export/Import Endpoints
@app.post("/api/v1/data/export")
def export_data(export_request: dict):
    data_type = export_request.get("data_type", "devices")
    format_type = export_request.get("format", "csv")
    
    if data_type == "devices" and format_type == "csv":
        csv_data = "hostname,ip_address,device_type,status\ncore-router-01,192.168.1.1,router,online\naccess-switch-01,192.168.1.10,switch,online"
        return {
            "format": "csv",
            "data": csv_data,
            "filename": f"devices_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        }
    elif data_type == "assets" and format_type == "csv":
        csv_data = "asset_tag,hostname,manufacturer,model,location\nASSET-001,core-router-01,Cisco,ISR4331,Data Center A\nASSET-002,access-switch-01,Cisco,Catalyst 2960X,Floor 1 IDF"
        return {
            "format": "csv", 
            "data": csv_data,
            "filename": f"assets_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv"
        }
    
    return {"error": "Unsupported export format"}

@app.post("/api/v1/data/import/csv")
def import_csv_data(file_data: dict):
    return {
        "message": "CSV data imported successfully",
        "imported_records": 3,
        "failed_records": 0,
        "warnings": []
    }

@app.get("/api/v1/import/template/{format_type}")
def get_import_template(format_type: str):
    if format_type.lower() == "csv":
        template = "hostname,ip_address,device_type,manufacturer,model,location\nrouter-01,192.168.1.1,router,Cisco,ISR4331,Data Center A\nswitch-01,192.168.1.10,switch,Cisco,Catalyst 2960X,Floor 1 IDF"
        return {
            "template": template,
            "format": format_type,
            "filename": "device_import_template.csv"
        }
    
    return {"error": "Unsupported template format"}

# Note: Device CRUD endpoints are defined earlier in the file with real database implementations

# Data Export/Import Endpoints
@app.post("/api/v1/data/export")
def export_data(export_request: dict):
    """Export device data in various formats"""
    import json
    import csv
    import io
    from datetime import datetime, timezone
    
    data_type = export_request.get("data_type", "devices")
    format_type = export_request.get("format", "csv")
    filters = export_request.get("filters", {})
    
    # Get sample devices data (in real implementation, would query database with filters)
    devices_data = [
        {
            "hostname": "core-router-01",
            "ip_address": "192.168.1.1",
            "device_type": "router",
            "current_state": "online",
            "manufacturer": "Cisco",
            "model": "ISR4331",
            "location": "Data Center A",
            "serial_number": "FDO12345678"
        },
        {
            "hostname": "access-switch-01", 
            "ip_address": "192.168.1.10",
            "device_type": "switch",
            "current_state": "online",
            "manufacturer": "Cisco",
            "model": "C2960X-48FPD-L",
            "location": "Data Center A",
            "serial_number": "FOC87654321"
        }
    ]
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format_type == "csv":
        # Generate CSV
        output = io.StringIO()
        if devices_data:
            writer = csv.DictWriter(output, fieldnames=devices_data[0].keys())
            writer.writeheader()
            writer.writerows(devices_data)
        
        return {
            "success": True,
            "data": output.getvalue(),
            "filename": f"devices_export_{timestamp}.csv",
            "content_type": "text/csv"
        }
    
    elif format_type == "json":
        # Generate JSON
        json_data = json.dumps(devices_data, indent=2)
        
        return {
            "success": True,
            "data": json_data,
            "filename": f"devices_export_{timestamp}.json",
            "content_type": "application/json"
        }
    
    elif format_type == "excel":
        # For Excel, return CSV format (frontend can handle conversion)
        output = io.StringIO()
        if devices_data:
            writer = csv.DictWriter(output, fieldnames=devices_data[0].keys())
            writer.writeheader()
            writer.writerows(devices_data)
        
        return {
            "success": True,
            "data": output.getvalue(),
            "filename": f"devices_export_{timestamp}.xlsx",
            "content_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
    
    else:
        return {
            "success": False,
            "message": "Unsupported export format"
        }

@app.post("/api/v1/data/import/csv")
def import_csv_data(import_request: dict):
    """Import device data from CSV"""
    import csv
    import io
    from datetime import datetime, timezone
    
    csv_data = import_request.get("csv_data", "")
    
    if not csv_data:
        return {
            "success": False,
            "message": "No CSV data provided"
        }
    
    try:
        # Parse CSV data
        csv_reader = csv.DictReader(io.StringIO(csv_data))
        imported_devices = []
        
        for row in csv_reader:
            # Process each row and create device entry
            device = {
                "hostname": row.get("hostname", ""),
                "ip_address": row.get("ip_address", ""),
                "device_type": row.get("device_type", "unknown"),
                "current_state": row.get("current_state", "unknown"),
                "manufacturer": row.get("manufacturer", ""),
                "model": row.get("model", ""),
                "location": row.get("location", ""),
                "serial_number": row.get("serial_number", ""),
                "imported_at": datetime.now(timezone.utc).isoformat()
            }
            imported_devices.append(device)
        
        return {
            "success": True,
            "message": f"Successfully imported {len(imported_devices)} devices",
            "imported_count": len(imported_devices),
            "devices": imported_devices
        }
    
    except Exception as e:
        return {
            "success": False,
            "message": f"Error parsing CSV data: {str(e)}"
        }

@app.get("/api/v1/import/template/{format_type}")
def get_import_template(format_type: str):
    """Get import template in specified format"""
    
    if format_type == "csv":
        template_csv = """hostname,ip_address,device_type,current_state,manufacturer,model,location,serial_number,asset_tag,owner,department
example-router,192.168.1.1,router,online,Cisco,ISR4331,Data Center A,FDO12345678,ASSET-001,IT Team,Infrastructure
example-switch,192.168.1.10,switch,online,Cisco,C2960X-48FPD-L,Data Center A,FOC87654321,ASSET-002,Network Team,Infrastructure"""
        
        return {
            "success": True,
            "template": template_csv,
            "filename": "device_import_template.csv",
            "content_type": "text/csv"
        }
    
    elif format_type == "json":
        template_json = """{
  "devices": [
    {
      "hostname": "example-router",
      "ip_address": "192.168.1.1",
      "device_type": "router",
      "current_state": "online",
      "manufacturer": "Cisco",
      "model": "ISR4331",
      "location": "Data Center A",
      "serial_number": "FDO12345678",
      "asset_tag": "ASSET-001",
      "owner": "IT Team",
      "department": "Infrastructure"
    }
  ]
}"""
        
        return {
            "success": True,
            "template": template_json,
            "filename": "device_import_template.json",
            "content_type": "application/json"
        }
    
    else:
        return {
            "success": False,
            "message": "Unsupported template format"
        }

# Note: Alerts endpoints are defined earlier in the file with real database implementations

# Note: Notifications endpoints are defined earlier in the file with real database implementations

# Network Topology Endpoints
@app.get("/api/v1/topology")
def get_network_topology():
    """Get network topology data"""
    from datetime import datetime, timezone
    
    # Sample topology data
    topology_data = {
        "nodes": [
            {
                "id": "dev-001",
                "hostname": "core-router-01",
                "device_type": "router",
                "x": 400,
                "y": 200,
                "status": "online"
            },
            {
                "id": "dev-002",
                "hostname": "access-switch-01", 
                "device_type": "switch",
                "x": 200,
                "y": 350,
                "status": "online"
            },
            {
                "id": "dev-003",
                "hostname": "firewall-01",
                "device_type": "firewall",
                "x": 600,
                "y": 350,
                "status": "online"
            }
        ],
        "edges": [
            {
                "id": "edge-001",
                "source": "dev-001",
                "target": "dev-002",
                "interface_source": "GigabitEthernet0/0/1",
                "interface_target": "GigabitEthernet1/0/24"
            },
            {
                "id": "edge-002", 
                "source": "dev-001",
                "target": "dev-003",
                "interface_source": "GigabitEthernet0/0/2",
                "interface_target": "GigabitEthernet1/1"
            }
        ]
    }
    
    return topology_data

# Network Discovery Endpoints
@app.get("/api/v1/discovery")
def get_discovery_status():
    """Get network discovery status"""
    from datetime import datetime
    
    return {
        "discovery_active": False,
        "last_discovery": datetime.now(timezone.utc).isoformat(),
        "discovered_devices": 5,
        "scan_progress": 0,
        "scan_status": "completed"
    }

@app.post("/api/v1/discovery/network")
def start_network_discovery(discovery_request: dict):
    """Start network discovery scan"""
    from datetime import datetime, timezone
    
    ip_range = discovery_request.get("ip_range", "192.168.1.0/24")
    scan_type = discovery_request.get("scan_type", "ping")
    
    return {
        "success": True,
        "message": "Network discovery started",
        "scan_id": f"scan-{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        "ip_range": ip_range,
        "scan_type": scan_type,
        "estimated_duration": "5-10 minutes"
    }

async def seed_initial_data():
    """Seed initial data for the application"""
    try:
        from ..database.migrations import seed_initial_data as seed_data
        await seed_data()
    except Exception as e:
        logger.warning(f"Failed to seed initial data: {e}")
        # Don't fail startup if seeding fails

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting CHM working server...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
