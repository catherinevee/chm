"""
Network topology API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, or_, func
from pydantic import BaseModel, Field
import logging
import uuid

from backend.database.models import TopologyNode, TopologyEdge, Device
from backend.database.base import get_db
from backend.api.dependencies.auth import (
    get_current_user,
    standard_rate_limit
)
from backend.database.user_models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/topology", tags=["topology"])

# Database session dependency is imported from backend.database.base

class TopologyNodeCreate(BaseModel):
    device_id: Optional[str] = None
    node_type: str = Field(..., description="Type of node (device, switch, router, etc.)")
    x_position: float = Field(default=0.0)
    y_position: float = Field(default=0.0)
    properties: Optional[Dict[str, Any]] = Field(default={})

class TopologyNodeUpdate(BaseModel):
    x_position: Optional[float] = None
    y_position: Optional[float] = None
    properties: Optional[Dict[str, Any]] = None

class TopologyNodeResponse(BaseModel):
    id: str
    device_id: Optional[str]
    device_info: Optional[Dict[str, Any]]
    node_type: str
    x_position: float
    y_position: float
    properties: Dict[str, Any]
    created_at: datetime
    updated_at: Optional[datetime]

class TopologyEdgeCreate(BaseModel):
    source_node_id: str
    target_node_id: str
    edge_type: Optional[str] = Field(default="connection")
    source_interface: Optional[str] = None
    target_interface: Optional[str] = None
    properties: Optional[Dict[str, Any]] = Field(default={})

class TopologyEdgeResponse(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    edge_type: Optional[str]
    source_interface: Optional[str]
    target_interface: Optional[str]
    properties: Dict[str, Any]
    created_at: datetime

class TopologyMapResponse(BaseModel):
    nodes: List[TopologyNodeResponse]
    edges: List[TopologyEdgeResponse]
    statistics: Dict[str, Any]

@router.get("", response_model=TopologyMapResponse)
async def get_topology_map(
    include_inactive: bool = False,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Get the complete network topology map
    """
    try:
        # Get all topology nodes
        nodes_query = select(TopologyNode)
        nodes_result = await db_session.execute(nodes_query)
        nodes = nodes_result.scalars().all()
        
        # Get all topology edges
        edges_query = select(TopologyEdge)
        edges_result = await db_session.execute(edges_query)
        edges = edges_result.scalars().all()
        
        # Build node responses with device info
        node_responses = []
        for node in nodes:
            device_info = None
            if node.device_id:
                device = await db_session.get(Device, node.device_id)
                if device and (include_inactive or device.is_active):
                    device_info = {
                        "hostname": device.hostname,
                        "ip_address": device.ip_address,
                        "device_type": device.device_type,
                        "state": device.current_state,
                        "manufacturer": device.manufacturer,
                        "model": device.model
                    }
            
            if device_info or not node.device_id:
                node_responses.append(TopologyNodeResponse(
                    id=str(node.id),
                    device_id=str(node.device_id) if node.device_id else None,
                    device_info=device_info,
                    node_type=node.node_type,
                    x_position=node.x_position or 0,
                    y_position=node.y_position or 0,
                    properties=node.properties or {},
                    created_at=node.created_at,
                    updated_at=node.updated_at
                ))
        
        # Build edge responses
        edge_responses = [
            TopologyEdgeResponse(
                id=str(edge.id),
                source_node_id=str(edge.source_node_id),
                target_node_id=str(edge.target_node_id),
                edge_type=edge.edge_type,
                source_interface=edge.source_interface,
                target_interface=edge.target_interface,
                properties=edge.properties or {},
                created_at=edge.created_at
            )
            for edge in edges
        ]
        
        # Calculate statistics
        device_count = await db_session.scalar(
            select(func.count()).select_from(Device)
            .where(Device.is_active == True) if not include_inactive else select(func.count()).select_from(Device)
        )
        
        statistics = {
            "total_nodes": len(node_responses),
            "total_edges": len(edge_responses),
            "total_devices": device_count,
            "node_types": {}
        }
        
        # Count node types
        for node in node_responses:
            node_type = node.node_type
            statistics["node_types"][node_type] = statistics["node_types"].get(node_type, 0) + 1
        
        return TopologyMapResponse(
            nodes=node_responses,
            edges=edge_responses,
            statistics=statistics
        )
        
    except Exception as e:
        logger.error(f"Error getting topology map: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get topology map"
        )

@router.post("/nodes", response_model=TopologyNodeResponse, dependencies=[Depends(standard_rate_limit)])
async def create_topology_node(
    node_data: TopologyNodeCreate,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Create a new topology node
    """
    try:
        # Verify device exists if device_id provided
        device_info = None
        if node_data.device_id:
            device = await db_session.get(Device, node_data.device_id)
            if not device:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Device not found"
                )
            device_info = {
                "hostname": device.hostname,
                "ip_address": device.ip_address,
                "device_type": device.device_type,
                "state": device.current_state
            }
        
        # Create topology node
        node = TopologyNode(
            device_id=node_data.device_id,
            node_type=node_data.node_type,
            x_position=node_data.x_position,
            y_position=node_data.y_position,
            properties=node_data.properties or {},
            created_at=datetime.utcnow()
        )
        
        db_session.add(node)
        await db_session.commit()
        await db_session.refresh(node)
        
        logger.info(f"Topology node created by user {current_user.username}")
        
        return TopologyNodeResponse(
            id=str(node.id),
            device_id=str(node.device_id) if node.device_id else None,
            device_info=device_info,
            node_type=node.node_type,
            x_position=node.x_position,
            y_position=node.y_position,
            properties=node.properties,
            created_at=node.created_at,
            updated_at=node.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating topology node: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create topology node"
        )

@router.put("/nodes/{node_id}", response_model=TopologyNodeResponse)
async def update_topology_node(
    node_id: str,
    update_data: TopologyNodeUpdate,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Update a topology node position or properties
    """
    try:
        # Get node
        node = await db_session.get(TopologyNode, node_id)
        if not node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Topology node not found"
            )
        
        # Update fields
        if update_data.x_position is not None:
            node.x_position = update_data.x_position
        if update_data.y_position is not None:
            node.y_position = update_data.y_position
        if update_data.properties is not None:
            node.properties = update_data.properties
        
        node.updated_at = datetime.utcnow()
        
        await db_session.commit()
        await db_session.refresh(node)
        
        # Get device info if available
        device_info = None
        if node.device_id:
            device = await db_session.get(Device, node.device_id)
            if device:
                device_info = {
                    "hostname": device.hostname,
                    "ip_address": device.ip_address,
                    "device_type": device.device_type,
                    "state": device.current_state
                }
        
        return TopologyNodeResponse(
            id=str(node.id),
            device_id=str(node.device_id) if node.device_id else None,
            device_info=device_info,
            node_type=node.node_type,
            x_position=node.x_position,
            y_position=node.y_position,
            properties=node.properties,
            created_at=node.created_at,
            updated_at=node.updated_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating topology node: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update topology node"
        )

@router.delete("/nodes/{node_id}")
async def delete_topology_node(
    node_id: str,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Delete a topology node and its connected edges
    """
    try:
        # Get node
        node = await db_session.get(TopologyNode, node_id)
        if not node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Topology node not found"
            )
        
        # Delete connected edges
        await db_session.execute(
            select(TopologyEdge).where(
                or_(
                    TopologyEdge.source_node_id == node_id,
                    TopologyEdge.target_node_id == node_id
                )
            )
        )
        
        # Delete node
        await db_session.delete(node)
        await db_session.commit()
        
        logger.info(f"Topology node {node_id} deleted by user {current_user.username}")
        
        return {"message": "Topology node deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting topology node: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete topology node"
        )

@router.post("/edges", response_model=TopologyEdgeResponse, dependencies=[Depends(standard_rate_limit)])
async def create_topology_edge(
    edge_data: TopologyEdgeCreate,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Create a new topology edge (connection between nodes)
    """
    try:
        # Verify both nodes exist
        source_node = await db_session.get(TopologyNode, edge_data.source_node_id)
        if not source_node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Source node not found"
            )
        
        target_node = await db_session.get(TopologyNode, edge_data.target_node_id)
        if not target_node:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Target node not found"
            )
        
        # Check if edge already exists
        existing_edge = await db_session.execute(
            select(TopologyEdge).where(
                or_(
                    and_(
                        TopologyEdge.source_node_id == edge_data.source_node_id,
                        TopologyEdge.target_node_id == edge_data.target_node_id
                    ),
                    and_(
                        TopologyEdge.source_node_id == edge_data.target_node_id,
                        TopologyEdge.target_node_id == edge_data.source_node_id
                    )
                )
            )
        )
        if existing_edge.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Edge between these nodes already exists"
            )
        
        # Create edge
        edge = TopologyEdge(
            source_node_id=edge_data.source_node_id,
            target_node_id=edge_data.target_node_id,
            edge_type=edge_data.edge_type,
            source_interface=edge_data.source_interface,
            target_interface=edge_data.target_interface,
            properties=edge_data.properties or {},
            created_at=datetime.utcnow()
        )
        
        db_session.add(edge)
        await db_session.commit()
        await db_session.refresh(edge)
        
        logger.info(f"Topology edge created by user {current_user.username}")
        
        return TopologyEdgeResponse(
            id=str(edge.id),
            source_node_id=str(edge.source_node_id),
            target_node_id=str(edge.target_node_id),
            edge_type=edge.edge_type,
            source_interface=edge.source_interface,
            target_interface=edge.target_interface,
            properties=edge.properties,
            created_at=edge.created_at
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating topology edge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create topology edge"
        )

@router.delete("/edges/{edge_id}")
async def delete_topology_edge(
    edge_id: str,
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Delete a topology edge
    """
    try:
        # Get edge
        edge = await db_session.get(TopologyEdge, edge_id)
        if not edge:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Topology edge not found"
            )
        
        # Delete edge
        await db_session.delete(edge)
        await db_session.commit()
        
        logger.info(f"Topology edge {edge_id} deleted by user {current_user.username}")
        
        return {"message": "Topology edge deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting topology edge: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete topology edge"
        )

@router.post("/auto-discover")
async def auto_discover_topology(
    current_user: User = Depends(get_current_user),
    db_session: AsyncSession = Depends(get_db)
):
    """
    Automatically discover network topology based on device connections
    """
    try:
        # This would integrate with the discovery service to map network connections
        # For now, return a placeholder response
        
        logger.info(f"Topology auto-discovery triggered by user {current_user.username}")
        
        return {
            "message": "Topology discovery initiated",
            "status": "in_progress",
            "estimated_time": "5-10 minutes"
        }
        
    except Exception as e:
        logger.error(f"Error in topology auto-discovery: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to initiate topology discovery"
        )