"""
Production distributed state management system.
Provides coordination, leader election, and state synchronization across CHM instances.
"""

import asyncio
import json
import time
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import logging
from contextlib import asynccontextmanager
import socket
import platform

try:
    import redis.asyncio as redis
    from redis.asyncio.lock import Lock as RedisLock
    from redis.asyncio.sentinel import Sentinel
    from redis.exceptions import RedisError, ConnectionError as RedisConnectionError
    REDIS_AVAILABLE = True
except ImportError:
    redis = None
    RedisLock = None
    Sentinel = None
    RedisError = Exception
    RedisConnectionError = Exception
    REDIS_AVAILABLE = False

try:
    from kazoo.client import KazooClient
    from kazoo.exceptions import KazooException, NodeExistsError, NoNodeError
    from kazoo.recipe.lock import Lock as ZookeeperLock
    from kazoo.recipe.election import Election
    from kazoo.recipe.partitioner import PartitionState
    ZOOKEEPER_AVAILABLE = True
except ImportError:
    KazooClient = None
    KazooException = Exception
    NodeExistsError = Exception
    NoNodeError = Exception
    ZookeeperLock = None
    Election = None
    PartitionState = None
    ZOOKEEPER_AVAILABLE = False

logger = logging.getLogger(__name__)

# Import result objects
from ..utils.result_objects import (
    create_success_result, create_failure_result, create_partial_success_result,
    FallbackData, HealthStatus, HealthLevel
)


class CoordinationBackend(Enum):
    """Available coordination backends"""
    REDIS = "redis"
    ZOOKEEPER = "zookeeper"
    ETCD = "etcd"
    LOCAL = "local"  # For single-instance deployments


class NodeRole(Enum):
    """Node roles in distributed system"""
    LEADER = "leader"
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    OBSERVER = "observer"


@dataclass
class NodeInfo:
    """Information about a node in the cluster"""
    node_id: str
    hostname: str
    ip_address: str
    port: int
    role: NodeRole
    last_heartbeat: datetime
    metadata: Dict[str, Any]
    capacity: float = 1.0  # Relative capacity for work distribution
    load: float = 0.0  # Current load percentage
    
    def is_healthy(self, timeout_seconds: int = 30) -> bool:
        """Check if node is healthy based on heartbeat"""
        return (datetime.now() - self.last_heartbeat).total_seconds() < timeout_seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'node_id': self.node_id,
            'hostname': self.hostname,
            'ip_address': self.ip_address,
            'port': self.port,
            'role': self.role.value,
            'last_heartbeat': self.last_heartbeat.isoformat(),
            'metadata': self.metadata,
            'capacity': self.capacity,
            'load': self.load
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'NodeInfo':
        """Create from dictionary"""
        return cls(
            node_id=data['node_id'],
            hostname=data['hostname'],
            ip_address=data['ip_address'],
            port=data['port'],
            role=NodeRole(data['role']),
            last_heartbeat=datetime.fromisoformat(data['last_heartbeat']),
            metadata=data.get('metadata', {}),
            capacity=data.get('capacity', 1.0),
            load=data.get('load', 0.0)
        )


@dataclass
class DistributedLock:
    """Distributed lock abstraction"""
    name: str
    owner: Optional[str] = None
    acquired_at: Optional[datetime] = None
    ttl_seconds: int = 60
    
    def is_expired(self) -> bool:
        """Check if lock has expired"""
        if not self.acquired_at:
            return True
        return (datetime.now() - self.acquired_at).total_seconds() > self.ttl_seconds


class DistributedStateManager:
    """Main distributed state management system"""
    
    def __init__(self,
                 backend: CoordinationBackend = CoordinationBackend.REDIS,
                 connection_string: Optional[str] = None,
                 node_id: Optional[str] = None,
                 heartbeat_interval: float = 10.0):
        self.backend = backend
        self.connection_string = connection_string
        self.node_id = node_id or self._generate_node_id()
        self.heartbeat_interval = heartbeat_interval
        
        # Node information
        self.node_info = self._create_node_info()
        self.cluster_nodes: Dict[str, NodeInfo] = {}
        
        # Leadership
        self.is_leader = False
        self.current_leader: Optional[str] = None
        self.leader_callbacks: List[Callable] = []
        
        # Locks
        self._locks: Dict[str, DistributedLock] = {}
        
        # State storage
        self._distributed_state: Dict[str, Any] = {}
        self._state_callbacks: Dict[str, List[Callable]] = {}
        
        # Backend connections
        self._redis_client: Optional[redis.Redis] = None
        self._zk_client: Optional[KazooClient] = None
        
        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._election_task: Optional[asyncio.Task] = None
        self._sync_task: Optional[asyncio.Task] = None
        self._running = False
    
    def _generate_node_id(self) -> str:
        """Generate unique node ID"""
        hostname = platform.node()
        mac = uuid.getnode()
        timestamp = int(time.time())
        
        unique_string = f"{hostname}-{mac}-{timestamp}"
        return hashlib.sha256(unique_string.encode()).hexdigest()[:16]
    
    def _create_node_info(self) -> NodeInfo:
        """Create node information"""
        hostname = platform.node()
        
        # Get primary IP address
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
            s.close()
        except Exception:
            ip_address = "127.0.0.1"
        
        return NodeInfo(
            node_id=self.node_id,
            hostname=hostname,
            ip_address=ip_address,
            port=8080,  # Default, should be configurable
            role=NodeRole.FOLLOWER,
            last_heartbeat=datetime.now(),
            metadata={
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'start_time': datetime.now().isoformat()
            }
        )
    
    async def initialize(self) -> bool:
        """Initialize the distributed state manager"""
        try:
            if self.backend == CoordinationBackend.REDIS:
                return await self._init_redis()
            elif self.backend == CoordinationBackend.ZOOKEEPER:
                return await self._init_zookeeper()
            elif self.backend == CoordinationBackend.LOCAL:
                return await self._init_local()
            else:
                logger.error(f"Unsupported backend: {self.backend}")
                return False
        except Exception as e:
            logger.error(f"Failed to initialize distributed state manager: {e}")
            return False
    
    async def _init_redis(self) -> bool:
        """Initialize Redis backend"""
        if not REDIS_AVAILABLE:
            logger.error("Redis library not available")
            return False
        
        try:
            # Parse connection string for sentinel or standalone
            if self.connection_string and "sentinel" in self.connection_string:
                # Sentinel configuration
                sentinels = self._parse_sentinel_config(self.connection_string)
                sentinel = Sentinel(sentinels)
                self._redis_client = await sentinel.master_for('mymaster', decode_responses=True)
            else:
                # Standalone Redis
                url = self.connection_string or "redis://localhost:6379/0"
                self._redis_client = redis.from_url(url, decode_responses=True)
            
            # Test connection
            await self._redis_client.ping()
            
            # Register node
            await self._register_node()
            
            logger.info(f"Redis backend initialized for node {self.node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis backend: {e}")
            return False
    
    async def _init_zookeeper(self) -> bool:
        """Initialize Zookeeper backend"""
        if not ZOOKEEPER_AVAILABLE:
            logger.error("Kazoo (Zookeeper) library not available")
            return False
        
        try:
            hosts = self.connection_string or "localhost:2181"
            self._zk_client = KazooClient(hosts=hosts)
            
            # Start client in async compatible way
            await asyncio.get_event_loop().run_in_executor(
                None, self._zk_client.start
            )
            
            # Create base paths
            base_paths = [
                "/chm",
                "/chm/nodes",
                "/chm/locks",
                "/chm/state",
                "/chm/election"
            ]
            
            for path in base_paths:
                await asyncio.get_event_loop().run_in_executor(
                    None, self._zk_client.ensure_path, path
                )
            
            # Register node
            await self._register_node_zk()
            
            logger.info(f"Zookeeper backend initialized for node {self.node_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Zookeeper backend: {e}")
            return False
    
    async def _init_local(self) -> bool:
        """Initialize local backend for single-instance deployment"""
        # Local mode - node is always leader
        self.is_leader = True
        self.current_leader = self.node_id
        self.node_info.role = NodeRole.LEADER
        
        logger.info(f"Local backend initialized for node {self.node_id}")
        return True
    
    async def start(self):
        """Start the distributed state manager"""
        if self._running:
            return
        
        self._running = True
        
        # Start background tasks
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        
        if self.backend != CoordinationBackend.LOCAL:
            self._election_task = asyncio.create_task(self._election_loop())
            self._sync_task = asyncio.create_task(self._sync_loop())
        
        logger.info("Distributed state manager started")
    
    async def stop(self):
        """Stop the distributed state manager"""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel background tasks
        tasks = [self._heartbeat_task, self._election_task, self._sync_task]
        for task in tasks:
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
        
        # Cleanup connections
        if self._redis_client:
            await self._redis_client.close()
        
        if self._zk_client:
            await asyncio.get_event_loop().run_in_executor(
                None, self._zk_client.stop
            )
        
        logger.info("Distributed state manager stopped")
    
    async def _register_node(self):
        """Register node in the cluster"""
        if self.backend == CoordinationBackend.REDIS:
            # Store node info in Redis
            node_key = f"chm:nodes:{self.node_id}"
            node_data = json.dumps(self.node_info.to_dict())
            
            await self._redis_client.setex(
                node_key,
                int(self.heartbeat_interval * 3),  # TTL = 3x heartbeat interval
                node_data
            )
            
            # Add to node set
            await self._redis_client.sadd("chm:nodes:active", self.node_id)
    
    async def _register_node_zk(self):
        """Register node in Zookeeper"""
        node_path = f"/chm/nodes/{self.node_id}"
        node_data = json.dumps(self.node_info.to_dict()).encode()
        
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                self._zk_client.create,
                node_path,
                node_data,
                ephemeral=True  # Node disappears if connection lost
            )
        except NodeExistsError:
            # Update existing node
            await asyncio.get_event_loop().run_in_executor(
                None,
                self._zk_client.set,
                node_path,
                node_data
            )
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats"""
        try:
            while self._running:
                await self._send_heartbeat()
                await self._discover_nodes()
                await asyncio.sleep(self.heartbeat_interval)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in heartbeat loop: {e}")
    
    async def _send_heartbeat(self):
        """Send heartbeat signal"""
        self.node_info.last_heartbeat = datetime.now()
        
        if self.backend == CoordinationBackend.REDIS:
            node_key = f"chm:nodes:{self.node_id}"
            node_data = json.dumps(self.node_info.to_dict())
            
            await self._redis_client.setex(
                node_key,
                int(self.heartbeat_interval * 3),
                node_data
            )
        elif self.backend == CoordinationBackend.ZOOKEEPER:
            await self._register_node_zk()
    
    async def _discover_nodes(self):
        """Discover other nodes in the cluster"""
        if self.backend == CoordinationBackend.REDIS:
            # Get all active nodes
            node_ids = await self._redis_client.smembers("chm:nodes:active")
            
            current_nodes = {}
            for node_id in node_ids:
                node_key = f"chm:nodes:{node_id}"
                node_data = await self._redis_client.get(node_key)
                
                if node_data:
                    try:
                        node_dict = json.loads(node_data)
                        node_info = NodeInfo.from_dict(node_dict)
                        
                        if node_info.is_healthy(int(self.heartbeat_interval * 3)):
                            current_nodes[node_id] = node_info
                        else:
                            # Remove stale node
                            await self._redis_client.srem("chm:nodes:active", node_id)
                    except Exception as e:
                        logger.warning(f"Failed to parse node data for {node_id}: {e}")
            
            self.cluster_nodes = current_nodes
            
        elif self.backend == CoordinationBackend.ZOOKEEPER:
            # Get all nodes from Zookeeper
            nodes = await asyncio.get_event_loop().run_in_executor(
                None,
                self._zk_client.get_children,
                "/chm/nodes"
            )
            
            current_nodes = {}
            for node_id in nodes:
                node_path = f"/chm/nodes/{node_id}"
                try:
                    data, stat = await asyncio.get_event_loop().run_in_executor(
                        None,
                        self._zk_client.get,
                        node_path
                    )
                    
                    node_dict = json.loads(data.decode())
                    node_info = NodeInfo.from_dict(node_dict)
                    current_nodes[node_id] = node_info
                except Exception as e:
                    logger.warning(f"Failed to get node data for {node_id}: {e}")
            
            self.cluster_nodes = current_nodes
    
    async def _election_loop(self):
        """Handle leader election"""
        try:
            while self._running:
                await self._participate_in_election()
                await asyncio.sleep(5)  # Check election status every 5 seconds
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in election loop: {e}")
    
    async def _participate_in_election(self):
        """Participate in leader election"""
        if self.backend == CoordinationBackend.REDIS:
            # Redis-based leader election using SET NX with TTL
            leader_key = "chm:leader"
            ttl = int(self.heartbeat_interval * 2)
            
            # Try to become leader
            result = await self._redis_client.set(
                leader_key,
                self.node_id,
                nx=True,  # Only set if not exists
                ex=ttl    # Expire after TTL
            )
            
            if result:
                # Became leader
                if not self.is_leader:
                    await self._become_leader()
            else:
                # Check current leader
                current_leader = await self._redis_client.get(leader_key)
                
                if current_leader == self.node_id:
                    # Still leader, extend TTL
                    await self._redis_client.expire(leader_key, ttl)
                else:
                    # Someone else is leader
                    if self.is_leader:
                        await self._become_follower(current_leader)
                    self.current_leader = current_leader
        
        elif self.backend == CoordinationBackend.ZOOKEEPER:
            # Zookeeper-based leader election
            election_path = "/chm/election"
            election = Election(self._zk_client, election_path, self.node_id)
            
            # Run election (this is blocking, so run in executor)
            await asyncio.get_event_loop().run_in_executor(
                None,
                election.run,
                self._zk_leader_function
            )
    
    def _zk_leader_function(self):
        """Function to run when elected as leader in Zookeeper"""
        asyncio.create_task(self._become_leader())
    
    async def _become_leader(self):
        """Handle becoming the leader"""
        logger.info(f"Node {self.node_id} became leader")
        
        self.is_leader = True
        self.current_leader = self.node_id
        self.node_info.role = NodeRole.LEADER
        
        # Notify callbacks
        for callback in self.leader_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(True)
                else:
                    callback(True)
            except Exception as e:
                logger.error(f"Error in leader callback: {e}")
    
    async def _become_follower(self, leader_id: str):
        """Handle becoming a follower"""
        logger.info(f"Node {self.node_id} became follower (leader: {leader_id})")
        
        self.is_leader = False
        self.current_leader = leader_id
        self.node_info.role = NodeRole.FOLLOWER
        
        # Notify callbacks
        for callback in self.leader_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(False)
                else:
                    callback(False)
            except Exception as e:
                logger.error(f"Error in leader callback: {e}")
    
    async def _sync_loop(self):
        """Synchronize state with cluster"""
        try:
            while self._running:
                await self._sync_state()
                await asyncio.sleep(30)  # Sync every 30 seconds
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"Error in sync loop: {e}")
    
    async def _sync_state(self):
        """Synchronize distributed state"""
        if self.backend == CoordinationBackend.REDIS:
            # Get all state keys
            state_keys = await self._redis_client.keys("chm:state:*")
            
            for key in state_keys:
                state_name = key.replace("chm:state:", "")
                value = await self._redis_client.get(key)
                
                if value:
                    try:
                        parsed_value = json.loads(value)
                        
                        # Update local state if different
                        if state_name not in self._distributed_state or \
                           self._distributed_state[state_name] != parsed_value:
                            self._distributed_state[state_name] = parsed_value
                            
                            # Notify callbacks
                            if state_name in self._state_callbacks:
                                for callback in self._state_callbacks[state_name]:
                                    try:
                                        if asyncio.iscoroutinefunction(callback):
                                            await callback(parsed_value)
                                        else:
                                            callback(parsed_value)
                                    except Exception as e:
                                        logger.error(f"Error in state callback: {e}")
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse state value for {state_name}")
    
    @asynccontextmanager
    async def acquire_lock(self, 
                          lock_name: str, 
                          ttl_seconds: int = 60,
                          wait: bool = True,
                          timeout: float = 10.0):
        """Acquire a distributed lock"""
        lock_acquired = False
        
        try:
            if self.backend == CoordinationBackend.REDIS:
                lock_key = f"chm:locks:{lock_name}"
                lock_value = f"{self.node_id}:{uuid.uuid4()}"
                
                # Try to acquire lock
                start_time = time.time()
                
                while True:
                    result = await self._redis_client.set(
                        lock_key,
                        lock_value,
                        nx=True,
                        ex=ttl_seconds
                    )
                    
                    if result:
                        lock_acquired = True
                        self._locks[lock_name] = DistributedLock(
                            name=lock_name,
                            owner=self.node_id,
                            acquired_at=datetime.now(),
                            ttl_seconds=ttl_seconds
                        )
                        break
                    
                    if not wait or (time.time() - start_time) > timeout:
                        raise asyncio.TimeoutError(f"Failed to acquire lock {lock_name}")
                    
                    await asyncio.sleep(0.1)
                
                yield lock_acquired
                
            elif self.backend == CoordinationBackend.LOCAL:
                # Local lock (no-op for single instance)
                lock_acquired = True
                yield lock_acquired
                
        finally:
            if lock_acquired:
                await self.release_lock(lock_name)
    
    async def release_lock(self, lock_name: str):
        """Release a distributed lock"""
        if self.backend == CoordinationBackend.REDIS:
            lock_key = f"chm:locks:{lock_name}"
            await self._redis_client.delete(lock_key)
        
        if lock_name in self._locks:
            del self._locks[lock_name]
    
    async def set_state(self, key: str, value: Any, ttl: Optional[int] = None):
        """Set distributed state value"""
        self._distributed_state[key] = value
        
        if self.backend == CoordinationBackend.REDIS:
            state_key = f"chm:state:{key}"
            serialized = json.dumps(value)
            
            if ttl:
                await self._redis_client.setex(state_key, ttl, serialized)
            else:
                await self._redis_client.set(state_key, serialized)
        
        elif self.backend == CoordinationBackend.ZOOKEEPER:
            state_path = f"/chm/state/{key}"
            serialized = json.dumps(value).encode()
            
            try:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._zk_client.create,
                    state_path,
                    serialized
                )
            except NodeExistsError:
                await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._zk_client.set,
                    state_path,
                    serialized
                )
    
    async def get_state(self, key: str) -> Optional[Any]:
        """Get distributed state value"""
        # Check local cache first
        if key in self._distributed_state:
            return self._distributed_state[key]
        
        if self.backend == CoordinationBackend.REDIS:
            state_key = f"chm:state:{key}"
            value = await self._redis_client.get(state_key)
            
            if value:
                try:
                    parsed = json.loads(value)
                    self._distributed_state[key] = parsed
                    return parsed
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse state value for {key}")
        
        elif self.backend == CoordinationBackend.ZOOKEEPER:
            state_path = f"/chm/state/{key}"
            
            try:
                data, stat = await asyncio.get_event_loop().run_in_executor(
                    None,
                    self._zk_client.get,
                    state_path
                )
                
                parsed = json.loads(data.decode())
                self._distributed_state[key] = parsed
                return parsed
            except NoNodeError:
                return create_partial_success_result(
                    data=None,
                    error_code="STATE_NODE_NOT_FOUND",
                    message=f"State node not found for key: {key}",
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="State node not found",
                            details=f"No ZooKeeper node exists for state key: {key}"
                        )
                    ),
                    suggestions=["Check if state exists", "Verify ZooKeeper connection", "Ensure proper state initialization"]
                )
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse state value for {key}")
                return create_partial_success_result(
                    data=None,
                    error_code="STATE_PARSE_ERROR",
                    message=f"Failed to parse state value for key: {key}",
                    fallback_data=FallbackData(
                        data=None,
                        health_status=HealthStatus(
                            level=HealthLevel.WARNING,
                            message="State parsing failed",
                            details=f"JSON decode error for state key: {key}"
                        )
                    ),
                    suggestions=["Check state data format", "Verify JSON encoding", "Review state serialization"]
                )
        
        return create_partial_success_result(
            data=None,
            error_code="STATE_NOT_FOUND",
            message=f"State not found for key: {key}",
            fallback_data=FallbackData(
                data=None,
                health_status=HealthStatus(
                    level=HealthLevel.WARNING,
                    message="State not available",
                    details=f"No state value found for key: {key} in any backend"
                )
            ),
            suggestions=["Initialize state value", "Check backend connectivity", "Verify state key"]
        )
    
    def register_leader_callback(self, callback: Callable[[bool], None]):
        """Register callback for leader status changes"""
        self.leader_callbacks.append(callback)
    
    def register_state_callback(self, key: str, callback: Callable[[Any], None]):
        """Register callback for state changes"""
        if key not in self._state_callbacks:
            self._state_callbacks[key] = []
        self._state_callbacks[key].append(callback)
    
    def get_cluster_info(self) -> Dict[str, Any]:
        """Get information about the cluster"""
        return {
            'node_id': self.node_id,
            'is_leader': self.is_leader,
            'current_leader': self.current_leader,
            'node_role': self.node_info.role.value,
            'cluster_size': len(self.cluster_nodes) + 1,  # Include self
            'nodes': {
                node_id: {
                    'hostname': node.hostname,
                    'ip_address': node.ip_address,
                    'role': node.role.value,
                    'healthy': node.is_healthy(),
                    'load': node.load
                }
                for node_id, node in self.cluster_nodes.items()
            },
            'backend': self.backend.value
        }
    
    def _parse_sentinel_config(self, connection_string: str) -> List[Tuple[str, int]]:
        """Parse sentinel configuration from connection string"""
        # Format: sentinel://host1:port1,host2:port2,host3:port3/service_name
        sentinels = []
        
        # Extract sentinel hosts
        if connection_string.startswith("sentinel://"):
            parts = connection_string.replace("sentinel://", "").split("/")
            hosts_part = parts[0]
            
            for host_port in hosts_part.split(","):
                host, port = host_port.split(":")
                sentinels.append((host, int(port)))
        
        return sentinels or [("localhost", 26379)]