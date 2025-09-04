"""
Proper async coordination layer for distributed systems.
Provides truly async operations for Zookeeper, Etcd, and other backends.
"""

import asyncio
import json
import time
import uuid
import struct
import hashlib
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import logging
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
import threading
from collections import defaultdict

try:
    from kazoo.client import KazooClient, KazooState
    from kazoo.exceptions import (
        KazooException, NodeExistsError, NoNodeError, 
        ConnectionLoss, SessionExpiredError, LockTimeout
    )
    from kazoo.recipe.lock import Lock as ZkLock
    from kazoo.recipe.election import Election as ZkElection
    from kazoo.recipe.partitioner import PartitionState
    from kazoo.protocol.states import EventType, WatchedEvent
    ZOOKEEPER_AVAILABLE = True
except ImportError:
    ZOOKEEPER_AVAILABLE = False
    KazooClient = None
    KazooState = None
    KazooException = Exception

try:
    import etcd3
    import etcd3.exceptions
    from etcd3.events import PutEvent, DeleteEvent
    ETCD_AVAILABLE = True
except ImportError:
    ETCD_AVAILABLE = False
    etcd3 = None

try:
    import consul
    import consul.aio
    CONSUL_AVAILABLE = True
except ImportError:
    CONSUL_AVAILABLE = False
    consul = None

logger = logging.getLogger(__name__)


class AsyncZookeeperClient:
    """Truly async wrapper for Zookeeper operations"""
    
    def __init__(self, hosts: str, loop: Optional[asyncio.AbstractEventLoop] = None):
        self.hosts = hosts
        self.loop = loop or asyncio.get_event_loop()
        self._client: Optional[KazooClient] = None
        self._executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="zk-async")
        self._watches: Dict[str, List[Callable]] = defaultdict(list)
        self._state_listeners: List[Callable] = []
        self._connected = False
        self._session_id: Optional[int] = None
        self._password: Optional[bytes] = None
        
    async def start(self, timeout: float = 10.0) -> bool:
        """Start the Zookeeper client asynchronously"""
        if not ZOOKEEPER_AVAILABLE:
            raise RuntimeError("Kazoo library not available")
        
        try:
            # Create client in thread pool
            self._client = await self.loop.run_in_executor(
                self._executor,
                self._create_client
            )
            
            # Start connection with timeout
            future = self.loop.create_future()
            
            def connection_listener(state):
                if state == KazooState.CONNECTED:
                    if not future.done():
                        self.loop.call_soon_threadsafe(
                            future.set_result, True
                        )
                elif state == KazooState.LOST:
                    self._connected = False
                    self._notify_state_listeners(state)
                elif state == KazooState.SUSPENDED:
                    self._connected = False
                    self._notify_state_listeners(state)
            
            self._client.add_listener(connection_listener)
            
            # Start client
            await self.loop.run_in_executor(
                self._executor,
                self._client.start,
                timeout
            )
            
            # Wait for connection
            try:
                await asyncio.wait_for(future, timeout=timeout)
                self._connected = True
                self._session_id = self._client.client_id[0] if self._client.client_id else None
                self._password = self._client.client_id[1] if self._client.client_id else None
                logger.info(f"Connected to Zookeeper at {self.hosts}")
                return True
            except asyncio.TimeoutError:
                logger.error(f"Connection to Zookeeper timed out after {timeout}s")
                await self.stop()
                return False
                
        except Exception as e:
            logger.error(f"Failed to start Zookeeper client: {e}")
            return False
    
    def _create_client(self) -> KazooClient:
        """Create Zookeeper client (runs in thread)"""
        return KazooClient(
            hosts=self.hosts,
            timeout=10.0,
            max_retries=3,
            retry_defaults={
                'max_tries': 3,
                'delay': 0.5,
                'backoff': 2,
                'max_delay': 60
            }
        )
    
    def _notify_state_listeners(self, state: KazooState):
        """Notify state change listeners"""
        for listener in self._state_listeners:
            try:
                if asyncio.iscoroutinefunction(listener):
                    asyncio.create_task(listener(state))
                else:
                    listener(state)
            except Exception as e:
                logger.error(f"Error in state listener: {e}")
    
    async def stop(self):
        """Stop the Zookeeper client"""
        if self._client:
            try:
                await self.loop.run_in_executor(
                    self._executor,
                    self._client.stop
                )
                await self.loop.run_in_executor(
                    self._executor,
                    self._client.close
                )
            except Exception as e:
                logger.error(f"Error stopping Zookeeper client: {e}")
            finally:
                self._client = None
                self._connected = False
        
        self._executor.shutdown(wait=False)
    
    async def create(self, 
                    path: str, 
                    value: bytes = b"", 
                    acl: Optional[List] = None,
                    ephemeral: bool = False,
                    sequence: bool = False,
                    makepath: bool = False) -> str:
        """Create a node asynchronously"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        return await self.loop.run_in_executor(
            self._executor,
            self._client.create,
            path, value, acl, ephemeral, sequence, makepath
        )
    
    async def exists(self, path: str, watch: Optional[Callable] = None) -> Optional[Any]:
        """Check if node exists asynchronously"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        if watch:
            self._watches[path].append(watch)
            
            def sync_watch(event: WatchedEvent):
                self.loop.call_soon_threadsafe(
                    self._handle_watch, path, event
                )
            
            return await self.loop.run_in_executor(
                self._executor,
                self._client.exists,
                path, sync_watch
            )
        else:
            return await self.loop.run_in_executor(
                self._executor,
                self._client.exists,
                path
            )
    
    async def get(self, path: str, watch: Optional[Callable] = None) -> Tuple[bytes, Any]:
        """Get node data asynchronously"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        if watch:
            self._watches[path].append(watch)
            
            def sync_watch(event: WatchedEvent):
                self.loop.call_soon_threadsafe(
                    self._handle_watch, path, event
                )
            
            return await self.loop.run_in_executor(
                self._executor,
                self._client.get,
                path, sync_watch
            )
        else:
            return await self.loop.run_in_executor(
                self._executor,
                self._client.get,
                path
            )
    
    async def set(self, path: str, value: bytes, version: int = -1) -> Any:
        """Set node data asynchronously"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        return await self.loop.run_in_executor(
            self._executor,
            self._client.set,
            path, value, version
        )
    
    async def delete(self, path: str, version: int = -1, recursive: bool = False):
        """Delete node asynchronously"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        return await self.loop.run_in_executor(
            self._executor,
            self._client.delete,
            path, version, recursive
        )
    
    async def get_children(self, path: str, watch: Optional[Callable] = None) -> List[str]:
        """Get children of a node asynchronously"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        if watch:
            self._watches[path].append(watch)
            
            def sync_watch(event: WatchedEvent):
                self.loop.call_soon_threadsafe(
                    self._handle_watch, path, event
                )
            
            return await self.loop.run_in_executor(
                self._executor,
                self._client.get_children,
                path, sync_watch
            )
        else:
            return await self.loop.run_in_executor(
                self._executor,
                self._client.get_children,
                path
            )
    
    def _handle_watch(self, path: str, event: WatchedEvent):
        """Handle watch events"""
        if path in self._watches:
            for watch_callback in self._watches[path]:
                try:
                    if asyncio.iscoroutinefunction(watch_callback):
                        asyncio.create_task(watch_callback(event))
                    else:
                        watch_callback(event)
                except Exception as e:
                    logger.error(f"Error in watch callback for {path}: {e}")
    
    async def ensure_path(self, path: str, acl: Optional[List] = None):
        """Ensure a path exists"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        return await self.loop.run_in_executor(
            self._executor,
            self._client.ensure_path,
            path, acl
        )
    
    @asynccontextmanager
    async def lock(self, path: str, identifier: Optional[str] = None, timeout: float = 10.0):
        """Async context manager for distributed locking"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        lock = self._client.Lock(path, identifier)
        
        # Acquire lock
        acquired = await self.loop.run_in_executor(
            self._executor,
            lock.acquire,
            blocking=True,
            timeout=timeout
        )
        
        if not acquired:
            raise LockTimeout(f"Failed to acquire lock on {path}")
        
        try:
            yield
        finally:
            # Release lock
            await self.loop.run_in_executor(
                self._executor,
                lock.release
            )
    
    async def transaction(self) -> 'AsyncTransaction':
        """Create an async transaction"""
        if not self._connected:
            raise ConnectionLoss("Not connected to Zookeeper")
        
        return AsyncTransaction(self)
    
    def add_state_listener(self, listener: Callable):
        """Add connection state listener"""
        self._state_listeners.append(listener)
    
    def remove_state_listener(self, listener: Callable):
        """Remove connection state listener"""
        if listener in self._state_listeners:
            self._state_listeners.remove(listener)


class AsyncTransaction:
    """Async wrapper for Zookeeper transactions"""
    
    def __init__(self, client: AsyncZookeeperClient):
        self.client = client
        self._transaction = client._client.transaction()
    
    def create(self, path: str, value: bytes = b"", 
              acl: Optional[List] = None, ephemeral: bool = False):
        """Add create operation to transaction"""
        self._transaction.create(path, value, acl, ephemeral)
        return self
    
    def set(self, path: str, value: bytes, version: int = -1):
        """Add set operation to transaction"""
        self._transaction.set_data(path, value, version)
        return self
    
    def delete(self, path: str, version: int = -1):
        """Add delete operation to transaction"""
        self._transaction.delete(path, version)
        return self
    
    def check(self, path: str, version: int):
        """Add version check to transaction"""
        self._transaction.check(path, version)
        return self
    
    async def commit(self) -> List[Any]:
        """Commit the transaction asynchronously"""
        return await self.client.loop.run_in_executor(
            self.client._executor,
            self._transaction.commit
        )


class AsyncEtcdClient:
    """Async wrapper for Etcd v3 operations"""
    
    def __init__(self, 
                 host: str = 'localhost',
                 port: int = 2379,
                 ca_cert: Optional[str] = None,
                 cert_key: Optional[str] = None,
                 cert_cert: Optional[str] = None,
                 timeout: Optional[int] = None,
                 user: Optional[str] = None,
                 password: Optional[str] = None):
        self.host = host
        self.port = port
        self.config = {
            'host': host,
            'port': port,
            'ca_cert': ca_cert,
            'cert_key': cert_key,
            'cert_cert': cert_cert,
            'timeout': timeout,
            'user': user,
            'password': password
        }
        self._client: Optional[etcd3.Etcd3Client] = None
        self._executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix="etcd-async")
        self._loop = asyncio.get_event_loop()
        self._watchers: Dict[str, asyncio.Task] = {}
        self._lease_renewers: Dict[int, asyncio.Task] = {}
    
    async def connect(self) -> bool:
        """Connect to Etcd cluster"""
        if not ETCD_AVAILABLE:
            raise RuntimeError("etcd3 library not available")
        
        try:
            # Create client
            self._client = await self._loop.run_in_executor(
                self._executor,
                lambda: etcd3.client(**{k: v for k, v in self.config.items() if v is not None})
            )
            
            # Test connection
            await self._loop.run_in_executor(
                self._executor,
                self._client.status
            )
            
            logger.info(f"Connected to Etcd at {self.host}:{self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Etcd: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Etcd"""
        # Cancel all watchers
        for task in self._watchers.values():
            task.cancel()
        
        # Cancel lease renewers
        for task in self._lease_renewers.values():
            task.cancel()
        
        # Close client
        if self._client:
            await self._loop.run_in_executor(
                self._executor,
                self._client.close
            )
            self._client = None
        
        self._executor.shutdown(wait=False)
    
    async def get(self, key: Union[str, bytes]) -> Tuple[Optional[bytes], Optional[Any]]:
        """Get a key's value"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.get,
            key
        )
    
    async def get_prefix(self, prefix: Union[str, bytes]) -> List[Tuple[bytes, Any]]:
        """Get all keys with a prefix"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        result = await self._loop.run_in_executor(
            self._executor,
            self._client.get_prefix,
            prefix
        )
        return list(result)
    
    async def put(self, key: Union[str, bytes], value: Union[str, bytes], 
                  lease: Optional[int] = None) -> bool:
        """Put a key-value pair"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.put,
            key, value, lease
        )
    
    async def delete(self, key: Union[str, bytes]) -> bool:
        """Delete a key"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.delete,
            key
        )
    
    async def delete_prefix(self, prefix: Union[str, bytes]) -> bool:
        """Delete all keys with a prefix"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.delete_prefix,
            prefix
        )
    
    async def lease(self, ttl: int) -> int:
        """Create a lease"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        lease = await self._loop.run_in_executor(
            self._executor,
            self._client.lease,
            ttl
        )
        
        # Start auto-renewal task
        lease_id = lease.id
        self._lease_renewers[lease_id] = asyncio.create_task(
            self._renew_lease(lease, ttl)
        )
        
        return lease_id
    
    async def _renew_lease(self, lease, ttl: int):
        """Auto-renew a lease"""
        try:
            while True:
                await asyncio.sleep(ttl / 3)  # Renew at 1/3 of TTL
                await self._loop.run_in_executor(
                    self._executor,
                    lease.refresh
                )
        except asyncio.CancelledError:
            # Revoke lease on cancellation
            try:
                await self._loop.run_in_executor(
                    self._executor,
                    lease.revoke
                )
            except Exception:
                pass
            raise
        except Exception as e:
            logger.error(f"Lease renewal failed: {e}")
    
    async def revoke_lease(self, lease_id: int):
        """Revoke a lease"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        # Cancel auto-renewal
        if lease_id in self._lease_renewers:
            self._lease_renewers[lease_id].cancel()
            del self._lease_renewers[lease_id]
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.revoke_lease,
            lease_id
        )
    
    async def watch(self, key: Union[str, bytes], 
                   callback: Callable[[WatchedEvent], None]) -> str:
        """Watch a key for changes"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        watch_id = str(uuid.uuid4())
        
        async def watch_task():
            try:
                # Create watch iterator in thread
                events_iterator = await self._loop.run_in_executor(
                    self._executor,
                    self._client.watch,
                    key
                )
                
                # Process events
                while True:
                    events = await self._loop.run_in_executor(
                        self._executor,
                        next,
                        events_iterator,
                        None
                    )
                    
                    if events is None:
                        break
                    
                    for event in events:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(event)
                            else:
                                callback(event)
                        except Exception as e:
                            logger.error(f"Error in watch callback: {e}")
                            
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Watch error for {key}: {e}")
        
        self._watchers[watch_id] = asyncio.create_task(watch_task())
        return watch_id
    
    async def cancel_watch(self, watch_id: str):
        """Cancel a watch"""
        if watch_id in self._watchers:
            self._watchers[watch_id].cancel()
            del self._watchers[watch_id]
    
    async def transaction(self, 
                         compare: List[Any],
                         success: List[Any],
                         failure: Optional[List[Any]] = None) -> Tuple[bool, List[Any]]:
        """Execute a transaction"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.transaction,
            compare, success, failure
        )
    
    @asynccontextmanager
    async def lock(self, name: str, ttl: int = 60):
        """Distributed lock using Etcd"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        lock = self._client.lock(name, ttl)
        
        # Acquire lock
        acquired = await self._loop.run_in_executor(
            self._executor,
            lock.acquire
        )
        
        if not acquired:
            raise RuntimeError(f"Failed to acquire lock: {name}")
        
        try:
            yield
        finally:
            # Release lock
            await self._loop.run_in_executor(
                self._executor,
                lock.release
            )
    
    async def add_member(self, urls: List[str]) -> int:
        """Add a member to the cluster"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        member = await self._loop.run_in_executor(
            self._executor,
            self._client.add_member,
            urls
        )
        return member.id
    
    async def remove_member(self, member_id: int):
        """Remove a member from the cluster"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.remove_member,
            member_id
        )
    
    async def list_members(self) -> List[Any]:
        """List cluster members"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        return await self._loop.run_in_executor(
            self._executor,
            self._client.members
        )
    
    async def status(self) -> Dict[str, Any]:
        """Get cluster status"""
        if not self._client:
            raise RuntimeError("Not connected to Etcd")
        
        status = await self._loop.run_in_executor(
            self._executor,
            self._client.status
        )
        
        return {
            'version': status.version,
            'db_size': status.db_size,
            'leader': status.leader,
            'raft_index': status.raft_index,
            'raft_term': status.raft_term
        }


class AsyncConsulClient:
    """Async wrapper for Consul operations using consul.aio"""
    
    def __init__(self,
                 host: str = '127.0.0.1',
                 port: int = 8500,
                 token: Optional[str] = None,
                 scheme: str = 'http',
                 consistency: str = 'default',
                 dc: Optional[str] = None,
                 verify: bool = True):
        self.config = {
            'host': host,
            'port': port,
            'token': token,
            'scheme': scheme,
            'consistency': consistency,
            'dc': dc,
            'verify': verify
        }
        self._client: Optional[consul.aio.Consul] = None
    
    async def connect(self) -> bool:
        """Connect to Consul"""
        if not CONSUL_AVAILABLE:
            raise RuntimeError("python-consul library not available")
        
        try:
            self._client = consul.aio.Consul(**self.config)
            
            # Test connection
            await self._client.agent.self()
            
            logger.info(f"Connected to Consul at {self.config['host']}:{self.config['port']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to Consul: {e}")
            return False
    
    async def disconnect(self):
        """Disconnect from Consul"""
        if self._client:
            await self._client.close()
            self._client = None
    
    async def kv_get(self, key: str, index: Optional[int] = None, 
                     wait: Optional[str] = None) -> Tuple[Optional[int], Optional[Dict]]:
        """Get a key from KV store"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        return await self._client.kv.get(key, index=index, wait=wait)
    
    async def kv_put(self, key: str, value: Union[str, bytes], 
                    cas: Optional[int] = None, acquire: Optional[str] = None,
                    release: Optional[str] = None) -> bool:
        """Put a key in KV store"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        return await self._client.kv.put(key, value, cas=cas, 
                                         acquire=acquire, release=release)
    
    async def kv_delete(self, key: str, cas: Optional[int] = None) -> bool:
        """Delete a key from KV store"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        return await self._client.kv.delete(key, cas=cas)
    
    @asynccontextmanager
    async def lock(self, key: str, session_id: Optional[str] = None, 
                   value: Optional[bytes] = None, ttl: int = 15):
        """Distributed lock using Consul sessions"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        # Create session if not provided
        if not session_id:
            session_id = await self._client.session.create(
                ttl=ttl,
                behavior='delete',
                lock_delay=0
            )
        
        lock_key = f"locks/{key}"
        acquired = False
        
        try:
            # Try to acquire lock
            acquired = await self._client.kv.put(
                lock_key,
                value or b"locked",
                acquire=session_id
            )
            
            if not acquired:
                raise RuntimeError(f"Failed to acquire lock: {key}")
            
            yield
            
        finally:
            if acquired:
                # Release lock
                await self._client.kv.put(
                    lock_key,
                    b"",
                    release=session_id
                )
            
            # Destroy session if we created it
            if not session_id:
                await self._client.session.destroy(session_id)
    
    async def register_service(self, 
                              name: str,
                              service_id: Optional[str] = None,
                              address: Optional[str] = None,
                              port: Optional[int] = None,
                              tags: Optional[List[str]] = None,
                              check: Optional[Dict] = None) -> bool:
        """Register a service"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        return await self._client.agent.service.register(
            name=name,
            service_id=service_id,
            address=address,
            port=port,
            tags=tags,
            check=check
        )
    
    async def deregister_service(self, service_id: str) -> bool:
        """Deregister a service"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        return await self._client.agent.service.deregister(service_id)
    
    async def health_service(self, service: str, passing: bool = True) -> List[Dict]:
        """Get healthy service instances"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        _, nodes = await self._client.health.service(service, passing=passing)
        return nodes
    
    async def watch_key(self, key: str, callback: Callable, index: int = 0):
        """Watch a key for changes"""
        if not self._client:
            raise RuntimeError("Not connected to Consul")
        
        last_index = index
        
        while True:
            try:
                # Long poll for changes
                new_index, data = await self._client.kv.get(
                    key,
                    index=last_index,
                    wait='30s'
                )
                
                if new_index != last_index:
                    last_index = new_index
                    
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                        
            except Exception as e:
                logger.error(f"Watch error for {key}: {e}")
                await asyncio.sleep(5)  # Backoff on error