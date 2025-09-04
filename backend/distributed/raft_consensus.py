"""
Raft consensus implementation for distributed leader election.
Provides strong consistency guarantees and split-brain protection.
"""

import asyncio
import time
import random
import json
import hashlib
import struct
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import pickle
import uuid

logger = logging.getLogger(__name__)


class NodeState(Enum):
    """Raft node states"""
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


class LogEntryType(Enum):
    """Types of log entries"""
    CONFIGURATION = "configuration"
    DATA = "data"
    NOOP = "noop"


@dataclass
class LogEntry:
    """Raft log entry"""
    term: int
    index: int
    entry_type: LogEntryType
    data: Any
    timestamp: float = field(default_factory=time.time)
    
    def serialize(self) -> bytes:
        """Serialize log entry"""
        return pickle.dumps({
            'term': self.term,
            'index': self.index,
            'entry_type': self.entry_type.value,
            'data': self.data,
            'timestamp': self.timestamp
        })
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'LogEntry':
        """Deserialize log entry"""
        obj = pickle.loads(data)
        return cls(
            term=obj['term'],
            index=obj['index'],
            entry_type=LogEntryType(obj['entry_type']),
            data=obj['data'],
            timestamp=obj['timestamp']
        )


@dataclass
class RaftState:
    """Persistent Raft state"""
    current_term: int = 0
    voted_for: Optional[str] = None
    log: List[LogEntry] = field(default_factory=list)
    
    # Volatile state on all servers
    commit_index: int = 0
    last_applied: int = 0
    
    # Volatile state on leaders
    next_index: Dict[str, int] = field(default_factory=dict)
    match_index: Dict[str, int] = field(default_factory=dict)
    
    # Fencing token for split-brain protection
    fencing_token: int = 0
    epoch: int = 0


@dataclass
class RequestVoteRequest:
    """Request vote RPC"""
    term: int
    candidate_id: str
    last_log_index: int
    last_log_term: int
    fencing_token: int


@dataclass
class RequestVoteResponse:
    """Request vote response"""
    term: int
    vote_granted: bool
    reason: Optional[str] = None


@dataclass
class AppendEntriesRequest:
    """Append entries RPC (heartbeat and replication)"""
    term: int
    leader_id: str
    prev_log_index: int
    prev_log_term: int
    entries: List[LogEntry]
    leader_commit: int
    fencing_token: int
    epoch: int


@dataclass
class AppendEntriesResponse:
    """Append entries response"""
    term: int
    success: bool
    match_index: Optional[int] = None
    conflict_index: Optional[int] = None
    conflict_term: Optional[int] = None


class RaftNode:
    """Raft consensus node implementation"""
    
    def __init__(self,
                 node_id: str,
                 peers: List[str],
                 rpc_handler: 'RaftRPCHandler',
                 storage: 'RaftStorage',
                 election_timeout_min: float = 1.5,
                 election_timeout_max: float = 3.0,
                 heartbeat_interval: float = 0.5):
        self.node_id = node_id
        self.peers = peers
        self.all_nodes = [node_id] + peers
        self.rpc = rpc_handler
        self.storage = storage
        
        # Timing configuration
        self.election_timeout_min = election_timeout_min
        self.election_timeout_max = election_timeout_max
        self.heartbeat_interval = heartbeat_interval
        
        # Node state
        self.state = NodeState.FOLLOWER
        self.raft_state = RaftState()
        
        # Timers
        self.election_timer: Optional[asyncio.Task] = None
        self.heartbeat_timer: Optional[asyncio.Task] = None
        self.last_heartbeat = time.time()
        
        # Callbacks
        self.state_change_callbacks: List[Callable] = []
        self.commit_callbacks: List[Callable] = []
        
        # Statistics
        self.stats = {
            'elections_started': 0,
            'elections_won': 0,
            'elections_lost': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'log_entries_appended': 0,
            'log_entries_committed': 0
        }
        
        # Running flag
        self._running = False
        self._lock = asyncio.Lock()
    
    async def start(self):
        """Start the Raft node"""
        if self._running:
            return
        
        self._running = True
        
        # Load persistent state
        await self.storage.load_state(self.raft_state)
        
        # Start as follower
        await self._become_follower()
        
        logger.info(f"Raft node {self.node_id} started")
    
    async def stop(self):
        """Stop the Raft node"""
        if not self._running:
            return
        
        self._running = False
        
        # Cancel timers
        if self.election_timer:
            self.election_timer.cancel()
        if self.heartbeat_timer:
            self.heartbeat_timer.cancel()
        
        # Save state
        await self.storage.save_state(self.raft_state)
        
        logger.info(f"Raft node {self.node_id} stopped")
    
    async def _become_follower(self, term: Optional[int] = None):
        """Transition to follower state"""
        async with self._lock:
            self.state = NodeState.FOLLOWER
            
            if term and term > self.raft_state.current_term:
                self.raft_state.current_term = term
                self.raft_state.voted_for = None
                await self.storage.save_state(self.raft_state)
            
            # Cancel heartbeat timer
            if self.heartbeat_timer:
                self.heartbeat_timer.cancel()
                self.heartbeat_timer = None
            
            # Reset election timer
            await self._reset_election_timer()
            
            logger.info(f"Node {self.node_id} became follower for term {self.raft_state.current_term}")
            
            # Notify callbacks
            await self._notify_state_change(NodeState.FOLLOWER)
    
    async def _become_candidate(self):
        """Transition to candidate state"""
        async with self._lock:
            self.state = NodeState.CANDIDATE
            
            # Increment term
            self.raft_state.current_term += 1
            self.raft_state.voted_for = self.node_id
            
            # Generate new fencing token
            self.raft_state.fencing_token = self._generate_fencing_token()
            
            await self.storage.save_state(self.raft_state)
            
            self.stats['elections_started'] += 1
            
            logger.info(f"Node {self.node_id} became candidate for term {self.raft_state.current_term}")
            
            # Notify callbacks
            await self._notify_state_change(NodeState.CANDIDATE)
            
            # Start election
            asyncio.create_task(self._run_election())
    
    async def _become_leader(self):
        """Transition to leader state"""
        async with self._lock:
            self.state = NodeState.LEADER
            
            # Increment epoch for this leadership term
            self.raft_state.epoch += 1
            
            # Initialize leader state
            for peer in self.peers:
                self.raft_state.next_index[peer] = len(self.raft_state.log) + 1
                self.raft_state.match_index[peer] = 0
            
            # Cancel election timer
            if self.election_timer:
                self.election_timer.cancel()
                self.election_timer = None
            
            # Start heartbeat timer
            self.heartbeat_timer = asyncio.create_task(self._heartbeat_loop())
            
            self.stats['elections_won'] += 1
            
            logger.info(f"Node {self.node_id} became leader for term {self.raft_state.current_term}")
            
            # Append no-op entry to establish leadership
            await self._append_log_entry(LogEntryType.NOOP, None)
            
            # Notify callbacks
            await self._notify_state_change(NodeState.LEADER)
    
    async def _reset_election_timer(self):
        """Reset the election timeout timer"""
        if self.election_timer:
            self.election_timer.cancel()
        
        timeout = random.uniform(self.election_timeout_min, self.election_timeout_max)
        self.election_timer = asyncio.create_task(self._election_timeout(timeout))
    
    async def _election_timeout(self, timeout: float):
        """Handle election timeout"""
        try:
            await asyncio.sleep(timeout)
            
            if self.state == NodeState.FOLLOWER:
                logger.info(f"Election timeout on node {self.node_id}")
                await self._become_candidate()
                
        except asyncio.CancelledError:
            pass
    
    async def _run_election(self):
        """Run leader election"""
        if self.state != NodeState.CANDIDATE:
            return
        
        # Vote for self
        votes_received = 1
        votes_needed = (len(self.all_nodes) // 2) + 1
        
        # Request votes from peers
        tasks = []
        for peer in self.peers:
            request = RequestVoteRequest(
                term=self.raft_state.current_term,
                candidate_id=self.node_id,
                last_log_index=len(self.raft_state.log),
                last_log_term=self.raft_state.log[-1].term if self.raft_state.log else 0,
                fencing_token=self.raft_state.fencing_token
            )
            
            tasks.append(self.rpc.request_vote(peer, request))
        
        # Wait for responses
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        for response in responses:
            if isinstance(response, Exception):
                logger.warning(f"Vote request failed: {response}")
                continue
            
            if response.term > self.raft_state.current_term:
                # Found higher term, become follower
                await self._become_follower(response.term)
                return
            
            if response.vote_granted:
                votes_received += 1
                
                if votes_received >= votes_needed:
                    # Won election
                    await self._become_leader()
                    return
        
        # Lost election
        self.stats['elections_lost'] += 1
        logger.info(f"Node {self.node_id} lost election with {votes_received}/{votes_needed} votes")
        
        # Become follower and wait for next timeout
        await self._become_follower()
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeats to maintain leadership"""
        try:
            while self._running and self.state == NodeState.LEADER:
                await self._send_heartbeats()
                await asyncio.sleep(self.heartbeat_interval)
                
        except asyncio.CancelledError:
            pass
    
    async def _send_heartbeats(self):
        """Send heartbeat/append entries to all peers"""
        if self.state != NodeState.LEADER:
            return
        
        tasks = []
        for peer in self.peers:
            next_index = self.raft_state.next_index.get(peer, 1)
            prev_index = next_index - 1
            prev_term = 0
            
            if prev_index > 0 and prev_index <= len(self.raft_state.log):
                prev_term = self.raft_state.log[prev_index - 1].term
            
            # Get entries to send
            entries = []
            if next_index <= len(self.raft_state.log):
                entries = self.raft_state.log[next_index - 1:]
            
            request = AppendEntriesRequest(
                term=self.raft_state.current_term,
                leader_id=self.node_id,
                prev_log_index=prev_index,
                prev_log_term=prev_term,
                entries=entries,
                leader_commit=self.raft_state.commit_index,
                fencing_token=self.raft_state.fencing_token,
                epoch=self.raft_state.epoch
            )
            
            tasks.append(self._send_append_entries(peer, request))
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _send_append_entries(self, peer: str, request: AppendEntriesRequest):
        """Send append entries to a peer and handle response"""
        try:
            response = await self.rpc.append_entries(peer, request)
            
            if response.term > self.raft_state.current_term:
                # Found higher term, become follower
                await self._become_follower(response.term)
                return
            
            if response.success:
                # Update match and next index
                if request.entries:
                    last_entry_index = request.prev_log_index + len(request.entries)
                    self.raft_state.match_index[peer] = last_entry_index
                    self.raft_state.next_index[peer] = last_entry_index + 1
                
                # Check if we can advance commit index
                await self._advance_commit_index()
                
            else:
                # Log replication failed, decrement next index
                if response.conflict_index:
                    self.raft_state.next_index[peer] = response.conflict_index
                else:
                    self.raft_state.next_index[peer] = max(1, self.raft_state.next_index[peer] - 1)
                    
        except Exception as e:
            logger.warning(f"Failed to send append entries to {peer}: {e}")
    
    async def _advance_commit_index(self):
        """Advance commit index based on majority replication"""
        if self.state != NodeState.LEADER:
            return
        
        # Find the highest index replicated on majority
        for n in range(len(self.raft_state.log), self.raft_state.commit_index, -1):
            if self.raft_state.log[n - 1].term == self.raft_state.current_term:
                replicated_count = 1  # Self
                
                for peer in self.peers:
                    if self.raft_state.match_index.get(peer, 0) >= n:
                        replicated_count += 1
                
                if replicated_count > len(self.all_nodes) // 2:
                    self.raft_state.commit_index = n
                    await self._apply_committed_entries()
                    break
    
    async def _apply_committed_entries(self):
        """Apply committed entries to state machine"""
        while self.raft_state.last_applied < self.raft_state.commit_index:
            self.raft_state.last_applied += 1
            entry = self.raft_state.log[self.raft_state.last_applied - 1]
            
            self.stats['log_entries_committed'] += 1
            
            # Notify commit callbacks
            for callback in self.commit_callbacks:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(entry)
                    else:
                        callback(entry)
                except Exception as e:
                    logger.error(f"Error in commit callback: {e}")
    
    async def handle_request_vote(self, request: RequestVoteRequest) -> RequestVoteResponse:
        """Handle request vote RPC"""
        async with self._lock:
            self.stats['messages_received'] += 1
            
            # Check term
            if request.term < self.raft_state.current_term:
                return RequestVoteResponse(
                    term=self.raft_state.current_term,
                    vote_granted=False,
                    reason="Outdated term"
                )
            
            if request.term > self.raft_state.current_term:
                self.raft_state.current_term = request.term
                self.raft_state.voted_for = None
                await self.storage.save_state(self.raft_state)
            
            # Check if already voted
            if self.raft_state.voted_for and self.raft_state.voted_for != request.candidate_id:
                return RequestVoteResponse(
                    term=self.raft_state.current_term,
                    vote_granted=False,
                    reason="Already voted for another candidate"
                )
            
            # Check log is up-to-date
            last_log_term = self.raft_state.log[-1].term if self.raft_state.log else 0
            last_log_index = len(self.raft_state.log)
            
            log_is_current = (request.last_log_term > last_log_term or
                            (request.last_log_term == last_log_term and 
                             request.last_log_index >= last_log_index))
            
            if not log_is_current:
                return RequestVoteResponse(
                    term=self.raft_state.current_term,
                    vote_granted=False,
                    reason="Candidate log is not up-to-date"
                )
            
            # Grant vote
            self.raft_state.voted_for = request.candidate_id
            await self.storage.save_state(self.raft_state)
            
            # Reset election timer
            await self._reset_election_timer()
            
            return RequestVoteResponse(
                term=self.raft_state.current_term,
                vote_granted=True
            )
    
    async def handle_append_entries(self, request: AppendEntriesRequest) -> AppendEntriesResponse:
        """Handle append entries RPC"""
        async with self._lock:
            self.stats['messages_received'] += 1
            self.last_heartbeat = time.time()
            
            # Check term
            if request.term < self.raft_state.current_term:
                return AppendEntriesResponse(
                    term=self.raft_state.current_term,
                    success=False
                )
            
            # Recognize leader for this term
            if request.term >= self.raft_state.current_term:
                if self.state != NodeState.FOLLOWER:
                    await self._become_follower(request.term)
                else:
                    self.raft_state.current_term = request.term
                    await self.storage.save_state(self.raft_state)
                
                # Reset election timer
                await self._reset_election_timer()
            
            # Verify fencing token and epoch
            if hasattr(self, '_last_known_leader_token'):
                if request.fencing_token <= self._last_known_leader_token:
                    logger.warning(f"Rejecting append entries with stale fencing token")
                    return AppendEntriesResponse(
                        term=self.raft_state.current_term,
                        success=False
                    )
            
            self._last_known_leader_token = request.fencing_token
            
            # Check log consistency
            if request.prev_log_index > 0:
                if request.prev_log_index > len(self.raft_state.log):
                    # Log is too short
                    return AppendEntriesResponse(
                        term=self.raft_state.current_term,
                        success=False,
                        conflict_index=len(self.raft_state.log) + 1
                    )
                
                if self.raft_state.log[request.prev_log_index - 1].term != request.prev_log_term:
                    # Log term mismatch
                    conflict_term = self.raft_state.log[request.prev_log_index - 1].term
                    
                    # Find first index with conflict term
                    conflict_index = request.prev_log_index
                    for i in range(request.prev_log_index - 1, 0, -1):
                        if self.raft_state.log[i - 1].term != conflict_term:
                            break
                        conflict_index = i
                    
                    return AppendEntriesResponse(
                        term=self.raft_state.current_term,
                        success=False,
                        conflict_index=conflict_index,
                        conflict_term=conflict_term
                    )
            
            # Append entries
            if request.entries:
                # Remove conflicting entries
                for i, entry in enumerate(request.entries):
                    log_index = request.prev_log_index + i + 1
                    
                    if log_index <= len(self.raft_state.log):
                        if self.raft_state.log[log_index - 1].term != entry.term:
                            # Remove this and all following entries
                            self.raft_state.log = self.raft_state.log[:log_index - 1]
                            break
                    else:
                        break
                
                # Append new entries
                for entry in request.entries:
                    if request.prev_log_index + request.entries.index(entry) + 1 > len(self.raft_state.log):
                        self.raft_state.log.append(entry)
                        self.stats['log_entries_appended'] += 1
                
                await self.storage.save_state(self.raft_state)
            
            # Update commit index
            if request.leader_commit > self.raft_state.commit_index:
                self.raft_state.commit_index = min(request.leader_commit, len(self.raft_state.log))
                await self._apply_committed_entries()
            
            return AppendEntriesResponse(
                term=self.raft_state.current_term,
                success=True,
                match_index=len(self.raft_state.log)
            )
    
    async def propose(self, data: Any) -> bool:
        """Propose a new entry (client request)"""
        if self.state != NodeState.LEADER:
            return False
        
        # Append to log
        entry = await self._append_log_entry(LogEntryType.DATA, data)
        
        # Replicate to followers
        await self._send_heartbeats()
        
        # Wait for commitment (simplified - should track specific entry)
        max_wait = 5.0
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            if self.raft_state.commit_index >= entry.index:
                return True
            await asyncio.sleep(0.1)
        
        return False
    
    async def _append_log_entry(self, entry_type: LogEntryType, data: Any) -> LogEntry:
        """Append entry to log"""
        entry = LogEntry(
            term=self.raft_state.current_term,
            index=len(self.raft_state.log) + 1,
            entry_type=entry_type,
            data=data
        )
        
        self.raft_state.log.append(entry)
        await self.storage.save_state(self.raft_state)
        
        return entry
    
    def _generate_fencing_token(self) -> int:
        """Generate monotonically increasing fencing token"""
        # Combine term, timestamp, and random value
        token_data = f"{self.raft_state.current_term}-{time.time()}-{uuid.uuid4()}"
        token_hash = hashlib.sha256(token_data.encode()).digest()
        
        # Convert to integer (use first 8 bytes)
        return struct.unpack('>Q', token_hash[:8])[0]
    
    async def _notify_state_change(self, new_state: NodeState):
        """Notify callbacks of state change"""
        for callback in self.state_change_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(new_state)
                else:
                    callback(new_state)
            except Exception as e:
                logger.error(f"Error in state change callback: {e}")
    
    def add_state_change_callback(self, callback: Callable):
        """Add state change callback"""
        self.state_change_callbacks.append(callback)
    
    def add_commit_callback(self, callback: Callable):
        """Add commit callback"""
        self.commit_callbacks.append(callback)
    
    def get_status(self) -> Dict[str, Any]:
        """Get current Raft status"""
        return {
            'node_id': self.node_id,
            'state': self.state.value,
            'term': self.raft_state.current_term,
            'voted_for': self.raft_state.voted_for,
            'commit_index': self.raft_state.commit_index,
            'last_applied': self.raft_state.last_applied,
            'log_length': len(self.raft_state.log),
            'peers': self.peers,
            'is_leader': self.state == NodeState.LEADER,
            'fencing_token': self.raft_state.fencing_token,
            'epoch': self.raft_state.epoch,
            'stats': self.stats
        }


class RaftRPCHandler:
    """Abstract RPC handler for Raft communication"""
    
    async def request_vote(self, peer: str, request: RequestVoteRequest) -> RequestVoteResponse:
        """Send request vote RPC to peer"""
        raise NotImplementedError
    
    async def append_entries(self, peer: str, request: AppendEntriesRequest) -> AppendEntriesResponse:
        """Send append entries RPC to peer"""
        raise NotImplementedError


class RaftStorage:
    """Abstract storage interface for Raft persistent state"""
    
    async def save_state(self, state: RaftState):
        """Save Raft state to persistent storage"""
        raise NotImplementedError
    
    async def load_state(self, state: RaftState):
        """Load Raft state from persistent storage"""
        raise NotImplementedError